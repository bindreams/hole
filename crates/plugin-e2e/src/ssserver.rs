//! In-process shadowsocks server fixtures.
//!
//! [`start_real_ss_server`] spins up a plain `shadowsocks_service::server::Server`
//! on a HELD loopback port (no plugin). The `_with_plugin_*` helpers front a held
//! ss-server with a SERVER-mode plugin chain via [`spawn_ss_with_plugin`] — a
//! `garter::ChainRunner(Mode::Server)`, symmetric to the client-side
//! [`crate::roundtrip::run_roundtrip`]. Readiness is inferred from the plugin's
//! own sitrep `hello` ([`garter::ReadinessMode::Auto`]); the public port is
//! pre-allocated and retried on the in-band `bind_conflict` signal. There is NO
//! `shadowsocks-service` `PluginConfig` (its bind-and-drop rendezvous-port juggling
//! is the #197 race; and it HANGS the test process on an assertion failure by
//! leaving the plugin subprocess tree unreaped). The returned [`PluginServer`]
//! must be kept alive for the duration of the test that uses it.

use crate::certs::TestCerts;
use base64::Engine as _;
use garter::{BinaryPlugin, ChainRunner, Mode, PluginEnv, ReadinessMode, StartError};
use shadowsocks::config::{Mode as SsMode, ServerConfig};
use shadowsocks::crypto::CipherKind;
use shadowsocks_service::server::ServerBuilder as SsServerBuilder;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use util::port_alloc::{self, Protocols};

pub const TEST_METHOD_STR: &str = "aes-256-gcm";
pub const TEST_METHOD: CipherKind = CipherKind::AES_256_GCM;
pub const TEST_PASSWORD: &str = "test-password-1234";

/// Generate a fresh random "password" for the given cipher in the format the
/// cipher expects.
///
/// - For ALL AEAD-2022 ciphers (`2022-blake3-*`, all four variants), the
///   "password" is a base64-encoded random key of `cipher.key_len()` bytes.
///   Passing an arbitrary string fails inside `ServerConfig::new`.
/// - For all other ciphers (stream, AEAD v1), the password is just an
///   arbitrary string and we hex-encode the random bytes for legibility.
pub fn random_password_for(method: CipherKind) -> String {
    use rand::Rng;
    let key_len = method.key_len();
    let mut bytes = vec![0u8; key_len];
    rand::rng().fill_bytes(&mut bytes);
    if method.is_aead_2022() {
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    } else {
        hex::encode(&bytes)
    }
}

/// Spin up a real shadowsocks server on a freshly-allocated loopback
/// port with the given cipher/password. Returns the bound TCP address
/// and a handle to the running server task. The server relays anything
/// the client asks for.
///
/// The fixture owns port allocation and the bind, retrying both as a
/// unit via [`port_alloc::bind_ephemeral`]. This absorbs the residual
/// probe-drop-to-bind TOCTOU on Windows, where independent TCP/UDP
/// excluded-port-range tables can reject a freshly-allocated port on
/// the paired transport. shadowsocks-rust's `ServerBuilder` clones
/// `svr_cfg` when constructing both `TcpServer` and `UdpServer`, so
/// passing port 0 would hand the two sockets distinct kernel-allocated
/// ports — the explicit allocation here keeps them on the same port.
pub async fn start_real_ss_server(method: CipherKind, password: &str) -> (SocketAddr, JoinHandle<()>) {
    let (port, server) = port_alloc::bind_ephemeral(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Protocols::TCP | Protocols::UDP,
        |port| {
            let password = password.to_string();
            async move {
                let mut svr_cfg = ServerConfig::new(("127.0.0.1", port), password, method).unwrap();
                svr_cfg.set_mode(SsMode::TcpAndUdp);
                SsServerBuilder::new(svr_cfg).build().await
            }
        },
    )
    .await
    .expect("start_real_ss_server: bind/build failed");

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let handle = tokio::spawn(async move {
        // Server::run consumes self and only ever returns Err on teardown
        // ("server exited unexpectedly"). The test ignores the error.
        let _ = server.run().await;
    });

    (addr, handle)
}

/// Front a held ss-server with a SERVER-mode plugin (websocket, no TLS) and
/// return the public address external clients connect to. The public port is
/// allocated for `Protocols::TCP` only — WS is TCP per RFC 6455.
pub async fn start_real_ss_server_with_plugin_ws(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
) -> (SocketAddr, PluginServer) {
    spawn_ss_with_plugin(
        method,
        password,
        Protocols::TCP,
        plugin_path,
        "server;host=cloudfront.com;path=/",
    )
    .await
}

/// Front a held ss-server with a SERVER-mode plugin (websocket + TLS). Same
/// shape as [`start_real_ss_server_with_plugin_ws`] but with TLS enabled and the
/// cert+key from `certs` mounted on the server side.
pub async fn start_real_ss_server_with_plugin_ws_tls(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    certs: &TestCerts,
) -> (SocketAddr, PluginServer) {
    let opts = format!("server;host=cloudfront.com;path=/;tls;{}", certs.plugin_opts_fragment());
    spawn_ss_with_plugin(method, password, Protocols::TCP, plugin_path, &opts).await
}

/// Front a held ss-server with a QUIC-transport SERVER-mode plugin. QUIC
/// auto-enables TLS in `generateConfig`
/// ([crates/ex-ray/config.go](../../ex-ray/config.go), the `case "quic"` arm
/// sets `*tlsEnabled = true`), so the cert+key pair must still be supplied. The
/// public port is allocated for `Protocols::UDP` because QUIC runs over UDP.
///
/// Works with either the **galoshes** binary (which drives its embedded ex-ray)
/// or a bare **ex-ray** binary: since bindreams/hole#421, ex-ray UDP-probes its
/// inbound and reports `transports:["udp"]` for server+quic.
pub async fn start_real_ss_server_with_plugin_quic(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    certs: &TestCerts,
) -> (SocketAddr, PluginServer) {
    let opts = format!("server;host=cloudfront.com;mode=quic;{}", certs.plugin_opts_fragment());
    spawn_ss_with_plugin(method, password, Protocols::UDP, plugin_path, &opts).await
}

/// Keeps a plugin-fronted ss-server alive for a test's duration. Hold it for as
/// long as the server must stay up.
///
/// Cleanup: `Drop` cancels the chain's token (SIP003u graceful-stop signal).
/// Final reaping of the galoshes/ex-ray subprocess is guaranteed by
/// `BinaryPlugin`'s `kill_on_drop`: when this guard drops, the chain + ss-server
/// `JoinHandle`s drop (detaching their tasks), and the suite's per-test `rt()`
/// runtime is then dropped at the end of `block_on`, which drops those tasks'
/// futures — dropping the chain's `tokio::process::Child` and killing the
/// subprocess. nextest runs each test in its own process, so a `kill`-orphaned
/// inner ex-ray (when graceful stop didn't run, e.g. on a test panic) is reaped
/// by the OS when that per-test process exits — it does NOT block process exit
/// (the load-bearing fail-fast property; see the #197 hang investigation).
pub struct PluginServer {
    cancel: CancellationToken,
    _chain: JoinHandle<garter::Result<()>>,
    _ss: JoinHandle<()>,
}

impl Drop for PluginServer {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Inner helper used by every `_with_plugin_*` variant: front a plain held
/// ss-server with a single-plugin `ChainRunner(Mode::Server)` and return the
/// public address. Symmetric to the client-side
/// [`crate::roundtrip::run_roundtrip`]; readiness is inferred from the plugin's
/// own sitrep `hello` ([`ReadinessMode::Auto`]).
///
/// The public port is PRE-ALLOCATED. ex-ray rejects port 0 (v2ray-core does not
/// expose an OS-assigned bound port — see crates/ex-ray/main.go), so an ephemeral
/// public listener is impossible. The narrow window between `free_port` releasing
/// the probe socket and the plugin subprocess binding the port is closed by
/// retrying on the in-band `StartError::BindConflict` signal with a fresh port —
/// the same unbounded "no budget" discipline as `port_alloc::bind_ephemeral`
/// (terminates only on ready or a non-race error; the nextest per-test timeout is
/// the failure-to-human bound).
async fn spawn_ss_with_plugin(
    method: CipherKind,
    password: &str,
    protocols: Protocols,
    plugin_path: &str,
    plugin_opts: &str,
) -> (SocketAddr, PluginServer) {
    // Plain ss-server on a HELD loopback port (no plugin). The plugin chain
    // forwards decapsulated traffic here; the port is held for the server's
    // lifetime, so there is no bind-and-drop rendezvous race (the #197 class).
    let (ss_addr, ss_handle) = start_real_ss_server(method, password).await;

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;

        // Pre-allocate the public port. `free_port` (not `bind_ephemeral`)
        // because the port must be returned to us so the plugin SUBPROCESS can
        // bind it out-of-process — the documented exception to the bind_ephemeral
        // rule (CONTRIBUTING.md#port-allocation / clippy.toml).
        #[allow(clippy::disallowed_methods)]
        let public_port = port_alloc::free_port(IpAddr::V4(Ipv4Addr::LOCALHOST), protocols)
            .await
            .expect("spawn_ss_with_plugin: allocate public port");

        // Sanctioned: plugin-e2e is outside the bridge cancel chain (clippy.toml
        // `CancellationToken::new` rule); this token owns the chain's whole life
        // (mirrors roundtrip.rs).
        #[allow(clippy::disallowed_methods)]
        let cancel = CancellationToken::new();
        let (ready_tx, ready_rx) = oneshot::channel();

        let plugin = BinaryPlugin::new(plugin_path, Some(plugin_opts)).readiness(ReadinessMode::Auto);
        let runner = ChainRunner::new()
            .mode(Mode::Server)
            .add(Box::new(plugin))
            .cancel_token(cancel.clone())
            .on_ready(ready_tx);
        let env = PluginEnv {
            local_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: ss_addr.port(),
            remote_host: "127.0.0.1".to_string(),
            remote_port: public_port,
            plugin_options: None, // BinaryPlugin carries its own SS_PLUGIN_OPTIONS
        };
        let chain = tokio::spawn(async move { runner.run(env).await });

        // Bound readiness: a wedged server plugin chain must FAIL LOUDLY, not
        // hang the fixture forever — a fixture hang yields no captured output and
        // wedges the whole serial group (the #197/#518 lesson). The chain becomes
        // ready in seconds; this generous bound only catches a genuine never-ready.
        // Class-2 subprocess failure-bound surfaced to a human, not intra-process sync.
        match tokio::time::timeout(std::time::Duration::from_secs(60), ready_rx).await {
            Err(_elapsed) => {
                // Don't `chain.await` here (unlike the Fatal/recv arms below): the
                // chain is wedged — that's why readiness timed out — so awaiting it
                // could re-hang. `cancel` signals it; BinaryPlugin's kill_on_drop
                // reaps the subprocess when the panicking process tears down.
                cancel.cancel();
                panic!("server plugin did not become ready within 60s (attempt {attempt})");
            }
            Ok(Ok(Ok(chain_ready))) => {
                return (
                    chain_ready.listen,
                    PluginServer {
                        cancel,
                        _chain: chain,
                        _ss: ss_handle,
                    },
                );
            }
            Ok(Ok(Err(StartError::BindConflict { addr, errno }))) => {
                // Adaptive milestone logging (mirrors port_alloc) so a stuck loop
                // is visible without flooding the happy path.
                if attempt == 1 || attempt.is_multiple_of(10) {
                    tracing::info!(
                        attempt,
                        %addr,
                        errno,
                        "server plugin public-port bind conflict; retrying with a fresh port"
                    );
                }
                cancel.cancel();
                let _ = chain.await;
                // retry with a fresh public_port
            }
            Ok(Ok(Err(StartError::Fatal { detail, errno }))) => {
                cancel.cancel();
                let _ = chain.await;
                panic!("server plugin failed to start: {detail} (errno={errno:?})");
            }
            Ok(Err(_recv)) => {
                cancel.cancel();
                let outcome = chain.await;
                panic!("server plugin exited before readiness: {outcome:?}");
            }
        }
    }
}
