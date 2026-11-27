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
//! races, and it HANGS the test process on an assertion failure by leaving the
//! plugin subprocess tree unreaped). The returned [`PluginServer`]
//! must be kept alive for the duration of the test that uses it.

use crate::certs::TestCerts;
use crate::ports;
use base64::Engine as _;
use garter::{BinaryPlugin, ChainRunner, Mode, PluginEnv, ReadinessMode, StartError};
use shadowsocks::config::{Mode as SsMode, ServerConfig};
use shadowsocks::crypto::CipherKind;
use shadowsocks::net::ConnectOpts;
use shadowsocks_service::server::ServerBuilder as SsServerBuilder;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
/// The levels [`route_logs`] takes.
pub use tracing_log::log::LevelFilter;
use util::port_alloc::{self, Protocols};

/// Where a fixture server listens unless it is told otherwise.
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

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

/// Route this process's `log` records at `max_level` and above into `tracing`. The ss server logs through `log`, and
/// the test subscriber installs no `LogTracer`, so without this its relay lines and errors go nowhere. Records below
/// `max_level` are never allocated; the subscriber's filter still decides which of the rest are written.
///
/// The first call decides the level. If another `log` logger is already installed, the records are not routed and
/// stderr says so (`eprintln!`, which no log filter can drop).
pub fn route_logs(max_level: LevelFilter) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if let Err(e) = tracing_log::LogTracer::builder().with_max_level(max_level).init() {
            eprintln!("[ss-server-logs] not routed into tracing: {e}");
        }
    });
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
    start_real_ss_server_via(method, password, LOOPBACK, None).await
}

/// A network interface of the machine and its own IPv4 address: where a server's dials leave from.
#[derive(Clone, Debug)]
pub struct OutboundInterface {
    /// Its friendly name on Windows, its device name elsewhere.
    pub name: String,
    pub ipv4: Ipv4Addr,
}

/// [`start_real_ss_server`] listening on `listen` (TCP and UDP, one port), whose own dials to its targets leave through
/// `outbound`, not through the routing table. Loopback and `None` are
/// [`start_real_ss_server`].
///
/// A server on the machine a full tunnel runs on needs this: dialing through the routing table sends its dials back
/// into the tunnel, which hands them to the server again. Naming the interface (`bind_interface`) is not enough:
/// shadowsocks-service 1.24.0 sends an IPv4 UDP relay on an IPv6 socket, and on Windows that socket is held to the
/// interface only by `IPV6_UNICAST_IF`. A datagram on it followed the tunnel's split route into the TUN (measured: one
/// NTP request became 256 relays and stalled the galoshes transport). On Windows the server also binds to the
/// interface's own address (`bind_local_addr`), which holds that socket. TCP is held by the interface alone, an IPv4
/// socket with `IP_UNICAST_IF` (measured: the page requests of the journey leave by it).
///
/// Binding the IPv4 address makes the server's sockets IPv4-only: on Windows a dial to a native IPv6 target fails, TCP
/// with `WSAENETUNREACH` and UDP with `WSAEADDRNOTAVAIL` (measured with a socket bound to a mapped address, as
/// shadowsocks binds it). macOS gets no such bind: there shadowsocks sets `IPV6_BOUND_IF` after binding the mapped
/// address, and that fails with `EINVAL` on every UDP relay (measured on a CI runner).
pub async fn start_real_ss_server_via(
    method: CipherKind,
    password: &str,
    listen: IpAddr,
    outbound: Option<&OutboundInterface>,
) -> (SocketAddr, JoinHandle<()>) {
    let (port, server) = port_alloc::bind_ephemeral(listen, Protocols::TCP | Protocols::UDP, |port| {
        let password = password.to_string();
        let outbound = outbound.cloned();
        async move {
            let mut svr_cfg = ServerConfig::new(SocketAddr::new(listen, port), password, method).unwrap();
            svr_cfg.set_mode(SsMode::TcpAndUdp);
            let mut builder = SsServerBuilder::new(svr_cfg);
            if let Some(outbound) = outbound {
                builder.set_connect_opts(ConnectOpts {
                    bind_interface: Some(outbound.name),
                    bind_local_addr: cfg!(windows).then(|| SocketAddr::new(IpAddr::V4(outbound.ipv4), 0)),
                    ..ConnectOpts::default()
                });
            }
            builder.build().await
        }
    })
    .await
    .expect("start_real_ss_server: bind/build failed");

    let addr = SocketAddr::new(listen, port);
    let handle = tokio::spawn(async move {
        // Server::run consumes self and only ever returns Err on teardown
        // ("server exited unexpectedly"). The test ignores the error.
        let _ = server.run().await;
    });

    (addr, handle)
}

/// Server-mode options for the plain-WS fixture. Tests that need to pin an
/// extra directive build on this.
pub const WS_SERVER_OPTS: &str = "server;host=cloudfront.com;path=/";

/// Front a held ss-server with a SERVER-mode plugin (websocket, no TLS) and
/// return the public address external clients connect to. The public port is
/// reserved for `Protocols::TCP` only — ex-ray's WS server binds a single TCP
/// listener there, nothing else.
pub async fn start_real_ss_server_with_plugin_ws(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
) -> (SocketAddr, PluginServer) {
    start_real_ss_server_with_plugin_ws_via(method, password, plugin_path, LOOPBACK, None).await
}

/// [`start_real_ss_server_with_plugin_ws`] whose plugin listens on `listen` and whose ss-server dials its targets out
/// of `outbound`, as [`start_real_ss_server_via`] does; the ss-server itself stays on loopback behind the plugin.
/// Loopback and `None` are [`start_real_ss_server_with_plugin_ws`].
pub async fn start_real_ss_server_with_plugin_ws_via(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    listen: IpAddr,
    outbound: Option<&OutboundInterface>,
) -> (SocketAddr, PluginServer) {
    spawn_ss_with_plugin(
        method,
        password,
        Protocols::TCP,
        plugin_path,
        WS_SERVER_OPTS,
        listen,
        outbound,
    )
    .await
}

/// [`start_real_ss_server_with_plugin_ws`] with the server-mode options string
/// supplied by the caller, for tests that pin a specific plugin directive.
pub async fn start_real_ss_server_with_plugin_ws_opts(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    opts: &str,
) -> (SocketAddr, PluginServer) {
    spawn_ss_with_plugin(method, password, Protocols::TCP, plugin_path, opts, LOOPBACK, None).await
}

/// Front a held ss-server with a SERVER-mode plugin (websocket + TLS). Same
/// shape as [`start_real_ss_server_with_plugin_ws`] but with TLS enabled and the
/// cert+key from `certs` mounted on the server side. TLS wraps the same single
/// TCP listener, so the public port is still `Protocols::TCP` only.
pub async fn start_real_ss_server_with_plugin_ws_tls(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    certs: &TestCerts,
) -> (SocketAddr, PluginServer) {
    let opts = format!("server;host=cloudfront.com;path=/;tls;{}", certs.plugin_opts_fragment());
    spawn_ss_with_plugin(method, password, Protocols::TCP, plugin_path, &opts, LOOPBACK, None).await
}

/// Front a held ss-server with a QUIC-transport SERVER-mode plugin. QUIC
/// auto-enables TLS in `generateConfig`
/// ([crates/ex-ray/config.go](../../ex-ray/config.go), the `case "quic"` arm
/// sets `*tlsEnabled = true`), so the cert+key pair must still be supplied. The
/// public port is reserved for `Protocols::UDP` only — ex-ray's QUIC server
/// binds a single UDP socket there, nothing else.
///
/// Works with either the **galoshes** binary (which drives its embedded ex-ray)
/// or a bare **ex-ray** binary: ex-ray UDP-probes its inbound and reports
/// `transports:["udp"]` for server+quic.
pub async fn start_real_ss_server_with_plugin_quic(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    certs: &TestCerts,
) -> (SocketAddr, PluginServer) {
    let opts = format!("server;host=cloudfront.com;mode=quic;{}", certs.plugin_opts_fragment());
    spawn_ss_with_plugin(method, password, Protocols::UDP, plugin_path, &opts, LOOPBACK, None).await
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
/// (the load-bearing fail-fast property).
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
/// own sitrep `hello` ([`ReadinessMode::Auto`]). The plugin's public endpoint is on `listen`.
///
/// The public port is PRE-ALLOCATED. ex-ray rejects port 0 (v2ray-core does not
/// expose an OS-assigned bound port — see crates/ex-ray/main.go), so an ephemeral
/// public listener is impossible. `public_bind_protocols` names what the plugin
/// SUBPROCESS binds there — TCP for WS/WS-TLS, UDP for QUIC — not a property of
/// the wire transport. The narrow window between the reservation releasing its
/// probe socket and the plugin subprocess binding the port is closed by retrying
/// on the in-band `StartError::BindConflict` signal with a fresh port — the same
/// unbounded "no budget" discipline as `port_alloc::bind_ephemeral` (terminates
/// only on ready or a non-race error; the failure-to-human bound is the
/// `test-plugin-e2e` step's `timeout-minutes` in `ci.yaml`, which fails the
/// step with its log kept — the milestone logging below leaves evidence if
/// that fires).
async fn spawn_ss_with_plugin(
    method: CipherKind,
    password: &str,
    public_bind_protocols: Protocols,
    plugin_path: &str,
    plugin_opts: &str,
    listen: IpAddr,
    outbound: Option<&OutboundInterface>,
) -> (SocketAddr, PluginServer) {
    // Plain ss-server on a HELD loopback port (no plugin). The plugin chain
    // forwards decapsulated traffic here; the port is held for the server's
    // lifetime, so there is no bind-and-drop rendezvous race.
    let (ss_addr, ss_handle) = start_real_ss_server_via(method, password, LOOPBACK, outbound).await;

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;

        // Pre-allocate the public port through the crate's reservation seam —
        // the port must be returned to us so the plugin SUBPROCESS can bind it
        // out-of-process.
        let public_port = ports::reserve_public(listen, public_bind_protocols)
            .await
            .expect("spawn_ss_with_plugin: allocate public port")
            .port();

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
            local_host: LOOPBACK,
            local_port: ss_addr.port(),
            remote_host: listen.to_string(),
            remote_port: public_port,
            plugin_options: None, // BinaryPlugin carries its own SS_PLUGIN_OPTIONS
        };
        let chain = tokio::spawn(async move { runner.run(env).await });

        // Bound readiness: a wedged server plugin chain must FAIL LOUDLY, not
        // hang the fixture forever — a fixture hang yields no captured output and
        // wedges the whole serial group. The chain becomes
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
