//! In-process shadowsocks server fixtures.
//!
//! Each helper spins up a real `shadowsocks_service::server::Server`
//! bound to a loopback port the fixture allocates and binds in a single
//! retry-wrapped operation via
//! [`hole_common::port_alloc::bind_with_retry`], mirroring the
//! [`crate::dns::server::LocalDnsServer::bind`] pattern. The returned
//! [`JoinHandle`]s own the server loop and must be kept alive for the
//! duration of the test that uses them.

use crate::test_support::certs::TestCerts;
use base64::Engine as _;
use hole_common::port_alloc::{self, Protocols};
use shadowsocks::config::{Mode, ServerConfig};
use shadowsocks::crypto::CipherKind;
use shadowsocks::plugin::PluginConfig;
use shadowsocks_service::server::ServerBuilder as SsServerBuilder;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use tokio::task::JoinHandle;

pub(crate) const TEST_METHOD_STR: &str = "aes-256-gcm";
pub(crate) const TEST_METHOD: CipherKind = CipherKind::AES_256_GCM;
pub(crate) const TEST_PASSWORD: &str = "test-password-1234";

/// Generate a fresh random "password" for the given cipher in the format the
/// cipher expects.
///
/// - For ALL AEAD-2022 ciphers (`2022-blake3-*`, all four variants), the
///   "password" is a base64-encoded random key of `cipher.key_len()` bytes.
///   Passing an arbitrary string fails inside `ServerConfig::new`.
/// - For all other ciphers (stream, AEAD v1), the password is just an
///   arbitrary string and we hex-encode the random bytes for legibility.
pub(crate) fn random_password_for(method: CipherKind) -> String {
    use rand::RngCore;
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
/// unit via [`port_alloc::bind_with_retry`]. This absorbs the residual
/// probe-drop-to-bind TOCTOU on Windows, where independent TCP/UDP
/// excluded-port-range tables can reject a freshly-allocated port on
/// the paired transport. shadowsocks-rust's `ServerBuilder` clones
/// `svr_cfg` when constructing both `TcpServer` and `UdpServer`, so
/// passing port 0 would hand the two sockets distinct kernel-allocated
/// ports — the explicit allocation here keeps them on the same port.
pub(crate) async fn start_real_ss_server(method: CipherKind, password: &str) -> (SocketAddr, JoinHandle<()>) {
    let (port, server) = port_alloc::bind_with_retry(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Protocols::TCP | Protocols::UDP,
        port_alloc::BIND_RETRY_ATTEMPTS,
        |port| {
            let password = password.to_string();
            async move {
                let mut svr_cfg = ServerConfig::new(("127.0.0.1", port), password, method).unwrap();
                svr_cfg.set_mode(Mode::TcpAndUdp);
                SsServerBuilder::new(svr_cfg).build().await
            }
        },
    )
    .await
    .expect("start_real_ss_server: bind/build failed after retries");

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let handle = tokio::spawn(async move {
        // Server::run consumes self and only ever returns Err on teardown
        // ("server exited unexpectedly"). The test ignores the error.
        let _ = server.run().await;
    });

    (addr, handle)
}

/// Spin up a real shadowsocks server with v2ray-plugin (websocket, no TLS)
/// in front. Returns the public-facing socket address and the spawned
/// server task handle. The plugin's public listen port is verified for
/// `Protocols::TCP` only — WS is TCP per RFC 6455.
pub(crate) async fn start_real_ss_server_with_plugin_ws(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
) -> (SocketAddr, JoinHandle<()>) {
    spawn_ss_with_plugin(
        method,
        password,
        Protocols::TCP,
        plugin_path,
        "server;host=cloudfront.com;path=/",
    )
    .await
}

/// Spin up a real shadowsocks server with v2ray-plugin (websocket + TLS) in
/// front. Same shape as [`start_real_ss_server_with_plugin_ws`] but with TLS
/// enabled and the cert+key from `certs` mounted on the server side.
pub(crate) async fn start_real_ss_server_with_plugin_ws_tls(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    certs: &TestCerts,
) -> (SocketAddr, JoinHandle<()>) {
    let opts = format!("server;host=cloudfront.com;path=/;tls;{}", certs.plugin_opts_fragment());
    spawn_ss_with_plugin(method, password, Protocols::TCP, plugin_path, &opts).await
}

/// Spin up a real shadowsocks server with v2ray-plugin (QUIC transport) in
/// front. QUIC auto-enables TLS inside v2ray-plugin
/// ([main.go:142](../../../external/v2ray-plugin/main.go)), so the cert+key
/// pair must still be supplied. The plugin's public listen port is verified
/// for `Protocols::UDP` because QUIC runs over UDP.
pub(crate) async fn start_real_ss_server_with_plugin_quic(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    certs: &TestCerts,
) -> (SocketAddr, JoinHandle<()>) {
    let opts = format!("server;host=cloudfront.com;mode=quic;{}", certs.plugin_opts_fragment());
    spawn_ss_with_plugin(method, password, Protocols::UDP, plugin_path, &opts).await
}

/// Inner helper used by every `_with_plugin_*` variant. Allocates +
/// binds the public port on the right [`Protocols`] for the plugin
/// transport, builds a server-side `ServerConfig` with `PluginConfig`,
/// and spawns the server loop.
///
/// **Retry-asymmetry note.** `bind_with_retry`'s outer retry catches
/// `is_bind_race` errors that surface as `io::Error` from
/// [`SsServerBuilder::build`]. For the plugin variants the public_port
/// bind happens inside the **plugin subprocess**, after `build()`
/// returns Ok — a public-port WSAEACCES surfaces as a `wait_for_port`
/// timeout / connection refused, never as an `io::Error`. The wrapper
/// here only catches races on the SS-side rendezvous loopback port
/// that shadowsocks-rust's `Plugin::start` allocates synchronously
/// (the long-standing #197 race class). Per-protocol correctness on
/// the public port comes from the right `protocols` argument, not
/// from the retry. See bindreams/hole#285 §"Where the fix actually
/// lands".
async fn spawn_ss_with_plugin(
    method: CipherKind,
    password: &str,
    protocols: Protocols,
    plugin_path: &str,
    plugin_opts: &str,
) -> (SocketAddr, JoinHandle<()>) {
    let (port, server) = port_alloc::bind_with_retry(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        protocols,
        port_alloc::BIND_RETRY_ATTEMPTS,
        |port| {
            let password = password.to_string();
            let plugin_path = plugin_path.to_string();
            let plugin_opts = plugin_opts.to_string();
            async move {
                let mut svr_cfg = ServerConfig::new(("127.0.0.1", port), password, method).unwrap();
                svr_cfg.set_mode(Mode::TcpAndUdp);
                svr_cfg.set_plugin(PluginConfig {
                    plugin: plugin_path,
                    plugin_opts: Some(plugin_opts),
                    plugin_args: vec![],
                    plugin_mode: Mode::TcpAndUdp,
                });
                SsServerBuilder::new(svr_cfg).build().await
            }
        },
    )
    .await
    .expect("spawn_ss_with_plugin: bind/build failed after retries");

    let public_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });
    (public_addr, handle)
}

/// Locate the cargo-built `v2ray-plugin` binary in the target directory.
/// Respects `CARGO_TARGET_DIR`.
pub(crate) fn locate_built_v2ray_plugin() -> PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("target"));
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    let bin = if cfg!(windows) {
        "v2ray-plugin.exe"
    } else {
        "v2ray-plugin"
    };
    target_dir.join(profile).join(bin)
}

/// Locate the galoshes binary built by `cargo xtask galoshes`.
///
/// Galoshes is built inside the galoshes subrepo's own target directory,
/// always in release mode (it embeds v2ray-plugin at compile time).
pub(crate) fn locate_built_galoshes() -> PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let bin = if cfg!(windows) { "galoshes.exe" } else { "galoshes" };
    workspace_root
        .join("external")
        .join("galoshes")
        .join("target")
        .join("release")
        .join(bin)
}
