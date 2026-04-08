//! In-process shadowsocks server fixtures.
//!
//! Each helper spins up a real `shadowsocks_service::server::Server` bound to
//! `127.0.0.1:0` (or a caller-chosen port when a plugin is in front). The
//! returned [`JoinHandle`]s own the server loop and must be kept alive for
//! the duration of the test that uses them.

use shadowsocks::config::{Mode, ServerConfig};
use shadowsocks::crypto::CipherKind;
use shadowsocks::plugin::PluginConfig;
use shadowsocks_service::server::ServerBuilder as SsServerBuilder;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::task::JoinHandle;

pub(crate) const TEST_METHOD_STR: &str = "aes-256-gcm";
pub(crate) const TEST_METHOD: CipherKind = CipherKind::AES_256_GCM;
pub(crate) const TEST_PASSWORD: &str = "test-password-1234";

/// Spin up a real shadowsocks server bound to `127.0.0.1:0` with the given
/// cipher/password. Returns the bound TCP address and a handle to the
/// running server task. The server relays anything the client asks for.
pub(crate) async fn start_real_ss_server(method: CipherKind, password: &str) -> (SocketAddr, JoinHandle<()>) {
    let mut svr_cfg = ServerConfig::new(("127.0.0.1", 0u16), password.to_string(), method).unwrap();
    svr_cfg.set_mode(Mode::TcpOnly); // skip UDP — the runner is TCP-only

    let server = SsServerBuilder::new(svr_cfg).build().await.unwrap();

    // Read the bound address BEFORE moving `server` into the spawn closure.
    // The `&TcpServer` borrow ends at the semicolon.
    let addr = server
        .tcp_server()
        .expect("TCP mode is enabled, tcp_server should exist")
        .local_addr()
        .unwrap();

    let handle = tokio::spawn(async move {
        // Server::run consumes self and only ever returns Err on teardown
        // ("server exited unexpectedly"). The test ignores the error.
        let _ = server.run().await;
    });

    (addr, handle)
}

/// Spin up a real shadowsocks server with v2ray-plugin (websocket, no TLS)
/// in front. The plugin listens on `public_port` (which the caller
/// pre-allocates and passes here) and forwards to the SS server. Returns the
/// public-facing socket address and the spawned server task handle.
///
/// Historical name: this was `start_real_ss_server_with_plugin` before the
/// test_support extraction. Renamed with a `_ws` suffix so sibling variants
/// (`_ws_tls`, `_quic`) can coexist in the plugin matrix.
pub(crate) async fn start_real_ss_server_with_plugin_ws(
    method: CipherKind,
    password: &str,
    public_port: u16,
    plugin_path: &str,
) -> (SocketAddr, JoinHandle<()>) {
    let mut svr_cfg = ServerConfig::new(("127.0.0.1", public_port), password.to_string(), method).unwrap();
    svr_cfg.set_mode(Mode::TcpOnly);

    // SS_PLUGIN_OPTIONS="server" puts v2ray-plugin in server mode (defaults
    // are websocket transport, no TLS, host=cloudfront.com, path=/).
    svr_cfg.set_plugin(PluginConfig {
        plugin: plugin_path.to_string(),
        plugin_opts: Some("server".to_string()),
        plugin_args: vec![],
        plugin_mode: Mode::TcpOnly,
    });

    let server = SsServerBuilder::new(svr_cfg).build().await.unwrap();

    let public_addr: SocketAddr = format!("127.0.0.1:{public_port}").parse().unwrap();
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
