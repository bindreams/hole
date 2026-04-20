//! In-process shadowsocks server fixtures.
//!
//! Each helper spins up a real `shadowsocks_service::server::Server` bound to
//! `127.0.0.1:0` (or a caller-chosen port when a plugin is in front). The
//! returned [`JoinHandle`]s own the server loop and must be kept alive for
//! the duration of the test that uses them.

use crate::test_support::certs::TestCerts;
use base64::Engine as _;
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

/// Spin up a real shadowsocks server bound to `127.0.0.1:0` with the given
/// cipher/password. Returns the bound TCP address and a handle to the
/// running server task. The server relays anything the client asks for.
pub(crate) async fn start_real_ss_server(method: CipherKind, password: &str) -> (SocketAddr, JoinHandle<()>) {
    let mut svr_cfg = ServerConfig::new(("127.0.0.1", 0u16), password.to_string(), method).unwrap();
    svr_cfg.set_mode(Mode::TcpAndUdp);

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
pub(crate) async fn start_real_ss_server_with_plugin_ws(
    method: CipherKind,
    password: &str,
    public_port: u16,
    plugin_path: &str,
) -> (SocketAddr, JoinHandle<()>) {
    spawn_ss_with_plugin(
        method,
        password,
        public_port,
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
    public_port: u16,
    plugin_path: &str,
    certs: &TestCerts,
) -> (SocketAddr, JoinHandle<()>) {
    let opts = format!("server;host=cloudfront.com;path=/;tls;{}", certs.plugin_opts_fragment());
    spawn_ss_with_plugin(method, password, public_port, plugin_path, &opts).await
}

/// Spin up a real shadowsocks server with v2ray-plugin (QUIC transport) in
/// front. QUIC auto-enables TLS inside v2ray-plugin
/// ([main.go:142](../../../external/v2ray-plugin/main.go)), so the cert+key
/// pair must still be supplied.
pub(crate) async fn start_real_ss_server_with_plugin_quic(
    method: CipherKind,
    password: &str,
    public_port: u16,
    plugin_path: &str,
    certs: &TestCerts,
) -> (SocketAddr, JoinHandle<()>) {
    let opts = format!("server;host=cloudfront.com;mode=quic;{}", certs.plugin_opts_fragment());
    spawn_ss_with_plugin(method, password, public_port, plugin_path, &opts).await
}

/// Inner helper used by every `_with_plugin_*` variant. Builds a server-side
/// `ServerConfig`, attaches a `PluginConfig` with the given `plugin_opts`,
/// and spawns the server loop.
async fn spawn_ss_with_plugin(
    method: CipherKind,
    password: &str,
    public_port: u16,
    plugin_path: &str,
    plugin_opts: &str,
) -> (SocketAddr, JoinHandle<()>) {
    let mut svr_cfg = ServerConfig::new(("127.0.0.1", public_port), password.to_string(), method).unwrap();
    svr_cfg.set_mode(Mode::TcpAndUdp);

    svr_cfg.set_plugin(PluginConfig {
        plugin: plugin_path.to_string(),
        plugin_opts: Some(plugin_opts.to_string()),
        plugin_args: vec![],
        plugin_mode: Mode::TcpAndUdp,
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
