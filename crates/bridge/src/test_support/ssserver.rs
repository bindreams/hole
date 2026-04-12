//! In-process shadowsocks server fixtures.
//!
//! Each helper spins up a real `shadowsocks_service::server::Server` bound to
//! `127.0.0.1:0` (or a caller-chosen port when a plugin is in front). The
//! returned [`JoinHandle`]s own the server loop and must be kept alive for
//! the duration of the test that uses them.

use crate::proxy::plugin::PluginChain;
use crate::test_support::certs::TestCerts;
use base64::Engine as _;
use shadowsocks::config::{Mode, ServerConfig};
use shadowsocks::crypto::CipherKind;
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

/// Spin up a real shadowsocks server with galoshes (websocket, no TLS)
/// in front. Returns the public-facing socket address, the spawned server
/// task handle, and the plugin chain (which must be kept alive).
pub(crate) async fn start_real_ss_server_with_plugin_ws(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
) -> (SocketAddr, JoinHandle<()>, PluginChain) {
    spawn_ss_with_galoshes(method, password, plugin_path, "server;host=cloudfront.com;path=/").await
}

/// Spin up a real shadowsocks server with galoshes (websocket + TLS) in
/// front. Same shape as [`start_real_ss_server_with_plugin_ws`] but with TLS
/// enabled and the cert+key from `certs` mounted on the server side.
pub(crate) async fn start_real_ss_server_with_plugin_ws_tls(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    certs: &TestCerts,
) -> (SocketAddr, JoinHandle<()>, PluginChain) {
    let opts = format!("server;host=cloudfront.com;path=/;tls;{}", certs.plugin_opts_fragment());
    spawn_ss_with_galoshes(method, password, plugin_path, &opts).await
}

/// Spin up a real shadowsocks server with galoshes (QUIC transport) in
/// front. QUIC auto-enables TLS inside galoshes's wrapped v2ray-plugin,
/// so the cert+key pair must still be supplied.
pub(crate) async fn start_real_ss_server_with_plugin_quic(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    certs: &TestCerts,
) -> (SocketAddr, JoinHandle<()>, PluginChain) {
    let opts = format!("server;host=cloudfront.com;mode=quic;{}", certs.plugin_opts_fragment());
    spawn_ss_with_galoshes(method, password, plugin_path, &opts).await
}

/// Start an SS server (no plugin) + galoshes independently via garter.
///
/// Uses `start_plugin_chain` (the same production code path the bridge
/// uses on the client side) to spawn galoshes and wait for readiness.
/// No TOCTOU: garter allocates the local port and the readiness probe
/// confirms galoshes has bound before returning.
///
/// v2ray-plugin LISTENS on SS_LOCAL and CONNECTS to SS_REMOTE in both
/// client and server mode (the "server" flag only changes the transport
/// protocol direction, not the address mapping). So we pass:
/// - `SS_LOCAL`  = garter-allocated port (galoshes listens here)
/// - `SS_REMOTE` = SS server's internal port (galoshes forwards here)
///
/// The caller must keep the returned [`PluginChain`] alive; dropping it
/// shuts down galoshes.
async fn spawn_ss_with_galoshes(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    plugin_opts: &str,
) -> (SocketAddr, JoinHandle<()>, PluginChain) {
    // 1. Start SS server with no plugin, ephemeral port.
    //    No TOCTOU: SsServerBuilder binds and holds the listener.
    let (ss_addr, ss_handle) = start_real_ss_server(method, password).await;

    // 2. Start galoshes via garter, pointing at the SS server.
    //    Same code path the bridge uses on the client side.
    match crate::proxy::plugin::start_plugin_chain(
        plugin_path,
        Some(plugin_opts),
        &ss_addr.ip().to_string(),
        ss_addr.port(),
        None,
    )
    .await
    {
        Ok(chain) => (chain.local_addr(), ss_handle, chain),
        Err(e) => {
            // Diagnostic: try running galoshes directly to capture its stderr.
            let output = std::process::Command::new(plugin_path)
                .env("SS_LOCAL_HOST", "127.0.0.1")
                .env("SS_LOCAL_PORT", "0")
                .env("SS_REMOTE_HOST", ss_addr.ip().to_string())
                .env("SS_REMOTE_PORT", ss_addr.port().to_string())
                .env("SS_PLUGIN_OPTIONS", plugin_opts)
                .output()
                .expect("spawn galoshes for diagnostics");
            panic!(
                "start server-side galoshes: {e}\n\
                 --- diagnostic run ---\n\
                 exit: {:?}\n\
                 stdout: {}\n\
                 stderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }
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
