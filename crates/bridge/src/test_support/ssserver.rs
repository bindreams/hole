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
) -> (SocketAddr, JoinHandle<()>, GaloshesHandle) {
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
) -> (SocketAddr, JoinHandle<()>, GaloshesHandle) {
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
) -> (SocketAddr, JoinHandle<()>, GaloshesHandle) {
    let opts = format!("server;host=cloudfront.com;mode=quic;{}", certs.plugin_opts_fragment());
    spawn_ss_with_galoshes(method, password, plugin_path, &opts).await
}

/// Start an SS server (no plugin) + galoshes independently via garter.
///
/// Uses garter to spawn galoshes and waits for readiness via TCP connect
/// probe. No TOCTOU: garter allocates ports and the readiness probe
/// confirms galoshes has bound before this function returns.
///
/// ## SIP003 env var mapping for server mode
///
/// v2ray-plugin in server mode **swaps** the roles of SS_LOCAL/SS_REMOTE:
/// it LISTENS on SS_REMOTE (public-facing) and CONNECTS to SS_LOCAL (the
/// SS server). The chain inside galoshes is wired as:
///
/// ```text
/// clients → v2ray (LISTENS on SS_REMOTE) → intermediate → yamux-server → SS_LOCAL → SS server
/// ```
///
/// So we set:
/// - `SS_LOCAL`  = the SS server's internal address
/// - `SS_REMOTE` = the galoshes public port (where clients connect)
///
/// The caller must keep the returned [`GaloshesHandle`] alive; dropping it
/// shuts down galoshes.
async fn spawn_ss_with_galoshes(
    method: CipherKind,
    password: &str,
    plugin_path: &str,
    plugin_opts: &str,
) -> (SocketAddr, JoinHandle<()>, GaloshesHandle) {
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    // 1. Start SS server with no plugin, ephemeral port.
    //    No TOCTOU: SsServerBuilder binds and holds the listener.
    let (ss_addr, ss_handle) = start_real_ss_server(method, password).await;

    // 2. Allocate a public port for galoshes (where external clients connect).
    let public_addr = garter::chain::allocate_ports(1)
        .expect("allocate public port for server-side galoshes")
        .into_iter()
        .next()
        .expect("allocate_ports(1) returns exactly 1");

    // 3. Spawn galoshes with server-mode SIP003 env vars.
    //    SS_LOCAL  → SS server (galoshes connects here internally)
    //    SS_REMOTE → public port (v2ray-plugin listens here in server mode)
    let env = garter::PluginEnv {
        local_host: ss_addr.ip(),
        local_port: ss_addr.port(),
        remote_host: public_addr.ip().to_string(),
        remote_port: public_addr.port(),
        plugin_options: Some(plugin_opts.to_string()),
    };

    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = oneshot::channel();

    let plugin = garter::BinaryPlugin::new(plugin_path, Some(plugin_opts));
    let runner = garter::ChainRunner::new()
        .add(Box::new(plugin))
        .cancel_token(cancel.clone())
        .on_ready(ready_tx);

    let handle = tokio::spawn(async move { runner.run(env).await });

    // 4. Wait for galoshes to become ready (v2ray binds the public port).
    //    The readiness probe targets addrs[0] = env.local_addr() = ss_addr,
    //    but that's the SS server which is already listening. We need to
    //    wait for the PUBLIC port instead. Do a manual TCP probe.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if tokio::net::TcpStream::connect(public_addr).await.is_ok() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            cancel.cancel();
            handle.abort();
            panic!("server-side galoshes did not bind {public_addr} within 30s");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Consume the readiness channel (it may fire on ss_addr, which is trivially ready).
    drop(ready_rx);

    let galoshes = GaloshesHandle {
        _handle: handle,
        _cancel: cancel,
    };
    (public_addr, ss_handle, galoshes)
}

/// Keeps the server-side galoshes alive. Dropping cancels the plugin chain.
pub(crate) struct GaloshesHandle {
    _handle: tokio::task::JoinHandle<Result<(), garter::Error>>,
    _cancel: tokio_util::sync::CancellationToken,
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
