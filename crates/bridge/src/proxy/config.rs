// Shadowsocks config construction, error types, and TUN/plugin constants.
//
// Split out of `proxy.rs` during the #165 rearchitecture so that `proxy.rs`
// can be a thin module-root file holding the `Proxy` / `RunningProxy`
// trait definitions. See `crates/bridge/src/proxy.rs` and
// `crates/bridge/src/proxy/shadowsocks.rs`.

use hole_common::config::is_valid_plugin_name;
use hole_common::protocol::ProxyConfig;
use shadowsocks::config::ServerAddr;
use shadowsocks::ServerConfig;
use shadowsocks_service::config::{
    Config, ConfigType, LocalConfig, LocalInstanceConfig, ProtocolType, ServerInstanceConfig,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

use hole_common::plugin;

// Errors ==============================================================================================================

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("invalid cipher method: {0}")]
    InvalidMethod(String),
    #[error("invalid plugin name: {0}")]
    InvalidPluginName(String),
    #[error("proxy runtime error: {0}")]
    Runtime(#[from] std::io::Error),
    #[error("gateway detection failed: {0}")]
    Gateway(String),
    #[error("DNS resolution failed for {host}: {source}")]
    DnsResolution { host: String, source: std::io::Error },
    #[error("route setup failed: {0}")]
    RouteSetup(String),
    #[error("proxy already running")]
    AlreadyRunning,
    /// The start was cancelled via `CancellationToken` before it could
    /// complete. The error message is the stable `CANCELLED_MESSAGE`
    /// constant from `hole_common::protocol` so bridge and client can
    /// round-trip it exactly. Not set as `last_error` — the user asked
    /// for the cancel, so it is not a diagnostic failure.
    #[error("cancelled")]
    Cancelled,
    #[error("wintun.dll not found (tried: {})", .tried.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "))]
    WintunMissing { tried: Vec<PathBuf> },
    #[error("wintun.dll load failed at {}: {message}", .path.display())]
    WintunLoad { path: PathBuf, message: String },
    #[error("plugin error: {0}")]
    Plugin(String),
}

// Config builder ======================================================================================================

/// TUN interface subnet (hardcoded, not configurable via IPC).
pub const TUN_SUBNET: &str = "10.255.0.1/24";

/// TUN interface device name.
pub const TUN_DEVICE_NAME: &str = "hole-tun";

/// Build a shadowsocks-service Config from our ProxyConfig.
///
/// Creates exactly one local instance: SOCKS5 on `127.0.0.1:{local_port}`.
/// The mode depends on `tunnel_mode`:
///
/// * **Full** — `TcpAndUdp`, so the dispatcher's UDP handler can use
///   SOCKS5 UDP ASSOCIATE to relay datagrams through the tunnel.
/// * **SocksOnly** — `TcpOnly`, because there is no dispatcher and nobody
///   uses UDP ASSOCIATE. See #189 for why this matters on Windows.
///
/// When `plugin_local` is `Some`, the server address is overridden to point
/// at the Garter-managed plugin chain's local port. The cipher and password
/// remain the original server's — the server address is just the transport
/// endpoint, not part of the shadowsocks protocol. No `PluginConfig` is set
/// on the `ServerConfig` because Garter owns the plugin lifecycle.
///
/// When `plugin_local` is `None`, the original server address is used as-is
/// (no plugin, or plugin management is handled elsewhere).
pub fn build_ss_config(config: &ProxyConfig, plugin_local: Option<SocketAddr>) -> Result<Config, ProxyError> {
    let entry = &config.server;

    // Validate plugin name (format check, not known-plugin check).
    if let Some(ref p) = entry.plugin {
        if !is_valid_plugin_name(p) {
            return Err(ProxyError::InvalidPluginName(p.clone()));
        }
    }

    // Parse cipher method
    let method = entry
        .method
        .parse()
        .map_err(|_| ProxyError::InvalidMethod(entry.method.clone()))?;

    // Build server config. When a plugin chain is running, point ss-service
    // at the chain's local port instead of the real server.
    let server_addr = match plugin_local {
        Some(addr) => ServerAddr::SocketAddr(addr),
        None => ServerAddr::DomainName(entry.server.clone(), entry.server_port),
    };
    let server_config = ServerConfig::new(server_addr, entry.password.clone(), method)
        .map_err(|e| ProxyError::InvalidMethod(e.to_string()))?;

    // No PluginConfig is set — Garter manages the plugin lifecycle externally.

    let mut ss_config = Config::new(ConfigType::Local);

    // Server
    ss_config
        .server
        .push(ServerInstanceConfig::with_server_config(server_config));

    // SOCKS5 local — the only local instance.
    //
    // Full mode: TcpAndUdp — the dispatcher's UDP handler needs SOCKS5
    // UDP ASSOCIATE to relay datagrams through the SS tunnel.
    //
    // SocksOnly mode: TcpOnly — there is no dispatcher, so nobody uses
    // UDP ASSOCIATE. Creating the UDP server on Windows can cause
    // select_all inside shadowsocks-service to drop the TCP listener
    // when the UDP future completes early. See #189.
    let socks_addr: SocketAddr = format!("127.0.0.1:{}", config.local_port)
        .parse()
        .expect("127.0.0.1:{u16} is always a valid SocketAddr");
    let mut socks_local = LocalConfig::new_with_addr(ServerAddr::SocketAddr(socks_addr), ProtocolType::Socks);
    socks_local.mode = match config.tunnel_mode {
        hole_common::protocol::TunnelMode::Full => shadowsocks::config::Mode::TcpAndUdp,
        hole_common::protocol::TunnelMode::SocksOnly => shadowsocks::config::Mode::TcpOnly,
    };
    ss_config
        .local
        .push(LocalInstanceConfig::with_local_config(socks_local));

    Ok(ss_config)
}

// Plugin resolution ===================================================================================================

/// Resolve a plugin binary path by looking next to the bridge executable.
pub fn resolve_plugin_path(name: &str) -> String {
    resolve_plugin_path_inner(name, std::env::current_exe().ok())
}

/// Whether UDP can be proxied through the shadowsocks server.
///
/// Returns `false` when a TCP-only plugin is configured (e.g. plain
/// v2ray-plugin). Returns `true` for plugins with UDP support (e.g.
/// galoshes, which uses YAMUX multiplexing). The dispatcher uses this
/// to block UDP traffic that cannot be proxied.
pub fn udp_proxy_available(config: &ProxyConfig) -> bool {
    match &config.server.plugin {
        None => true,
        Some(name) => plugin::lookup(name).is_some_and(|p| p.udp_supported),
    }
}

/// Inner implementation that accepts an explicit exe path for testability.
///
/// Looks for the plugin binary in the same directory as the bridge executable.
/// On Windows, appends `.exe` if the name doesn't already end with it.
/// Falls back to the bare name so that shadowsocks does a PATH lookup.
///
/// The PATH fallback is safe because `is_valid_plugin_name()` ensures the name
/// contains no path separators — PATH lookup can only find binaries in directories
/// that an administrator placed on PATH (standard system-level trust model).
pub(crate) fn resolve_plugin_path_inner(name: &str, bridge_exe: Option<PathBuf>) -> String {
    if let Some(exe) = bridge_exe {
        // Canonicalize to resolve symlinks — the bridge may be registered via symlink,
        // but the sibling plugin binary is next to the real binary.
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        if let Some(dir) = exe.parent() {
            let candidate = if cfg!(windows) && !name.ends_with(".exe") {
                dir.join(format!("{name}.exe"))
            } else {
                dir.join(name)
            };
            if candidate.is_file() {
                return candidate.to_string_lossy().to_string();
            }
        }
    }
    name.to_string()
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
