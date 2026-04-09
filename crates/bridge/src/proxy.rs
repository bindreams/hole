use hole_common::config::is_valid_plugin_name;
use hole_common::protocol::{ProxyConfig, TunnelMode};
use shadowsocks::config::ServerAddr;
use shadowsocks::ServerConfig;
use shadowsocks_service::config::{
    Config, ConfigType, LocalConfig, LocalInstanceConfig, ProtocolType, ServerInstanceConfig,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

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
}

// Config builder ======================================================================================================

/// TUN interface subnet (hardcoded, not configurable via IPC).
pub const TUN_SUBNET: &str = "10.255.0.1/24";

/// TUN interface device name.
pub const TUN_DEVICE_NAME: &str = "hole-tun";

/// Build a shadowsocks-service Config from our ProxyConfig.
///
/// The number of local instances depends on `config.tunnel_mode`:
/// - [`TunnelMode::Full`] (production default): TUN + SOCKS5. The TUN
///   adapter provides transparent proxying for all traffic; the SOCKS5
///   listener is there for advanced users.
/// - [`TunnelMode::SocksOnly`]: SOCKS5 only. No TUN adapter is created
///   by `shadowsocks-service::local::Server::new`, so the resulting
///   server works without elevation. Used by advanced users who want a
///   pure SOCKS5 provider (browser proxy settings, curl --socks5), and
///   by the e2e test harness to exercise the bridge without admin.
pub fn build_ss_config(config: &ProxyConfig) -> Result<Config, ProxyError> {
    let entry = &config.server;

    // Parse cipher method
    let method = entry
        .method
        .parse()
        .map_err(|_| ProxyError::InvalidMethod(entry.method.clone()))?;

    // Build server config
    let server_addr = ServerAddr::DomainName(entry.server.clone(), entry.server_port);
    let mut server_config = ServerConfig::new(server_addr, entry.password.clone(), method)
        .map_err(|e| ProxyError::InvalidMethod(e.to_string()))?;

    // Configure v2ray-plugin if present
    if let Some(ref plugin) = entry.plugin {
        if !is_valid_plugin_name(plugin) {
            return Err(ProxyError::InvalidPluginName(plugin.clone()));
        }
        let plugin_path = resolve_plugin_path(plugin);

        server_config.set_plugin(shadowsocks::plugin::PluginConfig {
            plugin: plugin_path,
            plugin_opts: entry.plugin_opts.clone(),
            plugin_args: Vec::new(),
            plugin_mode: shadowsocks::config::Mode::TcpOnly,
        });
    }

    let mut ss_config = Config::new(ConfigType::Local);

    // Server
    ss_config
        .server
        .push(ServerInstanceConfig::with_server_config(server_config));

    // Local 1: TUN (only in Full mode). SocksOnly deliberately skips
    // this — `shadowsocks-service::local::Server::new` would otherwise
    // try to open the TUN adapter, which requires elevation.
    if matches!(config.tunnel_mode, TunnelMode::Full) {
        let mut tun_local = LocalConfig::new(ProtocolType::Tun);
        tun_local.tun_interface_address = Some(TUN_SUBNET.parse().expect("TUN_SUBNET is a valid CIDR literal"));
        tun_local.tun_interface_name = Some(TUN_DEVICE_NAME.to_owned());
        ss_config.local.push(LocalInstanceConfig::with_local_config(tun_local));
    }

    // Local 2: SOCKS5 (always present — the production bridge has always
    // exposed this alongside TUN, and it's the only thing present in
    // SocksOnly mode).
    let socks_addr: SocketAddr = format!("127.0.0.1:{}", config.local_port)
        .parse()
        .expect("127.0.0.1:{u16} is always a valid SocketAddr");
    let socks_local = LocalConfig::new_with_addr(ServerAddr::SocketAddr(socks_addr), ProtocolType::Socks);
    ss_config
        .local
        .push(LocalInstanceConfig::with_local_config(socks_local));

    Ok(ss_config)
}

// Plugin resolution ===================================================================================================

/// Resolve a plugin binary path by looking next to the bridge executable.
fn resolve_plugin_path(name: &str) -> String {
    resolve_plugin_path_inner(name, std::env::current_exe().ok())
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
#[path = "proxy_tests.rs"]
mod proxy_tests;
