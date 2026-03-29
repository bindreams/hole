use hole_common::protocol::ProxyConfig;
use shadowsocks::config::ServerAddr;
use shadowsocks::ServerConfig;
use shadowsocks_service::config::{
    Config, ConfigType, LocalConfig, LocalInstanceConfig, ProtocolType, ServerInstanceConfig,
};
use std::net::SocketAddr;
use thiserror::Error;

// Errors ==============================================================================================================

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("invalid cipher method: {0}")]
    InvalidMethod(String),
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
}

// Config builder ======================================================================================================

/// TUN interface subnet (hardcoded, not configurable via IPC).
pub const TUN_SUBNET: &str = "10.255.0.1/24";

/// TUN interface device name.
pub const TUN_DEVICE_NAME: &str = "hole-tun";

/// Build a shadowsocks-service Config from our ProxyConfig.
///
/// Creates two local instances:
/// 1. TUN — transparent proxy for all traffic
/// 2. SOCKS5 — on `127.0.0.1:{local_port}` for advanced users
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
        let plugin_path = config
            .plugin_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| plugin.clone());

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

    // Local 1: TUN
    let mut tun_local = LocalConfig::new(ProtocolType::Tun);
    tun_local.tun_interface_address = Some(TUN_SUBNET.parse().expect("TUN_SUBNET is a valid CIDR literal"));
    tun_local.tun_interface_name = Some(TUN_DEVICE_NAME.to_owned());
    ss_config.local.push(LocalInstanceConfig::with_local_config(tun_local));

    // Local 2: SOCKS5
    let socks_addr: SocketAddr = format!("127.0.0.1:{}", config.local_port)
        .parse()
        .expect("127.0.0.1:{u16} is always a valid SocketAddr");
    let socks_local = LocalConfig::new_with_addr(ServerAddr::SocketAddr(socks_addr), ProtocolType::Socks);
    ss_config
        .local
        .push(LocalInstanceConfig::with_local_config(socks_local));

    Ok(ss_config)
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod proxy_tests;
