// Shadowsocks config construction, error types, and TUN/plugin constants.
//
// Split out of `proxy.rs` during the #165 rearchitecture so that `proxy.rs`
// can be a thin module-root file holding the `Proxy` / `RunningProxy`
// trait definitions. See `crates/bridge/src/proxy.rs` and
// `crates/bridge/src/proxy/shadowsocks.rs`.

use hole_common::config::is_valid_plugin_name;
use hole_common::protocol::ProxyConfig;
use shadowsocks::config::{Mode, ServerAddr};
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
    /// `tunnel_mode == Full` requires the SOCKS5 listener, because the
    /// TUN dispatcher hands captured traffic to it on `local_port`.
    #[error("tunnel_mode=full requires the SOCKS5 listener; enable proxy_socks5 or switch to tunnel_mode=socks-only")]
    TunnelRequiresSocks5,
    /// Both `proxy_socks5` and `proxy_http` are false — there is
    /// nothing to listen on.
    #[error("no local listeners enabled: at least one of proxy_socks5 / proxy_http must be true")]
    NoListenersEnabled,
    /// Both listeners enabled with identical ports. Each listener needs
    /// its own port because SOCKS5 and HTTP CONNECT are different
    /// handshake protocols.
    #[error("local_port and local_port_http must differ when both listeners are enabled (got {port})")]
    DuplicateListenerPort { port: u16 },
    /// A listener is enabled but its port is 0.
    #[error("{field} must be non-zero when the corresponding listener is enabled")]
    InvalidListenerPort { field: &'static str },
}

// Error conversions from tun-engine ===================================================================================
//
// `Routing` trait methods return `tun_engine::RoutingError`; wintun loading
// returns `tun_engine::DeviceError`. Bridge keeps its own `ProxyError` enum
// as the canonical proxy-lifecycle error, mapping incoming tun-engine
// errors into the matching variants so existing `?` propagation keeps
// working.

impl From<tun_engine::RoutingError> for ProxyError {
    fn from(e: tun_engine::RoutingError) -> Self {
        match e {
            tun_engine::RoutingError::Gateway(s) => ProxyError::Gateway(s),
            tun_engine::RoutingError::RouteSetup(s) => ProxyError::RouteSetup(s),
        }
    }
}

impl From<tun_engine::DeviceError> for ProxyError {
    fn from(e: tun_engine::DeviceError) -> Self {
        match e {
            tun_engine::DeviceError::WintunMissing { tried } => ProxyError::WintunMissing { tried },
            tun_engine::DeviceError::WintunLoad { path, message } => ProxyError::WintunLoad { path, message },
            tun_engine::DeviceError::TunOpen(err) => ProxyError::Runtime(err),
            tun_engine::DeviceError::InvalidConfig(msg) => ProxyError::RouteSetup(format!("device config: {msg}")),
        }
    }
}

// Config builder ======================================================================================================

/// TUN interface subnet (hardcoded, not configurable via IPC).
pub const TUN_SUBNET: &str = "10.255.0.1/24";

/// TUN interface device name.
pub const TUN_DEVICE_NAME: &str = "hole-tun";

/// Build a shadowsocks-service Config from our ProxyConfig.
///
/// Emits one local instance per enabled listener:
///
/// * **SOCKS5** (`proxy_socks5`): `127.0.0.1:{local_port}`, always
///   `TcpAndUdp`. In Full mode the TUN dispatcher uses UDP ASSOCIATE
///   to relay datagrams through the SS tunnel; in SocksOnly mode the
///   listener exposes UDP ASSOCIATE to local SOCKS5 clients
///   (hev-socks5-tunnel, ss-tunnel, proxychains-ng UDP, …).
///
///   Pre-#250, SocksOnly forced `TcpOnly` under #189's "select_all
///   drops the TCP listener when UDP completes early" attribution.
///   That attribution had no log evidence: `LogTracer` *is* installed
///   (via `tracing-subscriber`'s default features → `try_init`), but
///   the bridge's `HOLE_BRIDGE_LOG` parser dropped every directive
///   after the first comma, so `shadowsocks_service=*` directives in
///   a multi-crate filter were silently lost. #267 fixes that. The
///   original symptom for #189 was actually wintun-induced loopback
///   breakage on the Azure-hosted Windows runner (#200), correctly
///   addressed by PR #207's two-pass test ordering (`SKULD_LABELS=tun`
///   runs last so loopback-using tests precede any wintun adapter
///   destruction).
/// * **HTTP CONNECT** (`proxy_http`): `127.0.0.1:{local_port_http}`,
///   always `TcpOnly` (HTTP CONNECT is TCP-only by RFC 7231 §4.3.6).
///
/// # Validation
///
/// Rejected configurations (returns `ProxyError`):
///
/// 1. `tunnel_mode == Full && !proxy_socks5` — the TUN dispatcher needs
///    the SOCKS5 listener to exist on `local_port`
///    (`TunnelRequiresSocks5`).
/// 2. `!proxy_socks5 && !proxy_http` — nothing to listen on
///    (`NoListenersEnabled`).
/// 3. `proxy_socks5 && proxy_http && local_port == local_port_http` —
///    each listener needs its own port (`DuplicateListenerPort`).
/// 4. Port `0` on an enabled listener (`InvalidListenerPort`).
///
/// # Plugin handling
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
    validate_listeners(config)?;

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

    if config.proxy_socks5 {
        ss_config.local.push(build_local_instance(
            ProtocolType::Socks,
            loopback(config.local_port),
            Mode::TcpAndUdp,
        ));
    }

    if config.proxy_http {
        // HTTP CONNECT is TCP-only; do not honour tunnel_mode here.
        ss_config.local.push(build_local_instance(
            ProtocolType::Http,
            loopback(config.local_port_http),
            Mode::TcpOnly,
        ));
    }

    Ok(ss_config)
}

fn validate_listeners(config: &ProxyConfig) -> Result<(), ProxyError> {
    if config.tunnel_mode == hole_common::protocol::TunnelMode::Full && !config.proxy_socks5 {
        return Err(ProxyError::TunnelRequiresSocks5);
    }
    if !config.proxy_socks5 && !config.proxy_http {
        return Err(ProxyError::NoListenersEnabled);
    }
    if config.proxy_socks5 && config.local_port == 0 {
        return Err(ProxyError::InvalidListenerPort { field: "local_port" });
    }
    if config.proxy_http && config.local_port_http == 0 {
        return Err(ProxyError::InvalidListenerPort {
            field: "local_port_http",
        });
    }
    if config.proxy_socks5 && config.proxy_http && config.local_port == config.local_port_http {
        return Err(ProxyError::DuplicateListenerPort {
            port: config.local_port,
        });
    }
    Ok(())
}

fn loopback(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}")
        .parse()
        .expect("127.0.0.1:{u16} is always a valid SocketAddr")
}

fn build_local_instance(protocol: ProtocolType, addr: SocketAddr, mode: Mode) -> LocalInstanceConfig {
    let mut local = LocalConfig::new_with_addr(ServerAddr::SocketAddr(addr), protocol);
    local.mode = mode;
    LocalInstanceConfig::with_local_config(local)
}

// Plugin resolution ===================================================================================================

/// Resolve a plugin binary path by looking next to the bridge executable.
pub fn resolve_plugin_path(name: &str) -> String {
    resolve_plugin_path_inner(name, std::env::current_exe().ok())
}

/// Whether the configured plugin can carry UDP through the SS tunnel.
///
/// Returns `false` when a TCP-only plugin is configured (e.g. plain
/// v2ray-plugin). Returns `true` for plugins with UDP support (e.g.
/// galoshes, which uses YAMUX multiplexing), and `true` when no plugin
/// is configured (SS itself always supports UDP).
///
/// This is the bridge-internal name, plumbed into
/// [`crate::endpoint::Socks5Endpoint::supports_udp`]. The cascade in
/// [`crate::hole_router::HoleRouter::resolve_endpoint`] uses the
/// capability to enforce hole's privacy invariant: UDP-via-Proxy flows
/// are dropped, not cascaded to the clear-text bypass, when this
/// returns `false`.
///
/// **Naming note.** The corresponding wire-protocol field
/// [`hole_common::protocol::BridgeResponse::Status::udp_proxy_available`]
/// keeps its historical name for API stability. This helper uses the
/// more accurate internal name.
pub fn plugin_supports_udp(config: &ProxyConfig) -> bool {
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
