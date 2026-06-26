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
    /// Private DoH bootstrap could not resolve the proxy server's hostname and
    /// `dns.allow_insecure_bootstrap` is off. PII-free `Display` (the wrapped
    /// error names neither host nor path) so it is safe to surface verbatim to
    /// the start-error toast; the hostname is logged at the resolve call site.
    #[error("{0}")]
    DohBootstrap(#[from] crate::dns::bootstrap::BootstrapError),
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
    /// A plugin reported a typed bind conflict (`StartError::BindConflict`
    /// via sitrep) at its local listener. This is the retryable
    /// class: `proxy_err_to_io_err` synthesizes an `AddrInUse`-kind
    /// `io::Error` from it so `bind_ephemeral` allocates a fresh port and
    /// retries. The `errno` is the plugin's host-native OS error (0 if
    /// unknown), preserved for `bridge.log` diagnostics.
    #[error("plugin bind conflict on {addr} (errno {errno})")]
    BindRace { errno: i32, addr: SocketAddr },
    /// `tunnel_mode == Full` with the HTTP listener enabled requires the
    /// user-facing SOCKS5 listener: the TUN data plane either rides the
    /// user-facing SOCKS5 listener on `local_port`, or — when no
    /// user-facing listener is requested at all (pure-VPN, #459) — an
    /// internal one on an ephemeral port. A mixed user-facing-HTTP +
    /// internal-SOCKS5 split is rejected.
    #[error("tunnel_mode=full with proxy_http requires the SOCKS5 listener; enable proxy_socks5, or disable proxy_http for a pure-VPN start, or switch to tunnel_mode=socks-only")]
    TunnelRequiresSocks5,
    /// SocksOnly mode with both `proxy_socks5` and `proxy_http` false —
    /// there is nothing to listen on and no TUN to serve.
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
    /// The DNS forwarder self-test failed before TUN routes were installed.
    /// `routes` / `system DNS` were never touched on this path — the user's
    /// system DNS is untouched. Used by the start-time self-test gate so the
    /// GUI never reports "Running" while a dead plugin chain would hijack all
    /// DNS into the tunnel.
    #[error("forwarder self-test failed after {attempts} attempts in {elapsed_ms}ms: {reason}")]
    ForwarderSelfTestFailed {
        reason: String,
        attempts: u32,
        elapsed_ms: u64,
    },
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
/// * **HTTP CONNECT** (`proxy_http`): `127.0.0.1:{local_port_http}`,
///   always `TcpOnly` (HTTP CONNECT is TCP-only by RFC 7231 §4.3.6).
///
/// # Pure-VPN starts (#459)
///
/// `Full && !proxy_socks5 && !proxy_http` is the pure-VPN configuration
/// (the GUI's "Local proxy server" master toggle off): no user-facing
/// listeners, but the TUN data plane still rides an SS SOCKS5 instance.
/// The caller allocates an ephemeral loopback port (via
/// `port_alloc::bind_ephemeral`) and passes it as `internal_socks5_port`;
/// a single SOCKS5 instance is emitted there instead of `local_port`,
/// so nothing is bound on the user-configured ports.
/// `internal_socks5_port` must be `Some` exactly on that path — see the
/// `debug_assert!`s.
///
/// # Validation
///
/// Rejected configurations (returns `ProxyError`, see
/// [`validate_proxy_config`]):
///
/// 1. `tunnel_mode == Full && !proxy_socks5 && proxy_http` — a mixed
///    user-facing-HTTP + internal-SOCKS5 split
///    (`TunnelRequiresSocks5`).
/// 2. `tunnel_mode == SocksOnly && !proxy_socks5 && !proxy_http` —
///    nothing to listen on and no TUN to serve (`NoListenersEnabled`).
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
pub fn build_ss_config(
    config: &ProxyConfig,
    plugin_local: Option<SocketAddr>,
    internal_socks5_port: Option<u16>,
) -> Result<Config, ProxyError> {
    validate_proxy_config(config)?;

    let full = config.tunnel_mode == hole_common::protocol::TunnelMode::Full;
    // Contract with proxy_manager::start_inner: the internal port exists
    // exactly when this is a Full-mode pure-VPN start. Production code
    // structurally upholds this (start_inner's pure-VPN branch always
    // passes Some); the asserts document the contract for future callers.
    debug_assert!(
        internal_socks5_port.is_none() || (full && !config.proxy_socks5),
        "internal_socks5_port is only meaningful for a Full-mode pure-VPN start"
    );
    debug_assert!(
        !full || config.proxy_socks5 || internal_socks5_port.is_some(),
        "a Full-mode pure-VPN start must supply internal_socks5_port"
    );

    let entry = &config.server;

    // Parse cipher method (validated by `validate_proxy_config` above).
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

    // User-facing SOCKS5 listener, or — on a Full-mode pure-VPN start —
    // the internal data-plane instance on the caller-allocated port.
    let socks5_port = if config.proxy_socks5 {
        Some(config.local_port)
    } else {
        internal_socks5_port
    };
    if let Some(port) = socks5_port {
        ss_config.local.push(build_local_instance(
            ProtocolType::Socks,
            loopback(port),
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

/// Typed, side-effect-free validation of everything [`build_ss_config`]
/// checks: listener invariants, plugin-name format, cipher method.
/// `proxy_manager::start_inner` runs this before the Full-mode preamble
/// when the config can only be built later (pure-VPN: the internal
/// SOCKS5 port arrives from `bind_ephemeral`), so rejects stay fast and
/// typed.
pub fn validate_proxy_config(config: &ProxyConfig) -> Result<(), ProxyError> {
    validate_listeners(config)?;
    if let Some(ref p) = config.server.plugin {
        if !is_valid_plugin_name(p) {
            return Err(ProxyError::InvalidPluginName(p.clone()));
        }
    }
    config
        .server
        .method
        .parse::<shadowsocks::crypto::CipherKind>()
        .map_err(|_| ProxyError::InvalidMethod(config.server.method.clone()))?;
    Ok(())
}

fn validate_listeners(config: &ProxyConfig) -> Result<(), ProxyError> {
    let full = config.tunnel_mode == hole_common::protocol::TunnelMode::Full;
    // Full mode with NO user-facing listeners is the pure-VPN
    // configuration (GUI "Local proxy server" master toggle off): the
    // TUN data plane binds an internal SOCKS5 instance on an ephemeral
    // port instead (proxy_manager::start_inner). The mixed split —
    // user-facing HTTP with an internal SOCKS5 — is rejected: the fixed
    // HTTP port must not live inside bind_ephemeral's unbounded retry
    // loop (a genuine conflict on a fixed port must surface, not spin).
    if full && !config.proxy_socks5 && config.proxy_http {
        return Err(ProxyError::TunnelRequiresSocks5);
    }
    if !full && !config.proxy_socks5 && !config.proxy_http {
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
    // Map the config token to its on-disk binary name. A known friendly
    // name (`v2ray-plugin`) resolves to its `binary_name` (`ex-ray`); an
    // unknown name falls back to itself so arbitrary plugins are
    // unaffected. See bindreams/hole#414.
    let binary = plugin::lookup(name).map(|d| d.binary_name).unwrap_or(name);
    if let Some(exe) = bridge_exe {
        // Canonicalize to resolve symlinks — the bridge may be registered via symlink,
        // but the sibling plugin binary is next to the real binary.
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        if let Some(dir) = exe.parent() {
            let candidate = if cfg!(windows) && !binary.ends_with(".exe") {
                dir.join(format!("{binary}.exe"))
            } else {
                dir.join(binary)
            };
            if candidate.is_file() {
                return candidate.to_string_lossy().to_string();
            }
        }
    }
    binary.to_string()
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
