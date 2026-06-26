use crate::config::{FilterRule, ServerEntry};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Typify-generated API types from `api/openapi.yaml` — `StatusResponse`,
/// `ErrorResponse`, `EmptyResponse`, and route constants.
#[allow(clippy::derivable_impls)]
mod api_generated {
    include!(concat!(env!("OUT_DIR"), "/api_generated.rs"));
}
pub use api_generated::*;

#[allow(clippy::derivable_impls)] // FilterMetrics is code-generated without Default
impl Default for FilterMetrics {
    fn default() -> Self {
        Self {
            total_connections: 0,
            proxied: 0,
            bypassed: 0,
            blocked: 0,
            sniffer_hits: 0,
            sniffer_misses: 0,
            active_udp_flows: 0,
            udp_drops_backpressure: 0,
        }
    }
}

// Types ===============================================================================================================

/// Client-side request enum. Used by the GUI client API and elevation flow
/// (base64 CLI serialization). Not part of the wire protocol — the client
/// maps variants to HTTP endpoints internally.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BridgeRequest {
    Start {
        config: ProxyConfig,
        /// Per-attempt idempotency key minted by the GUI (a UUID). Sent on the
        /// wire as the `X-Hole-Attempt-Id` header; the bridge scopes
        /// start-cancellation to it (#465). A struct field, not a
        /// client-side-only header, so it survives the elevation
        /// re-serialization path (`encode_request` / `write_request_file`).
        attempt_id: String,
    },
    Stop,
    /// Cancel the in-flight `Start` whose `attempt_id` matches, or pre-arm a
    /// cancel scoped to that attempt. Idempotent — a cancel that finds no
    /// matching in-flight start is consumed by the next start carrying the same
    /// id. See the `/v1/cancel` route in `openapi.yaml`.
    Cancel {
        attempt_id: String,
    },
    Status,
    Reload {
        config: ProxyConfig,
    },
    Metrics,
    Diagnostics,
    TestServer {
        entry: ServerEntry,
    },
    /// Set the standing kill switch intent (last-writer-wins). Maps to
    /// `POST /v1/lockdown`.
    SetLockdown {
        enabled: bool,
    },
    /// Apply a verified update via the service-manager cutover. Maps to
    /// `POST /v1/update-apply`. `consent` is the informed-consent seam: REQUIRED
    /// true for a lockdown-off update (the standing cover holds the gap under
    /// lockdown-on).
    ApplyUpdate {
        payload_path: PathBuf,
        target_version: String,
        consent: bool,
        /// The release `SHA256SUMS` manifest text the GUI already fetched, so the
        /// privileged bridge can re-verify the payload offline (no network).
        sha256sums: String,
        /// The minisign signature over `sha256sums`.
        sha256sums_minisig: String,
        /// The payload's filename, used to find its hash in `sha256sums`.
        asset_name: String,
        /// macOS only: the GUI's `current_exe`-derived `.app` swap target. A
        /// HINT the bridge re-validates (the bundle there must be a genuine
        /// `com.hole.app`) — never a trust anchor. `None` on Windows.
        app_dest: Option<String>,
    },
}

/// Host-free censorship toast text shown when the reachability probe finds the
/// network is resetting/dropping the server handshake. The canonical source of
/// this sentence.
pub const NETWORK_BLOCKED_MESSAGE: &str = "The network is blocking the connection to this server — the handshake was \
     reset or got no response. This usually means a firewall or censorship; \
     try a different server.";

/// Typed outcome of a failed `POST /v1/start` (the 500 body). The concurrent-start
/// rejection is a `ClientError::ConcurrentStart`, not a variant here, so `Failed`
/// is always a genuine `ProxyError`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StartError {
    /// User-cancelled, or a pre-armed cancel consumed this attempt.
    Cancelled,
    /// The proxy was already running — idempotent success GUI-side.
    AlreadyRunning,
    /// The network reset/dropped the server handshake (DPI / censorship).
    NetworkBlocked,
    /// Any other `ProxyError`. `message` is the system-authored, PII-free reason.
    Failed { message: String },
}

/// Client-side response enum. Used by the GUI client API and elevation flow.
/// Not part of the wire protocol — the client maps HTTP responses back to
/// these variants internally.
///
/// Error channels split by operation: `Start` failures are the typed
/// [`StartFailed`](BridgeResponse::StartFailed); every other operation uses
/// the stringly `Error { message }`.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum BridgeResponse {
    Ack,
    Status {
        running: bool,
        uptime_secs: u64,
        error: Option<String>,
        invalid_filters: Vec<InvalidFilter>,
        udp_proxy_available: bool,
        ipv6_bypass_available: bool,
        lockdown_enabled: bool,
        lockdown_active: bool,
    },
    Error {
        message: String,
    },
    /// Typed `POST /v1/start` failure. See [`StartError`].
    StartFailed(StartError),
    Metrics {
        bytes_in: u64,
        bytes_out: u64,
        speed_in_bps: u64,
        speed_out_bps: u64,
        uptime_secs: u64,
        filter: Option<FilterMetrics>,
    },
    Diagnostics {
        app: String,
        bridge: String,
        network: String,
        vpn_server: String,
        internet: String,
    },
    TestServerResult {
        outcome: ServerTestOutcome,
    },
}

/// Which parts of the network stack the bridge should install when starting
/// a proxy.
///
/// Per-request on `ProxyConfig` so the client can choose at start time. The
/// GUI currently always uses [`TunnelMode::Full`]; [`TunnelMode::SocksOnly`]
/// is exposed for advanced users (browser-only SOCKS5 usage), future
/// containerized deployments where routing is managed externally, and tests
/// that need to exercise the real bridge binary without elevation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    /// TUN adapter + SOCKS5 listener + split host routes. Requires
    /// elevation (admin on Windows, root on macOS). Production default.
    #[default]
    Full,
    /// SOCKS5 listener only. No TUN adapter is created; no host routes
    /// are installed; no DNS resolution or gateway detection is performed.
    /// Works without elevation. Clients must configure their own
    /// SOCKS5-aware traffic routing (browser proxy setting, curl --socks5,
    /// container netns, etc.).
    SocksOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyConfig {
    pub server: ServerEntry,
    pub local_port: u16,
    /// Defaults to [`TunnelMode::Full`] when absent — older clients (the
    /// current GUI) that don't send this field keep their existing behavior.
    #[serde(default)]
    pub tunnel_mode: TunnelMode,
    /// Filter rules applied by the bridge dispatcher. Defaults to empty
    /// (no filtering — all captured traffic proxied).
    #[serde(default)]
    pub filters: Vec<FilterRule>,
    /// Built-in DNS forwarder configuration. Defaults to
    /// [`DnsConfig::default()`] (enabled, DoH to Cloudflare). Older clients
    /// that don't send this field get the default, which silently enables
    /// the forwarder on upgrade.
    #[serde(default)]
    pub dns: crate::config::DnsConfig,
    /// Whether to bind a user-facing SOCKS5 listener on
    /// `127.0.0.1:{local_port}`. Defaults to `true` so older clients that
    /// omit the field keep their existing behaviour. In
    /// `tunnel_mode == Full`, `false` is only valid together with
    /// `proxy_http == false` — the pure-VPN start (#459), where the TUN
    /// data plane binds an internal SOCKS5 instance on an ephemeral
    /// loopback port and nothing listens on `local_port`; `false` with
    /// `proxy_http == true` is rejected (`TunnelRequiresSocks5`).
    #[serde(default = "proxy_config_defaults::proxy_socks5")]
    pub proxy_socks5: bool,
    /// Whether to bind an HTTP CONNECT listener on
    /// `127.0.0.1:{local_port_http}`. Defaults to `false`. HTTP CONNECT is
    /// TCP-only (RFC 7231 §4.3.6); UDP flows still require SOCKS5 UDP
    /// ASSOCIATE.
    #[serde(default)]
    pub proxy_http: bool,
    /// Port for the HTTP CONNECT listener when `proxy_http` is enabled.
    /// Defaults to `4074`. Must differ from `local_port` when both
    /// listeners are enabled (enforced at bridge start).
    #[serde(default = "proxy_config_defaults::local_port_http")]
    pub local_port_http: u16,
    /// Enable per-TCP-connection plugin tap diagnostics in `bridge.log`.
    /// Defaults to `false`. When `true`, the bridge wraps the plugin
    /// chain in [`garter::TapPlugin`] so per-connection
    /// `bytes_to_plugin` / `bytes_from_plugin` / `ttfb_ms` / `close_kind`
    /// land in the log. Sourced from
    /// [`crate::config::AppConfig::diagnostic_plugin_tap`]; the bridge
    /// can also be opted in via the `HOLE_BRIDGE_PLUGIN_TAP=1` env var
    /// (dev-shell only — env vars don't survive into SCM/launchd). The
    /// config flag exists so service-mode reproductions have a knob the
    /// env var can't reach.
    #[serde(default)]
    pub diagnostic_plugin_tap: bool,
}

mod proxy_config_defaults {
    pub(super) fn proxy_socks5() -> bool {
        true
    }
    pub(super) fn local_port_http() -> u16 {
        4074
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            server: crate::config::ServerEntry::default_placeholder(),
            local_port: 4073,
            tunnel_mode: TunnelMode::default(),
            filters: Vec::new(),
            dns: crate::config::DnsConfig::default(),
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
            diagnostic_plugin_tap: false,
        }
    }
}

// Server test outcome =================================================================================================

/// Outcome of a one-shot per-server test (see `crates/bridge/src/server_test.rs`).
///
/// Hand-written, NOT generated from `openapi.yaml`. The OpenAPI spec contains
/// only a documentation-only stub for `TestServerRequest`/`TestServerResponse`
/// because typify's discriminated-union support for unit variants is awkward
/// and the type is referenced from both `protocol.rs` and `config.rs`
/// (`ValidationState`), which would create a circular generation dependency.
///
/// Granularity ceiling: the shadowsocks protocol does not let a client
/// distinguish "wrong cipher" from "wrong password" from "v2ray-plugin
/// handshake rejected at the server side". All three collapse into
/// `TunnelHandshakeFailed`. The orthogonal "the network reset/dropped the
/// transport before any handshake" axis is separable out-of-band via the
/// reachability probe (`NetworkBlocked`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerTestOutcome {
    /// All phases succeeded. `latency_ms` is the wall-clock test duration,
    /// clamped to `>= 1` so it can never collide with the
    /// `LATENCY_VALIDATED_ON_CONNECT` sentinel.
    Reachable { latency_ms: u64 },
    /// Pre-flight `tokio::net::lookup_host` failed (only when `entry.server`
    /// is a domain name).
    DnsFailed,
    /// Pre-flight TCP connect to `entry.server:entry.server_port` got
    /// `ConnectionRefused`.
    TcpRefused,
    /// Pre-flight TCP connect timed out.
    TcpTimeout,
    /// `Plugin::start` returned `Err`, OR `wait_started` returned `false`,
    /// OR the plugin process exited within the wait window. The string
    /// carries the underlying error message.
    PluginStartFailed { detail: String },
    /// Pre-flight passed and `ProxyClientStream::connect` succeeded, but the
    /// shadowsocks server stopped responding without ever closing the stream.
    /// On the rust shadowsocks server with v1 AEAD ciphers, this is the
    /// canonical anti-probing behavior on AEAD decryption failure: the
    /// server enters `ignore_until_end` and silently drains forever. Catches
    /// wrong password, wrong cipher, and v2ray-plugin handshake rejected at
    /// the server side, indistinguishably.
    TunnelHandshakeFailed,
    /// Pre-flight reached the server at TCP but the network reset/dropped the
    /// transport handshake (e.g. DPI range-blocking). Out-of-band signal
    /// produced by the reachability probe; distinct from `TunnelHandshakeFailed`
    /// (credentials/config).
    NetworkBlocked,
    /// Tunnel established (server decrypted credentials successfully) but
    /// the upstream sentinel was unreachable through the tunnel. The
    /// shadowsocks server tried to forward our request and either could not
    /// connect to the sentinel or saw the upstream close immediately,
    /// causing it to close our tunnel side cleanly (EOF on the client).
    ServerCannotReachInternet,
    /// Bytes flowed back from the sentinel but did not start with the
    /// ASCII bytes "HTTP". `detail` carries the hex of the first ~32 bytes
    /// for diagnostics.
    SentinelMismatch { detail: String },
    /// Bug in the test runner; should not normally happen. `detail` carries
    /// the underlying message.
    InternalError { detail: String },
}

/// Sentinel value of `latency_ms` meaning "validated by a successful proxy
/// start, not by an explicit test run".
///
/// The bridge test runner clamps real latencies to `>= 1` so it can never
/// produce this value organically. The GUI's `mark_validated_by_proxy_start`
/// command writes this value when it observes a Stopped→Running transition.
pub const LATENCY_VALIDATED_ON_CONNECT: u64 = 0;

// Test-server request/response (hand-written; OpenAPI has stub schemas only)

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TestServerRequest {
    pub entry: ServerEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TestServerResponse {
    pub outcome: ServerTestOutcome,
}

/// Body of `POST /v1/lockdown`: the absolute lockdown intent to set
/// (last-writer-wins). Hand-written, not generated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockdownRequest {
    pub enabled: bool,
}

/// Wire body for `POST /v1/update-apply`. Hand-written (the openapi schema is
/// doc-only). `payload_path` is the GUI's already-downloaded+verified MSI/DMG;
/// the bridge re-verifies it offline against the supplied manifest + signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateApplyRequest {
    pub payload_path: String,
    pub target_version: String,
    pub consent: bool,
    /// The release `SHA256SUMS` manifest text (for offline re-verification).
    pub sha256sums: String,
    /// The minisign signature over `sha256sums`.
    pub sha256sums_minisig: String,
    /// The payload's filename, used to find its hash in `sha256sums`.
    pub asset_name: String,
    /// macOS only: the GUI's `current_exe`-derived `.app` swap target. A HINT the
    /// bridge re-validates against `CFBundleIdentifier == com.hole.app` — never a
    /// trust anchor. `None` on Windows (the SCM install dir is canonical there).
    pub app_dest: Option<String>,
}

// Constants ===========================================================================================================

/// Default bridge socket path.
pub fn default_bridge_socket_path() -> PathBuf {
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/var/run/hole-bridge.sock")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
            .join("hole")
            .join("hole-bridge.sock")
    }
}

/// Actionable instructions shown when a client is denied access to the bridge.
/// Both platform instructions are always printed regardless of the current OS.
pub const PERMISSION_DENIED_HELP: &str = "\
error: permission denied — you are not authorized to control the Hole bridge.

How to fix:

  macOS:
    sudo dseditgroup -o edit -a $(whoami) -t user hole
    Then log out and back in for the change to take effect.
    Or prefix your command with: sudo

  Windows:
    net localgroup hole %USERNAME% /add
    Then log out and back in for the change to take effect.
    Or run your terminal as Administrator.
";

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod protocol_tests;
