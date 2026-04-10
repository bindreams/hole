use crate::config::{FilterRule, ServerEntry};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Generated from api/openapi.yaml — StatusResponse, ErrorResponse, EmptyResponse, route constants
#[allow(clippy::derivable_impls)]
mod api_generated {
    include!(concat!(env!("OUT_DIR"), "/api_generated.rs"));
}
pub use api_generated::*;

// Types ===============================================================================================================

/// Client-side request enum. Used by the GUI client API and elevation flow
/// (base64 CLI serialization). Not part of the wire protocol — the client
/// maps variants to HTTP endpoints internally.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BridgeRequest {
    Start {
        config: ProxyConfig,
    },
    Stop,
    /// Cancel an in-flight `Start`. Idempotent — if no start is in flight, the
    /// cancel is pre-armed and consumed by the next start. See the
    /// `/v1/cancel` route in `openapi.yaml`.
    Cancel,
    Status,
    Reload {
        config: ProxyConfig,
    },
    Metrics,
    Diagnostics,
    PublicIp,
    TestServer {
        entry: ServerEntry,
    },
}

/// Error-payload message string that identifies a cancelled start. Both bridge
/// and client compare against this constant rather than re-parsing the error
/// text.
pub const CANCELLED_MESSAGE: &str = "cancelled";

/// Client-side response enum. Used by the GUI client API and elevation flow.
/// Not part of the wire protocol — the client maps HTTP responses back to
/// these variants internally.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum BridgeResponse {
    Ack,
    Status {
        running: bool,
        uptime_secs: u64,
        error: Option<String>,
    },
    Error {
        message: String,
    },
    Metrics {
        bytes_in: u64,
        bytes_out: u64,
        speed_in_bps: u64,
        speed_out_bps: u64,
        uptime_secs: u64,
    },
    Diagnostics {
        app: String,
        bridge: String,
        network: String,
        vpn_server: String,
        internet: String,
    },
    PublicIp {
        ip: String,
        country_code: String,
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
/// `TunnelHandshakeFailed`.
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

// Constants ===========================================================================================================

/// Default bridge socket path.
pub fn default_bridge_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
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
