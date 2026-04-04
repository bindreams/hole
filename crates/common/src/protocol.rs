use crate::config::ServerEntry;
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
pub enum DaemonRequest {
    Start { config: ProxyConfig },
    Stop,
    Status,
    Reload { config: ProxyConfig },
    Metrics,
    Diagnostics,
    PublicIp,
}

/// Client-side response enum. Used by the GUI client API and elevation flow.
/// Not part of the wire protocol — the client maps HTTP responses back to
/// these variants internally.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum DaemonResponse {
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
        daemon: String,
        network: String,
        vpn_server: String,
        internet: String,
    },
    PublicIp {
        ip: String,
        country_code: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyConfig {
    pub server: ServerEntry,
    pub local_port: u16,
}

// Constants ===========================================================================================================

/// Default daemon socket path.
pub fn default_daemon_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/var/run/hole-daemon.sock")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
            .join("hole")
            .join("hole-daemon.sock")
    }
}

/// Actionable instructions shown when a client is denied access to the daemon.
/// Both platform instructions are always printed regardless of the current OS.
pub const PERMISSION_DENIED_HELP: &str = "\
error: permission denied — you are not authorized to control the Hole daemon.

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
