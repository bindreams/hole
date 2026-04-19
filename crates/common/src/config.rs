use crate::protocol::ServerTestOutcome;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use thiserror::Error;
use time::OffsetDateTime;

// Errors ==============================================================================================================

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] serde_json::Error),
}

// Types ===============================================================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    Exactly,
    WithSubdomains,
    Wildcard,
    Subnet,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterAction {
    Proxy,
    Bypass,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FilterRule {
    pub address: String,
    pub matching: MatchType,
    pub action: FilterAction,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StartupBehavior {
    DoNotConnect,
    #[default]
    RestoreLastState,
    AlwaysConnect,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    Light,
    #[default]
    Dark,
    System,
}

// DNS forwarder =======================================================================================================

/// Transport used by the built-in DNS forwarder when talking upstream to
/// [`DnsConfig::servers`].
///
/// `PlainUdp` works only when the configured plugin can carry UDP (galoshes)
/// OR the upstream IP is covered by a bypass rule — otherwise the
/// forwarder's own UDP/53 queries are dropped by the HoleRouter the same way
/// the original bug drops OS queries. `PlainTcp`, `Tls`, `Https` all go over
/// TCP and ride through any plugin.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsProtocol {
    PlainUdp,
    PlainTcp,
    Tls,
    #[default]
    Https,
}

/// Built-in DNS forwarder configuration.
///
/// The bridge binds a loopback DNS server when `enabled`, reconfigures the
/// OS resolver to point at it, and forwards queries upstream via
/// [`DnsProtocol`]. Queries travel through the shadowsocks SOCKS5 listener,
/// so they're carried over the TCP tunnel even when the plugin is TCP-only.
///
/// `servers` is ordered: the first entry is primary, subsequent entries are
/// tried on failure. The UI currently renders exactly two rows
/// (primary + secondary), but the model accepts any number.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsConfig {
    pub enabled: bool,
    pub servers: Vec<IpAddr>,
    pub protocol: DnsProtocol,
    /// When `true`, the HoleRouter redirects any in-tunnel UDP/53 flow to
    /// the loopback forwarder (not only queries to the OS-configured
    /// resolver). Catches apps that hardcode DNS destinations like
    /// Chrome's Secure DNS to `8.8.8.8`.
    pub intercept_udp53: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            servers: vec![
                IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(std::net::Ipv4Addr::new(1, 0, 0, 1)),
            ],
            protocol: DnsProtocol::Https,
            intercept_udp53: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppConfig {
    pub servers: Vec<ServerEntry>,
    pub selected_server: Option<String>,
    pub local_port: u16,
    pub enabled: bool,

    /// Whether the elevation explanation dialog has been shown to the user.
    ///
    /// This is a GUI-only field stored in the shared config to avoid a second
    /// config file. Once set to `true`, subsequent PermissionDenied errors
    /// skip the explanation dialog and go directly to a UAC prompt.
    pub elevation_prompt_shown: bool,

    pub filters: Vec<FilterRule>,
    pub start_on_login: bool,
    pub on_startup: StartupBehavior,
    pub theme: Theme,
    pub proxy_server_enabled: bool,
    pub proxy_socks5: bool,
    pub proxy_http: bool,
    pub dns: DnsConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            selected_server: None,
            local_port: 4073,
            enabled: false,
            elevation_prompt_shown: false,
            filters: Vec::new(),
            start_on_login: false,
            on_startup: StartupBehavior::default(),
            theme: Theme::default(),
            proxy_server_enabled: true,
            proxy_socks5: true,
            proxy_http: false,
            dns: DnsConfig::default(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerEntry {
    pub id: String,
    pub name: String,
    pub server: String,
    pub server_port: u16,
    pub method: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<String>,
    /// Persisted result of the most recent server test (or `None` if untested).
    /// Set by the GUI's `test_server` and `mark_validated_by_proxy_start`
    /// commands. Drives the per-card status indicator and the
    /// `vpn_server`/`internet` diagnostics dots.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub validation: Option<ValidationState>,
}

impl std::fmt::Debug for ServerEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerEntry")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("server", &self.server)
            .field("server_port", &self.server_port)
            .field("method", &self.method)
            .field("password", &"<redacted>")
            .field("plugin", &self.plugin)
            .field("plugin_opts", &self.plugin_opts)
            .field("validation", &self.validation)
            .finish()
    }
}

/// Persisted state of the most recent test for a `ServerEntry`. The
/// `tested_at` timestamp is serialized as RFC3339 so the JS frontend can
/// parse it directly with `new Date(...)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationState {
    #[serde(with = "time::serde::rfc3339")]
    pub tested_at: OffsetDateTime,
    pub outcome: ServerTestOutcome,
}

// Validation ==========================================================================================================

/// Check whether a plugin name is a simple identifier (not a path).
///
/// Only allows ASCII alphanumerics, dots, underscores, and hyphens (`[a-zA-Z0-9._-]+`).
/// Rejects path separators, null bytes, spaces, shell metacharacters, and empty strings.
pub fn is_valid_plugin_name(name: &str) -> bool {
    !name.is_empty()
        && !name.bytes().all(|b| b == b'.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

// Methods =============================================================================================================

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(ConfigError::Read(e)),
        }
    }

    // Restrict config file permissions on macOS — the config contains plaintext
    // passwords and must not be world-readable (default umask 0022 yields 0644).
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let json = serde_json::to_string_pretty(self)?;

        #[cfg(target_os = "macos")]
        {
            use std::fs::{DirBuilder, OpenOptions, Permissions};
            use std::io::Write;
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

            // Only the leaf directory (e.g. `hole/`) is created by us — ancestor directories
            // like `~/Library/Application Support/` are system-managed and already exist.
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
                std::fs::set_permissions(parent, Permissions::from_mode(0o700))?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.set_permissions(Permissions::from_mode(0o600))?;
            file.write_all(json.as_bytes())?;
        }

        #[cfg(target_os = "windows")]
        {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, json)?;
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = json;
            compile_error!("save() is not implemented for this platform");
        }

        Ok(())
    }

    pub fn selected_entry(&self) -> Option<&ServerEntry> {
        let id = self.selected_server.as_ref()?;
        self.servers.iter().find(|s| &s.id == id)
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
