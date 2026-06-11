use crate::protocol::ServerTestOutcome;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use thiserror::Error;
use time::OffsetDateTime;

// Errors ==============================================================================================================

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {source}")]
    Read { source: std::io::Error },
    // Carries only content-safe scalars (category + position), NOT the
    // `serde_json::Error`: its `Display` echoes a fragment of the input near the
    // error, which for a config can include a password (see config_tests.rs).
    // Dropping the source makes a content leak structurally impossible (even via
    // `Debug`), while classify() + line/column keep the message actionable.
    #[error("failed to parse config file: {kind} (line {line}, column {column})")]
    Parse {
        kind: &'static str,
        line: usize,
        column: usize,
    },
    #[error("failed to serialize config: {source}")]
    Serialize { source: serde_json::Error },
    #[error("failed to create config directory: {source}")]
    CreateDir { source: std::io::Error },
    #[error("failed to write config file: {source}")]
    Write { source: std::io::Error },
    #[error("config saving is disabled: the corrupt config file could not be backed up at startup")]
    SaveBlocked,
}

/// Content-safe label for a `serde_json` parse failure (never echoes the input).
/// `pub(crate)` so `ConfigStore::load` builds the same leak-safe variant.
pub(crate) fn parse_kind(e: &serde_json::Error) -> &'static str {
    use serde_json::error::Category;
    match e.classify() {
        Category::Io => "I/O error",
        Category::Syntax => "syntax error",
        Category::Data => "data error",
        Category::Eof => "unexpected end of input",
    }
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
/// When `enabled`, the bridge points the OS adapters' DNS at the configured
/// `servers` resolver IPs. Those queries route into `hole-tun`, where the
/// in-TUN DNS endpoint intercepts them and forwards upstream via
/// [`DnsProtocol`] through the shadowsocks SOCKS5 listener — carried over the
/// TCP tunnel even when the plugin is TCP-only. There is no loopback server.
///
/// `servers` is ordered: the first entry is primary, subsequent entries are
/// tried on failure. The UI currently renders exactly two rows
/// (primary + secondary), but the model accepts any number.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsConfig {
    pub enabled: bool,
    pub servers: Vec<IpAddr>,
    pub protocol: DnsProtocol,
    /// Legacy field, retained for config back-compat. It no longer gates the
    /// in-TUN UDP/53 divert: the DNS endpoint is always active when DNS is
    /// enabled, so every in-tunnel UDP/53 flow is intercepted regardless of
    /// this value.
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
    /// Master switch for the user-facing local proxy listeners
    /// ("Local proxy server" in settings). When false,
    /// `build_proxy_config` zeroes `proxy_socks5` / `proxy_http` in the
    /// outgoing `ProxyConfig` and the bridge runs a pure-VPN start: the
    /// TUN data plane binds an internal ephemeral SOCKS5 instance and
    /// nothing listens on `local_port` / `local_port_http`. The nested
    /// toggles keep their persisted values for re-enable.
    pub proxy_server_enabled: bool,
    pub proxy_socks5: bool,
    pub proxy_http: bool,
    pub dns: DnsConfig,
    /// Port for the HTTP CONNECT listener when `proxy_http` is enabled. The
    /// SOCKS5 listener uses `local_port`; the two must differ when both
    /// toggles are on (enforced at bridge start by
    /// `hole_bridge::proxy::config::build_ss_config`).
    pub local_port_http: u16,
    /// When true, the bridge wraps the plugin chain in
    /// [`garter::TapPlugin`] so per-TCP-connection
    /// `bytes_to_plugin` / `bytes_from_plugin` / `ttfb_ms` / `close_kind`
    /// land in `bridge.log`. Off by default — adds a loopback round-trip
    /// per byte, inappropriate at browser-traffic scale. Enable when
    /// reproducing a "tunnel returns nothing" failure (e.g. a plugin
    /// outbound that silently hangs). See CLAUDE.md "Plugin tap" section.
    ///
    /// **Reaches service mode**: this flag travels via [`ProxyConfig`]
    /// in the IPC `BridgeRequest::Start` payload, unlike the
    /// `HOLE_BRIDGE_PLUGIN_TAP` env var which is dev-shell-only.
    pub diagnostic_plugin_tap: bool,
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
            local_port_http: 4074,
            diagnostic_plugin_tap: false,
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

impl ServerEntry {
    /// A minimal placeholder entry used as the stand-in for `impl Default`
    /// on `ProxyConfig` (tests and in-memory defaults). Never meant to be
    /// sent to the bridge as a real config — `server_port` is `0` and
    /// `password` is empty. Use it only when the `server` field is about to
    /// be overwritten with a real entry.
    pub fn default_placeholder() -> Self {
        Self {
            id: "placeholder".into(),
            name: "placeholder".into(),
            server: "127.0.0.1".into(),
            server_port: 0,
            method: "aes-256-gcm".into(),
            password: String::new(),
            plugin: None,
            plugin_opts: None,
            validation: None,
        }
    }
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
    // Loading lives in `ConfigStore::load` (crate::config_store) — it
    // quarantines corrupt files instead of returning an error to discard.

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        use std::io::Write;

        let json = serde_json::to_string_pretty(self).map_err(|source| ConfigError::Serialize { source })?;

        // The directory that will hold the config — and the atomic-rename temp.
        // The rename is only atomic within one filesystem, so the temp must be
        // created in this same directory.
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some(parent) = dir {
            ensure_config_dir(parent)?;
        }
        let temp_dir = dir.unwrap_or_else(|| Path::new("."));

        // Atomic write: a fresh temp file in the target directory, fully written
        // and synced, then renamed over the target. A crash or partial write can
        // never leave a truncated/corrupt config in place.
        let mut tmp = tempfile::Builder::new()
            .prefix(".config")
            .suffix(".tmp")
            .tempfile_in(temp_dir)
            .map_err(|source| ConfigError::Write { source })?;
        tmp.write_all(json.as_bytes())
            .map_err(|source| ConfigError::Write { source })?;
        // tempfile creates the temp 0600 on unix (O_EXCL + restrictive mode), and
        // rename preserves the mode — so the persisted config keeps its plaintext
        // passwords at 0600, never the umask-default 0644. The 0600 invariant is
        // guarded by `save_creates_file_with_owner_only_permissions`.
        tmp.as_file()
            .sync_all()
            .map_err(|source| ConfigError::Write { source })?;
        // persist() renames the temp over `path`. rename does NOT follow a target
        // symlink (it replaces the link itself), so there is no target-symlink
        // TOCTOU; the temp's random O_EXCL name in the 0700 dir is unguessable.
        tmp.persist(path).map_err(|e| ConfigError::Write { source: e.error })?;

        // Best-effort: fsync the directory so the rename is durable across power
        // loss. The atomic property (no truncated/partial config is ever visible)
        // already holds without this; only crash-durability of the *rename* needs
        // it, and a failure here must not fail an otherwise-successful save. Unix
        // only — Windows has no portable directory fsync.
        #[cfg(unix)]
        if let Some(parent) = dir {
            if let Err(e) = std::fs::File::open(parent).and_then(|d| d.sync_all()) {
                tracing::warn!(error = %e, "could not fsync config directory; rename may not survive power loss");
            }
        }

        Ok(())
    }

    pub fn selected_entry(&self) -> Option<&ServerEntry> {
        let id = self.selected_server.as_ref()?;
        self.servers.iter().find(|s| &s.id == id)
    }
}

/// Create the config's leaf directory (e.g. `hole/`). Ancestors like
/// `~/Library/Application Support/` are system-managed and already exist.
#[cfg(target_os = "macos")]
fn ensure_config_dir(parent: &Path) -> Result<(), ConfigError> {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|source| ConfigError::CreateDir { source })?;
    // Best-effort hardening of a *pre-existing* directory. The 0600 config file
    // is the load-bearing protection for its plaintext passwords; a directory we
    // don't own (e.g. left root-owned by an earlier privileged run) can't be
    // chmod'd by us, but that must not abort the save — if the directory is
    // genuinely unwritable the temp-file create fails with an accurate write
    // error instead of a spurious permission error here.
    if let Err(source) = std::fs::set_permissions(parent, Permissions::from_mode(0o700)) {
        tracing::warn!(error = %source, dir = %parent.display(),
            "could not tighten config directory permissions; continuing");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn ensure_config_dir(parent: &Path) -> Result<(), ConfigError> {
    std::fs::create_dir_all(parent).map_err(|source| ConfigError::CreateDir { source })
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn ensure_config_dir(_parent: &Path) -> Result<(), ConfigError> {
    compile_error!("save() is not implemented for this platform");
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
