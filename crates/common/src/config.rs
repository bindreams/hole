use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

// Errors ==============================================================================================================

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[from] serde_json::Error),
}

// Types ===============================================================================================================

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
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            selected_server: None,
            local_port: 4073,
            enabled: false,
            elevation_prompt_shown: false,
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
            .finish()
    }
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
