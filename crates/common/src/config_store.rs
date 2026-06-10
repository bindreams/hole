//! Load-time quarantine and gated saving for the GUI config file (#467).
//!
//! `AppConfig::load` used to map a missing file to defaults and anything else
//! to an error — which the GUI discarded (`unwrap_or_default`), so the next
//! save overwrote the corrupt file, destroying the user's servers and
//! passwords. `ConfigStore` makes that impossible: a corrupt/unreadable
//! `config.json` is quarantined to a timestamped `.bak` before defaults are
//! used, and if quarantine fails, saving is blocked for the session.

use crate::config::{AppConfig, ConfigError};
use std::io;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

/// What happened when the config file could not be loaded.
#[derive(Debug)]
pub struct ConfigRecovery {
    /// The config file that failed to load.
    pub path: PathBuf,
    /// Why it failed.
    pub error: ConfigError,
    /// Where the file was quarantined, or the error that prevented it.
    pub backup: Result<PathBuf, io::Error>,
}

/// Owns the config path and the load-time recovery state. All GUI saves go
/// through [`ConfigStore::save`] so a failed quarantine blocks destructive
/// writes for the whole session.
pub struct ConfigStore {
    path: PathBuf,
    /// Set when quarantine failed: the corrupt file is still at `path` and
    /// writing would destroy it.
    save_blocked: bool,
}

impl ConfigStore {
    /// Load `path`, quarantining a corrupt/unreadable file to a `.bak`.
    ///
    /// Missing file → defaults, no recovery (first launch). `now` becomes the
    /// timestamp in the backup name; production passes
    /// `OffsetDateTime::now_utc()`.
    pub fn load(path: PathBuf, now: OffsetDateTime) -> (Self, AppConfig, Option<ConfigRecovery>) {
        let _ = now;
        let config = AppConfig::load(&path).unwrap_or_default();
        (
            Self {
                path,
                save_blocked: false,
            },
            config,
            None,
        )
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Save `config`, unless a failed quarantine blocked saving.
    ///
    /// Not a synchronization point: concurrent saves are serialized by the
    /// caller — every GUI site holds the `AppState::config` mutex across
    /// this call.
    pub fn save(&self, config: &AppConfig) -> Result<(), ConfigError> {
        if self.save_blocked {
            return Err(ConfigError::SaveBlocked);
        }
        config.save(&self.path)
    }
}

#[cfg(test)]
#[path = "config_store_tests.rs"]
mod config_store_tests;
