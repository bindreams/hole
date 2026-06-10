//! Load-time quarantine and gated saving for the GUI config file (#467).
//!
//! `AppConfig::load` used to map a missing file to defaults and anything else
//! to an error — which the GUI discarded (`unwrap_or_default`), so the next
//! save overwrote the corrupt file, destroying the user's servers and
//! passwords. `ConfigStore` makes that impossible: a corrupt/unreadable
//! `config.json` is quarantined to a timestamped `.bak` before defaults are
//! used, and if quarantine fails, saving is blocked for the session.

use crate::config::{AppConfig, ConfigError};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use tracing::{error, warn};

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
        let (config, recovery) = match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(config) => (config, None),
                Err(e) => {
                    let backup = quarantine(&path, Some(&contents), now);
                    let recovery = ConfigRecovery {
                        path: path.clone(),
                        error: e.into(),
                        backup,
                    };
                    (AppConfig::default(), Some(recovery))
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (AppConfig::default(), None),
            Err(e) => {
                let backup = quarantine(&path, None, now);
                let recovery = ConfigRecovery {
                    path: path.clone(),
                    error: ConfigError::Read(e),
                    backup,
                };
                (AppConfig::default(), Some(recovery))
            }
        };

        if let Some(r) = &recovery {
            match &r.backup {
                Ok(bak) => error!(
                    path = %r.path.display(), error = %r.error, backup = %bak.display(),
                    "config file unreadable; quarantined to backup, starting with defaults"
                ),
                Err(bak_err) => error!(
                    path = %r.path.display(), error = %r.error, backup_error = %bak_err,
                    "config file unreadable and backup failed; saving disabled for this session"
                ),
            }
        }

        let save_blocked = matches!(&recovery, Some(r) if r.backup.is_err());
        (Self { path, save_blocked }, config, recovery)
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

/// Timestamp embedded in backup names. Dashes instead of colons — colons are
/// invalid in Windows file names.
const BACKUP_TS_FORMAT: &[time::format_description::BorrowedFormatItem<'static>] =
    time::macros::format_description!("[year]-[month]-[day]T[hour]-[minute]-[second]Z");

fn backup_path(path: &Path, now: OffsetDateTime, counter: u32) -> PathBuf {
    debug_assert!(path.file_name().is_some(), "config path must name a file: {path:?}");
    let ts = now.format(BACKUP_TS_FORMAT).expect("static format, in-range timestamp");
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let suffix = if counter == 1 {
        String::new()
    } else {
        format!("-{counter}")
    };
    path.with_file_name(format!("{name}.{ts}{suffix}.bak"))
}

/// Move the file at `path` aside to a timestamped sibling `.bak`.
///
/// Prefers an atomic `rename`: one step, and it preserves the original
/// file's permissions (the config holds plaintext passwords; macOS `save()`
/// enforces 0600). If rename fails and the contents are known (the file was
/// readable but unparsable), falls back to writing a fresh backup and
/// best-effort removing the original — on Windows a file held open by
/// another process refuses the rename but still allows new siblings.
fn quarantine(path: &Path, contents: Option<&str>, now: OffsetDateTime) -> Result<PathBuf, io::Error> {
    // The exists()-probe → rename pair is not atomic, and on unix a rename
    // would silently overwrite an existing destination — the probe is what
    // protects older backups. That is sound because nothing else creates
    // `config.json.*.bak` siblings: the webview engine shares this directory
    // but never writes backup-named files, and the single-instance lock
    // (held before setup) makes Hole itself sequential. `exists()` mapping
    // stat errors to `false` is the safe direction — the rename/create_new
    // below is authoritative and fails cleanly.
    let mut counter = 1;
    let bak = loop {
        let candidate = backup_path(path, now, counter);
        if !candidate.exists() {
            break candidate;
        }
        counter += 1;
    };

    let rename_err = match fs::rename(path, &bak) {
        Ok(()) => return Ok(bak),
        Err(e) => e,
    };
    let Some(contents) = contents else {
        return Err(rename_err);
    };
    warn!(error = %rename_err, "rename to backup failed; attempting copy fallback");

    // `create_new` is an atomic claim of the name, so this loop is race-free.
    loop {
        let candidate = backup_path(path, now, counter);
        match open_create_new(&candidate) {
            Ok(mut file) => {
                use std::io::Write;
                if let Err(e) = file.write_all(contents.as_bytes()) {
                    let _ = fs::remove_file(&candidate);
                    return Err(e);
                }
                if let Err(e) = fs::remove_file(path) {
                    warn!(
                        path = %path.display(), error = %e,
                        "backed up corrupt config by copy, but could not remove the original; \
                         it may be re-quarantined on next start"
                    );
                }
                return Ok(candidate);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => counter += 1,
            Err(e) => return Err(e),
        }
    }
}

/// The backup holds plaintext passwords — match `save()`'s 0600 on unix.
#[cfg(unix)]
fn open_create_new(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_create_new(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(test)]
#[path = "config_store_tests.rs"]
mod config_store_tests;
