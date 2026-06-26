//! Persisted lockdown INTENT (the standing kill switch's enabled bool),
//! bridge-owned and system-wide. Distinct from `bridge-failclosed.json`
//! (which records the transient cover's pf token): this file records what the
//! user *wants*, surviving bridge restarts and crashes. Modeled on
//! `failclosed_state.rs`: schema version, atomic save, load-None-on-mismatch.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Schema version. [`load`] discards a mismatched file rather than risk a
/// corrupt recovery (same policy as the route/failclosed state files).
pub const SCHEMA_VERSION: u32 = 1;

/// Filename under `state_dir`.
pub const STATE_FILE_NAME: &str = "bridge-lockdown.json";

/// Persisted lockdown intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockdownState {
    pub version: u32,
    /// Whether the standing kill switch is enabled.
    pub enabled: bool,
}

fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE_NAME)
}

/// Atomically persist `state` (temp file + same-dir rename, `sync_all`
/// before persist). Creates `state_dir`.
pub fn save(state_dir: &Path, state: &LockdownState, owner: Option<(u32, u32)>) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    util::ownership::chown_if_some(state_dir, owner);
    let json = serde_json::to_vec_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let path = state_file(state_dir);
    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(&path).map_err(|e| e.error)?;
    util::ownership::chown_if_some(&path, owner);
    Ok(())
}

/// Load the intent, or `None` on absent/corrupt/unknown-field/version
/// mismatch (logs at `warn`). An absent file means "default-off".
pub fn load(state_dir: &Path) -> Option<LockdownState> {
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "lockdown-state read failed");
            return None;
        }
    };
    match serde_json::from_slice::<LockdownState>(&bytes) {
        Ok(s) if s.version == SCHEMA_VERSION => Some(s),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "lockdown-state schema mismatch, discarding"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "lockdown-state parse failed");
            None
        }
    }
}

/// Convenience: the effective intent (absent file => false / default-off).
pub fn load_enabled(state_dir: &Path) -> bool {
    load(state_dir).map(|s| s.enabled).unwrap_or(false)
}

/// Last-writer-wins absolute set. Persists `enabled` under the current schema.
pub fn set_enabled(state_dir: &Path, enabled: bool, owner: Option<(u32, u32)>) -> std::io::Result<()> {
    save(
        state_dir,
        &LockdownState {
            version: SCHEMA_VERSION,
            enabled,
        },
        owner,
    )
}

/// Delete the state file; tolerates absence.
pub fn clear(state_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(state_file(state_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "lockdown_state_tests.rs"]
mod lockdown_state_tests;
