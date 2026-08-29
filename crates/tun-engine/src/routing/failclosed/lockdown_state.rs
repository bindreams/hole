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

/// What `bridge-lockdown.json` says about the standing kill switch. A closed
/// classification rather than a bool, so "the user recorded off" and "we could
/// not find out" stop being the same answer — conflating them is what let a
/// bridge with a wiped state dir sweep a live cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// The file parsed at the current schema and records `enabled: true`.
    On,
    /// The file parsed at the current schema and records `enabled: false`.
    Off,
    /// No file at all (`ErrorKind::NotFound`): a fresh install, a wiped or
    /// recreated state dir, or a second bridge's own `--state-dir`.
    Unset,
    /// A file exists but the read, the JSON parse, or the version check failed.
    Unreadable,
}

impl Intent {
    /// "Does the user believe the kill switch is armed?" — `On | Unreadable`.
    /// An unreadable record is not consent to disarm, so it reports armed and
    /// the tray's Unblock escape stays on the menu.
    ///
    /// Consumers, in full: `ProxyManager::lockdown_enabled`.
    pub fn reads_armed(self) -> bool {
        matches!(self, Intent::On | Intent::Unreadable)
    }

    /// "Should this start install the STANDING cover?" — `On` only.
    ///
    /// `Unreadable` answers **no**, and that is what keeps a corrupt-file start
    /// engaging the transient block-until-connected cover instead of skipping
    /// it for a standing cover that only arrives after `routing.install`: block
    /// early, don't leak.
    ///
    /// Consumers, in full: the transient-vs-standing branch, the
    /// reachability-probe suppression, the `install_lockdown` gate, and the
    /// update-consent gate.
    pub fn installs_standing_cover(self) -> bool {
        matches!(self, Intent::On)
    }
}

/// The one read+parse of the intent file. `Ok` is a file that parsed at the
/// current schema; `Err` carries the [`Intent`] its failure classifies to, so
/// [`load`] and [`load_intent`] share a single reader (and a single set of
/// `warn!` lines) instead of drifting apart.
fn read_state(state_dir: &Path) -> Result<LockdownState, Intent> {
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Intent::Unset),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "lockdown-state read failed");
            return Err(Intent::Unreadable);
        }
    };
    match serde_json::from_slice::<LockdownState>(&bytes) {
        Ok(s) if s.version == SCHEMA_VERSION => Ok(s),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "lockdown-state schema mismatch, discarding"
            );
            Err(Intent::Unreadable)
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "lockdown-state parse failed");
            Err(Intent::Unreadable)
        }
    }
}

/// Load the intent, or `None` on absent/corrupt/unknown-field/version
/// mismatch (logs at `warn`). Use [`load_intent`] where the *reason* for a
/// `None` matters.
pub fn load(state_dir: &Path) -> Option<LockdownState> {
    read_state(state_dir).ok()
}

/// Classify the intent file. Never collapses a failure into a recorded value —
/// see [`Intent`] and its two folds.
pub fn load_intent(state_dir: &Path) -> Intent {
    match read_state(state_dir) {
        Ok(s) if s.enabled => Intent::On,
        Ok(_) => Intent::Off,
        Err(i) => i,
    }
}

/// Convenience: [`Intent::reads_armed`] over [`load_intent`]. An absent file is
/// default-off; a corrupt one reads ARMED, because losing the record is not the
/// user telling us to disarm.
pub fn load_enabled(state_dir: &Path) -> bool {
    load_intent(state_dir).reads_armed()
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
