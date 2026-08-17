//! Persisted plugin process identities for crash recovery.
//!
//! The bridge writes each plugin child's `ProcessIdRecord` to a JSON file when
//! a plugin chain starts and reads it back on startup to reap processes leaked
//! by a previous crashed run. Mirrors the `routing::state` crash-recovery
//! pattern. `plugin_recovery` owns the reap and is the only component allowed
//! to delete the file.
//!
//! A record pairs the pid with the kernel's own start token, so a recycled pid
//! never restores to the recorded process — see `cosca::identity`.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

// Types ===============================================================================================================

pub const SCHEMA_VERSION: u32 = 2;

/// Filename of the persisted state file under `state_dir`. Exported so
/// external tooling can reference the single source of truth.
pub const STATE_FILE_NAME: &str = "bridge-plugins.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginState {
    pub version: u32,
    pub plugins: Vec<cosca::identity::ProcessIdRecord>,
}

/// What [`load`] found. Deliberately no `PartialEq`: a variant carrying an
/// `io::Error` joins this set, so callers and tests match with `matches!`.
#[derive(Debug)]
pub enum Loaded {
    /// No state file — nothing was ever recorded, or a reap already cleared it.
    Absent,
    /// Present, but the read itself failed: a sharing violation, an EACCES, a
    /// short read. The records may be perfectly valid and name live processes,
    /// so this is not "worthless". The io error travels with the variant
    /// because this is the one arm that deliberately leaves the file behind
    /// for a human, and the remedy depends on why.
    Unreadable(std::io::Error),
    /// Present and read, but provably worthless: an old schema, malformed
    /// JSON, or an unknown field. Nothing in it can name a process.
    Unusable,
    /// Parsed at the current schema version.
    State(PluginState),
}

fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE_NAME)
}

// I/O =================================================================================================================

/// Write `state` to `<state_dir>/bridge-plugins.json` atomically.
/// Same atomic-write pattern as `routing::state::save`.
pub fn save(state_dir: &Path, state: &PluginState, owner: Option<(u32, u32)>) -> std::io::Result<()> {
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

/// Append a single record to the state file. Creates the file if missing.
/// Reads existing records, merges, atomically writes the result.
///
/// Called at plugin spawn, where a file that will not parse is already dead
/// weight, so `Absent` and `Unusable` both start a fresh state. A file that
/// could not be *read* is not dead weight: rewriting it with a single record
/// would drop the previously-tracked plugins permanently, so the read error is
/// returned and nothing is written.
pub fn append_record(
    state_dir: &Path,
    record: cosca::identity::ProcessIdRecord,
    owner: Option<(u32, u32)>,
) -> std::io::Result<()> {
    let mut state = match load(state_dir) {
        Loaded::State(state) => state,
        Loaded::Unreadable(e) => return Err(e),
        Loaded::Absent | Loaded::Unusable => PluginState {
            version: SCHEMA_VERSION,
            plugins: Vec::new(),
        },
    };
    state.plugins.push(record);
    save(state_dir, &state, owner)
}

/// Load the state file, distinguishing "nothing recorded" from "could not be
/// read" from "recorded but worthless". Logs the schema/JSON detail where it
/// is detected; a failed read is reported to the caller instead, because the
/// caller is the one that knows the consequence.
pub fn load(state_dir: &Path) -> Loaded {
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Absent,
        Err(e) => return Loaded::Unreadable(e),
    };
    match serde_json::from_slice::<PluginState>(&bytes) {
        Ok(state) if state.version == SCHEMA_VERSION => Loaded::State(state),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "plugin-state schema mismatch, discarding"
            );
            Loaded::Unusable
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "plugin-state parse failed");
            Loaded::Unusable
        }
    }
}

/// Delete the state file. Tolerates a missing file.
pub fn clear(state_dir: &Path) -> std::io::Result<()> {
    let path = state_file(state_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "plugin_state_tests.rs"]
mod plugin_state_tests;
