// Persisted plugin PID state for crash recovery.
//
// The bridge writes plugin PIDs to a JSON file when a plugin chain starts,
// clears it on clean shutdown, and reads it on startup to kill leaked
// plugin processes from a previous crashed run. Mirrors the
// `route_state.rs` crash-recovery pattern.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

// Types ===============================================================================================================

pub const SCHEMA_VERSION: u32 = 1;

/// Filename of the persisted state file under `state_dir`. Exported so
/// external tooling can reference the single source of truth.
pub const STATE_FILE_NAME: &str = "bridge-plugins.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginState {
    pub version: u32,
    pub plugins: Vec<PluginRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginRecord {
    pub pid: u32,
    pub start_time_unix_ms: u64,
}

fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE_NAME)
}

// I/O =================================================================================================================

/// Write `state` to `<state_dir>/bridge-plugins.json` atomically.
/// Same atomic-write pattern as `route_state::save`.
pub fn save(state_dir: &Path, state: &PluginState) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;

    let json = serde_json::to_vec_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(state_file(state_dir)).map_err(|e| e.error)?;
    Ok(())
}

/// Append a single record to the state file. Creates the file if missing.
/// Reads existing records, merges, atomically writes the result.
pub fn append_record(state_dir: &Path, record: PluginRecord) -> std::io::Result<()> {
    let mut state = load(state_dir).unwrap_or(PluginState {
        version: SCHEMA_VERSION,
        plugins: Vec::new(),
    });
    state.plugins.push(record);
    save(state_dir, &state)
}

/// Load the state file. Returns `None` for any error — missing file,
/// corrupted JSON, unknown fields, version mismatch — and logs at `warn`.
pub fn load(state_dir: &Path) -> Option<PluginState> {
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "plugin-state read failed");
            return None;
        }
    };
    match serde_json::from_slice::<PluginState>(&bytes) {
        Ok(state) if state.version == SCHEMA_VERSION => Some(state),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "plugin-state schema mismatch, discarding"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "plugin-state parse failed");
            None
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
