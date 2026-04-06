// Persisted route state for crash recovery.
//
// The bridge writes a small JSON file before mutating the routing table,
// clears it after normal teardown, and reads it on startup to clean up
// leaked routes from a previous crashed run. Best-effort; not a
// multi-instance lock — see §"Known limitations" in the plan.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

// Types ===============================================================================================================

/// Schema version for [`RouteState`]. Bump when the struct changes in a
/// backwards-incompatible way; [`load`] rejects mismatched versions to force a
/// fresh run rather than corrupt recovery.
pub const SCHEMA_VERSION: u32 = 1;

/// Filename of the persisted state file under `state_dir`. Exported so
/// external tooling (notably `scripts/network-reset.py`) can reference the
/// single source of truth.
pub const STATE_FILE_NAME: &str = "bridge-routes.json";

/// Routes and interfaces the bridge installed for the current proxy run.
/// Persisted to `<state_dir>/bridge-routes.json` while active, cleared on
/// clean shutdown. On next startup, the bridge reads this file to clean up
/// any routes leaked by a previous crashed run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteState {
    pub version: u32,
    pub tun_name: String,
    pub server_ip: IpAddr,
    pub interface_name: String,
}

fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE_NAME)
}

// I/O =================================================================================================================

/// Write `state` to `<state_dir>/bridge-routes.json` atomically via a
/// same-directory temp file + rename. Contents are `sync_all`'d before
/// persist so a process crash (panic, SIGKILL, abort) sees either the old
/// contents or the new contents, never a truncated file. Creates
/// `state_dir` if missing.
///
/// Does NOT fsync the parent directory after the rename — power-loss
/// durability is out of scope. The design target is process-crash
/// recovery, not disk failure recovery.
pub fn save(state_dir: &Path, state: &RouteState) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;

    let json = serde_json::to_vec_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Same-directory NamedTempFile -> persist is a same-filesystem atomic rename.
    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(state_file(state_dir)).map_err(|e| e.error)?;
    Ok(())
}

/// Load the state file. Returns `None` for any error — missing file,
/// corrupted JSON, unknown fields, version mismatch — and logs at `warn`
/// level. Crash recovery is best-effort and should never fail the caller.
pub fn load(state_dir: &Path) -> Option<RouteState> {
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "route-state read failed");
            return None;
        }
    };
    match serde_json::from_slice::<RouteState>(&bytes) {
        Ok(state) if state.version == SCHEMA_VERSION => Some(state),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "route-state schema mismatch, discarding"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "route-state parse failed");
            None
        }
    }
}

/// Delete the state file. Tolerates a missing file (returns `Ok`). Returns
/// `Err` only on actual I/O errors (permissions, etc.).
pub fn clear(state_dir: &Path) -> std::io::Result<()> {
    let path = state_file(state_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "route_state_tests.rs"]
mod route_state_tests;
