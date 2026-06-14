//! Persisted fail-closed-cover state for crash recovery (macOS only).
//!
//! macOS engages the cover by enabling pf with `pfctl -E`, which returns a
//! reference-count token. We persist that token BEFORE loading the blocking
//! ruleset so a crashed update cutover can be cleanly reversed on the next
//! bridge start (`recover_cover`: restore `/etc/pf.conf` + `pfctl -X <token>`).
//! Windows needs no analogue: its WFP filters carry fixed GUIDs and are swept
//! by key, so there is nothing to persist.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Schema version for [`FailClosedState`]. Bumped on backwards-incompatible
/// changes; [`load`] discards a mismatched file rather than risk a corrupt
/// recovery.
pub const SCHEMA_VERSION: u32 = 1;

/// Filename under `state_dir`. Distinct from `bridge-routes.json` because the
/// cover lifecycle is independent of the route lifecycle (a cover is active
/// precisely while routes are down, mid-cutover).
pub const STATE_FILE_NAME: &str = "bridge-failclosed.json";

/// pf state captured at cover-engage time, persisted before the blocking
/// ruleset is loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailClosedState {
    pub version: u32,
    /// Opaque enable token returned by `pfctl -E`, replayed to `pfctl -X` on
    /// recovery. Stored as a string — it is an opaque handle, not arithmetic.
    pub pf_token: String,
    /// Whether pf reported `Status: Enabled` before we engaged. Diagnostic;
    /// recovery restores `/etc/pf.conf` and drops our refcount regardless.
    pub pf_was_enabled: bool,
}

fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE_NAME)
}

/// Atomically persist `state` to `<state_dir>/bridge-failclosed.json` (temp
/// file + same-dir rename, `sync_all` before persist). Creates `state_dir`.
pub fn save(state_dir: &Path, state: &FailClosedState) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let json = serde_json::to_vec_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(state_file(state_dir)).map_err(|e| e.error)?;
    Ok(())
}

/// Load the state file, or `None` on any error (absent / corrupt / unknown
/// field / version mismatch); logs at `warn`. Recovery is best-effort.
pub fn load(state_dir: &Path) -> Option<FailClosedState> {
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "failclosed-state read failed");
            return None;
        }
    };
    match serde_json::from_slice::<FailClosedState>(&bytes) {
        Ok(s) if s.version == SCHEMA_VERSION => Some(s),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "failclosed-state schema mismatch, discarding"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "failclosed-state parse failed");
            None
        }
    }
}

/// Delete the state file; tolerates absence (`Ok`). `Err` only on real I/O error.
pub fn clear(state_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(state_file(state_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "failclosed_state_tests.rs"]
mod failclosed_state_tests;
