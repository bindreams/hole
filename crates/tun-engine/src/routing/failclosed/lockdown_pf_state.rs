//! macOS-only persisted state for the STANDING lockdown cover. Distinct file
//! from `bridge-failclosed.json` (the transient cover): the lockdown cover has
//! an independent lifetime, and the cutover engages no transient cover. Records the
//! pf enable token (replayed to `pfctl -X` on Sweep) and the pre-lockdown
//! filter (`pfctl -sr`) and translation (`pfctl -sn`) snapshots (re-loaded on
//! Sweep to restore the host without `-Fa`, matching the engaged-without-flush
//! contract).

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;
pub const STATE_FILE_NAME: &str = "bridge-lockdown-pf.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockdownPfState {
    pub version: u32,
    /// Opaque enable token from `pfctl -E`, replayed to `pfctl -X` on Sweep.
    pub pf_token: String,
    /// The host's filter ruleset (`pfctl -sr`) captured before we replaced the
    /// main ruleset with the lockdown policy. Re-loaded on Sweep so the host
    /// returns to its pre-lockdown policy (NOT a blind `/etc/pf.conf` reload).
    pub main_snapshot: String,
    /// The host's translation rules (`pfctl -sn`: nat/rdr) captured alongside
    /// `main_snapshot`. Carried forward into the lockdown ruleset (so the
    /// session does not flush NAT) and re-loaded on Sweep for restore.
    pub nat_snapshot: String,
}

fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE_NAME)
}

pub fn save(state_dir: &Path, state: &LockdownPfState) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let json = serde_json::to_vec_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(state_file(state_dir)).map_err(|e| e.error)?;
    Ok(())
}

pub fn load(state_dir: &Path) -> Option<LockdownPfState> {
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "lockdown-pf-state read failed");
            return None;
        }
    };
    match serde_json::from_slice::<LockdownPfState>(&bytes) {
        Ok(s) if s.version == SCHEMA_VERSION => Some(s),
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "lockdown-pf-state schema mismatch, discarding"
            );
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "lockdown-pf-state parse failed");
            None
        }
    }
}

pub fn clear(state_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(state_file(state_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "lockdown_pf_state_tests.rs"]
mod lockdown_pf_state_tests;
