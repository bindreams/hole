//! Persisted route state for crash recovery.
//!
//! The caller (typically a bridge/VPN daemon) writes a small JSON file
//! before mutating the routing table, clears it after normal teardown, and
//! reads it on startup to clean up leaked routes from a previous crashed
//! run. Best-effort; not a multi-instance lock.

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{planned_routes, RouteId};

// Types ===============================================================================================================

/// Schema version for [`RouteState`]. Bump when the struct changes in a
/// backwards-incompatible way, and give [`load`] an arm that migrates the old
/// shape. Discarding an old file instead is not an option here: the file is
/// the only record of what a crashed run leaked, so dropping it strands the
/// host on routes pointing at a dead TUN.
pub const SCHEMA_VERSION: u32 = 2;

/// Filename of the persisted state file under `state_dir`. Exported so
/// external tooling (notably `scripts/network-reset.py`) can reference the
/// single source of truth.
pub const STATE_FILE_NAME: &str = "bridge-routes.json";

/// Routes and interfaces the caller installed for the current proxy run.
/// Persisted to `<state_dir>/bridge-routes.json` while active, cleared on
/// clean shutdown. On next startup, recovery reads this file to clean up
/// any routes leaked by a previous crashed run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteState {
    pub version: u32,
    pub tun_name: String,
    pub server_ip: IpAddr,
    pub interface_name: String,
    /// The routes that run got into the table. Recovery deletes these and
    /// nothing else — see [`RouteId`] for why nothing about the delete command
    /// itself can express "only if it is ours".
    pub installed: Vec<RouteId>,
}

/// Schema 1: no `installed` field. Its teardown deleted every route an install
/// for `server_ip` would have created, whether or not that install succeeded.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteStateV1 {
    version: u32,
    tun_name: String,
    server_ip: IpAddr,
    interface_name: String,
}

impl From<RouteStateV1> for RouteState {
    /// Reproduce v1's delete set exactly. A v1 file is written by a bridge
    /// that has already crashed, so its leak is whatever that run planned;
    /// assuming the full set cleans up at least as much as the old code did.
    fn from(old: RouteStateV1) -> Self {
        debug_assert_eq!(old.version, 1, "only load's version-1 arm may build this");
        Self {
            version: SCHEMA_VERSION,
            tun_name: old.tun_name,
            installed: planned_routes(old.server_ip),
            server_ip: old.server_ip,
            interface_name: old.interface_name,
        }
    }
}

/// Reads only the discriminant, tolerating fields from any schema.
#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
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
/// durability is out of scope. The design target is process-crash recovery,
/// not disk failure recovery.
pub fn save(state_dir: &Path, state: &RouteState, owner: Option<(u32, u32)>) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    util::ownership::chown_if_some(state_dir, owner);

    let json = serde_json::to_vec_pretty(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Same-directory NamedTempFile -> persist is a same-filesystem atomic rename.
    let path = state_file(state_dir);
    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(&path).map_err(|e| e.error)?;
    util::ownership::chown_if_some(&path, owner);
    Ok(())
}

/// Load the state file, migrating a schema-1 file forward. Returns `None` for
/// any error — missing file, corrupted JSON, unknown fields, a version with no
/// migration — and logs at `warn` level. Crash recovery is best-effort and
/// should never fail the caller.
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
    let version = match serde_json::from_slice::<VersionProbe>(&bytes) {
        Ok(probe) => probe.version,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "route-state parse failed");
            return None;
        }
    };
    let parsed = if version == SCHEMA_VERSION {
        serde_json::from_slice::<RouteState>(&bytes)
    } else if version == 1 {
        tracing::info!(got = version, want = SCHEMA_VERSION, "migrating route-state forward");
        serde_json::from_slice::<RouteStateV1>(&bytes).map(RouteState::from)
    } else {
        tracing::warn!(
            got = version,
            want = SCHEMA_VERSION,
            "route-state schema mismatch, discarding"
        );
        return None;
    };
    match parsed {
        Ok(state) => Some(state),
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
#[path = "state_tests.rs"]
mod state_tests;
