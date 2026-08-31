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
pub const SCHEMA_VERSION: u32 = 4;

/// The IPv4 server-bypass route's form when this record's own routes went
/// in — [`crate::gateway::NextHop`] at install time, persisted so a later
/// teardown (possibly a different process, after a crash) rebuilds the
/// matching delete command instead of guessing.
///
/// A separate field from `original_gateway`, not folded into its `None`
/// case: "no gateway was ever recorded" (a schema 1/2/3 migration, which
/// predates on-link support entirely) and "the route WAS on-link" are
/// different facts. Collapsing them would make a migrated record — which
/// really did have a real gateway, just an unrecorded one — look on-link,
/// emitting the interface-scoped delete for a route that was actually
/// installed through a gateway. See CONTRIBUTING's Route ownership section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteForm {
    /// The bypass names a gateway (today's form).
    Via,
    /// The bypass names only the interface — there was no gateway to name.
    OnLink,
}

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
    /// The gateway `install` bypassed the tunnel through when this record's
    /// own routes went in. `None` only for a record migrated from schema 1
    /// or 2, which never persisted it — those deletes fall back to the old
    /// unscoped form (a disclosed residual; see CONTRIBUTING's Route
    /// ownership section). A fresh schema-3 write always sets `Some`.
    pub original_gateway: Option<IpAddr>,
    /// The form `original_gateway`'s bypass route was installed in — see
    /// [`RouteForm`]. Migrated records default to [`RouteForm::Via`], same as
    /// `original_gateway` defaulting to `None`: on-link support postdates
    /// every schema this migrates from.
    pub route_form: RouteForm,
    /// The routes that run got into the table. Recovery deletes these and
    /// nothing else — see [`RouteId`] for the delete-side selectivity this
    /// provides on top of.
    pub installed: Vec<RouteId>,
    /// Route groups an earlier `install` in this same process retained
    /// because their own teardown could not confirm the routes gone —
    /// carried forward so a later `install`'s checkpoints layer on top
    /// instead of silently overwriting the only record of that leak. Each
    /// entry keeps its own provenance because it may belong to a different
    /// `tun_name`/`server_ip`/gateway than the record's own fields above.
    pub stale: Vec<StaleRecord>,
}

/// One retained-but-unswept group from a prior `install`/session — same
/// shape as [`RouteState`]'s own identity + `installed` fields, kept
/// separate because a `RouteState` can carry more than one such group
/// (a sweep can itself fail to fully drain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaleRecord {
    pub tun_name: String,
    pub server_ip: IpAddr,
    pub interface_name: String,
    pub original_gateway: Option<IpAddr>,
    pub route_form: RouteForm,
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
    /// No gateway or stale-group provenance existed in v1 either.
    fn from(old: RouteStateV1) -> Self {
        debug_assert_eq!(old.version, 1, "only load's version-1 arm may build this");
        Self {
            version: SCHEMA_VERSION,
            tun_name: old.tun_name,
            installed: planned_routes(old.server_ip),
            server_ip: old.server_ip,
            interface_name: old.interface_name,
            original_gateway: None,
            route_form: RouteForm::Via,
            stale: Vec::new(),
        }
    }
}

/// Schema 2: like [`RouteState`] but without `original_gateway`/`stale` — the
/// gateway a v2 record's own routes used was never persisted, and v2 had no
/// concept of carried-forward leftovers.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteStateV2 {
    version: u32,
    tun_name: String,
    server_ip: IpAddr,
    interface_name: String,
    installed: Vec<RouteId>,
}

impl From<RouteStateV2> for RouteState {
    fn from(old: RouteStateV2) -> Self {
        debug_assert_eq!(old.version, 2, "only load's version-2 arm may build this");
        Self {
            version: SCHEMA_VERSION,
            tun_name: old.tun_name,
            server_ip: old.server_ip,
            interface_name: old.interface_name,
            installed: old.installed,
            original_gateway: None,
            route_form: RouteForm::Via,
            stale: Vec::new(),
        }
    }
}

/// Schema 3: like [`RouteState`] but without `route_form` — a schema-3
/// record predates on-link support entirely, so every route it names was
/// installed through a real gateway.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteStateV3 {
    version: u32,
    tun_name: String,
    server_ip: IpAddr,
    interface_name: String,
    original_gateway: Option<IpAddr>,
    installed: Vec<RouteId>,
    stale: Vec<StaleRecordV3>,
}

/// [`StaleRecord`] without `route_form`, matching [`RouteStateV3`]'s vintage.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaleRecordV3 {
    tun_name: String,
    server_ip: IpAddr,
    interface_name: String,
    original_gateway: Option<IpAddr>,
    installed: Vec<RouteId>,
}

impl From<StaleRecordV3> for StaleRecord {
    fn from(old: StaleRecordV3) -> Self {
        Self {
            tun_name: old.tun_name,
            server_ip: old.server_ip,
            interface_name: old.interface_name,
            original_gateway: old.original_gateway,
            route_form: RouteForm::Via,
            installed: old.installed,
        }
    }
}

impl From<RouteStateV3> for RouteState {
    fn from(old: RouteStateV3) -> Self {
        debug_assert_eq!(old.version, 3, "only load's version-3 arm may build this");
        Self {
            version: SCHEMA_VERSION,
            tun_name: old.tun_name,
            server_ip: old.server_ip,
            interface_name: old.interface_name,
            original_gateway: old.original_gateway,
            route_form: RouteForm::Via,
            installed: old.installed,
            stale: old.stale.into_iter().map(StaleRecord::from).collect(),
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

// Canonical form ======================================================================================================

/// Reduce a list of route-provenance groups to canonical form: groups
/// sharing an identity — `tun_name`, `server_ip`, `interface_name`,
/// `original_gateway`, `route_form`, the tuple that determines the teardown
/// argv a group emits — merge into one whose `installed` is the union, each
/// surviving
/// group's `installed` is sanitized against `planned_routes(server_ip)` (an
/// id with no possible teardown command can never drain, so it would pin the
/// group non-empty forever), and a group left with an empty `installed` is
/// dropped. Two groups with the same identity would otherwise emit
/// byte-identical teardown commands: the second is either never confirmed
/// (permanently stuck bookkeeping) or, on macOS's unscoped split-route
/// deletes, removes whatever a third party claimed after the first delete
/// freed the prefix. The sole shared entry point for every path that folds a
/// group into a persisted `stale`/`installed` set — sweep and crash
/// recovery alike — so they cannot drift apart on this discipline.
pub fn coalesce(groups: Vec<StaleRecord>) -> Vec<StaleRecord> {
    let mut merged: Vec<StaleRecord> = Vec::new();
    for g in groups {
        match merged.iter_mut().find(|m| {
            m.tun_name == g.tun_name
                && m.server_ip == g.server_ip
                && m.interface_name == g.interface_name
                && m.original_gateway == g.original_gateway
                && m.route_form == g.route_form
        }) {
            Some(existing) => {
                for id in g.installed {
                    if !existing.installed.contains(&id) {
                        existing.installed.push(id);
                    }
                }
            }
            None => merged.push(g),
        }
    }

    for g in &mut merged {
        let plannable = planned_routes(g.server_ip);
        let before = g.installed.len();
        g.installed.retain(|id| plannable.contains(id));
        if g.installed.len() != before {
            tracing::warn!(
                tun = %g.tun_name,
                server_ip = %g.server_ip,
                "route-provenance group names a route with no possible teardown command — dropping it"
            );
        }
    }

    merged.retain(|g| !g.installed.is_empty());
    merged
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
    } else if version == 3 {
        tracing::info!(got = version, want = SCHEMA_VERSION, "migrating route-state forward");
        serde_json::from_slice::<RouteStateV3>(&bytes).map(RouteState::from)
    } else if version == 2 {
        tracing::info!(got = version, want = SCHEMA_VERSION, "migrating route-state forward");
        serde_json::from_slice::<RouteStateV2>(&bytes).map(RouteState::from)
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
