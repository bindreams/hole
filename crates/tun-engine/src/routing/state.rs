//! Persisted route state for crash recovery.
//!
//! The caller (typically a bridge/VPN daemon) writes a small JSON file
//! before mutating the routing table, clears it after normal teardown, and
//! reads it on startup to clean up leaked routes from a previous crashed
//! run. Best-effort; not a multi-instance lock.
//!
//! The file is a [`VersionedFile`] of role [`Role::OsRecord`]: it is the only
//! evidence of what a run left in the routing table, so one this release
//! cannot read (a newer schema, or corrupt) or whose read fails with an I/O
//! error is never replaced, removed or acted on, and a connect is refused
//! over it. Discarding an old or unreadable file is not an option: it strands
//! the host on routes pointing at a dead TUN.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use util::versioned_file::{
    CannotRead, DefaultPlacement, Loaded, Obsolete, Removal, Role, Schema, StoreError, VersionedFile, VersionedState,
};

use super::{planned_routes, RouteId};

// Types ===============================================================================================================

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
pub struct RouteState {
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
pub struct StaleRecord {
    pub tun_name: String,
    pub server_ip: IpAddr,
    pub interface_name: String,
    pub original_gateway: Option<IpAddr>,
    pub route_form: RouteForm,
    pub installed: Vec<RouteId>,
}

// Schema history ------------------------------------------------------------------------------------------------------
//
// Each version is its own frozen type, linked to the one before it. The file's
// framing carries the version, so no type below holds it.

/// Schema 1: no `installed` field. Its teardown deleted every route an install
/// for `server_ip` would have created, whether or not that install succeeded.
#[derive(Debug, Deserialize)]
pub struct RouteStateV1 {
    tun_name: String,
    server_ip: IpAddr,
    interface_name: String,
}

impl Schema for RouteStateV1 {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

/// Schema 2: like [`RouteState`] but without `original_gateway`/`stale` — the
/// gateway a v2 record's own routes used was never persisted, and v2 had no
/// concept of carried-forward leftovers.
#[derive(Debug, Deserialize)]
pub struct RouteStateV2 {
    tun_name: String,
    server_ip: IpAddr,
    interface_name: String,
    installed: Vec<RouteId>,
}

impl Schema for RouteStateV2 {
    const VERSION: u32 = 2;
    type Prev = RouteStateV1;

    /// Reproduce v1's delete set exactly. A v1 file is written by a bridge
    /// that has already crashed, so its leak is whatever that run planned;
    /// assuming the full set cleans up at least as much as the old code did.
    fn upgrade(prev: RouteStateV1) -> Self {
        Self {
            installed: planned_routes(prev.server_ip),
            tun_name: prev.tun_name,
            server_ip: prev.server_ip,
            interface_name: prev.interface_name,
        }
    }
}

/// Schema 3: like [`RouteState`] but without `route_form` — a schema-3
/// record predates on-link support entirely, so every route it names was
/// installed through a real gateway.
#[derive(Debug, Deserialize)]
pub struct RouteStateV3 {
    tun_name: String,
    server_ip: IpAddr,
    interface_name: String,
    original_gateway: Option<IpAddr>,
    installed: Vec<RouteId>,
    stale: Vec<StaleRecordV3>,
}

/// [`StaleRecord`] without `route_form`, matching [`RouteStateV3`]'s vintage.
#[derive(Debug, Deserialize)]
pub struct StaleRecordV3 {
    tun_name: String,
    server_ip: IpAddr,
    interface_name: String,
    original_gateway: Option<IpAddr>,
    installed: Vec<RouteId>,
}

impl Schema for RouteStateV3 {
    const VERSION: u32 = 3;
    type Prev = RouteStateV2;

    /// The gateway v2 never persisted stays unknown, and there were no stale
    /// groups.
    fn upgrade(prev: RouteStateV2) -> Self {
        Self {
            tun_name: prev.tun_name,
            server_ip: prev.server_ip,
            interface_name: prev.interface_name,
            original_gateway: None,
            installed: prev.installed,
            stale: Vec::new(),
        }
    }
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

/// Schema 4, the current one.
impl Schema for RouteState {
    const VERSION: u32 = 4;
    type Prev = RouteStateV3;

    /// No older schema had an on-link bypass, so every group takes the
    /// gateway form.
    fn upgrade(prev: RouteStateV3) -> Self {
        Self {
            tun_name: prev.tun_name,
            server_ip: prev.server_ip,
            interface_name: prev.interface_name,
            original_gateway: prev.original_gateway,
            route_form: RouteForm::Via,
            installed: prev.installed,
            stale: prev.stale.into_iter().map(StaleRecord::from).collect(),
        }
    }
}

impl VersionedState for RouteState {
    const FILE_NAME: &'static str = STATE_FILE_NAME;
    const ROLE: Role = Role::OsRecord;
}

// Every schema, not just the current one: a gap is reported by the build, not
// by `cargo check`, unless each type's link is named.
util::assert_contiguous!(RouteStateV1);
util::assert_contiguous!(RouteStateV2);
util::assert_contiguous!(RouteStateV3);
util::assert_contiguous!(RouteState);

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

/// The route record's file. Every read and write of it goes through this type.
pub(crate) type RouteFile = VersionedFile<RouteState>;

pub(crate) fn file(state_dir: &Path) -> RouteFile {
    VersionedFile::new(state_dir)
}

/// Why a route record that exists is not one to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cause {
    /// Newer or corrupt: the bytes were read and are not a record.
    CannotRead(CannotRead),
    /// The read failed with an I/O error: nothing is known about the bytes.
    ReadFailed(std::io::ErrorKind),
}

impl Cause {
    /// Whether a record in this state stops the bridge from connecting; the
    /// route record's role decides, for either cause.
    pub(crate) fn blocks_connect(self) -> bool {
        match self {
            Cause::CannotRead(why) => RouteState::ROLE.unreadable_blocks_connect(why),
            Cause::ReadFailed(_) => RouteState::ROLE.io_failure_blocks_connect(),
        }
    }
}

impl std::fmt::Display for Cause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cause::CannotRead(why) => write!(f, "{why}"),
            Cause::ReadFailed(kind) => write!(f, "the read failed ({kind})"),
        }
    }
}

/// What a caller that acts on route records finds in the file.
#[derive(Debug)]
pub(crate) enum Found {
    /// A record to act on, migrated to the current schema if it was older.
    Records(RouteState),
    /// No record to act on.
    Nothing,
    /// A record this release cannot act on: newer, corrupt, or unread. It may
    /// name a leak nobody here can interpret, so nothing runs against it and
    /// nothing replaces it.
    Unreadable { path: PathBuf, cause: Cause },
}

/// Reads the record and classifies it. The one place a [`Loaded`] becomes an
/// action, shared by every load site.
pub(crate) fn read(file: &RouteFile) -> Found {
    match file.load() {
        Loaded::Current { value, .. } => Found::Records(value),
        Loaded::Absent => Found::Nothing,
        Loaded::Unreadable(e) => Found::Unreadable {
            path: file.path().to_path_buf(),
            cause: Cause::ReadFailed(e.kind()),
        },
        Loaded::Newer { .. } => Found::Unreadable {
            path: file.path().to_path_buf(),
            cause: Cause::CannotRead(CannotRead::Newer),
        },
        Loaded::Corrupt { .. } => Found::Unreadable {
            path: file.path().to_path_buf(),
            cause: Cause::CannotRead(CannotRead::Corrupt),
        },
        // The chain's floor is 0 and the framing reads version 0 as corrupt,
        // so no file decodes to `Obsolete`.
        Loaded::Obsolete { .. } => unreachable!("the route-state chain has no obsolete version"),
    }
}

/// Reads `<state_dir>/bridge-routes.json`.
pub fn load(state_dir: &Path) -> Loaded<RouteState> {
    file(state_dir).load()
}

/// The record's path, iff the connect gate must refuse to start over it: it
/// is newer, corrupt, or its read fails. `None` for a readable record and no
/// record.
pub fn blocking(state_dir: &Path) -> Option<PathBuf> {
    match read(&file(state_dir)) {
        Found::Unreadable { path, cause } if cause.blocks_connect() => Some(path),
        Found::Unreadable { .. } => None,
        Found::Records(_) => None,
        Found::Nothing => None,
    }
}

/// Writes `state` atomically (same-directory temp file, `sync_all`, rename),
/// creating `state_dir` if missing. A record this release cannot read, or
/// whose read fails with an I/O error, is refused, never overwritten. An older
/// record is replaced.
pub fn save(state_dir: &Path, state: &RouteState, owner: Option<(u32, u32)>) -> Result<(), StoreError> {
    write(&file(state_dir), state, owner)
}

pub(crate) fn write(file: &RouteFile, state: &RouteState, owner: Option<(u32, u32)>) -> Result<(), StoreError> {
    file.store(state, &DefaultPlacement { owner })
}

/// Deletes the record. Tolerates a missing file. A record this release cannot
/// read, or whose read fails, is kept and named in the log: it is not this
/// process's to remove.
/// Returns `Err` only on actual I/O errors (permissions, etc.).
pub fn clear(state_dir: &Path) -> std::io::Result<()> {
    remove(&file(state_dir))
}

pub(crate) fn remove(file: &RouteFile) -> std::io::Result<()> {
    match file.remove()? {
        Removal::Removed | Removal::Absent => Ok(()),
        Removal::Kept => {
            tracing::error!(path = %file.path().display(), "route record cannot be read; left in place");
            Ok(())
        }
        Removal::MovedAside(backup) => {
            tracing::warn!(backup = %backup.display(), "route record moved aside");
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod state_tests;
