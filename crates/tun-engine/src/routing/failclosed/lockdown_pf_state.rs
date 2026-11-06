//! macOS-only persisted state for the STANDING lockdown cover. Distinct file
//! from `bridge-failclosed.json` (the transient cover): the lockdown cover has
//! an independent lifetime, and the cutover engages no transient cover. Records the
//! pf enable token (replayed to `pfctl -X` on Sweep) and the pre-lockdown
//! filter (`pfctl -sr`) and translation (`pfctl -sn`) snapshots (re-loaded on
//! Sweep to restore the host without `-Fa`, matching the engaged-without-flush
//! contract).

use std::path::Path;

use serde::{Deserialize, Serialize};
use util::versioned_file::{
    Change, DefaultPlacement, Obsolete, Role, Schema, StoreError, UpdateOutcome, VersionedFile, VersionedState,
};

pub const STATE_FILE_NAME: &str = "bridge-lockdown-pf.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockdownPfState {
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
    /// `false` when the host's filter ruleset at engage time was our OWN cover,
    /// so there was no pre-lockdown baseline to capture; a restore then reloads
    /// `/etc/pf.conf` instead of `main_snapshot`. Read by `disengage_lockdown`
    /// and by `release_all_with`'s standing `Present` arm.
    ///
    /// A bool, not `main_snapshot.is_empty()`: a host really can have an empty
    /// filter ruleset, and that IS its policy — keying on emptiness would
    /// silently reload `/etc/pf.conf` over it.
    ///
    /// Defaults `true` (NO schema bump) so a file written before this field
    /// existed reads as the captured baseline it was. Bumping the schema
    /// version instead would make every existing file `Unusable`, which
    /// [`load`] collapses to `None`, which makes `disengage_lockdown`
    /// early-return `Ok(())` over a still-blocked host — silently breaking
    /// `hole bridge unlock` and the tray's Unblock item on the ordinary macOS
    /// upgrade path.
    #[serde(default = "default_true")]
    pub main_snapshot_captured: bool,
}

fn default_true() -> bool {
    true
}

impl Schema for LockdownPfState {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

/// A cover's evidence: one this release cannot read is moved aside by a clear and backed up by a store, and its
/// token is still salvaged for the sweep ([`super::StateFile::from`]).
impl VersionedState for LockdownPfState {
    const FILE_NAME: &'static str = STATE_FILE_NAME;
    const ROLE: Role = Role::Cover;
}

util::assert_contiguous!(LockdownPfState);

/// The record file. Every read and write of it goes through this type.
pub type LockdownPfFile = VersionedFile<LockdownPfState>;

pub fn file(state_dir: &Path) -> LockdownPfFile {
    VersionedFile::new(state_dir)
}

/// Atomically persist `state`, creating `state_dir`. A file this release cannot read is backed up beside it first.
pub fn save(state_dir: &Path, state: &LockdownPfState, owner: Option<(u32, u32)>) -> Result<(), StoreError> {
    file(state_dir)
        .update(&DefaultPlacement { owner }, |_| (Change::Store(state.clone()), ()))
        .map(|_| ())
}

/// Trichotomy read distinguishing "no cover was ever engaged" (`Absent`) from
/// "a cover's evidence exists but we cannot read it" (`Unusable`) — a corrupt,
/// unparseable, or version-skewed file. Collapsing `Unusable` into `Absent`
/// would make a release read a live, blocking cover as nothing to clear (see
/// `release_all`'s doc). `Absent` is ONLY `ErrorKind::NotFound`; every other
/// read/parse/version failure is `Unusable`. The parse failure is logged by the
/// read as a category and a position: `main_snapshot` is a captured `pfctl -sr`
/// ruleset, which holds the server IP whenever it captured Hole's own cover.
pub fn load_presence(state_dir: &Path) -> super::StateFile<LockdownPfState> {
    super::StateFile::from(file(state_dir).observe().loaded)
}

/// Load the state file, or `None` on any error (absent / corrupt / version
/// mismatch). Thin wrapper over [`load_presence`], collapsing
/// `Unusable` into `None` alongside `Absent` — every existing caller treats
/// the two identically.
pub fn load(state_dir: &Path) -> Option<LockdownPfState> {
    match load_presence(state_dir) {
        super::StateFile::Present(s) => Some(s),
        super::StateFile::Absent | super::StateFile::Unusable { .. } => None,
    }
}

/// Remove the state file; absence is [`UpdateOutcome::Absent`]. A record this release cannot read is moved aside, and
/// one whose read failed is [`UpdateOutcome::Kept`]. `Err` only on a real I/O error.
pub fn clear(state_dir: &Path) -> Result<UpdateOutcome, StoreError> {
    file(state_dir)
        .update(&DefaultPlacement::default(), |_| (Change::Remove, ()))
        .map(|((), outcome)| outcome)
}

#[cfg(test)]
#[path = "lockdown_pf_state_tests.rs"]
mod lockdown_pf_state_tests;
