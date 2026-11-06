//! Persisted fail-closed-cover state for crash recovery (macOS only).
//!
//! macOS engages the cover by enabling pf with `pfctl -E`, which returns a
//! reference-count token. We persist that token BEFORE loading the blocking
//! ruleset so a crashed update cutover can be cleanly reversed on the next
//! bridge start (`recover_cover`: restore `/etc/pf.conf` + `pfctl -X <token>`).
//! Windows needs no analogue: its WFP filters carry fixed GUIDs and are swept
//! by key, so there is nothing to persist.

use std::path::Path;

use serde::{Deserialize, Serialize};
use util::versioned_file::{
    Change, DefaultPlacement, Obsolete, Role, Schema, StoreError, UpdateOutcome, VersionedFile, VersionedState,
};

/// Filename under `state_dir`. Distinct from `bridge-routes.json` because the
/// cover lifecycle is independent of the route lifecycle (a cover is active
/// precisely while routes are down, mid-cutover).
pub const STATE_FILE_NAME: &str = "bridge-failclosed.json";

/// pf state captured at cover-engage time, persisted before the blocking
/// ruleset is loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailClosedState {
    /// Opaque enable token returned by `pfctl -E`, replayed to `pfctl -X` on
    /// recovery. Stored as a string — it is an opaque handle, not arithmetic.
    pub pf_token: String,
    /// Whether pf reported `Status: Enabled` before we engaged; `false` also
    /// when that read failed (the engage warns and does not fail on it). Diagnostic
    /// only: recovery restores `/etc/pf.conf` and drops our refcount regardless.
    ///
    /// Stays a plain `bool`, never an `Option`: this file must parse under every
    /// release that may run the sweep after a crash, and a rolled-back binary's
    /// `bool` rejects `null` — `state::load` then reads the file as absent and
    /// leaves `block out all` on the host.
    pub pf_was_enabled: bool,
}

impl Schema for FailClosedState {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

/// A cover's evidence: one this release cannot read is moved aside by a clear and backed up by a store, and its
/// token is still salvaged for the sweep ([`super::StateFile::from`]).
impl VersionedState for FailClosedState {
    const FILE_NAME: &'static str = STATE_FILE_NAME;
    const ROLE: Role = Role::Cover;
}

util::assert_contiguous!(FailClosedState);

/// The record file. Every read and write of it goes through this type.
pub type FailClosedFile = VersionedFile<FailClosedState>;

pub fn file(state_dir: &Path) -> FailClosedFile {
    VersionedFile::new(state_dir)
}

/// Atomically persist `state` to `<state_dir>/bridge-failclosed.json`, creating `state_dir`. A file this release
/// cannot read is backed up beside it first.
pub fn save(state_dir: &Path, state: &FailClosedState, owner: Option<(u32, u32)>) -> Result<(), StoreError> {
    file(state_dir)
        .update(&DefaultPlacement { owner }, |_| (Change::Store(state.clone()), ()))
        .map(|_| ())
}

/// Trichotomy read distinguishing "no cover was ever engaged" (`Absent`) from
/// "a cover's evidence exists but we cannot read it" (`Unusable`) — a corrupt,
/// unparseable, or version-skewed file. Collapsing `Unusable` into `Absent`
/// would make a release read a live, blocking cover as nothing to clear (see
/// `release_all`'s doc). `Absent` is ONLY `ErrorKind::NotFound`; every other
/// read/parse/version failure is `Unusable`.
pub fn load_presence(state_dir: &Path) -> super::StateFile<FailClosedState> {
    super::StateFile::from(file(state_dir).observe().loaded)
}

/// Load the state file, or `None` on any error (absent / corrupt /
/// version mismatch); logs at `warn`. Recovery is best-effort. Thin
/// wrapper over [`load_presence`], collapsing `Unusable` into `None` alongside
/// `Absent` — every existing caller treats the two identically.
pub fn load(state_dir: &Path) -> Option<FailClosedState> {
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
#[path = "failclosed_state_tests.rs"]
mod failclosed_state_tests;
