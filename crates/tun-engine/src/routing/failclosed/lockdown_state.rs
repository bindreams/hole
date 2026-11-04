//! Persisted lockdown INTENT (the standing kill switch's enabled bool),
//! bridge-owned and system-wide. Distinct from `bridge-failclosed.json`
//! (which records the transient cover's pf token): this file records what the
//! user *wants*, surviving bridge restarts and crashes. Modeled on
//! `failclosed_state.rs`; a `VersionedFile` of role `Decision`.

use std::path::Path;

use serde::{Deserialize, Serialize};
use util::versioned_file::{
    Change, DefaultPlacement, Loaded, Obsolete, Role, Schema, StoreError, UpdateOutcome, VersionedFile, VersionedState,
};

/// Filename under `state_dir`.
pub const STATE_FILE_NAME: &str = "bridge-lockdown.json";

/// Persisted lockdown intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockdownState {
    /// Whether the standing kill switch is enabled.
    pub enabled: bool,
}

impl Schema for LockdownState {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

/// The user's latest decision: one this release cannot read is backed up, then replaced, and never blocks a connect.
impl VersionedState for LockdownState {
    const FILE_NAME: &'static str = STATE_FILE_NAME;
    const ROLE: Role = Role::Decision;
}

util::assert_contiguous!(LockdownState);

/// The intent file. Every read and write of it goes through this type.
pub type LockdownFile = VersionedFile<LockdownState>;

pub fn file(state_dir: &Path) -> LockdownFile {
    VersionedFile::new(state_dir)
}

/// What `bridge-lockdown.json` says about the standing kill switch. A closed
/// classification rather than a bool, so "the user recorded off" and "we could
/// not find out" stop being the same answer — conflating them is what let a
/// bridge with a wiped state dir sweep a live cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// The file parsed at the current schema and records `enabled: true`.
    On,
    /// The file parsed at the current schema and records `enabled: false`.
    Off,
    /// No file at all (`ErrorKind::NotFound`): a fresh install, a wiped or
    /// recreated state dir, or a second bridge's own `--state-dir`.
    Unset,
    /// A file exists but the read, the JSON parse, or the version check failed.
    Unreadable,
}

impl Intent {
    /// "Does the user believe the kill switch is armed?" — `On | Unreadable`.
    /// An unreadable record is not consent to disarm, so it reports armed and
    /// the tray's Unblock escape stays on the menu.
    ///
    /// Consumers, in full: `ProxyManager::lockdown_enabled`.
    pub fn reads_armed(self) -> bool {
        matches!(self, Intent::On | Intent::Unreadable)
    }

    /// "Should this start install the STANDING cover?" — `On` only.
    ///
    /// `Unreadable` answers **no**, and that is what keeps a corrupt-file start
    /// engaging the transient block-until-connected cover instead of skipping
    /// it for a standing cover that only arrives after `routing.install`: block
    /// early, don't leak.
    ///
    /// Consumers, in full: the transient-vs-standing branch, the
    /// reachability-probe suppression, the `install_lockdown` gate, and the
    /// update-consent gate.
    pub fn installs_standing_cover(self) -> bool {
        matches!(self, Intent::On)
    }
}

/// The one reading of the intent file. `Ok` is a file that parsed at the current schema; `Err` carries the [`Intent`]
/// its failure classifies to, so [`load`] and [`load_intent`] share a single reader (and a single set of `warn!`
/// lines) instead of drifting apart.
fn read_state(state_dir: &Path) -> Result<LockdownState, Intent> {
    match file(state_dir).observe().loaded {
        Loaded::Current { value, .. } => Ok(value),
        Loaded::Absent => Err(Intent::Unset),
        Loaded::Obsolete { .. } => Err(Intent::Unreadable),
        Loaded::Newer { .. } => Err(Intent::Unreadable),
        Loaded::Corrupt { .. } => Err(Intent::Unreadable),
        Loaded::Unreadable { .. } => Err(Intent::Unreadable),
    }
}

/// Load the intent, or `None` on absent/corrupt/newer/obsolete (the read logs at `warn`). Use [`load_intent`] where
/// the *reason* for a `None` matters.
pub fn load(state_dir: &Path) -> Option<LockdownState> {
    read_state(state_dir).ok()
}

/// Classify the intent file. Never collapses a failure into a recorded value —
/// see [`Intent`] and its two folds.
pub fn load_intent(state_dir: &Path) -> Intent {
    match read_state(state_dir) {
        Ok(s) if s.enabled => Intent::On,
        Ok(_) => Intent::Off,
        Err(i) => i,
    }
}

/// Convenience: [`Intent::reads_armed`] over [`load_intent`]. An absent file is
/// default-off; a corrupt one reads ARMED, because losing the record is not the
/// user telling us to disarm.
pub fn load_enabled(state_dir: &Path) -> bool {
    load_intent(state_dir).reads_armed()
}

/// Last-writer-wins absolute set, atomic, creating `state_dir`. A file this release cannot read is backed up beside
/// it first.
pub fn set_enabled(state_dir: &Path, enabled: bool, owner: Option<(u32, u32)>) -> Result<(), StoreError> {
    file(state_dir)
        .update(&DefaultPlacement { owner }, |_| {
            (Change::Store(LockdownState { enabled }), ())
        })
        .map(|_| ())
}

/// Delete the state file; tolerates absence.
pub fn clear(state_dir: &Path) -> Result<UpdateOutcome, StoreError> {
    file(state_dir)
        .update(&DefaultPlacement::default(), |_| (Change::Remove, ()))
        .map(|((), outcome)| outcome)
}

#[cfg(test)]
#[path = "lockdown_state_tests.rs"]
mod lockdown_state_tests;
