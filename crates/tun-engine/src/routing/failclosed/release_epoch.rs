//! Orders an engage against a release inside this process, without either
//! waiting for the other.
//!
//! A release (the tray's Unblock, `bridge unlock`, a cover sweep) must never
//! block on a start that is wedged, so it cannot take a lock the engage holds.
//! It announces itself instead: [`begin_release`] counts it in flight BEFORE the
//! release touches the firewall. When the guard ends it moves an epoch, so a
//! release SUPERSEDES by default; the one opt-out is
//! [`ReleaseInFlight::changed_nothing`], for a release that failed before it
//! changed anything. The guard and the watch own all of this: no caller marks,
//! flags or taints anything.
//!
//! An install opens a [`ReleaseWatch`] when it starts and checks it where it
//! commits to a cover and after it installs. [`ReleaseWatch::check`] answers
//! with one verdict: clear, [`Overtaken::Superseded`] (a release ended with a
//! change since the watch opened) or [`Overtaken::InDoubt`] (a release is in
//! flight and has not said what it did). What an install does with a cover it
//! holds is decided once, on that verdict. An install's record writes check the
//! watch inside their critical section, so no write lands once a release has
//! begun.
//!
//! An engage is ordered by checking AFTER the install and dropping the cover it
//! just installed on any verdict, so no lock spans an OS call. A release that
//! begins after the check does its deletes after the install and takes the
//! cover; one that began before it is either in flight or ended, and either way
//! the fresh cover cannot be told from one the release left live and unreported.
//! Only a cover held from an EARLIER attempt, whose deletes are still to come,
//! is kept under a release in flight.
//!
//! The epoch orders an engage against ANY release: the tray's Unblock holds its guard through its persisted
//! `Off`, a sweep through its witness write. It does not decide what a start records; that is the user's
//! decision to be Off, which only the tray's Unblock makes and the bridge's `unblock_generation` carries.
//!
//! In-process only: another bridge, or `hole bridge unlock` run from a shell,
//! is not ordered by this.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use crate::error::RoutingError;

/// One `state_dir`'s release count. Both fields move under one lock, so a reader sees them together and no
/// read order can miss a release that began and ended between two reads. The lock is a leaf: nothing is called
/// while it is held, so a watch can be checked inside a record update.
#[derive(Debug, Default)]
struct Slot {
    state: Mutex<SlotState>,
}

#[derive(Debug, Default, Clone, Copy)]
struct SlotState {
    /// Releases that ended with a change since the process started.
    epoch: u64,
    /// Releases begun and not yet ended.
    in_flight: usize,
}

impl Slot {
    /// A poisoned lock is recovered: nothing under it can be left half-updated.
    fn state(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Per-`state_dir` slots. A leaf lock: only the map lives under it, and a slot is cloned out before anything is
/// done with it. A poisoned map is recovered: nothing under the lock can leave it half-updated.
static SLOTS: Mutex<BTreeMap<PathBuf, Arc<Slot>>> = Mutex::new(BTreeMap::new());

fn slot(state_dir: &Path) -> Arc<Slot> {
    let mut slots = SLOTS.lock().unwrap_or_else(PoisonError::into_inner);
    slots.entry(state_dir.to_owned()).or_default().clone()
}

/// A release in progress on one `state_dir`; ends when dropped.
#[must_use = "the release is in flight only while this guard is alive"]
pub struct ReleaseInFlight {
    slot: Arc<Slot>,
    /// Cleared only by [`Self::changed_nothing`].
    supersedes: bool,
}

/// Announce a release. Call it BEFORE the first firewall call, and hold the
/// guard until everything the release must be ordered against is done (for the
/// tray's Unblock: through the persisted `Off`). It supersedes every watch
/// opened before it ends, unless consumed by [`ReleaseInFlight::changed_nothing`].
pub fn begin_release(state_dir: &Path) -> ReleaseInFlight {
    let slot = slot(state_dir);
    slot.state().in_flight += 1;
    ReleaseInFlight { slot, supersedes: true }
}

impl ReleaseInFlight {
    /// End a release that failed before it changed anything an install could have raced: it supersedes
    /// nothing. Consumes the guard, so no later step can still claim to have changed something.
    pub fn changed_nothing(mut self) {
        self.supersedes = false;
    }
}

impl Drop for ReleaseInFlight {
    fn drop(&mut self) {
        let mut state = self.slot.state();
        debug_assert!(state.in_flight > 0, "a release guard outlived its own count");
        state.in_flight = state.in_flight.saturating_sub(1);
        if self.supersedes {
            state.epoch += 1;
        }
    }
}

/// Why a release stops an install, as [`ReleaseWatch::check`] reports it. What each means for a cover the
/// install holds is the caller's one decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overtaken {
    /// A release ended with a change since the watch opened: the cover it names is gone or going.
    Superseded,
    /// A release is in flight and has not said what it did: the install must stop, and nothing it holds is
    /// known to be gone.
    InDoubt,
}

impl std::fmt::Display for Overtaken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Overtaken::Superseded => f.write_str("a release ended since the install began"),
            Overtaken::InDoubt => f.write_str("a release is in flight"),
        }
    }
}

/// An install's view of the releases when it opened.
#[derive(Debug, Clone)]
pub struct ReleaseWatch {
    slot: Arc<Slot>,
    epoch: u64,
}

/// Open a watch when an install starts, before it reads any state a release
/// writes. Never refuses: whether a release stops the install is decided by
/// [`ReleaseWatch::check`], where the install commits to a cover.
pub fn watch_releases(state_dir: &Path) -> ReleaseWatch {
    let slot = slot(state_dir);
    let epoch = slot.state().epoch;
    ReleaseWatch { slot, epoch }
}

impl ReleaseWatch {
    /// `Ok` if no release has overtaken the install this watch guards. An epoch that moved since the watch
    /// opened is [`Overtaken::Superseded`] even while another release is in flight; a release in flight with
    /// the epoch unmoved is [`Overtaken::InDoubt`]. A watch opened during a release that then ends with a
    /// change is superseded by it, which covers an install that read state the release was still writing.
    ///
    /// A cover installed before an `Err` is dropped, never kept.
    ///
    /// Takes no lock but the slot's leaf one, so a record write can check it inside its own critical section.
    pub fn check(&self) -> Result<(), Overtaken> {
        let state = *self.slot.state();
        if state.epoch != self.epoch {
            return Err(Overtaken::Superseded);
        }
        if state.in_flight > 0 {
            return Err(Overtaken::InDoubt);
        }
        Ok(())
    }
}

impl From<Overtaken> for RoutingError {
    fn from(verdict: Overtaken) -> Self {
        RoutingError::SupersededByRelease(verdict)
    }
}

#[cfg(test)]
#[path = "release_epoch_tests.rs"]
mod release_epoch_tests;
