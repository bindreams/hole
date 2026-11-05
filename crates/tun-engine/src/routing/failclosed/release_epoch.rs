//! Orders an engage against a release inside this process, without either
//! waiting for the other.
//!
//! A release (the tray's Unblock, `bridge unlock`, a cover sweep) must never
//! block on a start that is wedged, so it cannot take a lock the engage holds.
//! It announces itself instead: [`begin_release`] counts it in flight BEFORE the
//! release touches the firewall, and the release calls
//! [`ReleaseInFlight::about_to_delete`] just before its first delete, which moves
//! an epoch. A release that fails before then changed nothing and supersedes
//! nothing; the type, not its callers, owns what "superseded" means.
//!
//! An install opens a [`ReleaseWatch`] before it installs and checks it after. A
//! check fails while any release is in flight, marked or not, and after any
//! release marked itself since the watch opened. A watch cannot open at all while
//! a release is in flight. An install's record writes check the watch inside
//! their critical section, so no write lands once a release has begun.
//!
//! The epoch orders an engage against ANY release: the tray's Unblock holds its guard through its persisted
//! `Off`, a sweep through its witness write. It does not decide what a start records; that is the user's
//! decision to be Off, which only the tray's Unblock makes and the bridge's `unblock_generation` carries.
//!
//! In-process only: another bridge, or `hole bridge unlock` run from a shell,
//! is not ordered by this.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::error::RoutingError;

/// One `state_dir`'s release count. Atomics, so that a watch can be checked while
/// a record lock is held without taking a second lock.
#[derive(Debug, Default)]
struct Slot {
    /// Releases that marked themselves since the process started.
    epoch: AtomicU64,
    /// Releases begun and not yet ended.
    in_flight: AtomicUsize,
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
}

/// Announce a release. Call it BEFORE the first firewall call, and hold the
/// guard until everything the release must be ordered against is done (for the
/// tray's Unblock: through the persisted `Off`). It supersedes an install only
/// once [`ReleaseInFlight::about_to_delete`] is called.
pub fn begin_release(state_dir: &Path) -> ReleaseInFlight {
    let slot = slot(state_dir);
    slot.in_flight.fetch_add(1, Ordering::SeqCst);
    ReleaseInFlight { slot }
}

impl ReleaseInFlight {
    /// Mark the release as touching the firewall. Call it just before the
    /// first delete is attempted; a partial failure after it still counts. May
    /// be called again, before each delete.
    pub fn about_to_delete(&self) {
        self.slot.epoch.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for ReleaseInFlight {
    fn drop(&mut self) {
        let before = self.slot.in_flight.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(before > 0, "a release guard outlived its own count");
    }
}

/// An install's view of the epoch when it opened.
#[derive(Debug)]
pub struct ReleaseWatch {
    slot: Arc<Slot>,
    epoch: u64,
}

/// Open a watch before installing a cover. Refuses while a release is in
/// flight: nothing may be installed over it.
pub fn watch_releases(state_dir: &Path) -> Result<ReleaseWatch, RoutingError> {
    let slot = slot(state_dir);
    let epoch = slot.epoch.load(Ordering::SeqCst);
    if slot.in_flight.load(Ordering::SeqCst) > 0 {
        return Err(RoutingError::SupersededByRelease);
    }
    Ok(ReleaseWatch { slot, epoch })
}

impl ReleaseWatch {
    /// Fails if a release is in flight, or marked itself since the watch opened:
    /// the install it guards may have raced it. Takes no lock, so a record write
    /// can check it inside its own critical section.
    ///
    /// The in-flight count is read before the epoch: a release that began, marked
    /// and ended between the two reads is seen by the epoch.
    pub fn check(&self) -> Result<(), RoutingError> {
        if self.slot.in_flight.load(Ordering::SeqCst) > 0 || self.slot.epoch.load(Ordering::SeqCst) != self.epoch {
            return Err(RoutingError::SupersededByRelease);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "release_epoch_tests.rs"]
mod release_epoch_tests;
