//! Orders an engage against a release inside this process, without either
//! waiting for the other.
//!
//! A release (the tray's Unblock, `bridge unlock`, a cover sweep) must never
//! block on a start that is wedged, so it cannot take a lock the engage holds.
//! It announces itself instead: [`begin_release`] bumps an epoch BEFORE the
//! release touches the firewall. An install opens a [`ReleaseWatch`] before it
//! installs and checks it after; a release that began in between moved the
//! epoch, so the install backs out and the host stays as the release left it.
//! A watch cannot open at all while a release is in flight. An install's record
//! writes check the watch inside their critical section, so no write lands once a
//! release has begun.
//!
//! In-process only: another bridge, or `hole bridge unlock` run from a shell,
//! is not ordered by this.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::error::RoutingError;
use crate::exclusive::RecordLock;

/// One `state_dir`'s release count. Atomics, so that a watch can be checked while
/// a record lock is held without taking a second lock.
#[derive(Debug, Default)]
struct Slot {
    /// Releases begun on this `state_dir` since the process started.
    epoch: AtomicU64,
    /// Releases begun and not yet ended.
    in_flight: AtomicUsize,
}

/// Per-`state_dir` slots. A leaf lock ([`RecordLock`]): only the map lives under
/// it, and a slot is cloned out before anything is done with it.
static SLOTS: RecordLock<BTreeMap<PathBuf, Arc<Slot>>> = RecordLock::new(BTreeMap::new());

fn slot(state_dir: &Path) -> Arc<Slot> {
    SLOTS.acquire().entry(state_dir.to_owned()).or_default().clone()
}

/// A release in progress on one `state_dir`; ends when dropped.
#[must_use = "the release is in flight only while this guard is alive"]
pub struct ReleaseInFlight {
    slot: Arc<Slot>,
}

/// Announce a release. Call it BEFORE the first firewall call, and hold the
/// guard until everything the release must be ordered against is done (for the
/// tray's Unblock: through the persisted `Off`).
///
/// In flight first, epoch second; [`watch_releases`] reads them the other way
/// round. A watch that reads the epoch before this moves it is failed by its
/// check; one that reads it after finds the release in flight.
pub fn begin_release(state_dir: &Path) -> ReleaseInFlight {
    let slot = slot(state_dir);
    slot.in_flight.fetch_add(1, Ordering::SeqCst);
    slot.epoch.fetch_add(1, Ordering::SeqCst);
    ReleaseInFlight { slot }
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
    /// Fails if a release began since the watch opened, whether or not it has
    /// ended: the install it guards may have raced it. Takes no lock, so a
    /// record write can check it inside its own critical section.
    pub fn check(&self) -> Result<(), RoutingError> {
        if self.slot.epoch.load(Ordering::SeqCst) != self.epoch {
            return Err(RoutingError::SupersededByRelease);
        }
        Ok(())
    }
}

/// Run `engage` inside a watch. A cover that a release overtook is dropped (its
/// own disengage is the back-out) and the engage reports
/// [`RoutingError::SupersededByRelease`]; an `engage` error is returned as is.
pub(crate) fn engage_within_watch<C>(
    state_dir: &Path,
    engage: impl FnOnce(&ReleaseWatch) -> Result<C, RoutingError>,
) -> Result<C, RoutingError> {
    let watch = watch_releases(state_dir)?;
    let cover = engage(&watch)?;
    watch.check()?;
    Ok(cover)
}

#[cfg(test)]
#[path = "release_epoch_tests.rs"]
mod release_epoch_tests;
