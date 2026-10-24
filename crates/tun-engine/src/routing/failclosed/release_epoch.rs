//! Orders an engage against a release inside this process, without either
//! waiting for the other.
//!
//! A release (the tray's Unblock, `bridge unlock`, a cover sweep) must never
//! block on a start that is wedged, so it cannot take a lock the engage holds.
//! It announces itself instead: [`begin_release`] bumps an epoch BEFORE the
//! release touches the firewall. An install opens a [`ReleaseWatch`] before it
//! installs and checks it after; a release that began in between moved the
//! epoch, so the install backs out and the host stays as the release left it.
//! A watch cannot open at all while a release is in flight.
//!
//! In-process only: another bridge, or `hole bridge unlock` run from a shell,
//! is not ordered by this.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::RoutingError;
use crate::exclusive::RecordLock;

#[derive(Clone, Copy, Default)]
struct Slot {
    /// Releases begun on this `state_dir` since the process started.
    epoch: u64,
    /// Releases begun and not yet ended.
    in_flight: usize,
}

/// Per-`state_dir` slots. A leaf lock ([`RecordLock`]): only integers live
/// under it.
static SLOTS: RecordLock<BTreeMap<PathBuf, Slot>> = RecordLock::new(BTreeMap::new());

/// A release in progress on one `state_dir`; ends when dropped.
#[must_use = "the release is in flight only while this guard is alive"]
pub struct ReleaseInFlight {
    state_dir: PathBuf,
}

/// Announce a release. Call it BEFORE the first firewall call, and hold the
/// guard until everything the release must be ordered against is done (for the
/// tray's Unblock: through the persisted `Off`).
pub fn begin_release(state_dir: &Path) -> ReleaseInFlight {
    let mut slots = SLOTS.acquire();
    let slot = slots.entry(state_dir.to_owned()).or_default();
    slot.epoch += 1;
    slot.in_flight += 1;
    ReleaseInFlight {
        state_dir: state_dir.to_owned(),
    }
}

impl Drop for ReleaseInFlight {
    fn drop(&mut self) {
        let mut slots = SLOTS.acquire();
        let slot = slots.entry(self.state_dir.clone()).or_default();
        debug_assert!(slot.in_flight > 0, "a release guard outlived its own count");
        slot.in_flight = slot.in_flight.saturating_sub(1);
    }
}

/// An install's view of the epoch when it opened.
#[derive(Debug)]
pub struct ReleaseWatch {
    state_dir: PathBuf,
    epoch: u64,
}

/// Open a watch before installing a cover. Refuses while a release is in
/// flight: nothing may be installed over it.
pub fn watch_releases(state_dir: &Path) -> Result<ReleaseWatch, RoutingError> {
    let slots = SLOTS.acquire();
    let slot = slots.get(state_dir).copied().unwrap_or_default();
    if slot.in_flight > 0 {
        return Err(RoutingError::SupersededByRelease);
    }
    Ok(ReleaseWatch {
        state_dir: state_dir.to_owned(),
        epoch: slot.epoch,
    })
}

impl ReleaseWatch {
    /// Fails if a release began since the watch opened, whether or not it has
    /// ended: the install it guards may have raced it.
    pub fn check(&self) -> Result<(), RoutingError> {
        let slots = SLOTS.acquire();
        let now = slots.get(self.state_dir.as_path()).copied().unwrap_or_default();
        if now.epoch != self.epoch {
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
    engage: impl FnOnce() -> Result<C, RoutingError>,
) -> Result<C, RoutingError> {
    let watch = watch_releases(state_dir)?;
    let cover = engage()?;
    watch.check()?;
    Ok(cover)
}

#[cfg(test)]
#[path = "release_epoch_tests.rs"]
mod release_epoch_tests;
