//! The persisted record of whether a `FWPM_FILTER_FLAG_BOOTTIME` twin was armed on this host and has not since been
//! watched being removed. The design is in docs/contributing/architecture/kill-switch-windows.md#the-witness.
//!
//! A boot-time key cannot report on itself on a boot where its runtime object is not live (see
//! [`super::KeyLifetime::BootTime`]). [`super::KeyRole::BootTimeSibling`] is the evidence that a record is possible
//! here, and a sweep that removes the sibling consumes it. This file is where that evidence is copied before it is
//! consumed. It does not replace the sibling, because a wiped `state_dir` reads as "never armed":
//! [`super::Clearance::leftover_keys`] reports when either says a record is possible.
//!
//! # What clears the record
//!
//! Exactly one observation: a by-key delete that removed a live twin ([`super::KeyOutcome::Removed`]). An empty
//! answer never does.
//!
//! That rests on an unmeasured assumption: that `FwpmFilterDeleteByKey0` purges the boot-time policy record along
//! with the runtime object. Every read this crate can take goes through the Base Filtering Engine, and the record
//! is what applies before it starts, so only a reboot could tell. If the assumption is wrong, a host that watched its
//! twins go is silent over a stranded pre-BFE block-all.
//!
//! # Disclosed residuals
//!
//! - **A host whose twins went without a sweep watching keeps reporting** (an external FWPM delete, a firewall reset,
//!   an image restore). No sweep held the evidence to copy; only the write at engage covers this.
//! - **A failed write loses the witness.** The sweep that failed to write still reports, since it holds the sibling
//!   evidence, but a later one does not. The failure is warned, not propagated, because refusing the release over
//!   bookkeeping would trade a bounded early-boot block for an unremovable product.
//! - **The record is per `state_dir`; the WFP filters are machine-wide.** The uninstall gate reads its peers' records
//!   too (`cutover::release_covers_with`), but a bridge given an explicit `--state-dir` outside that set stays
//!   invisible. The read is one-way: a sweep writes its `Disarm` only to its own directory, so a peer's `Armed`
//!   survives a SYSTEM sweep that watched those twins go and keeps reporting.

use std::path::Path;

use serde::{Deserialize, Serialize};
use util::versioned_file::{
    Change, DefaultPlacement, Loaded, Obsolete, Role, Schema, StoreError, VersionedFile, VersionedState,
};

use super::{ArmingWitness, CoverLock};

/// Filename under `state_dir`.
pub const STATE_FILE_NAME: &str = "bridge-boottime.json";

/// The persisted record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BootTimeState {
    /// Whether a boot-time twin is outstanding on this host: armed at some
    /// point and never since watched being removed.
    armed: bool,
}

impl Schema for BootTimeState {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

/// A decision, not an OS record: a file this release cannot read is backed up and replaced. It must never read as
/// "nothing armed" ([`load`]), and a sweep that watched the twin go may write over it.
impl VersionedState for BootTimeState {
    const FILE_NAME: &'static str = STATE_FILE_NAME;
    const ROLE: Role = Role::Decision;
}

util::assert_contiguous!(BootTimeState);

fn file(state_dir: &Path) -> VersionedFile<BootTimeState> {
    VersionedFile::new(state_dir)
}

/// Classify the record. A failure is never collapsed into a recorded value: "no file" and "a file I could not
/// read" are different findings ([`ArmingWitness`]). A version this release does not know is `Unreadable`, which
/// reports, not absence.
pub fn load(state_dir: &Path) -> ArmingWitness {
    arming_of(&file(state_dir).observe().loaded)
}

/// The one reading of a record: `load` and `apply`'s decision both classify through it.
fn arming_of(loaded: &Loaded<BootTimeState>) -> ArmingWitness {
    match loaded {
        Loaded::Absent => ArmingWitness::Unset,
        Loaded::Current { value, .. } if value.armed => ArmingWitness::Armed,
        Loaded::Current { .. } => ArmingWitness::Disarmed,
        Loaded::Obsolete { .. } => ArmingWitness::Unreadable,
        Loaded::Newer { .. } => ArmingWitness::Unreadable,
        Loaded::Corrupt { .. } => ArmingWitness::Unreadable,
        Loaded::Unreadable { .. } => ArmingWitness::Unreadable,
    }
}

/// Atomically persist `armed`, creating `state_dir`. A record this release cannot read is backed up beside it first.
fn save(state_dir: &Path, armed: bool, owner: Option<(u32, u32)>) -> Result<(), StoreError> {
    file(state_dir)
        .update(&DefaultPlacement { owner }, |_| {
            (Change::Store(BootTimeState { armed }), ())
        })
        .map(|_| ())
}

/// Record that a twin is outstanding on this host.
///
/// Called when `FwpmTransactionCommit0` returns `ERROR_SUCCESS`, on a platform whose standing cover arms boot-time
/// keys (`platform::commit_and_record`). Recording at the engage covers a host whose sibling is later removed by
/// something that is not a sweep, where no sweep could have copied the evidence. It is not deferred to after the
/// twins read back (`platform::verify_boottime_twins`), because that read-back can fail over a cover already in force.
///
/// A macOS production build omits it: `commit_and_record` is its only caller and is Windows-only. Test builds keep it
/// on every platform.
#[cfg(any(target_os = "windows", test, feature = "test-utils"))]
pub(crate) fn record_armed(lock: &CoverLock, owner: Option<(u32, u32)>) {
    write_or_warn(lock.state_dir(), true, owner);
}

/// Arm the record from a test in a downstream crate, which cannot reach [`record_armed`]'s caller without a real
/// firewall. `hole-bridge`'s uninstall gate reads its peers' records, and testing that needs a peer directory with an
/// armed record and no other evidence. `owner` is passed through to the write. Behind `test-utils`.
#[cfg(feature = "test-utils")]
pub fn record_armed_for_test(lock: &CoverLock, owner: Option<(u32, u32)>) {
    record_armed(lock, owner);
}

/// What a sweep's own observations say the record should now hold, derived once in
/// [`super::Clearance::witness_update`] and never at a write site. The only update that clears the record is
/// [`Self::Disarm`], which rests on the purge assumption in the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WitnessUpdate {
    /// A boot-time key went unproven on a host where a record is possible:
    /// copy that finding into the file before the evidence for it is gone.
    Arm,
    /// Every boot-time key this sweep touched was watched being removed ([`super::KeyObservation::proves_empty`]).
    /// Nothing is outstanding.
    Disarm,
    /// The sweep says nothing about a boot-time key's record, so the file keeps what it held: the sweep touched no
    /// boot-time key, or found an unproven one on a host whose siblings answered empty, which is not evidence of
    /// absence.
    Leave,
}

/// The record's next value, or `None` when nothing needs writing.
///
/// Pure, and a table rather than a condition spread over the write site. An `Arm` never rewrites an existing `Armed`,
/// and a `Disarm` never writes `false` over `Unset` or `Disarmed`, which would litter every host that never armed a
/// twin with a file saying so.
fn next_record(current: ArmingWitness, update: WitnessUpdate) -> Option<bool> {
    match update {
        WitnessUpdate::Leave => None,
        WitnessUpdate::Arm => (current != ArmingWitness::Armed).then_some(true),
        // `Unreadable` is written: a corrupt file would otherwise report forever, and this sweep proved there is
        // nothing to report.
        WitnessUpdate::Disarm => (!matches!(current, ArmingWitness::Disarmed | ArmingWitness::Unset)).then_some(false),
    }
}

/// Apply a sweep's [`WitnessUpdate`], decided against the record as it is NOW; the read and the write are one
/// `update`. Takes no owner: a sweep writes only on a boot-time sighting, which exists only on Windows, where
/// placement ignores unix ids.
pub(crate) fn apply(lock: &CoverLock, update: WitnessUpdate) {
    // `Leave` writes nothing for any record, so it must not even open the directory.
    if update == WitnessUpdate::Leave {
        return;
    }
    let mut decided = None;
    let written = file(lock.state_dir()).update(&DefaultPlacement::default(), |now| {
        match next_record(arming_of(&now.loaded), update) {
            Some(armed) => {
                decided = Some(armed);
                (Change::Store(BootTimeState { armed }), ())
            }
            None => (Change::Keep, ()),
        }
    });
    if let Err(e) = written {
        warn_unwritten(&e, decided);
    }
}

/// Warn, never propagate — see the module doc's residuals.
fn write_or_warn(state_dir: &Path, armed: bool, owner: Option<(u32, u32)>) {
    if let Err(e) = save(state_dir, armed, owner) {
        warn_unwritten(&e, Some(armed));
    }
}

/// `armed` is the value that was to be written; `None` when the write failed before one was chosen.
fn warn_unwritten(e: &StoreError, armed: Option<bool>) {
    tracing::warn!(
        error = e as &dyn std::error::Error,
        armed = ?armed,
        file = STATE_FILE_NAME,
        "the boot-time witness could not be written; a later sweep that can no longer see a \
         standing cover's PERSISTENT sibling will have nothing to fall back on"
    );
}

// Not platform-gated, like `clearance_tests`.
#[cfg(test)]
#[path = "boottime_witness_tests.rs"]
mod boottime_witness_tests;
