//! The persisted record of whether a `FWPM_FILTER_FLAG_BOOTTIME` twin was ever
//! armed on this host and has not since been watched being removed.
//!
//! # Why a sweep's own observations are not enough
//!
//! A boot-time key cannot report on itself: on any boot where its runtime
//! object is not live it answers `FWP_E_FILTER_NOT_FOUND` whether or not a
//! policy record survives behind it (see [`super::KeyLifetime::BootTime`]).
//! [`super::KeyRole::BootTimeSibling`] is the one key in a sweep that can say
//! whether a record was ever POSSIBLE here — but only while the sibling is
//! still installed, and the sibling and the twin are guaranteed to be added
//! together, never removed together. The twin's removal is precisely the
//! unprovable event.
//!
//! So any sweep that removes the sibling while the twin answers not-found
//! CONSUMES the only live evidence. Every later sweep sees an empty sibling
//! set, reads it as "no standing cover was ever here", and suppresses the
//! report — permanently, after an entirely ordinary user action (turning the
//! kill switch off, or the tray's Unblock item). The uninstall gate then
//! deletes `hole.exe` in silence, which is bindreams/hole#1003's outcome for
//! the pre-BFE window.
//!
//! This file is what the evidence is copied into before it is consumed. The
//! sweep that can still SEE the sibling records what it saw; every later sweep
//! reads it back.
//!
//! # Why not this file alone
//!
//! A wiped or recreated `state_dir` reads as "never armed" and would suppress
//! a report that is real. That is why the record does not replace the sibling:
//! [`super::Clearance::leftover_keys`] reports when EITHER says a record is
//! possible. The two fail in different directions — a wiped state dir still
//! has its sibling to fall back on, a consumed sibling still has its record —
//! so the union is silent only when both are lost.
//!
//! # Disclosed residuals
//!
//! - A `record` write that FAILS (an unwritable `state_dir`) loses the witness
//!   with nothing left to re-derive it from. The sweep that failed to write
//!   still reports — it holds the sibling evidence itself — but a later one
//!   does not. The failure is warned, not propagated: the sweep already
//!   happened and refusing the release over bookkeeping would trade a bounded
//!   early-boot block for a permanently unremovable product (the trade
//!   `cutover::release_covers` refuses for the same reason).
//! - The record is per-`state_dir` while the WFP filters it describes are
//!   machine-wide. The uninstall gate reads its peers' records too
//!   (`cutover::release_covers_with`); a bridge given an explicit `--state-dir`
//!   outside that set is still invisible, the same residual `peer_state_dirs`
//!   already discloses for the liveness probe.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::ArmingWitness;

/// Schema version. A mismatched file classifies [`ArmingWitness::Unreadable`]
/// — which REPORTS — rather than being discarded as absence: losing the record
/// is not evidence that nothing was armed.
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// Filename under `state_dir`.
pub(crate) const STATE_FILE_NAME: &str = "bridge-boottime.json";

/// The persisted record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootTimeState {
    version: u32,
    /// Whether a boot-time twin is outstanding on this host: armed at some
    /// point and never since watched being removed.
    armed: bool,
}

fn state_file(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE_NAME)
}

/// Classify the record. Never collapses a failure into a recorded value — see
/// [`ArmingWitness`], whose whole point is that "no file" and "a file I could
/// not read" are different findings.
pub fn load(state_dir: &Path) -> ArmingWitness {
    let path = state_file(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ArmingWitness::Unset,
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "boot-time witness read failed");
            return ArmingWitness::Unreadable;
        }
    };
    match serde_json::from_slice::<BootTimeState>(&bytes) {
        Ok(s) if s.version == SCHEMA_VERSION && s.armed => ArmingWitness::Armed,
        Ok(s) if s.version == SCHEMA_VERSION => ArmingWitness::Disarmed,
        Ok(other) => {
            tracing::warn!(
                got = other.version,
                want = SCHEMA_VERSION,
                "boot-time witness schema mismatch"
            );
            ArmingWitness::Unreadable
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "boot-time witness parse failed");
            ArmingWitness::Unreadable
        }
    }
}

/// Atomically persist `armed` (temp file + same-dir rename, `sync_all` before
/// persist), the same write shape `lockdown_state` uses. Creates `state_dir`.
fn save(state_dir: &Path, armed: bool, owner: Option<(u32, u32)>) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    util::ownership::chown_if_some(state_dir, owner);
    let state = BootTimeState {
        version: SCHEMA_VERSION,
        armed,
    };
    let json =
        serde_json::to_vec_pretty(&state).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let path = state_file(state_dir);
    let mut tmp = tempfile::NamedTempFile::new_in(state_dir)?;
    tmp.write_all(&json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(&path).map_err(|e| e.error)?;
    util::ownership::chown_if_some(&path, owner);
    Ok(())
}

/// Record that a twin is outstanding on this host.
///
/// Called from the facade's `engage_lockdown` on a platform whose standing
/// cover arms boot-time keys, at the moment the fact becomes true — the twins
/// are committed AND read back out of the boot-time view. Doing it here rather
/// than leaving it to the first sweep covers the host whose sibling is removed
/// by something that is not a sweep at all (an external FWPM delete, a
/// firewall reset): no sweep ever observed the sibling, so no sweep could have
/// copied the evidence.
pub(crate) fn record_armed(state_dir: &Path, owner: Option<(u32, u32)>) {
    write_or_warn(state_dir, true, owner);
}

/// Arm the record from a test in a DOWNSTREAM crate, which cannot reach
/// [`record_armed`]'s facade caller without a real firewall.
///
/// `hole-bridge`'s uninstall gate reads its peers' records
/// (`cutover::release_covers_with`), and the host that needs that is one whose
/// bridge armed a twin under a different `state_dir`. Reproducing it needs a
/// peer dir with an armed record and no other evidence at all — which is
/// exactly the state a Windows `engage_lockdown` leaves and nothing else does.
/// Behind `test-utils`, so no production build can reach it.
#[cfg(feature = "test-utils")]
pub fn record_armed_for_test(state_dir: &Path) {
    record_armed(state_dir, None);
}

/// What a sweep's own observations say the record should now hold.
///
/// Derived once, in [`super::Clearance::witness_update`], from what the sweep
/// saw — never re-derived at a write site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WitnessUpdate {
    /// A boot-time key went unproven on a host where a record is possible:
    /// copy that finding into the file before the evidence for it is gone.
    Arm,
    /// Every boot-time key this sweep touched was watched being removed, which
    /// is proof for any lifetime ([`super::KeyObservation::proves_empty`]).
    /// Nothing is outstanding.
    Disarm,
    /// The sweep says nothing about a boot-time key's record, so the file
    /// keeps whatever it held. Two causes, and the second is the one that
    /// matters: the sweep touched no boot-time key at all, or it found an
    /// unproven one on a host whose siblings answered empty — and an empty
    /// sibling set is exactly the reading this module exists to stop treating
    /// as evidence of absence.
    Leave,
}

/// The record's next value, or `None` when nothing needs writing. Pure, so the
/// one rule that must never write `false` over a real `Armed` is a table
/// rather than a condition spread over a write site.
fn next_record(current: ArmingWitness, update: WitnessUpdate) -> Option<bool> {
    match update {
        WitnessUpdate::Leave => None,
        // Already recorded; rewriting it would only risk an I/O failure.
        WitnessUpdate::Arm => (current != ArmingWitness::Armed).then_some(true),
        // `Unset` is a host with no file and nothing outstanding — writing
        // `false` there would litter every host that never armed a twin.
        // `Unreadable` IS written, because a corrupt file reports forever
        // otherwise and this sweep just proved there is nothing to report.
        WitnessUpdate::Disarm => (!matches!(current, ArmingWitness::Disarmed | ArmingWitness::Unset)).then_some(false),
    }
}

/// Apply a sweep's [`WitnessUpdate`] to the record it was folded against.
pub(crate) fn apply(state_dir: &Path, current: ArmingWitness, update: WitnessUpdate, owner: Option<(u32, u32)>) {
    if let Some(armed) = next_record(current, update) {
        write_or_warn(state_dir, armed, owner);
    }
}

/// Warn, never propagate — see the module doc's residuals.
fn write_or_warn(state_dir: &Path, armed: bool, owner: Option<(u32, u32)>) {
    if let Err(e) = save(state_dir, armed, owner) {
        tracing::warn!(
            error = %e,
            armed,
            path = %state_file(state_dir).display(),
            "the boot-time witness could not be written; a later sweep that can no longer see a \
             standing cover's PERSISTENT sibling will have nothing to fall back on"
        );
    }
}

// Deliberately NOT platform-gated, for the reason `clearance_tests` gives: the
// hazard is Windows-only and the proof must not live only there.
#[cfg(test)]
#[path = "boottime_witness_tests.rs"]
mod boottime_witness_tests;
