//! Repairing the start type an interrupted uninstall left behind, and enabling
//! the service on request.
//!
//! A retirement disables the start type and writes the record that it did
//! ([`crate::disable_record`]) first. Record and start type together say whose
//! disable a Disabled service carries: with the record it is an uninstall's
//! that never finished, and the elevated paths undo it; without, an
//! administrator's, and nothing here changes it. Only [`enable`], which the
//! administrator asks for, overrides that.
//!
//! The real session holds the machine-wide start-type lock for as long as it is
//! open, so a repair or an enable never runs under a retirement that is still
//! going. Both stamp the record with their own identity before they change the
//! start type, so the GUI's read, which never touches the lock, sees a change
//! in progress while they work ([`display`]).

use std::io;

use tracing::warn;

use super::retire::{clear_record, RecordWrite, StartConfig, StartRead, StartWrite};
use crate::disable_record::{DisabledState, RecordState};
use crate::service_start::RepairStep;

/// Why a repair failed, by the step that failed.
#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("the service's start type could not be read: {0}")]
    StartType(io::Error),
    #[error("the service's start type could not be set to automatic: {0}")]
    Reset(io::Error),
}

/// The step a repair would take, reading both facts and writing neither. The
/// only failure is the start type's read, so the error is the read's own.
pub fn observe<S: StartConfig>(session: &mut S) -> io::Result<RepairStep> {
    let start = session.start_type()?;
    Ok(RepairStep::of(session.record_state(), start))
}

/// What the GUI's status shows of the service: a reader that must never fail.
/// It reads the change mark, the start type and the record's changer, and
/// writes nothing. A lock holder or record writer that still runs is a change
/// in progress, whatever the start type says (or whether it could be read);
/// otherwise a start type that could not be read says nothing is disabled.
///
/// The reads are separate, so a change that begins or ends between them would
/// be read half done. The mark is read before and after, and a pass counts
/// only if the second equals the first (no holder began or ended in between);
/// else it is read again. The passes have no count or timer; each re-reads the
/// real values, and a holder that crashed leaves its mark as it is, so they
/// end.
pub fn display<S: StartRead>(session: &mut S) -> DisabledState {
    loop {
        let before = session.read_mark();
        let start = session.read_start_type();
        let changer = session.read_changer();
        if session.read_mark() != before {
            continue;
        }
        let record = match changer {
            Some(_) => RecordState::Present,
            None => RecordState::Absent,
        };
        if let Err(error) = &start {
            warn!(%error, "could not read the service's start type, so it is taken as not disabled");
        }
        let disabled_by = start.ok().and_then(|start| RepairStep::of(record, start).disabled_by());
        return DisabledState::of(before.holder(), changer, disabled_by);
    }
}

/// Stamps the record with this process before a repair or an enable changes
/// the start type, and says whether it was written. A failure costs the reader
/// only its wording (it would read the earlier stamp's process), so it is a
/// warning.
fn stamp<S: StartConfig>(session: &mut S) -> bool {
    match session.write_record() {
        Ok(()) => true,
        Err(error) => {
            warn!(%error, "could not stamp the record with this process; a status read may call this change interrupted");
            false
        }
    }
}

/// Takes the step [`observe`] finds and returns it.
///
/// The start type is written before the record is cleared, so a repair cut
/// short between them leaves a stale record over a service that is not
/// Disabled, never a Disabled service of ours with no record. A failed reset is
/// the error and leaves the record; a failed clear is a warning, because the
/// next retirement, cutover or install sweeps a stale record.
pub fn repair<S: StartConfig>(session: &mut S) -> Result<RepairStep, RepairError> {
    let step = observe(session).map_err(RepairError::StartType)?;
    match step {
        RepairStep::Nothing => {}
        RepairStep::LeaveDisabled => {}
        RepairStep::ClearRecordOnly => clear_record(session),
        RepairStep::ResetThenClear => {
            let _ = stamp(session);
            session.set_start_type(StartWrite::Auto).map_err(RepairError::Reset)?;
            clear_record(session);
        }
    }
    Ok(step)
}

/// Sets the start type to automatic whatever it is and the record says, then
/// clears the record. The administrator asked for it.
///
/// A failed write removes a record this call made: over an administrator's
/// Disable (no record) it would otherwise leave an interrupted Hole change,
/// which the repair and the cutover undo. A record that was there stays.
pub fn enable<S: StartConfig>(session: &mut S) -> Result<(), RepairError> {
    let write = RecordWrite::over(session.record_state());
    let stamped = stamp(session);
    if let Err(error) = session.set_start_type(StartWrite::Auto) {
        if stamped && write.clears_on_failure() {
            clear_record(session);
        }
        return Err(RepairError::Reset(error));
    }
    clear_record(session);
    Ok(())
}

#[cfg(test)]
#[path = "repair_tests.rs"]
mod repair_tests;
