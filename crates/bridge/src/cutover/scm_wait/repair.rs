//! Repairing the start type an interrupted uninstall left behind, and enabling
//! the service on request.
//!
//! A retirement disables the start type and writes the record that it did
//! ([`crate::disable_record`]) first. Record and start type together say whose
//! disable a Disabled service carries: with the record it is an uninstall's
//! that never finished, and the elevated paths undo it; without, an
//! administrator's, and nothing here changes it. Only [`enable`], which the
//! administrator asks for, overrides that.

use std::io;

use super::retire::{clear_record, StartConfig, StartWrite};
use crate::disable_record::DisabledBy;
use crate::service_start::RepairStep;

/// Why a repair failed, by the step that failed.
#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("the service's start type could not be read: {0}")]
    StartType(io::Error),
    #[error("the service's start type could not be set to automatic: {0}")]
    Reset(io::Error),
}

/// The step a repair would take, reading both facts and writing neither.
pub fn observe<S: StartConfig>(session: &mut S) -> Result<RepairStep, RepairError> {
    let start = session.start_type().map_err(RepairError::StartType)?;
    Ok(RepairStep::of(session.record_state(), start))
}

/// Who disabled the service, for a reader that must never fail (the GUI's
/// status). A start type that could not be read says nothing is disabled.
pub fn for_display(observed: Result<RepairStep, RepairError>) -> Option<DisabledBy> {
    match observed {
        Ok(step) => step.disabled_by(),
        Err(RepairError::StartType(_)) => None,
        Err(RepairError::Reset(_)) => None,
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
    let step = observe(session)?;
    match step {
        RepairStep::Nothing => {}
        RepairStep::LeaveDisabled => {}
        RepairStep::ClearRecordOnly => clear_record(session),
        RepairStep::ResetThenClear => {
            session.set_start_type(StartWrite::Auto).map_err(RepairError::Reset)?;
            clear_record(session);
        }
    }
    Ok(step)
}

/// Sets the start type to automatic whatever it is and the record says, then
/// clears the record. The administrator asked for it.
pub fn enable<S: StartConfig>(session: &mut S) -> Result<(), RepairError> {
    session.set_start_type(StartWrite::Auto).map_err(RepairError::Reset)?;
    clear_record(session);
    Ok(())
}

#[cfg(test)]
#[path = "repair_tests.rs"]
mod repair_tests;
