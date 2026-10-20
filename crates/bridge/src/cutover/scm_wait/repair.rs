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

use super::retire::{clear_record, StartConfig, StartType, StartWrite};
use crate::disable_record::{DisabledBy, RecordState};

/// What a repair does about a service, from the record and the start type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairStep {
    /// Nothing is out of step.
    Nothing,
    /// A record over a service that is not Disabled: stale, swept.
    ClearRecordOnly,
    /// A Disabled service with a record: an interrupted uninstall's.
    ResetThenClear,
    /// A Disabled service with no record: an administrator's, which stays so.
    LeaveDisabled,
}

impl RepairStep {
    /// The step for what was found.
    pub fn of(record: RecordState, start: StartType) -> RepairStep {
        match (record, start) {
            (RecordState::Present, StartType::Disabled) => RepairStep::ResetThenClear,
            (RecordState::Present, StartType::Auto) => RepairStep::ClearRecordOnly,
            (RecordState::Present, StartType::Demand) => RepairStep::ClearRecordOnly,
            (RecordState::Present, StartType::Other) => RepairStep::ClearRecordOnly,
            (RecordState::Absent, StartType::Disabled) => RepairStep::LeaveDisabled,
            (RecordState::Absent, StartType::Auto) => RepairStep::Nothing,
            (RecordState::Absent, StartType::Demand) => RepairStep::Nothing,
            (RecordState::Absent, StartType::Other) => RepairStep::Nothing,
        }
    }

    /// Whether the elevated path that repaired goes on to start the service.
    /// One left Disabled is not started: starting it would fail, and the
    /// administrator's choice is the reason.
    pub fn starts_service(self) -> bool {
        match self {
            RepairStep::Nothing => true,
            RepairStep::ClearRecordOnly => true,
            RepairStep::ResetThenClear => true,
            RepairStep::LeaveDisabled => false,
        }
    }

    /// Who disabled the service, if it is Disabled as the step found it.
    pub fn disabled_by(self) -> Option<DisabledBy> {
        match self {
            RepairStep::Nothing => None,
            RepairStep::ClearRecordOnly => None,
            RepairStep::ResetThenClear => Some(DisabledBy::InterruptedUninstall),
            RepairStep::LeaveDisabled => Some(DisabledBy::Elsewhere),
        }
    }
}

/// The start type an install registers the service with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallStart {
    /// The service starts at boot.
    Automatic,
    /// The service is registered Disabled: an administrator disabled the one
    /// being replaced, and the replacement keeps that.
    LeaveDisabled,
}

impl InstallStart {
    /// The start type a reinstall registers over a service found `disabled_by`
    /// someone, or not disabled. Only an administrator's disable is kept: an
    /// interrupted uninstall's is the product's own breakage.
    pub fn for_disabled_by(disabled_by: Option<DisabledBy>) -> InstallStart {
        match disabled_by {
            None => InstallStart::Automatic,
            Some(DisabledBy::InterruptedUninstall) => InstallStart::Automatic,
            Some(DisabledBy::Elsewhere) => InstallStart::LeaveDisabled,
        }
    }
}

/// Why a repair failed, by the step that failed.
#[derive(Debug, thiserror::Error)]
pub enum RepairError {
    #[error("the service's start type could not be read: {0}")]
    StartType(io::Error),
    #[error("the record that an uninstall disabled the service could not be read: {source}")]
    Record {
        /// The start type, which was read first.
        start: StartType,
        source: io::Error,
    },
    #[error("the service's start type could not be set to automatic: {0}")]
    Reset(io::Error),
}

/// The step a repair would take, reading both facts and writing neither.
pub fn observe<S: StartConfig>(session: &mut S) -> Result<RepairStep, RepairError> {
    let start = session.start_type().map_err(RepairError::StartType)?;
    let record = session
        .record_state()
        .map_err(|source| RepairError::Record { start, source })?;
    Ok(RepairStep::of(record, start))
}

/// Who disabled the service, for a reader that must never fail (the GUI's
/// status). A start type that could not be read says nothing is disabled; a
/// record that could not be read leaves the service an administrator's, because
/// only a record that is there says the disable is ours.
pub fn for_display(observed: Result<RepairStep, RepairError>) -> Option<DisabledBy> {
    match observed {
        Ok(step) => step.disabled_by(),
        Err(RepairError::StartType(_)) => None,
        Err(RepairError::Record { start, .. }) => RepairStep::of(RecordState::Absent, start).disabled_by(),
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
