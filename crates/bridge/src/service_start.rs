//! The service start types and the decisions made over them, which the install
//! path and the platform layer exchange on every target. The SCM code that reads
//! and writes a start type is Windows-only (`cutover::scm_wait`); these types
//! are pure so a build for any target can name them.

use crate::disable_record::{DisabledBy, RecordState};

/// A service's start type as the SCM reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartType {
    Auto,
    Demand,
    Disabled,
    /// A boot or system start, which a service of its own process never has.
    Other,
}

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

#[cfg(test)]
#[path = "service_start_tests.rs"]
mod service_start_tests;
