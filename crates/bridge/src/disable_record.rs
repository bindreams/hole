//! The record that an uninstall disabled the bridge service.
//!
//! The retirement disables the service's start type so that its stop is final,
//! and puts the start type back (or deletes the service) when it is done. A
//! process killed in between leaves the service Disabled, which looks like an
//! administrator's choice. The record is written before the start type is
//! disabled and cleared after it is restored or the service is deleted, so
//! its presence tells the two apart: present, the disable is ours and the
//! elevated paths undo it; absent, nothing here changes a Disabled service.
//!
//! On Windows the record is a value in the service's own registry key
//! ([`RecordKey`]), so it dies with the service and an unprivileged reader can
//! see it. A record that cannot be read counts as present, and the record
//! never blocks an uninstall, an install, a cutover or a connect.
//!
//! Neither write nor clear takes a lock. Two overlapping retirements can clear
//! a record the other still needs; the service then reads as an
//! administrator's, which the GUI still offers to enable.

#[cfg(windows)]
#[path = "disable_record/record_key.rs"]
mod record_key;
#[cfg(windows)]
pub use record_key::RecordKey;

/// Whether the record is there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    Absent,
    Present,
}

/// Who disabled the service, as far as the record can say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledBy {
    /// The record is present: an uninstall of ours was interrupted.
    InterruptedUninstall,
    /// No record: an administrator, or a tool, other than Hole.
    Elsewhere,
}

impl DisabledBy {
    pub fn of(state: RecordState) -> DisabledBy {
        match state {
            RecordState::Present => DisabledBy::InterruptedUninstall,
            RecordState::Absent => DisabledBy::Elsewhere,
        }
    }
}

#[cfg(test)]
#[path = "disable_record_tests.rs"]
mod disable_record_tests;
