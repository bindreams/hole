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
//! (`RecordKey`), so it dies with the service and an unprivileged reader can
//! see it. A record that cannot be read counts as present. A failed write fails
//! the retirement before the start type changes.
//!
//! Record and start type are read and written under the machine-wide start-type
//! lock (Windows `StartTypeLock`), from a caller's first read to its last write,
//! so a record is never read mid-change by anything that acts on it. The GUI's
//! status read takes the lock without waiting and says when it is held
//! ([`DisabledState::InChange`]).

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

/// What the GUI's status read finds about the service being disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledState {
    /// The service is not disabled, or its start type could not be read.
    NotDisabled,
    /// The service is disabled, by the one the record names.
    By(DisabledBy),
    /// A retirement, repair or enable holds the start-type lock: the start
    /// type and the record are being changed, and neither says anything yet.
    InChange,
}

impl DisabledState {
    /// The state for a read that held the lock.
    pub fn of(disabled_by: Option<DisabledBy>) -> DisabledState {
        match disabled_by {
            Some(by) => DisabledState::By(by),
            None => DisabledState::NotDisabled,
        }
    }
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
