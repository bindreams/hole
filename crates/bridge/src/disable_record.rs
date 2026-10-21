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
//! so a record is never read mid-change by anything that acts on it. The writer
//! stamps the record with its own identity (process id and creation time), and
//! the GUI's status read, which never touches the lock, asks whether that
//! process is still running: running, a change is in progress
//! ([`DisabledState::InChange`]); gone, the change was interrupted and the
//! record's usual answer stands. The record sits in the service's key, which no
//! user can write, so no user can forge a live stamp.
//!
//! The reads of a status call are separate, so every holder of the lock also
//! sets a change mark (`ChangeKey`) when its outermost hold begins and ends,
//! and the status read goes again if the mark moved between its reads.

#[cfg(windows)]
#[path = "disable_record/record_key.rs"]
mod record_key;
#[cfg(windows)]
pub use record_key::RecordKey;
#[cfg(windows)]
#[path = "disable_record/change_mark.rs"]
mod change_mark;
#[cfg(all(windows, test))]
pub(crate) use change_mark::scratch::ScratchChangeKey;
#[cfg(windows)]
pub use change_mark::ChangeKey;
#[cfg(windows)]
#[path = "disable_record/stamp.rs"]
mod stamp;
#[cfg(windows)]
pub use stamp::Stamp;

/// Whether the record is there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    Absent,
    Present,
}

/// Who disabled the service, as far as the record can say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledBy {
    /// The record is present: an uninstall or an update of ours was interrupted.
    InterruptedChange,
    /// No record: an administrator, or a tool, other than Hole.
    Elsewhere,
}

/// Whether the process that stamped the record is still changing the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Changer {
    /// The stamped process is running.
    Running,
    /// It is gone, or the pid names another process now.
    NotRunning,
}

impl Changer {
    /// The reader's answer from the probe of the stamped process. A probe that
    /// failed cannot say the process runs, and waiting on a change that ended
    /// would leave the user no way out; reading it as not running leaves the
    /// Repair, which waits on the lock, to settle it.
    pub fn of(running: std::io::Result<bool>) -> Changer {
        match running {
            Ok(true) => Changer::Running,
            Ok(false) => Changer::NotRunning,
            Err(_) => Changer::NotRunning,
        }
    }
}

/// What a status read saw of the change mark ([`ChangeKey`] on Windows): the
/// value exactly as read, and whether the process it names, if any, runs. Two
/// reads that see equal marks saw no change begin or end between them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChangeMark {
    raw: Option<String>,
    holder: Option<Changer>,
}

impl ChangeMark {
    pub fn new(raw: Option<String>, holder: Option<Changer>) -> Self {
        Self { raw, holder }
    }

    /// The mark of a reader that holds the start-type lock itself: nothing can
    /// change under it, so it never differs from itself.
    pub fn unchanging() -> Self {
        Self::default()
    }

    /// The process holding the start-type lock to change the service, if the
    /// mark names one, and whether it still runs.
    pub fn holder(&self) -> Option<Changer> {
        self.holder
    }
}

/// What the GUI's status read finds about the service being disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledState {
    /// The service is not disabled, or its start type could not be read.
    NotDisabled,
    /// The service is disabled, by the one the record names.
    By(DisabledBy),
    /// A retirement, repair or enable is changing the start type and the
    /// record: the record names a process that is still running.
    InChange,
}

impl DisabledState {
    /// The state for what a read found: the process holding the start-type
    /// lock, if the change mark names one; who stamped the record, if there is
    /// one; and who disabled the service, if it is disabled. A running holder
    /// or changer is a change in progress whatever the start type says, since
    /// the start type is being changed.
    pub fn of(holder: Option<Changer>, changer: Option<Changer>, disabled_by: Option<DisabledBy>) -> DisabledState {
        let running = |who: Option<Changer>| match who {
            Some(Changer::Running) => true,
            Some(Changer::NotRunning) => false,
            None => false,
        };
        if running(holder) || running(changer) {
            return DisabledState::InChange;
        }
        match disabled_by {
            Some(by) => DisabledState::By(by),
            None => DisabledState::NotDisabled,
        }
    }
}

impl DisabledBy {
    pub fn of(state: RecordState) -> DisabledBy {
        match state {
            RecordState::Present => DisabledBy::InterruptedChange,
            RecordState::Absent => DisabledBy::Elsewhere,
        }
    }
}

#[cfg(test)]
#[path = "disable_record_tests.rs"]
mod disable_record_tests;
