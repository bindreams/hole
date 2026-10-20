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
//! The file is a [`Role::Decision`]: a hint about wording and about whether to
//! repair without asking, with a safe default (absent). A record that is
//! corrupt or newer still counts as present, because only a Hole release
//! writes the state directory, and never blocks a write, a clear or a
//! connect: it is backed up and replaced or removed.
//!
//! Neither [`write`] nor [`clear`] takes a lock. Two overlapping retirements
//! can clear a record the other still needs; the service then reads as an
//! administrator's, which the GUI still offers to enable.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use util::versioned_file::{
    DefaultPlacement, Loaded, Obsolete, Removal, Role, Schema, StoreError, VersionedFile, VersionedState,
};

/// The record. It has no content: its presence is the fact.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DisableRecord {}

impl Schema for DisableRecord {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for DisableRecord {
    const FILE_NAME: &'static str = "bridge-service-disabled.json";
    const ROLE: Role = Role::Decision;
}

util::assert_contiguous!(DisableRecord);

/// Whether the record is there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    Absent,
    Present,
}

impl RecordState {
    /// What reading the record found. A file that is there but cannot be
    /// interpreted is present; a read that failed with an I/O error says
    /// nothing about the file, so it is the error.
    pub fn of(loaded: Loaded<DisableRecord>) -> io::Result<RecordState> {
        match loaded {
            Loaded::Absent => Ok(RecordState::Absent),
            Loaded::Unreadable(error) => Err(error),
            Loaded::Corrupt { .. } => Ok(RecordState::Present),
            Loaded::Obsolete { .. } => Ok(RecordState::Present),
            Loaded::Newer { .. } => Ok(RecordState::Present),
            Loaded::Current { .. } => Ok(RecordState::Present),
        }
    }
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

fn file(state_dir: &Path) -> VersionedFile<DisableRecord> {
    VersionedFile::new(state_dir)
}

/// Whether the record is in `state_dir`.
pub fn record_state(state_dir: &Path) -> io::Result<RecordState> {
    RecordState::of(file(state_dir).load())
}

/// Writes the record, over one that cannot be read after backing it up.
pub fn write(state_dir: &Path) -> io::Result<()> {
    file(state_dir)
        .store(&DisableRecord {}, &DefaultPlacement::default())
        .map_err(|error| match error {
            StoreError::Io(error) => error,
            other => io::Error::other(other),
        })
}

/// Removes the record, or moves one that cannot be read aside. Nothing to
/// remove is success.
pub fn clear(state_dir: &Path) -> io::Result<()> {
    match file(state_dir).remove()? {
        Removal::Removed => Ok(()),
        Removal::Absent => Ok(()),
        Removal::MovedAside(_) => Ok(()),
        Removal::Kept => unreachable!("a Role::Decision file is removed or moved aside, never kept"),
    }
}

#[cfg(test)]
#[path = "disable_record_tests.rs"]
mod disable_record_tests;
