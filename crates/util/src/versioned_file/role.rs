//! What a file that cannot be read means, per kind of file.

use super::loaded::CannotRead;

/// What a file is for, and so what it means when this release cannot read it.
///
/// Every decision is one exhaustive `match` over the role (and the cause, for
/// a file that is newer or corrupt) with every case spelled out (no `A | B =>`,
/// no wildcard), so a new role or cause must choose in each function. A read
/// that failed with an I/O error is a third thing, not a [`CannotRead`]: it
/// has its own cell per role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The user's latest decision, with a safe default to fall back on.
    Decision,
    /// What this bridge did to the OS, needed for cleanup.
    OsRecord,
    /// An OS record a past release wrote and no release writes any more:
    /// kept, never overwritten, and it never blocks a connect.
    LegacyRecord,
    /// The user's own data.
    Config,
}

/// What `store` does over a file that cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOver {
    /// Back it up, then write.
    MoveAside,
    /// Write nothing.
    Refuse,
    /// Replace it.
    Overwrite,
}

/// What `remove` does to a file that cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveOver {
    /// Back it up, then remove the original.
    MoveAside,
    /// Leave it.
    Keep,
    /// Delete it.
    Remove,
}

impl Role {
    pub fn on_store(self, why: CannotRead) -> StoreOver {
        match (self, why) {
            (Role::Decision, CannotRead::Newer) => StoreOver::MoveAside,
            (Role::Decision, CannotRead::Corrupt) => StoreOver::MoveAside,
            (Role::OsRecord, CannotRead::Newer) => StoreOver::Refuse,
            (Role::OsRecord, CannotRead::Corrupt) => StoreOver::Refuse,
            (Role::LegacyRecord, CannotRead::Newer) => StoreOver::Refuse,
            (Role::LegacyRecord, CannotRead::Corrupt) => StoreOver::Refuse,
            (Role::Config, CannotRead::Newer) => StoreOver::Refuse,
            // A corrupt `config.json` is replaced by the next save (owner decision 2026-10-19).
            (Role::Config, CannotRead::Corrupt) => StoreOver::Overwrite,
        }
    }

    pub fn on_remove(self, why: CannotRead) -> RemoveOver {
        match (self, why) {
            (Role::Decision, CannotRead::Newer) => RemoveOver::MoveAside,
            (Role::Decision, CannotRead::Corrupt) => RemoveOver::MoveAside,
            (Role::OsRecord, CannotRead::Newer) => RemoveOver::Keep,
            (Role::OsRecord, CannotRead::Corrupt) => RemoveOver::Keep,
            (Role::LegacyRecord, CannotRead::Newer) => RemoveOver::Keep,
            (Role::LegacyRecord, CannotRead::Corrupt) => RemoveOver::Keep,
            (Role::Config, CannotRead::Newer) => RemoveOver::Keep,
            (Role::Config, CannotRead::Corrupt) => RemoveOver::Keep,
        }
    }

    /// What `store` does over a file whose read failed with an I/O error. The
    /// bytes were never seen, so no role replaces them without a backup: a link
    /// needs no read.
    pub fn on_store_io_failure(self) -> StoreOver {
        match self {
            Role::Decision => StoreOver::MoveAside,
            Role::OsRecord => StoreOver::Refuse,
            Role::LegacyRecord => StoreOver::Refuse,
            Role::Config => StoreOver::MoveAside,
        }
    }

    /// What `remove` does to a file whose read failed with an I/O error.
    pub fn on_remove_io_failure(self) -> RemoveOver {
        match self {
            Role::Decision => RemoveOver::MoveAside,
            Role::OsRecord => RemoveOver::Keep,
            Role::LegacyRecord => RemoveOver::Keep,
            Role::Config => RemoveOver::MoveAside,
        }
    }

    /// Whether a file of this role that cannot be read stops the bridge from
    /// connecting.
    pub fn unreadable_blocks_connect(self, why: CannotRead) -> bool {
        match (self, why) {
            (Role::Decision, CannotRead::Newer) => false,
            (Role::Decision, CannotRead::Corrupt) => false,
            (Role::OsRecord, CannotRead::Newer) => true,
            (Role::OsRecord, CannotRead::Corrupt) => true,
            (Role::LegacyRecord, CannotRead::Newer) => false,
            (Role::LegacyRecord, CannotRead::Corrupt) => false,
            (Role::Config, CannotRead::Newer) => false,
            (Role::Config, CannotRead::Corrupt) => false,
        }
    }
}

#[cfg(test)]
#[path = "role_tests.rs"]
mod role_tests;
