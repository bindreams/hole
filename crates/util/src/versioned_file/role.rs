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
    /// What this bridge did to the OS, needed for cleanup. A type of this role must be added to the bridge's connect
    /// gate (`state_gate::check`).
    OsRecord,
    /// An OS record a past release wrote and no release writes any more:
    /// kept, never overwritten, and it never blocks a connect.
    LegacyRecord,
    /// The user's own data.
    Config,
    /// A claim a process makes on a name (the update marker): a store is refused
    /// over a file this release cannot read, and a remove takes it whatever it
    /// holds. It never blocks a connect.
    Claim,
    /// What this bridge did to the OS where an unreadable record must still be
    /// cleaned up after (a macOS pf record): moved aside, never destroyed
    /// unread, and it blocks a connect. A type of this role must be added to the bridge's connect gate
    /// (`state_gate::check`).
    Cover,
}

/// What a [`Change::Store`](super::Change::Store) does over a file that cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOver {
    /// Back it up, then write.
    MoveAside,
    /// Write nothing.
    Refuse,
    /// Replace it.
    Overwrite,
}

/// What a [`Change::Remove`](super::Change::Remove) does to a file that cannot be read.
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
            // A corrupt `config.json` is replaced by the next save.
            (Role::Config, CannotRead::Corrupt) => StoreOver::Overwrite,
            (Role::Claim, CannotRead::Newer) => StoreOver::Refuse,
            (Role::Claim, CannotRead::Corrupt) => StoreOver::Refuse,
            (Role::Cover, CannotRead::Newer) => StoreOver::MoveAside,
            (Role::Cover, CannotRead::Corrupt) => StoreOver::MoveAside,
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
            (Role::Claim, CannotRead::Newer) => RemoveOver::Remove,
            (Role::Claim, CannotRead::Corrupt) => RemoveOver::Remove,
            (Role::Cover, CannotRead::Newer) => RemoveOver::MoveAside,
            (Role::Cover, CannotRead::Corrupt) => RemoveOver::MoveAside,
        }
    }

    /// What a store does over a file whose read failed with an I/O error. The
    /// bytes were never seen, so no role replaces them without a backup: a link
    /// needs no read.
    pub fn on_store_io_failure(self) -> StoreOver {
        match self {
            Role::Decision => StoreOver::MoveAside,
            Role::OsRecord => StoreOver::Refuse,
            Role::LegacyRecord => StoreOver::Refuse,
            Role::Config => StoreOver::MoveAside,
            Role::Claim => StoreOver::Refuse,
            Role::Cover => StoreOver::MoveAside,
        }
    }

    /// What a remove does to a file whose read failed with an I/O error.
    pub fn on_remove_io_failure(self) -> RemoveOver {
        match self {
            Role::Decision => RemoveOver::MoveAside,
            Role::OsRecord => RemoveOver::Keep,
            Role::LegacyRecord => RemoveOver::Keep,
            Role::Config => RemoveOver::MoveAside,
            Role::Claim => RemoveOver::Remove,
            Role::Cover => RemoveOver::Keep,
        }
    }

    /// Whether a file of this role that this release cannot act on stops the bridge from connecting. One answer for
    /// every way a file is unreadable (newer, corrupt, a failed read): an OS record may name what a connect would
    /// strand, however it came to be unreadable.
    pub fn blocks_connect(self) -> bool {
        match self {
            Role::Decision => false,
            Role::OsRecord => true,
            Role::LegacyRecord => false,
            Role::Config => false,
            Role::Claim => false,
            Role::Cover => true,
        }
    }
}

#[cfg(test)]
#[path = "role_tests.rs"]
mod role_tests;
