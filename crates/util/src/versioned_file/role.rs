//! What a file that cannot be read means, per kind of file.

use super::loaded::{CannotRead, WhyUnreadable};
use crate::dir::Principal;

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
    /// A claim a process makes on a name (the update marker): a store is refused
    /// over a file this release cannot read, and a remove takes it whatever it
    /// holds. It never blocks a connect.
    Claim,
    /// What this bridge did to the OS where an unreadable record must still be
    /// cleaned up after (a macOS pf record): moved aside, never destroyed
    /// unread, and it blocks a connect.
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
    /// Whose process handles a file of this role, and so how its folder is walked and the file read. `process` is the
    /// privilege of the running process: the user's own file (`Config`) is handled as the process is, so a
    /// privileged process (a GUI run under `sudo` keeps the user's home) walks the user's folder as the system, and what
    /// its read refuses (a link at the name, a file another account owns) is left in place by the caller, never moved
    /// aside (`ConfigStore`); every other role is a privileged process's whoever runs it.
    pub const fn principal(self, process: Principal) -> Principal {
        match self {
            Role::Decision => Principal::System,
            Role::OsRecord => Principal::System,
            Role::LegacyRecord => Principal::System,
            Role::Config => process,
            Role::Claim => Principal::System,
            Role::Cover => Principal::System,
        }
    }

    /// Whether the privilege of the running process changes [`Role::principal`]: a file of such a role is built with
    /// the process ([`super::VersionedFile::for_process`]), never by a constructor that guesses it.
    pub const fn depends_on_the_process(self) -> bool {
        !matches!(
            (self.principal(Principal::System), self.principal(Principal::User)),
            (Principal::System, Principal::System) | (Principal::User, Principal::User)
        )
    }

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

    /// Whether a file of this role, unreadable for `why`, stops the bridge from
    /// connecting.
    pub fn blocks_connect(self, why: WhyUnreadable) -> bool {
        match why {
            WhyUnreadable::CannotRead(why) => self.unreadable_blocks_connect(why),
            WhyUnreadable::ReadFailed(_) => self.io_failure_blocks_connect(),
        }
    }

    /// Whether a file of this role whose read failed with an I/O error stops the
    /// bridge from connecting. The bytes were never seen, so the file may name
    /// what an OS record exists to clean up.
    pub fn io_failure_blocks_connect(self) -> bool {
        match self {
            Role::Decision => false,
            Role::OsRecord => true,
            Role::LegacyRecord => false,
            Role::Config => false,
            Role::Claim => false,
            Role::Cover => true,
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
            (Role::Claim, CannotRead::Newer) => false,
            (Role::Claim, CannotRead::Corrupt) => false,
            (Role::Cover, CannotRead::Newer) => true,
            (Role::Cover, CannotRead::Corrupt) => true,
        }
    }
}

#[cfg(test)]
#[path = "role_tests.rs"]
mod role_tests;
