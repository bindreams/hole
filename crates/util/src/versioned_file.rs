//! One type for every file Hole reads back across a restart.
//!
//! A file is one flat JSON object, `{"version": N, ...payload}`. Each version
//! of its payload is its own frozen type, linked to the one before by
//! [`Schema::Prev`], so [`VersionedFile::load`] reads any version it knows
//! into the current one and a missing step does not build. A file it cannot
//! read, whether newer than this release or corrupt, meets one rule per
//! [`Role`]; so does one whose read failed with an I/O error, under its own
//! cell: a write or remove never destroys it unread. `store`, `remove` and `move_aside` hold an exclusive lock on
//! `<name>.lock`, a file the type creates and never deletes; `load` takes none.
//! The lock file can be opened by exactly the principals that may write the
//! file it guards, and its owner, so a principal that can only read the file
//! cannot stall its writers. For that the state directory must not let a
//! principal create files in it that may not write the state file.
//!
//! Who may write the file is read from its mode bits (unix) or its DACL
//! (Windows): a principal that writes it through a POSIX or macOS ACL entry is
//! not seen. On unix the lock is owned by the file's owner, so only that owner,
//! or root, can create it; a group writer can open a lock the owner made, not
//! make one. A link or anything but a regular file at `<name>.lock` is an
//! error, never followed.
//!
//! # Compatibility
//!
//! - Readers ignore unknown fields: no schema, current or frozen, nested or
//!   top level, declares `deny_unknown_fields`.
//! - Bump the version only for a change an older reader would act wrongly on:
//!   a field removed, renamed, retyped or given a new meaning, or new data
//!   that an older release's cleanup of an OS record would need. Adding an
//!   optional field takes no step.
//! - A rolled-back release drops the fields it does not know when it stores, so
//!   data an OS-record cleanup needs takes a version bump.
//!
//! # Adding a version
//!
//! Freeze the current type under its number (`FooV1`), add `FooV2` with
//! `type Prev = FooV1` and an infallible `upgrade`, point
//! [`VersionedState`] at `FooV2`. A version that cannot be migrated is not a
//! fallible step: raise the floor (`Obsolete<N>`) instead.
//!
//! # Template
//!
//! `versioned_file_tests.rs` is a complete `Role::OsRecord` schema with
//! `assert_contiguous!`, a store and a load. It is a test, so CI runs it: copy
//! it, not a snippet that can rot.

mod chain;
#[cfg(test)]
mod fixtures;
mod frame;
mod loaded;
mod lock;
mod lock_access;
mod role;
mod store;
mod sys;

pub use chain::{Chain, ChainError, Obsolete, Schema};
pub use loaded::{CannotRead, Loaded, Raw};
pub use role::{RemoveOver, Role, StoreOver};
pub use store::{DefaultPlacement, Placement, Removal, StoreError, VersionedFile};

#[cfg(test)]
#[path = "versioned_file_tests.rs"]
mod versioned_file_tests;

/// The current schema of a file: the one that is written and, through its
/// chain, the one every older version is read into.
pub trait VersionedState: Schema + serde::Serialize {
    /// The file's name inside its directory.
    const FILE_NAME: &'static str;

    /// What a copy this release cannot read means for this file.
    const ROLE: Role;

    /// What a file with no `version` key reads as. `None`: such a file is
    /// corrupt. Only for a file that existed before it was versioned. Must be
    /// in `1..=VERSION`: [`VersionedFile::new`] does not build otherwise.
    const UNVERSIONED_AS: Option<u32> = None;
}

/// Fails to compile when any link of `$t`'s chain, down to its floor, has a
/// gap.
///
/// A gap in generic code is reported by a build but not by a bare `cargo
/// check`, which stops before the check is evaluated; naming each current type
/// once with this macro makes a type-check fail too.
#[macro_export]
macro_rules! assert_contiguous {
    ($t:ty) => {
        const _: () = <$t as $crate::versioned_file::Chain>::LINKED;
    };
}
