//! One type for every file Hole reads back across a restart.
//!
//! A file is one flat JSON object, `{"version": N, ...payload}`. Each version
//! of its payload is its own frozen type, linked to the one before by
//! [`Schema::Prev`], so [`VersionedFile::observe`] reads any version it knows
//! into the current one and a missing step does not build. A file it cannot
//! read, whether newer than this release or corrupt, meets one rule per
//! [`Role`]; so does one whose read failed with an I/O error, under its own
//! cell: a write or remove never destroys it unread.
//!
//! # Exclusion
//!
//! [`VersionedFile::observe`] and [`VersionedFile::update`] take an in-process lock keyed by the file's path, so two
//! threads never interleave a read and the write that depends on it, and the [`Generation`] an `observe` returns is
//! the one that goes with its bytes. The lock is a leaf: nothing is acquired while it is held, and the `decide`
//! closure of an `update` does no I/O. It does not exclude another process; for the bridge's state files that is
//! `BridgeLiveness`, held by the running bridge and by every CLI that writes state.
//! [`VersionedFile::create_new`] takes no lock: the rename that publishes the file (refusing to replace) is atomic
//! across processes.
//!
//! `observe` needs no exclusion from other processes, on Windows too: a write replaces the file with POSIX semantics,
//! so a reader that has it open neither fails nor makes the write fail. That holds for a reader that opens the file
//! with delete sharing, as `observe` and `std` do; one that does not (some editors and scanners) makes the write fail
//! with a sharing violation. A volume that lacks POSIX rename (FAT, exFAT, some network shares) gets a plain
//! replace, where a reader can make the write fail; see [`VersionedFile::update`]. Durability of the replace is
//! described at `Placement::sync_dir`.
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
//! `assert_contiguous!`, an update and an observe.

mod chain;
#[cfg(test)]
mod fixtures;
mod frame;
mod generation;
mod loaded;
mod role;
mod store;
mod update;

pub use chain::{Chain, ChainError, Obsolete, Schema};
pub use generation::Generation;
pub use loaded::{CannotRead, Loaded, Raw, UnreadableKind, WhyUnreadable};
pub use role::{RemoveOver, Role, StoreOver};
#[cfg(feature = "test-support")]
pub use store::Fs;
pub use store::{DefaultPlacement, KeepOwner, Placement, StoreError, VersionedFile};
pub use update::{Change, CreateOutcome, Observed, UpdateOutcome};

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
