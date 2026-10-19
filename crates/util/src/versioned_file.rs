//! One type for every file Hole reads back across a restart.
//!
//! A file is one flat JSON object, `{"version": N, ...payload}`. Each version
//! of its payload is its own frozen type, linked to the one before by
//! [`Schema::Prev`], so [`VersionedFile::load`] reads any version it knows
//! into the current one and a missing step does not build. A file it cannot
//! read, whether newer than this release or corrupt, meets one rule per
//! [`Role`].
//!
//! # Compatibility
//!
//! - Readers ignore unknown fields: no schema, current or frozen, nested or
//!   top level, declares `deny_unknown_fields`.
//! - Bump the version only for a change an older reader would act wrongly on:
//!   a field removed, renamed, retyped or given a new meaning, or new data
//!   that an older release's cleanup of an OS record would need. Adding an
//!   optional field takes no step.
//! - A release that is rolled back and stores a file drops the fields it did
//!   not know; the rule above is what keeps that harmless for records.
//!
//! # Adding a version
//!
//! Freeze the current type under its number (`FooV1`), add `FooV2` with
//! `type Prev = FooV1` and an infallible `upgrade`, point
//! [`VersionedState`] at `FooV2`. A version that cannot be migrated is not a
//! fallible step: raise the floor (`Obsolete<N>`) instead.
//!
//! # Example
//!
//! The shape of an OS record: what the bridge laid on disk and needs to undo,
//! so a copy this release cannot read stops it from connecting.
//!
//! ```
//! use serde::{Deserialize, Serialize};
//! use util::versioned_file::{DefaultPlacement, Loaded, Obsolete, Role, Schema, VersionedFile, VersionedState};
//!
//! #[derive(Debug, PartialEq, Serialize, Deserialize)]
//! struct Layout {
//!     plugin_dir: String,
//! }
//!
//! impl Schema for Layout {
//!     const VERSION: u32 = 1;
//!     type Prev = Obsolete<0>; // nothing came before version 1
//!     fn upgrade(prev: Obsolete<0>) -> Self {
//!         match prev {}
//!     }
//! }
//!
//! impl VersionedState for Layout {
//!     const FILE_NAME: &'static str = "layout.json";
//!     const ROLE: Role = Role::OsRecord;
//! }
//!
//! // A gap in the chain fails here, even under `cargo check`.
//! util::assert_contiguous!(Layout);
//!
//! let dir = std::env::temp_dir().join(format!("versioned-file-doc-{}", std::process::id()));
//! let file = VersionedFile::<Layout>::new(&dir);
//! file.store(&Layout { plugin_dir: "plugins".into() }, &DefaultPlacement::default())?;
//! assert!(matches!(file.load(), Loaded::Current { found: 1, .. }));
//! # std::fs::remove_dir_all(&dir)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod chain;
#[cfg(test)]
mod fixtures;
mod frame;
mod loaded;
mod role;
mod store;

pub use chain::{Chain, ChainError, Obsolete, Schema};
pub use loaded::{CannotRead, Loaded, Raw};
pub use role::{RemoveOver, Role, StoreOver};
pub use store::{DefaultPlacement, Placement, Removal, StoreError, VersionedFile};

/// The current schema of a file: the one that is written and, through its
/// chain, the one every older version is read into.
pub trait VersionedState: Schema + serde::Serialize {
    /// The file's name inside its directory.
    const FILE_NAME: &'static str;

    /// What a copy this release cannot read means for this file.
    const ROLE: Role;

    /// What a file with no `version` key reads as. `None`: such a file is
    /// corrupt. Only for a file that existed before it was versioned.
    const UNVERSIONED_AS: Option<u32> = None;
}

/// Fails to compile when `$t`'s chain has a gap.
///
/// A gap in generic code is reported by the build but not by `cargo check`;
/// naming each current type once in a test makes a type-check fail too.
#[macro_export]
macro_rules! assert_contiguous {
    ($t:ty) => {
        const _: () = <$t as $crate::versioned_file::Schema>::CONTIGUOUS;
    };
}
