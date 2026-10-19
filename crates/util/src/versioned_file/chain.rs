//! A file's schema history as a chain of types.

use serde::de::DeserializeOwned;

use crate::parse_error::ParseFailure;

/// The bottom of a chain: every version `<= BELOW` is deliberately
/// unmigratable. Uninhabited, so a root schema's `upgrade` is `match prev {}`.
pub enum Obsolete<const BELOW: u32> {}

/// Why a version could not be decoded into the chain's top type.
#[derive(Debug)]
pub enum ChainError {
    /// At or below the chain's floor.
    Obsolete,
    /// Right version, wrong shape.
    Shape(ParseFailure),
}

mod sealed {
    pub trait Sealed {}
}

/// A decodable run of schema versions. Implemented only by every [`Schema`]
/// and by [`Obsolete`].
pub trait Chain: Sized + sealed::Sealed {
    /// Highest version this chain decodes.
    const TOP: u32;

    /// Compile-time proof that every link from here down is contiguous. The
    /// trait is sealed, so no schema can replace it.
    #[doc(hidden)]
    const LINKED: ();

    #[doc(hidden)]
    fn decode(version: u32, bytes: &[u8]) -> Result<Self, ChainError>;
}

/// One version of a file's schema, linked to the one before it by [`Prev`].
///
/// Each version is its own frozen type. The link makes a chain contiguous by
/// construction: a gap, a duplicate number, or a floor that leaves a version
/// neither dropped nor described fails to build, wherever in the chain it is.
/// Only a build reports it: a bare `cargo check` stops before the check is
/// evaluated, so name each current type once with
/// [`assert_contiguous!`](crate::assert_contiguous) in a test.
///
/// A schema never declares `deny_unknown_fields` (readers ignore what they do
/// not know) and never carries the `version` key itself: the framing owns it.
///
/// [`Prev`]: Schema::Prev
pub trait Schema: Sized + DeserializeOwned {
    const VERSION: u32;

    /// The previous schema, or `Obsolete<N>` at the root: every version `<= N`
    /// is deliberately unmigratable.
    type Prev: Chain;

    /// Infallible: a version that cannot be migrated raises the floor instead.
    fn upgrade(prev: Self::Prev) -> Self;
}

impl<const N: u32> sealed::Sealed for Obsolete<N> {}
impl<S: Schema> sealed::Sealed for S {}

impl<const N: u32> Chain for Obsolete<N> {
    const TOP: u32 = N;
    const LINKED: () = ();

    fn decode(version: u32, _bytes: &[u8]) -> Result<Self, ChainError> {
        debug_assert!(version <= N, "version {version} is above this chain's floor {N}");
        Err(ChainError::Obsolete)
    }
}

impl<S: Schema> Chain for S {
    const TOP: u32 = S::VERSION;
    const LINKED: () = {
        assert!(S::VERSION == <S::Prev as Chain>::TOP + 1, "migration chain has a gap");
        <S::Prev as Chain>::LINKED
    };

    fn decode(version: u32, bytes: &[u8]) -> Result<Self, ChainError> {
        // Evaluated for every schema that is ever decoded.
        let () = <S as Chain>::LINKED;
        if version == S::VERSION {
            return serde_json::from_slice(bytes).map_err(|e| ChainError::Shape(ParseFailure::from(&e)));
        }
        debug_assert!(version < S::VERSION, "version {version} is above schema {}", S::VERSION);
        <S::Prev as Chain>::decode(version, bytes).map(S::upgrade)
    }
}

#[cfg(test)]
#[path = "chain_tests.rs"]
mod chain_tests;
