//! The two pf cover records (`bridge-failclosed.json`, `bridge-lockdown-pf.json`) as one generic module.
//!
//! Every writer holds the [`CoverLock`](super::CoverLock), and nothing outside the process writes these records while
//! a bridge runs (`hole bridge unlock`, the uninstall and the cutover run under `BridgeLiveness`). So no function here
//! compares what a caller read against what is on disk: there is no concurrent party for the compare to catch.
//! What a record still guards is a failure a sequential order reaches. A release whose `pfctl -X` failed leaves a
//! record, so a later engage that overwrites it must drop the token it names ([`swap`]). A clear by a party whose
//! token a later engage displaced must not remove the newer record ([`clear_if_token`]). A record that cannot be read
//! is neither absent nor removable ([`StateFile::Unreadable`], [`Cleared::Kept`]).

use std::path::Path;

use util::versioned_file::{Change, DefaultPlacement, Role, StoreError, UpdateOutcome, VersionedFile, VersionedState};

use super::StateFile;
use crate::error::RoutingError;

/// A persisted pf cover record, which names the `pfctl -E` token it holds.
pub trait PfRecord: VersionedState + Clone {
    fn pf_token(&self) -> &str;
}

impl<T: PfRecord> StateFile<T> {
    /// The token the record names: a `Present` record's, or what an `Unusable` one could still be read for. `None`
    /// for `Absent`, `Unreadable` and a record that yielded no token.
    pub fn pf_token(&self) -> Option<&str> {
        match self {
            StateFile::Absent => None,
            StateFile::Unreadable => None,
            StateFile::Unusable { pf_token } => pf_token.as_deref(),
            StateFile::Present(record) => Some(record.pf_token()),
        }
    }

    /// What a release acts by: the token to drop and to clear the record under (`None`: nothing to drop), or, for a
    /// record that could not be read, the refusal. An unread record names no token, and a clear keyed to "no token"
    /// would call a record that has since become readable not ours. Every release path reads this; none matches
    /// `Unreadable` itself.
    pub fn release_token(&self) -> Result<Option<&str>, RoutingError> {
        match self {
            StateFile::Absent => Ok(None),
            StateFile::Unreadable => Err(unread_record()),
            StateFile::Unusable { pf_token } => Ok(pf_token.as_deref()),
            StateFile::Present(record) => Ok(Some(record.pf_token())),
        }
    }
}

/// The answer for a record a release could not read. The text names no path: it reaches a toast.
fn unread_record() -> RoutingError {
    RoutingError::RouteSetup(
        "the cover record could not be read, so it was left in place and the host may still be blocked".into(),
    )
}

/// What a clear of a record under a token found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cleared {
    /// The record named the token and is gone now (an unusable one moved aside).
    Removed,
    /// Nothing there, or a record that names another token: nothing of the caller's to clear.
    Gone,
    /// The record could not be read, so it was left in place. The host may still be blocked.
    Kept,
}

impl Cleared {
    /// The release is not clean when a record it could not read stands: a false success is the one wrong answer. The
    /// text names no path: it reaches a toast.
    pub fn refusal(self) -> Option<RoutingError> {
        match self {
            Cleared::Removed => None,
            Cleared::Gone => None,
            Cleared::Kept => Some(unread_record()),
        }
    }

    /// What a clear did, given the `verdict` its decision computed and the outcome of the write it asked for.
    pub fn after_update(verdict: Cleared, outcome: UpdateOutcome) -> Cleared {
        match outcome {
            UpdateOutcome::Absent => Cleared::Gone,
            UpdateOutcome::Removed => Cleared::Removed,
            UpdateOutcome::MovedAside(_) => Cleared::Removed,
            UpdateOutcome::Kept => Cleared::Kept,
            UpdateOutcome::Unchanged => verdict,
            UpdateOutcome::Stored => verdict,
        }
    }
}

/// What clearing the record under `token` finds in `current`: a record that names it, or an unusable one that yielded
/// none when `token` is `None`, is the caller's to remove.
pub fn sweep_clear<R: PfRecord>(current: &StateFile<R>, token: Option<&str>) -> Cleared {
    match current {
        StateFile::Absent => Cleared::Gone,
        StateFile::Unreadable => Cleared::Kept,
        StateFile::Unusable { .. } | StateFile::Present(_) => match names(current, token) {
            true => Cleared::Removed,
            false => Cleared::Gone,
        },
    }
}

/// Whether `current` is a record naming `token` (`None`: an unusable file that yielded none). A record that could not
/// be read names nothing.
pub fn names<R: PfRecord>(current: &StateFile<R>, token: Option<&str>) -> bool {
    match current {
        StateFile::Absent => false,
        StateFile::Unreadable => false,
        StateFile::Unusable { .. } => current.pf_token() == token,
        StateFile::Present(_) => current.pf_token() == token,
    }
}

/// The one constructor: a pf record is a [`Role::Cover`], so an unreadable one is moved aside, never destroyed unread.
fn record<R: PfRecord>(state_dir: &Path) -> VersionedFile<R> {
    const { assert!(matches!(R::ROLE, Role::Cover)) };
    VersionedFile::new(state_dir)
}

/// The record as the sweep's trichotomy (plus `Unreadable`): "no cover was ever engaged" is `Absent` only for a
/// missing file, never for one that cannot be read.
pub fn read<R: PfRecord>(state_dir: &Path) -> StateFile<R> {
    StateFile::view(&record::<R>(state_dir).observe().loaded)
}

/// Persist `new`, creating `state_dir`; a file this release cannot read is backed up beside it first. Returns the
/// token the replaced record named, if it named one: the caller drops it (the macOS sequencers), because this write took
/// the only record that did. The caller holds the cover lock.
pub fn swap<R: PfRecord>(state_dir: &Path, new: &R, owner: Option<(u32, u32)>) -> Result<Option<String>, StoreError> {
    record::<R>(state_dir)
        .update(&DefaultPlacement { owner }, |now| {
            let displaced = StateFile::view(&now.loaded).pf_token().map(str::to_owned);
            (Change::Store(new.clone()), displaced)
        })
        .map(|(displaced, _)| displaced)
}

/// Remove the record iff it names `token` (`None`: iff it is an unusable file that yielded none), and say what it
/// found. A record that cannot be read is kept. The caller holds the cover lock.
pub fn clear_if_token<R: PfRecord>(state_dir: &Path, token: Option<&str>) -> Result<Cleared, StoreError> {
    let (verdict, outcome) = record::<R>(state_dir).update(&DefaultPlacement::default(), |now| {
        let verdict = sweep_clear(&StateFile::view(&now.loaded), token);
        match verdict {
            Cleared::Removed => (Change::Remove, verdict),
            Cleared::Gone => (Change::Keep, verdict),
            Cleared::Kept => (Change::Keep, verdict),
        }
    })?;
    Ok(Cleared::after_update(verdict, outcome))
}

#[cfg(test)]
#[path = "pf_record_tests.rs"]
mod pf_record_tests;
