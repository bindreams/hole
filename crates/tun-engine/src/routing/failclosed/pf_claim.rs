//! Who owns a pf cover record, and so who may drop its pf enable token.
//!
//! An engage and a release are two parties over one record and one refcount.
//! The rules, as pure decisions over what the record reads (the record modules
//! apply them under their lock):
//!
//! - A release **claims** the record before any pf call by rewriting it as a
//!   *tombstone*: the same record plus `releasing`. A tombstone still names the
//!   token, so a crash or a failed restore leaves what recovery already acts on.
//! - Whoever's **clear** removes the record drops the token. Nobody drops a
//!   token whose record somebody else removed, so no token is dropped twice.
//! - An engage whose own restore failed **re-asserts** its record over a
//!   tombstone (or over nothing), so the release that restored earlier cannot
//!   clear the only evidence of a host the engage then re-blocked.

use super::{PfRecord, StateFile};
use crate::error::RoutingError;

/// What an engage's commit check found when it re-read its record after the
/// ruleset loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    /// A live record naming the engage's token: nothing intervened.
    Held,
    /// The record is gone, claimed, or another engage's: a release ran.
    Released,
    /// The record cannot be read or parsed. Says nothing about a release.
    Unreadable,
}

impl Held {
    /// Classify `current` against the token the engage holds.
    pub fn of<R: PfRecord>(current: &StateFile<R>, token: &str) -> Held {
        match current {
            StateFile::Present(r) if r.pf_token() == token && !r.releasing() => Held::Held,
            StateFile::Present(_) | StateFile::Absent => Held::Released,
            StateFile::Unusable { .. } => Held::Unreadable,
        }
    }

    /// Why the engage must back out, or `None` to commit. One exhaustive match:
    /// a release cancels the start, a record that cannot be read fails it.
    /// `what` names the cover ("transient", "standing") for the message, which
    /// carries no path: it reaches a toast.
    pub fn refusal(self, what: &str) -> Option<RoutingError> {
        match self {
            Held::Held => None,
            Held::Released => Some(RoutingError::SupersededByRelease),
            Held::Unreadable => Some(RoutingError::RouteSetup(format!(
                "the {what} cover's record could not be read after its ruleset loaded, so the engage was backed out"
            ))),
        }
    }
}

/// What a release's final clear found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cleared {
    /// This clear removed the record: the token is the release's to drop.
    Removed,
    /// Nothing there: whoever removed the record owns the token.
    Gone,
    /// A record the release did not claim stands there, typically one an engage
    /// re-asserted after its own restore failed. Left alone.
    Replaced,
}

impl Cleared {
    /// Whether the release drops the token. One exhaustive match.
    pub fn drops_the_token(self) -> bool {
        match self {
            Cleared::Removed => true,
            Cleared::Gone => false,
            Cleared::Replaced => false,
        }
    }

    /// The release is not clean when a record it did not claim stands: the host
    /// may be blocked, and a false success is the one wrong answer.
    pub fn refusal(self) -> Option<RoutingError> {
        match self {
            Cleared::Removed | Cleared::Gone => None,
            Cleared::Replaced => Some(RoutingError::RouteSetup(
                "a cover record was re-asserted while it was being released, so the host may still be blocked".into(),
            )),
        }
    }
}

/// The tombstone a release writes to claim `current`, if it can: a live record.
/// An absent one has nothing to claim, a tombstone is already claimed (by this
/// or a concurrent release), and an unusable file carries no flag.
pub fn tombstone<R: PfRecord>(current: &StateFile<R>) -> Option<R> {
    match current {
        StateFile::Present(r) if !r.releasing() => Some(r.with_releasing(true)),
        StateFile::Present(_) | StateFile::Absent | StateFile::Unusable { .. } => None,
    }
}

/// The live record an engage writes to take back a tombstone it found at entry (a
/// release that failed to restore left it): adopting that cover is a new owner.
pub fn unclaimed<R: PfRecord>(current: &StateFile<R>) -> Option<R> {
    match current {
        StateFile::Present(r) if r.releasing() => Some(r.with_releasing(false)),
        StateFile::Present(_) | StateFile::Absent | StateFile::Unusable { .. } => None,
    }
}

/// A release's final clear of the record it settled under `token`. Only the
/// tombstone it claimed (or an unusable file, which could not be claimed) is
/// removed.
pub fn release_clear<R: PfRecord>(current: &StateFile<R>, token: Option<&str>) -> Cleared {
    match current {
        StateFile::Absent => Cleared::Gone,
        StateFile::Present(r) if r.releasing() && Some(r.pf_token()) == token => Cleared::Removed,
        StateFile::Present(_) => Cleared::Replaced,
        StateFile::Unusable { pf_token } if pf_token.as_deref() == token => Cleared::Removed,
        StateFile::Unusable { .. } => Cleared::Replaced,
    }
}

/// Whether an engage backing out may clear `current`: its own live record, or
/// its own record gone unreadable. Never a tombstone, which a release owns.
pub fn holds_clear<R: PfRecord>(current: &StateFile<R>, token: &str) -> bool {
    match current {
        StateFile::Present(r) => r.pf_token() == token && !r.releasing(),
        StateFile::Unusable { pf_token } => pf_token.as_deref() == Some(token),
        StateFile::Absent => false,
    }
}

/// Whether an engage whose restore failed puts its record back over `current`:
/// over nothing (a release already cleared) or over its own tombstone (a release
/// is yet to clear).
pub fn reasserts<R: PfRecord>(current: &StateFile<R>, token: &str) -> bool {
    match current {
        StateFile::Absent => true,
        StateFile::Present(r) => r.releasing() && r.pf_token() == token,
        StateFile::Unusable { .. } => false,
    }
}

/// Whether `current` is a record naming `token` (`None`: an unusable file that
/// yielded none): the match a sweep without a claim clears by.
pub fn names<R: PfRecord>(current: &StateFile<R>, token: Option<&str>) -> bool {
    match current {
        StateFile::Absent => false,
        StateFile::Present(_) | StateFile::Unusable { .. } => current.pf_token() == token,
    }
}

#[cfg(test)]
#[path = "pf_claim_tests.rs"]
mod pf_claim_tests;
