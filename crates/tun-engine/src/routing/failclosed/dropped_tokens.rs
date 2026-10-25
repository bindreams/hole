//! Which pf enable tokens this process has dropped.
//!
//! `pfctl -X <token>` releases a refcount that was taken once. Several parties
//! can come to drop the same token: a release, an engage backing out, the engage
//! whose record write replaced the record that named it, a cover's drop. None can
//! tell whether another got there first, and a second drop either fails or
//! releases a reference somebody else took. So every drop is a [`drop_once`]: a
//! token this process already dropped is not dropped again, and a party that
//! wants one gone asks, rather than negotiating who owns it.
//!
//! The lock is held across the `pfctl -X`, so a second asker waits for the first
//! and then finds the token dropped. It is not a [`crate::exclusive::RecordLock`]:
//! it spans a process call. Nothing else is acquired under it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use crate::error::RoutingError;

type Key = (PathBuf, String);

static DROPPED: Mutex<BTreeSet<Key>> = Mutex::new(BTreeSet::new());

/// Run `drop` (the `pfctl -X`) unless this process already dropped `token` under
/// `state_dir`. A drop that fails is not remembered, so a retry runs it again.
pub fn drop_once(
    state_dir: &Path,
    token: &str,
    drop: impl FnOnce() -> Result<(), RoutingError>,
) -> Result<(), RoutingError> {
    let mut dropped = DROPPED.lock().unwrap_or_else(PoisonError::into_inner);
    let key = (state_dir.to_owned(), token.to_owned());
    if dropped.contains(&key) {
        return Ok(());
    }
    drop()?;
    dropped.insert(key);
    Ok(())
}

/// Forget that `token` was dropped: `pfctl -E` returned it again, and this is a
/// new refcount.
pub fn minted(state_dir: &Path, token: &str) {
    DROPPED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&(state_dir.to_owned(), token.to_owned()));
}

#[cfg(test)]
#[path = "dropped_tokens_tests.rs"]
mod dropped_tokens_tests;
