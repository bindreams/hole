//! Structural "is a bridge running" check for `hole bridge unlock` and
//! `release-covers`.
//!
//! A point-in-time probe (`launchctl print`, SCM `query_status`) only answers
//! "was a bridge running a moment ago", not "is one running for the whole
//! duration of what I am about to do". So the running bridge holds a real
//! OS-level exclusive lock for its entire lifetime, and `unlock` holds
//! [`BridgeLiveness::try_acquire`] on the same lock file across its whole
//! sequence. While a bridge holds the lock, `unlock` refuses; while `unlock`
//! holds it, a bridge's [`BridgeLiveness::acquire`] blocks until it is released,
//! so there is no window where neither is true. A second bridge instance never
//! reaches `acquire`: the IPC socket bind refuses it first.
//!
//! The lock file lives in one state dir, so the exclusion covers only a bridge on
//! the state dir the caller probes. A foreground `hole bridge run` defaults to
//! the per-user state dir, which `unlock` does not probe (bindreams/hole#1214).
//!
//! Unlike the in-process lock of a `VersionedFile` (a leaf), this lock is meant to
//! be held for a whole process's lifetime, across other locks (the state files' own,
//! taken and released inside that span) and across `.await` points, so it carries no
//! `!Send` marker.

use std::io;
use std::path::Path;

use file_lock::Exclusive;

/// Lock filename, alongside `bridge-target.json` in the same root-owned
/// state directory. Never itself holds any state.
const LOCK_FILE_NAME: &str = "bridge-liveness.lock";

/// A held claim that "a bridge is running", for as long as this value lives.
pub struct BridgeLiveness(#[allow(dead_code)] Exclusive);

impl BridgeLiveness {
    /// Acquire for the running bridge's own lifetime: call once, early in
    /// boot, and hold the returned value until process exit. Blocks, but a
    /// second real bridge instance never reaches this call — the IPC socket
    /// bind already refuses it first.
    pub fn acquire(state_dir: &Path, owner: Option<(u32, u32)>) -> io::Result<Self> {
        Ok(Self(Exclusive::acquire(&state_dir.join(LOCK_FILE_NAME), owner)?))
    }

    /// Attempt to acquire without blocking. `Ok(None)` means a running
    /// bridge holds this lock right now. `Ok(Some(_))` returns a token that must be held
    /// across every mutation the caller is about to perform, so a bridge
    /// that starts afterward contends on this same lock instead of
    /// interleaving with them.
    pub fn try_acquire(state_dir: &Path, owner: Option<(u32, u32)>) -> io::Result<Option<Self>> {
        Ok(Exclusive::try_acquire(&state_dir.join(LOCK_FILE_NAME), owner)?.map(Self))
    }
}

#[cfg(test)]
#[path = "liveness_tests.rs"]
mod liveness_tests;
