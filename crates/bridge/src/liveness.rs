//! Structural "is a bridge running" check for `hole bridge unlock` (#840).
//!
//! Replaces a point-in-time `launchctl print`/SCM `query_status` probe —
//! which only answers "was a bridge running a moment ago", not "is one
//! running for the whole duration of what I am about to do" — with a real
//! OS-level exclusive lock the running bridge holds for its entire
//! lifetime. `unlock`'s refusal check and its target-write → disengage →
//! intent-flip sequence both go through [`BridgeLiveness::try_acquire`] on
//! the SAME lock file, so a bridge on that state directory that starts
//! mid-unlock waits on the lock instead of interleaving with it, or `unlock`
//! observes the lock held and refuses outright, with no window where neither
//! is true. The lock is per state directory: `unlock` probes the installed
//! service's, so it does not see a bridge on another one (a foreground run's
//! default, or `--state-dir`). The socket bind takes its name over, so nothing
//! here keeps two bridges apart: one bridge per host is the user's to keep
//! (CONTRIBUTING.md, "One bridge per host").
//!
//! Unlike the in-process lock of a `VersionedFile` (a leaf), this lock is
//! meant to be held for a whole process's lifetime, across other locks
//! (the state files' own, taken and released inside that span) and across
//! `.await` points, so it carries no `!Send` marker.

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
    /// boot, and hold the returned value until process exit. Blocks: a second
    /// bridge on the same state directory waits here until the first exits.
    pub fn acquire(state_dir: &Path, owner: Option<(u32, u32)>) -> io::Result<Self> {
        Ok(Self(Exclusive::acquire(&state_dir.join(LOCK_FILE_NAME), owner)?))
    }

    /// Attempt to acquire without blocking. `Ok(None)` means a running
    /// bridge holds this lock right now — `unlock`'s replacement for the old
    /// `is_running` probe. `Ok(Some(_))` returns a token that must be held
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
