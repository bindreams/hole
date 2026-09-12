//! Structural "is a bridge running" check for `hole bridge unlock` (#840).
//!
//! Replaces a point-in-time `launchctl print`/SCM `query_status` probe —
//! which only answers "was a bridge running a moment ago", not "is one
//! running for the whole duration of what I am about to do" — with a real
//! OS-level exclusive lock the running bridge holds for its entire
//! lifetime. `unlock`'s refusal check and its target-write → disengage →
//! intent-flip sequence both go through [`BridgeLiveness::try_acquire`] on
//! the SAME lock file, so a bridge that starts mid-unlock contends on the
//! lock instead of interleaving with it: either it observes the lock held
//! and is not the thing racing (single-instance is separately enforced by
//! the IPC socket bind, which fails first), or `unlock` observes the lock
//! held and refuses outright, with no window where neither is true.
//!
//! Unlike [`crate::target::TargetExclusive`], this lock is not a leaf lock —
//! it is meant to be held for a whole process's lifetime, across other
//! locks (`target::apply`'s own, taken and released inside that span) and
//! across `.await` points, so it carries no `!Send` marker.

use std::io;
use std::path::Path;

use tun_engine::exclusive::Exclusive;

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
        std::fs::create_dir_all(state_dir)?;
        Ok(Self(Exclusive::acquire(&state_dir.join(LOCK_FILE_NAME), owner)?))
    }

    /// Attempt to acquire without blocking. `Ok(None)` means a running
    /// bridge holds this lock right now — `unlock`'s replacement for the old
    /// `is_running` probe. `Ok(Some(_))` returns a token that must be held
    /// across every mutation the caller is about to perform, so a bridge
    /// that starts afterward contends on this same lock instead of
    /// interleaving with them.
    pub fn try_acquire(state_dir: &Path, owner: Option<(u32, u32)>) -> io::Result<Option<Self>> {
        std::fs::create_dir_all(state_dir)?;
        Ok(Exclusive::try_acquire(&state_dir.join(LOCK_FILE_NAME), owner)?.map(Self))
    }
}

#[cfg(test)]
#[path = "liveness_tests.rs"]
mod liveness_tests;
