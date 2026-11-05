//! The in-process lock of one state file and the generation it guards.

use std::cell::Cell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

/// How many writes this process has made to one path through `update`: equal values mean no write in between. A
/// `create_new` does not move it (a claim is made across processes and nothing compares its generation).
///
/// Per path, process-wide, and moved once by every `update` that is not a `Keep` or that fails to open the
/// directory, under the path's lock and before any I/O, so an attempt that is refused or fails still moves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation(u64);

impl Generation {
    /// The generation right after one write of this process.
    pub fn next(self) -> Generation {
        Generation(self.0 + 1)
    }
}

struct Slot {
    generation: Mutex<u64>,
}

/// Never evicted: the key set is the handful of state paths a process names, and a leaked slot is what lets a guard
/// borrow it for `'static`.
static SLOTS: LazyLock<Mutex<HashMap<PathBuf, &'static Slot>>> = LazyLock::new(Default::default);

thread_local! {
    static INSIDE: Cell<bool> = const { Cell::new(false) };
}

fn slot(path: &Path) -> &'static Slot {
    let mut slots = SLOTS.lock().unwrap_or_else(PoisonError::into_inner);
    // The key is the path as given: resolving a link first is what the privileged-code scans forbid.
    slots.entry(path.to_path_buf()).or_insert_with(|| {
        Box::leak(Box::new(Slot {
            generation: Mutex::new(0),
        }))
    })
}

/// The lock of one path, held. A leaf: nothing else is acquired while it is held, so a caller's `decide` that calls
/// back into a `VersionedFile` panics in a debug build instead of deadlocking.
pub(super) struct Held {
    guard: MutexGuard<'static, u64>,
}

impl Held {
    pub(super) fn generation(&self) -> Generation {
        Generation(*self.guard)
    }

    /// Called by `update` only, once per attempt.
    pub(super) fn bump(&mut self) {
        *self.guard += 1;
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        INSIDE.with(|inside| inside.set(false));
    }
}

/// Waits for a write in flight on `path`. A lock poisoned by a panicking `decide` is recovered: the counter is
/// still valid.
pub(super) fn lock(path: &Path) -> Held {
    INSIDE.with(|inside| {
        debug_assert!(
            !inside.get(),
            "a state-file lock is a leaf: nothing under `decide` may observe or update a state file"
        );
    });
    let guard = slot(path).generation.lock().unwrap_or_else(PoisonError::into_inner);
    INSIDE.with(|inside| inside.set(true));
    Held { guard }
}

/// Whether `path`'s lock is held right now, by any thread.
#[cfg(test)]
pub(super) fn is_locked(path: &Path) -> bool {
    use std::sync::TryLockError;
    matches!(slot(path).generation.try_lock(), Err(TryLockError::WouldBlock))
}

#[cfg(test)]
#[path = "generation_tests.rs"]
mod generation_tests;
