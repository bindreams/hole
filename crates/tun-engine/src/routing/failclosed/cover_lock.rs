//! One lock over every mutation of a fail-closed cover inside this process.
//!
//! An engage, a guard's release or drop, a sweep and crash recovery each change the firewall in several steps, and
//! a decision that reads state those steps write (the kill-switch intent, the target) is only sound if no other
//! mutation runs between the read and the act. [`CoverLock`] is that exclusion: mutators take `&CoverLock`, readers
//! take a path, so a mutation without the lock does not compile. A read taken outside the lock is a measurement that
//! races a locked writer as the old or the new state; a read that decides a write is taken again under the lock,
//! inside one synchronous section.
//!
//! The lock is per `state_dir`, a std mutex, and never held across an `.await`: [`CoverLock`] is `!Send`, so a
//! future that held it could not be spawned. Poison is recovered; nothing under the lock is left half-updated by
//! an unwind (the counters are single atomic writes). In-process only: `hole bridge unlock`, uninstall and the
//! cutover run with no live bridge (`BridgeLiveness`), so there is nothing to race.
//!
//! Lock order, outermost first: the bridge's `state.proxy` -> this lock -> the record files' own locks and the
//! boot-time witness lock (leaves).
//!
//! A guard keeps the [`InstallStamp`] its install produced. Windows filter keys are fixed and a macOS cover owns
//! one pf token, so a guard that outlived its cover must delete nothing: its release or drop runs its delete only
//! while the stamp is current, that is, until the next install of that [`CoverKind`] or the next sweep that released
//! it. A sweep outdates the stamps of the kinds it released, even when it failed on the other kind; a kind it did not
//! release keeps its stamps, so a held guard's drop still retries its deletes.
//!
//! A guard dropped on a thread that already holds the lock (an early return or an unwind inside a section) deletes
//! under that held lock ([`InstallStamp::release_on_drop`]), handing its delete a non-owning view of it; it can
//! neither deadlock nor panic while unwinding. A guard's explicit release is that same drop, after a check that the
//! lock is its directory's: no second delete path exists to disagree with it.
//! [`CoverLock::acquire`] on a lock this thread already holds is a bug a std mutex would turn into a hang, so it
//! panics and names the two release paths instead.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Which cover a guard or a sweep concerns. The transient block-until-connected cover and the standing lockdown
/// cover are installed and swept independently, so each has its own stamp counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverKind {
    Transient,
    Lockdown,
}

impl CoverKind {
    const COUNT: usize = 2;

    fn index(self) -> usize {
        match self {
            CoverKind::Transient => 0,
            CoverKind::Lockdown => 1,
        }
    }
}

/// One `state_dir`'s lock and stamp counters. Leaked once per directory: the map retained the old per-directory
/// slots for the life of the process too.
#[derive(Debug)]
struct Slot {
    dir: PathBuf,
    lock: Mutex<()>,
    /// Written only while `lock` is held; read lock-free by [`InstallStamp::is_current`].
    stamps: [AtomicU64; CoverKind::COUNT],
}

/// Per-`state_dir` slots. A leaf lock: only the map lives under it. A poisoned map is recovered.
static SLOTS: Mutex<BTreeMap<PathBuf, &'static Slot>> = Mutex::new(BTreeMap::new());

fn slot(state_dir: &Path) -> &'static Slot {
    let mut slots = SLOTS.lock().unwrap_or_else(PoisonError::into_inner);
    slots.entry(state_dir.to_owned()).or_insert_with(|| {
        Box::leak(Box::new(Slot {
            dir: state_dir.to_owned(),
            lock: Mutex::new(()),
            stamps: [AtomicU64::new(0), AtomicU64::new(0)],
        }))
    })
}

thread_local! {
    /// The slots this thread holds a [`CoverLock`] on.
    static HELD: RefCell<Vec<&'static Slot>> = const { RefCell::new(Vec::new()) };
}

fn held_by_this_thread(slot: &'static Slot) -> bool {
    HELD.with(|held| held.borrow().iter().any(|h| std::ptr::eq(*h, slot)))
}

/// The lock over every cover mutation under one `state_dir`; see the module doc. `!Send`.
#[must_use = "the cover lock is held only while this value is alive"]
pub struct CoverLock {
    slot: &'static Slot,
    /// `None` for the non-owning view [`CoverLock::view_of_held`] builds.
    guard: Option<MutexGuard<'static, ()>>,
}

impl CoverLock {
    /// Block until the lock for `state_dir` is free, then hold it.
    ///
    /// Panics if this thread already holds it: a std mutex is not reentrant, so the alternative is a hang with the
    /// lock held and the user's Unblock waiting on it. A guard releases under a held lock when dropped
    /// ([`InstallStamp::release_on_drop`], through a non-owning view of the held lock), and its explicit
    /// `release(&lock)` is that drop; neither acquires.
    pub fn acquire(state_dir: &Path) -> CoverLock {
        Self::lock_slot(slot(state_dir))
    }

    fn lock_slot(slot: &'static Slot) -> CoverLock {
        assert!(
            !held_by_this_thread(slot),
            "the cover lock for this state dir is already held by this thread: a cover is released under a held \
             lock with `release(&lock)` or by dropping it (`release_on_drop`), never by acquiring the lock again"
        );
        let guard = slot.lock.lock().unwrap_or_else(PoisonError::into_inner);
        HELD.with(|held| held.borrow_mut().push(slot));
        CoverLock {
            slot,
            guard: Some(guard),
        }
    }

    /// A non-owning view of the lock this thread already holds on `slot`, for a drop inside a section that must hand
    /// a `&CoverLock` down. It owns nothing, so dropping it neither unlocks nor leaves `HELD`: it is not a second
    /// way to acquire. Only [`InstallStamp::release_on_drop`] builds one, after `held_by_this_thread` confirmed it.
    fn view_of_held(slot: &'static Slot) -> CoverLock {
        debug_assert!(held_by_this_thread(slot), "a view is of a lock this thread holds");
        CoverLock { slot, guard: None }
    }

    /// The directory this lock is for: the one source of it for every function that takes `&CoverLock`.
    pub fn state_dir(&self) -> &Path {
        &self.slot.dir
    }

    /// Mint the stamp of a cover just installed, and make every earlier stamp of `kind` stale. Call once per
    /// engage, at the point the firewall changed.
    pub fn stamp_install(&self, kind: CoverKind) -> InstallStamp {
        let value = self.bump(kind);
        InstallStamp {
            slot: self.slot,
            kind,
            value,
        }
    }

    /// Make every stamp of `kind` stale: a sweep RELEASED that kind, so whatever a guard still holds is gone.
    /// A kind whose release failed is not outdated; the held guard's drop retries.
    pub fn outdate_stamps(&self, kind: CoverKind) {
        self.bump(kind);
    }

    fn bump(&self, kind: CoverKind) -> u64 {
        // Only this lock's holder writes, so the load-add-store is not a race; `Release` publishes it to
        // `is_current`'s `Acquire` read.
        let counter = &self.slot.stamps[kind.index()];
        let next = counter.load(Ordering::Relaxed) + 1;
        counter.store(next, Ordering::Release);
        next
    }
}

impl Drop for CoverLock {
    fn drop(&mut self) {
        // A view owns nothing; the lock it views is released by its owner.
        if self.guard.is_none() {
            return;
        }
        HELD.with(|held| {
            let mut held = held.borrow_mut();
            let at = held.iter().rposition(|h| std::ptr::eq(*h, self.slot));
            debug_assert!(
                at.is_some(),
                "a cover lock was released by a thread that did not hold it"
            );
            if let Some(at) = at {
                held.remove(at);
            }
        });
    }
}

/// Which install a cover guard came from. See the module doc for when it stops being current.
#[derive(Debug)]
pub struct InstallStamp {
    slot: &'static Slot,
    kind: CoverKind,
    value: u64,
}

impl InstallStamp {
    pub fn kind(&self) -> CoverKind {
        self.kind
    }

    /// Whether no install or sweep that released this kind has happened since this stamp was minted. A lock-free
    /// read: a report (status) may call it, but a decision must call it under the lock, where the answer cannot
    /// change.
    pub fn is_current(&self) -> bool {
        self.slot.stamps[self.kind.index()].load(Ordering::Acquire) == self.value
    }

    /// Panics unless `lock` is the lock of this stamp's own state dir.
    pub fn assert_held_under(&self, lock: &CoverLock) {
        assert!(
            std::ptr::eq(self.slot, lock.slot),
            "a cover is released under the lock of its own state dir"
        );
    }

    /// A guard's `Drop`: run `delete` iff this stamp is current, under the lock of the stamp's directory. A drop
    /// inside a section meets the lock this thread already holds and passes `delete` a non-owning view of it, else
    /// the lock is acquired for the call. A stamp is a fact about one install, so asking twice is harmless: the
    /// guard that owns it decides when to ask.
    pub fn release_on_drop(&self, delete: impl FnOnce(&CoverLock)) {
        let lock = if held_by_this_thread(self.slot) {
            CoverLock::view_of_held(self.slot)
        } else {
            CoverLock::lock_slot(self.slot)
        };
        if self.is_current() {
            delete(&lock);
        }
    }
}

#[cfg(test)]
#[path = "cover_lock_tests.rs"]
mod cover_lock_tests;
