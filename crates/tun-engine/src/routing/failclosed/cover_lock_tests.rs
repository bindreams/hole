//! The cover lock excludes every cover mutation under one `state_dir` and makes a stale guard delete nothing.
//! Each test drives one interleaving with channels and barriers, so nothing here depends on timing.

use std::cell::Cell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use super::*;

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// A fake cover guard: its drop runs `deleted` through the stamp exactly as a platform guard's does.
struct FakeCover {
    stamp: InstallStamp,
    deleted: Rc<Cell<u32>>,
}

impl FakeCover {
    fn install(lock: &CoverLock, kind: CoverKind, deleted: &Rc<Cell<u32>>) -> FakeCover {
        FakeCover {
            stamp: lock.stamp_install(kind),
            deleted: Rc::clone(deleted),
        }
    }
}

impl Drop for FakeCover {
    fn drop(&mut self) {
        let deleted = Rc::clone(&self.deleted);
        self.stamp.release_on_drop(move |_| deleted.set(deleted.get() + 1));
    }
}

#[skuld::test]
fn a_sweep_waits_for_an_engage_inside_its_os_step() {
    let d = dir();
    let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let (in_engage_tx, in_engage_rx) = mpsc::channel::<()>();
    let (go_tx, go_rx) = mpsc::channel::<()>();

    let (order, path) = (&order, d.path());
    std::thread::scope(|scope| {
        let engage = scope.spawn(move || {
            let _lock = CoverLock::acquire(path);
            order.lock().unwrap().push("engage begins");
            in_engage_tx.send(()).unwrap();
            go_rx.recv().unwrap();
            order.lock().unwrap().push("engage ends");
        });
        // The engage holds the lock, parked inside its OS step. Any other acquire blocks on this very mutex, so
        // that it is held is the whole contention: observed here, not inferred from the order of two pushes.
        in_engage_rx.recv().unwrap();
        let held = matches!(slot(path).lock.try_lock(), Err(std::sync::TryLockError::WouldBlock));
        let sweep = scope.spawn(move || {
            let _lock = CoverLock::acquire(path);
            order.lock().unwrap().push("sweep deletes");
        });
        go_tx.send(()).unwrap();
        engage.join().unwrap();
        sweep.join().unwrap();
        assert!(
            held,
            "an engage inside its OS step holds the mutex a sweep would have to take"
        );
    });

    assert_eq!(
        *order.lock().unwrap(),
        ["engage begins", "engage ends", "sweep deletes"]
    );
}

#[skuld::test]
fn the_lock_serializes_read_modify_writes_across_threads() {
    // Without exclusion a split load/store loses updates; with it the total is exact. No timing: the barrier only
    // lines the threads up, and the assertion is on the count.
    use std::sync::atomic::{AtomicU64, Ordering};
    const THREADS: u64 = 4;
    const ROUNDS: u64 = 500;
    let d = dir();
    let counter = AtomicU64::new(0);
    let start = std::sync::Barrier::new(THREADS as usize);
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                start.wait();
                for _ in 0..ROUNDS {
                    let _lock = CoverLock::acquire(d.path());
                    let seen = counter.load(Ordering::Relaxed);
                    std::thread::yield_now();
                    counter.store(seen + 1, Ordering::Relaxed);
                }
            });
        }
    });
    assert_eq!(counter.load(Ordering::Relaxed), THREADS * ROUNDS);
}

#[skuld::test]
fn a_stale_stamp_releases_nothing() {
    let d = dir();
    let lock = CoverLock::acquire(d.path());
    let a = lock.stamp_install(CoverKind::Lockdown);
    lock.outdate_stamps(CoverKind::Lockdown);
    let b = lock.stamp_install(CoverKind::Lockdown);

    let mut ran = Vec::new();
    a.release_on_drop(|_| ran.push("a"));
    b.release_on_drop(|_| ran.push("b"));

    assert_eq!(ran, ["b"]);
}

#[skuld::test]
fn a_stamp_dropped_after_a_newer_install_deletes_nothing() {
    let d = dir();
    let deleted = Rc::new(Cell::new(0));
    let older = {
        let lock = CoverLock::acquire(d.path());
        FakeCover::install(&lock, CoverKind::Transient, &deleted)
    };
    let newer = {
        let lock = CoverLock::acquire(d.path());
        FakeCover::install(&lock, CoverKind::Transient, &deleted)
    };

    drop(older);
    assert_eq!(deleted.get(), 0, "the older guard no longer owns the cover");
    drop(newer);
    assert_eq!(deleted.get(), 1);
}

#[skuld::test]
fn a_stamp_outdated_by_a_completed_sweep_deletes_nothing() {
    let d = dir();
    let deleted = Rc::new(Cell::new(0));
    let cover = {
        let lock = CoverLock::acquire(d.path());
        FakeCover::install(&lock, CoverKind::Lockdown, &deleted)
    };
    CoverLock::acquire(d.path()).outdate_stamps(CoverKind::Lockdown);

    drop(cover);

    assert_eq!(deleted.get(), 0, "the sweep already took what the guard held");
}

#[skuld::test]
fn a_stamp_no_sweep_outdated_still_deletes_so_a_failed_sweep_is_retried() {
    let d = dir();
    let deleted = Rc::new(Cell::new(0));
    let cover = {
        let lock = CoverLock::acquire(d.path());
        FakeCover::install(&lock, CoverKind::Lockdown, &deleted)
    };

    drop(cover);

    assert_eq!(deleted.get(), 1);
}

#[skuld::test]
fn an_outdated_transient_stamp_leaves_a_lockdown_stamp_current() {
    let d = dir();
    let lock = CoverLock::acquire(d.path());
    let transient = lock.stamp_install(CoverKind::Transient);
    let lockdown = lock.stamp_install(CoverKind::Lockdown);

    lock.outdate_stamps(CoverKind::Transient);

    assert!(!transient.is_current());
    assert!(lockdown.is_current());
    lock.outdate_stamps(CoverKind::Lockdown);
    assert!(!lockdown.is_current());
}

#[skuld::test]
fn is_current_follows_install_and_outdate() {
    let d = dir();
    let lock = CoverLock::acquire(d.path());
    let first = lock.stamp_install(CoverKind::Transient);
    assert!(first.is_current());
    assert_eq!(first.kind(), CoverKind::Transient);
    let second = lock.stamp_install(CoverKind::Transient);
    assert!(!first.is_current(), "a newer install of the kind supersedes it");
    assert!(second.is_current());
    lock.outdate_stamps(CoverKind::Transient);
    assert!(!second.is_current());
}

#[skuld::test]
fn a_stamp_is_held_under_its_own_dirs_lock() {
    let d = dir();
    let lock = CoverLock::acquire(d.path());
    let stamp = lock.stamp_install(CoverKind::Transient);

    stamp.assert_held_under(&lock);
}

#[skuld::test(should_panic = "released under the lock of its own state dir")]
fn a_stamp_is_not_held_under_another_dirs_lock() {
    let (d, other) = (dir(), dir());
    let stamp = CoverLock::acquire(d.path()).stamp_install(CoverKind::Transient);
    let wrong = CoverLock::acquire(other.path());

    stamp.assert_held_under(&wrong);
}

#[skuld::test]
fn a_cover_dropped_under_the_lock_releases_under_it() {
    let d = dir();
    let deleted = Rc::new(Cell::new(0));
    let lock = CoverLock::acquire(d.path());
    let cover = FakeCover::install(&lock, CoverKind::Transient, &deleted);

    // The drop meets the lock this very thread holds: it must delete under it, not wait for it.
    drop(cover);

    assert_eq!(deleted.get(), 1);
    drop(lock);
}

#[skuld::test]
fn a_panic_with_a_cover_local_under_the_lock_does_not_abort() {
    let d = dir();
    let deleted = Rc::new(Cell::new(0));

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let lock = CoverLock::acquire(d.path());
        let _cover = FakeCover::install(&lock, CoverKind::Lockdown, &deleted);
        panic!("a step after the install fails");
    }));

    assert!(outcome.is_err());
    assert_eq!(deleted.get(), 1, "the unwind dropped the cover under the held lock");
    // And the lock is free again, poison recovered.
    let _again = CoverLock::acquire(d.path());
}

#[skuld::test(should_panic = "release_on_drop")]
fn acquiring_the_lock_twice_on_one_thread_panics() {
    let d = dir();
    let _first = CoverLock::acquire(d.path());
    let _second = CoverLock::acquire(d.path());
}

#[skuld::test]
fn a_cover_dropped_on_another_thread_deletes_under_the_lock() {
    let d = dir();
    let stamp = CoverLock::acquire(d.path()).stamp_install(CoverKind::Transient);

    // The thread holds no lock of its own, so the mutex the delete finds taken is the one the drop acquired.
    let held_during_delete = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut held = None;
                stamp.release_on_drop(|lock| {
                    held = Some(matches!(
                        lock.slot.lock.try_lock(),
                        Err(std::sync::TryLockError::WouldBlock)
                    ));
                });
                held
            })
            .join()
            .unwrap()
    });

    assert_eq!(held_during_delete, Some(true), "the delete ran, under the mutex");
}

#[skuld::test]
fn a_drop_hands_its_delete_the_lock_of_the_stamps_directory() {
    let d = dir();
    let stamp = CoverLock::acquire(d.path()).stamp_install(CoverKind::Transient);
    let mut seen = Vec::new();

    // Outside a section the drop acquires the lock for the delete.
    stamp.release_on_drop(|lock| seen.push((lock.state_dir().to_owned(), held_by_this_thread(lock.slot))));
    // Inside one it passes down a view of the lock this thread holds.
    let held = CoverLock::acquire(d.path());
    stamp.release_on_drop(|lock| seen.push((lock.state_dir().to_owned(), held_by_this_thread(lock.slot))));
    drop(held);

    assert_eq!(seen, vec![(d.path().to_owned(), true); 2]);
    assert!(!held_by_this_thread(slot(d.path())), "neither drop left the lock held");
}

#[skuld::test]
fn dropping_a_view_of_the_held_lock_leaves_the_lock_held() {
    let d = dir();
    let lock = CoverLock::acquire(d.path());

    drop(CoverLock::view_of_held(lock.slot));

    assert!(
        held_by_this_thread(lock.slot),
        "the view's drop left the thread's claim on the lock"
    );
    assert!(
        matches!(lock.slot.lock.try_lock(), Err(std::sync::TryLockError::WouldBlock)),
        "the view's drop left the mutex held, so another thread's acquire still blocks"
    );
}

#[skuld::test]
fn a_cover_lock_is_neither_send_nor_sync() {
    // `!Sync` as well: a `&CoverLock` on another thread would not find the slot in that thread's `HELD`.
    static_assertions::assert_not_impl_any!(CoverLock: Send, Sync);
}

#[skuld::test]
fn the_lock_is_per_state_dir() {
    let (a, b) = (dir(), dir());
    let held = CoverLock::acquire(a.path());
    // A second directory's lock is free while the first is held.
    let other = CoverLock::acquire(b.path());
    assert_eq!(held.state_dir(), a.path());
    assert_eq!(other.state_dir(), b.path());
    // And its stamps are its own.
    let on_b = other.stamp_install(CoverKind::Transient);
    held.outdate_stamps(CoverKind::Transient);
    assert!(on_b.is_current());
}

#[skuld::test]
fn a_panic_under_the_lock_releases_it() {
    let d = dir();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let _lock = CoverLock::acquire(d.path());
        panic!("a section fails");
    }));
    assert!(outcome.is_err());

    let lock = CoverLock::acquire(d.path());
    assert_eq!(lock.state_dir(), d.path());
}

// The sweeps ==========================================================================================================

use super::super::{sweep_with_witness, Clearance, SweepOutcome};
use crate::error::RoutingError;

#[skuld::test]
fn a_sweep_that_completes_makes_an_earlier_stamp_stale() {
    let d = dir();
    let lock = CoverLock::acquire(d.path());
    let stamp = lock.stamp_install(CoverKind::Lockdown);
    let _clearance = sweep_with_witness(&lock, |_| {
        SweepOutcome::per_kind(Clearance::proven(), [(CoverKind::Lockdown, None)])
    })
    .unwrap();
    assert!(!stamp.is_current());
}

#[skuld::test]
fn a_sweep_with_nothing_to_delete_makes_an_earlier_stamp_stale() {
    // A macOS sweep has no unreached exit: a successful sweep over nothing to restore is a release too.
    let d = dir();
    let lock = CoverLock::acquire(d.path());
    let stamp = lock.stamp_install(CoverKind::Transient);
    let result = sweep_with_witness(&lock, |_| {
        SweepOutcome::per_kind(Clearance::proven(), [(CoverKind::Transient, None)])
    });
    assert!(result.is_ok());
    assert!(!stamp.is_current());
}

/// Stamps of both kinds, then a sweep that fails with `outcome`. Returns `(transient_current, lockdown_current)`:
/// a kind the outcome released must stop deleting (its OS objects are gone, a delete would hit whatever replaced
/// them); the other kind's guard stays current and retries.
fn stamps_after_a_failed_sweep(outcome: impl FnOnce() -> SweepOutcome) -> (bool, bool) {
    let d = dir();
    let lock = CoverLock::acquire(d.path());
    let transient = lock.stamp_install(CoverKind::Transient);
    let lockdown = lock.stamp_install(CoverKind::Lockdown);
    let result = sweep_with_witness(&lock, |_| outcome());
    assert!(result.is_err());
    (transient.is_current(), lockdown.is_current())
}

/// [`stamps_after_a_failed_sweep`] for a sweep that failed on every kind it did not list as released.
fn stamps_after_a_failed_sweep_that_released(released: &[CoverKind]) -> (bool, bool) {
    stamps_after_a_failed_sweep(|| {
        let outcome_of = |kind| {
            let error =
                (!released.contains(&kind)).then(|| RoutingError::RouteSetup("one kind could not be released".into()));
            (kind, error)
        };
        SweepOutcome::per_kind(
            Clearance::proven(),
            [outcome_of(CoverKind::Transient), outcome_of(CoverKind::Lockdown)],
        )
    })
}

#[skuld::test]
fn a_failed_sweep_outdates_the_stamp_of_the_kind_it_released() {
    assert_eq!(
        stamps_after_a_failed_sweep_that_released(&[CoverKind::Transient]),
        (false, true)
    );
}

#[skuld::test]
fn a_failed_sweep_outdates_the_lockdown_stamp_when_only_the_lockdown_was_released() {
    assert_eq!(
        stamps_after_a_failed_sweep_that_released(&[CoverKind::Lockdown]),
        (true, false)
    );
}

#[skuld::test]
fn a_sweep_that_released_neither_kind_outdates_neither_stamp() {
    assert_eq!(stamps_after_a_failed_sweep_that_released(&[]), (true, true));
}

#[skuld::test]
fn a_sweep_that_failed_to_open_the_firewall_outdates_no_stamp() {
    // `SweepOutcome::failed` attributes no kind: the firewall was never reached, so every held guard still owns
    // its cover and retries.
    let current = stamps_after_a_failed_sweep(|| {
        SweepOutcome::failed(
            Clearance::proven(),
            RoutingError::RouteSetup("the engine did not open".into()),
        )
    });
    assert_eq!(current, (true, true));
}

#[skuld::test]
fn a_failing_sweep_releases_the_lock() {
    let d = dir();
    {
        let lock = CoverLock::acquire(d.path());
        let result = sweep_with_witness(&lock, |_| {
            SweepOutcome::failed(Clearance::proven(), RoutingError::RouteSetup("the sweep failed".into()))
        });
        assert!(result.is_err());
    }
    let _again = CoverLock::acquire(d.path());
}
