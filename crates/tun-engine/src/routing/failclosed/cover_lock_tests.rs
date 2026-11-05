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
    stamp: Option<InstallStamp>,
    deleted: Rc<Cell<u32>>,
}

impl FakeCover {
    fn install(lock: &CoverLock, kind: CoverKind, deleted: &Rc<Cell<u32>>) -> FakeCover {
        FakeCover {
            stamp: Some(lock.stamp_install(kind)),
            deleted: Rc::clone(deleted),
        }
    }
}

impl Drop for FakeCover {
    fn drop(&mut self) {
        let deleted = Rc::clone(&self.deleted);
        self.stamp
            .take()
            .unwrap()
            .release_on_drop(move || deleted.set(deleted.get() + 1));
    }
}

#[skuld::test]
fn a_sweep_waits_for_an_engage_inside_its_os_step() {
    let d = dir();
    let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let (in_engage_tx, in_engage_rx) = mpsc::channel::<()>();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (sweep_started_tx, sweep_started_rx) = mpsc::channel::<()>();

    let (order, path) = (&order, d.path());
    std::thread::scope(|scope| {
        let engage = scope.spawn(move || {
            let _lock = CoverLock::acquire(path);
            order.lock().unwrap().push("engage begins");
            in_engage_tx.send(()).unwrap();
            go_rx.recv().unwrap();
            order.lock().unwrap().push("engage ends");
        });
        // The engage holds the lock, parked inside its OS step.
        in_engage_rx.recv().unwrap();
        let sweep = scope.spawn(move || {
            sweep_started_tx.send(()).unwrap();
            let _lock = CoverLock::acquire(path);
            order.lock().unwrap().push("sweep deletes");
        });
        sweep_started_rx.recv().unwrap();
        // The sweep is at (or inside) `acquire` and cannot have run: only the engage may release it.
        go_tx.send(()).unwrap();
        engage.join().unwrap();
        sweep.join().unwrap();
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
    a.release(&lock, || ran.push("a"));
    b.release(&lock, || ran.push("b"));

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
fn a_cover_released_with_the_lock_deletes_once() {
    let d = dir();
    let lock = CoverLock::acquire(d.path());
    let stamp = lock.stamp_install(CoverKind::Transient);
    let mut deleted = 0;

    stamp.release(&lock, || deleted += 1);

    assert_eq!(deleted, 1);
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
fn a_cover_dropped_on_another_thread_waits_for_the_lock() {
    let d = dir();
    let deleted = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let (dropping_tx, dropping_rx) = mpsc::channel::<()>();

    let stamp = CoverLock::acquire(d.path()).stamp_install(CoverKind::Transient);
    let lock = CoverLock::acquire(d.path());
    std::thread::scope(|scope| {
        let deleted = &deleted;
        let dropper = scope.spawn(move || {
            dropping_tx.send(()).unwrap();
            stamp.release_on_drop(|| deleted.lock().unwrap().push("delete"));
        });
        dropping_rx.recv().unwrap();
        deleted.lock().unwrap().push("holder done");
        drop(lock);
        dropper.join().unwrap();
    });

    assert_eq!(*deleted.lock().unwrap(), ["holder done", "delete"]);
}

#[skuld::test]
fn a_cover_lock_is_not_send() {
    static_assertions::assert_not_impl_any!(CoverLock: Send);
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
