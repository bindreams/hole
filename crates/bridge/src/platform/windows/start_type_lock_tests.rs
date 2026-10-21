use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use super::*;

#[skuld::test]
fn a_free_lock_is_taken_and_is_then_taken_for_every_other_thread() {
    let lock = StartTypeLock::scratch("taken");
    assert!(!lock.is_held_for_another_thread(), "nothing holds it yet");
    let held = lock.acquire().expect("acquire");
    assert!(lock.is_held_for_another_thread());
    drop(held);
    assert!(!lock.is_held_for_another_thread(), "released");
}

#[skuld::test]
fn a_lock_held_by_another_thread_is_waited_for_and_then_taken() {
    let lock = StartTypeLock::scratch("waited-for");
    let held = lock.acquire().expect("acquire");
    let released = AtomicBool::new(false);
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|s| {
        let waiter = s.spawn(|| {
            let acquired = lock
                .acquire_noting_wait(|| tx.send(()).unwrap())
                .expect("the waiter acquired");
            // Taken only after the holder let go: the flag is set before it does.
            let holder_had_let_go = released.load(Ordering::SeqCst);
            drop(acquired);
            holder_had_let_go
        });
        // The waiter says it must wait before it can have the lock.
        rx.recv().expect("the waiter ended without waiting");
        released.store(true, Ordering::SeqCst);
        drop(held);
        assert!(
            waiter.join().expect("the waiter"),
            "the waiter took the lock while it was held"
        );
    });
}

#[skuld::test]
fn a_free_lock_is_taken_without_noting_a_wait() {
    let lock = StartTypeLock::scratch("not-noted");
    let held = lock.acquire_noting_wait(|| panic!("nothing held it")).expect("acquire");
    drop(held);
}

#[skuld::test]
fn the_thread_that_holds_the_lock_may_take_it_again() {
    let lock = StartTypeLock::scratch("recursive");
    let outer = lock.acquire().expect("acquire");
    let inner = lock
        .acquire_noting_wait(|| panic!("this thread holds it"))
        .expect("acquire again");
    drop(inner);
    assert!(lock.is_held_for_another_thread(), "the outer hold is still in force");
    drop(outer);
    assert!(!lock.is_held_for_another_thread());
}

#[skuld::test]
fn a_lock_whose_holder_ended_without_releasing_it_is_taken_over() {
    let lock = StartTypeLock::scratch("abandoned");
    std::thread::scope(|s| {
        s.spawn(|| {
            // The thread ends holding it, as a process killed mid-retirement does.
            std::mem::forget(lock.acquire().expect("acquire"));
        })
        .join()
        .unwrap();
    });
    let held = lock
        .try_acquire()
        .expect("try")
        .expect("the dead holder's lock is free");
    drop(held);
}
