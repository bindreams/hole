use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Barrier};

use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

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
                .acquire_noting_wait(move || tx.send(()).unwrap())
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

/// The boundary is what keeps a caller who is not in it from creating,
/// opening or waiting on the lock. SYSTEM's SID is in no user's token, an
/// elevated administrator's included.
#[skuld::test]
fn a_lock_whose_boundary_the_caller_is_outside_of_can_be_neither_taken_nor_tried() {
    let lock = StartTypeLock::scratch_within("outside", "SY");
    let taken = lock.acquire().err().expect("the caller is outside the boundary");
    assert_eq!(taken.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{taken}");
    let tried = lock.try_acquire().err().expect("the caller is outside the boundary");
    assert_eq!(tried.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32), "{tried}");
}

/// Two threads that take a lock for the first time in this process meet one
/// namespace, not two, and then take the lock in turn.
#[skuld::test]
fn two_threads_taking_a_fresh_lock_at_once_both_get_it_in_turn() {
    let lock = StartTypeLock::scratch("first-use");
    let barrier = Barrier::new(2);
    let inside = AtomicBool::new(false);
    std::thread::scope(|s| {
        let both: Vec<_> = (0..2)
            .map(|_| {
                s.spawn(|| {
                    barrier.wait();
                    let held = lock.acquire().expect("acquire");
                    assert!(
                        !inside.swap(true, Ordering::SeqCst),
                        "both threads were inside the lock at once"
                    );
                    inside.store(false, Ordering::SeqCst);
                    drop(held);
                })
            })
            .collect();
        for thread in both {
            thread.join().expect("a thread that took the lock");
        }
    });
}

/// A namespace another process made is opened, not made again: the second
/// process finds it by the same boundary under an alias of its own.
#[skuld::test]
fn a_namespace_that_another_process_already_made_is_opened() {
    let lock = StartTypeLock::scratch("made-elsewhere");
    lock.make_the_namespace_under_another_alias();
    let held = lock.acquire().expect("the namespace exists; this opens it");
    assert!(lock.is_held_for_another_thread());
    drop(held);
}

/// The namespace is named by its boundary as a whole, SIDs included: a caller
/// who makes a namespace of the same boundary name with a SID of their own
/// makes another namespace, and does not stand between us and ours.
#[skuld::test]
fn a_boundary_of_the_same_name_but_another_sid_is_another_namespace() {
    let ours = StartTypeLock::scratch("squat-ours");
    let squatter = ours.with_the_same_boundary_name_within("AU");
    let squatting = squatter.acquire().expect("the squatter is in its own boundary");
    let held = ours
        .try_acquire()
        .expect("try")
        .expect("the squatter's lock is not ours");
    drop((squatting, held));
}
