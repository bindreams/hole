use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Barrier};

use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

use super::*;
use crate::disable_record::{ChangeMark, Changer, ScratchChangeKey};

/// The change mark's value name, written out so that renaming it is a decision.
const MARK_VALUE: &str = "HoleChangeMark";

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

// The change mark -----------------------------------------------------------------------------------------------------

/// A lock of the test's own that sets the mark in a scratch key.
fn marking(test: &str) -> (StartTypeLock, ScratchChangeKey) {
    let (scratch, _key) = ScratchChangeKey::created(test);
    let lock = StartTypeLock::scratch_marking(test, scratch.mark());
    (lock, scratch)
}

fn holder_of_the_mark(scratch: &ScratchChangeKey) -> Option<Changer> {
    scratch.mark().read().holder()
}

/// A reader of the mark that sees no holder must be able to trust that no
/// change runs: the mark names this process from the moment the lock is taken
/// to the moment it is let go.
#[skuld::test]
fn holding_the_lock_marks_a_change_in_progress_until_it_is_let_go() {
    let (lock, scratch) = marking("marks");
    assert_eq!(holder_of_the_mark(&scratch), None);
    let held = lock.acquire().expect("acquire");
    assert_eq!(
        holder_of_the_mark(&scratch),
        Some(Changer::Running),
        "this process holds it"
    );
    drop(held);
    assert_eq!(holder_of_the_mark(&scratch), None, "let go");
}

/// A reinstall deletes the service's key, and the mark with it, and registers a
/// new key with none: between the registration and the end of the change a
/// reader would see no change, and no record. The change marks the new key
/// again as soon as it exists, and still ends it when the hold is let go.
#[skuld::test]
fn a_key_made_during_a_change_is_marked_again_and_the_change_still_ends() {
    let (scratch, key) = ScratchChangeKey::created("reinstall");
    let lock = StartTypeLock::scratch_marking("reinstall", scratch.mark());
    let held = lock.acquire().expect("acquire");
    assert_eq!(holder_of_the_mark(&scratch), Some(Changer::Running));

    key.remove_value(MARK_VALUE)
        .expect("the old key's mark goes with the old key");
    assert_eq!(
        scratch.mark().read(),
        ChangeMark::new(None, None),
        "the new key has no mark"
    );

    held.mark_again();
    assert_eq!(
        holder_of_the_mark(&scratch),
        Some(Changer::Running),
        "the new key names the change"
    );

    drop(held);
    assert_eq!(holder_of_the_mark(&scratch), None, "let go");
}

/// The thread that holds the lock takes it again for each step of a change; the
/// first hold is the change, and the mark stays until it is let go.
#[skuld::test]
fn a_nested_hold_leaves_the_mark_until_the_outermost_is_let_go() {
    let (lock, scratch) = marking("nested");
    let outer = lock.acquire().expect("acquire");
    let at_the_outer = scratch.mark().read();
    let inner = lock.acquire().expect("acquire again");
    let tried = lock.try_acquire().expect("try").expect("this thread holds it");
    assert_eq!(scratch.mark().read(), at_the_outer, "taking it again is no transition");
    drop(tried);
    drop(inner);
    assert_eq!(scratch.mark().read(), at_the_outer, "an inner let-go is no transition");
    assert_eq!(holder_of_the_mark(&scratch), Some(Changer::Running));
    drop(outer);
    assert_eq!(holder_of_the_mark(&scratch), None);
    assert_ne!(scratch.mark().read(), at_the_outer);
}

/// A thread that does not get the lock changes nothing, and one that waits
/// marks nothing until it has it.
#[skuld::test]
fn a_thread_that_does_not_hold_the_lock_leaves_the_mark_alone() {
    let (lock, scratch) = marking("others");
    let held = lock.acquire().expect("acquire");
    let at_the_hold = scratch.mark().read();
    assert!(lock.is_held_for_another_thread());
    assert_eq!(scratch.mark().read(), at_the_hold, "a failed try is no transition");

    let (tx, rx) = mpsc::channel();
    std::thread::scope(|s| {
        let waiter = s.spawn(|| {
            let acquired = lock
                .acquire_noting_wait(move || tx.send(()).unwrap())
                .expect("the waiter acquired");
            drop(acquired);
        });
        rx.recv().expect("the waiter ended without waiting");
        assert_eq!(scratch.mark().read(), at_the_hold, "waiting is no transition");
        drop(held);
        waiter.join().expect("the waiter");
    });
    assert_eq!(holder_of_the_mark(&scratch), None);
}

/// Each hold, by whichever thread, is a begin and an end.
#[skuld::test]
fn every_hold_by_every_thread_changes_the_mark_twice() {
    let (lock, scratch) = marking("counted");
    for _ in 0..2 {
        drop(lock.acquire().expect("acquire"));
        std::thread::scope(|s| {
            s.spawn(|| drop(lock.acquire().expect("acquire")))
                .join()
                .expect("the thread");
        });
    }
    let raw = scratch.mark().read();
    assert_eq!(raw, ChangeMark::new(Some("8".to_string()), None));
}

/// No service yet (the first install): there is no key to mark, and the hold
/// is taken all the same.
#[skuld::test]
fn a_lock_over_no_key_is_taken_without_a_mark() {
    let scratch = ScratchChangeKey::named("no-key");
    let lock = StartTypeLock::scratch_marking("no-key", scratch.mark());
    drop(lock.acquire().expect("acquire"));
    assert!(!scratch.exists(), "no key was made");
}

/// A caller who is inside the boundary but not in the namespace's DACL cannot
/// put the lock's mutex there, so it cannot squat the name before the first
/// Hole process: opening a namespace is not checked against the DACL (measured:
/// an open from another alias succeeds), making an object in it is. SYSTEM
/// alone is in the DACL, and no test runs as SYSTEM.
#[skuld::test]
fn a_caller_the_namespace_dacl_leaves_out_cannot_make_the_mutex_in_it() {
    let name = format!("hole-test-{}-dacl", std::process::id());
    let lock = StartTypeLock::at(&name, "WD", &name, Some("D:(A;;GA;;;SY)"), None);
    let refused = lock.acquire().err().expect("the DACL leaves the caller out");
    assert_eq!(
        refused.raw_os_error(),
        Some(ERROR_ACCESS_DENIED.0 as i32),
        "making the mutex in a namespace whose DACL names only SYSTEM: {refused}"
    );
}
