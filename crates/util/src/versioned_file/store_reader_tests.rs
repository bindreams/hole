//! A reader that takes no lock never makes a `store` or a `move_aside` fail, and is never told the file is unreadable
//! by the replace. `Absent` is accepted because, on Windows, a read inside a replace can answer it for a file that
//! exists.
//!
//! These are smoke tests: the loader races the writer and meets a replace only by chance. A read of a delete-pending
//! file is pinned in `dir::windows::status_tests`, and a file with no name in `dir_tests` and `dir::trail_tests`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use super::{DefaultPlacement, VersionedFile};
use crate::dir::ReadDir;
use crate::versioned_file::fixtures::{dir, OsRecordFile, UpdateShortcuts};
use crate::versioned_file::Loaded;

/// The writer's whole workload; the loader runs until the writer is done.
const STORES: usize = 1000;

/// `move_aside` claims the first free backup name by trying each in turn, so
/// its cost grows with the backups made: keep the workload small.
const MOVES: usize = 100;

fn record(n: usize) -> OsRecordFile {
    OsRecordFile { value: format!("v{n}") }
}

/// Runs `write` on this thread while another thread reads the file in a loop
/// without the in-process lock, until `write` is done. Returns what `write`
/// collected, the number of loads, and the loads that were neither `Current` nor `Absent`.
fn while_loading<T>(file: &VersionedFile<OsRecordFile>, write: impl FnOnce() -> T) -> (T, usize, Vec<String>) {
    /// Sets the flag when dropped, so a panicking `write` still stops the loader.
    struct Done<'a>(&'a AtomicBool);

    impl Drop for Done<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let written = AtomicBool::new(false);
    let (loading, loaded_once) = mpsc::sync_channel(1);

    std::thread::scope(|scope| {
        let written = &written;
        // `move`: a loader that panics drops `loading`, so `recv` below fails
        // the test instead of waiting for a first load that never comes.
        let loader = scope.spawn(move || {
            let reader = ReadDir::open(&file.dir).expect("the directory opens");
            let (mut loads, mut torn) = (0usize, Vec::new());
            while !written.load(Ordering::Acquire) {
                match file.read_through(&reader) {
                    Loaded::Current { .. } | Loaded::Absent => {}
                    other => torn.push(format!("{other:?}")),
                }
                loads += 1;
                // Only the first send is read; a full queue drops the rest.
                let _ = loading.try_send(());
            }
            (loads, torn)
        });

        loaded_once.recv().expect("the loader has read once");
        let done = Done(written);
        let out = write();
        drop(done);

        let (loads, torn) = loader.join().expect("the loader did not panic");
        (out, loads, torn)
    })
}

/// Reads through `read_vouched`, as every state file does, so the vouch runs against the replace.
#[skuld::test]
fn an_unlocked_reader_never_makes_a_store_fail() {
    let dir = dir();
    let file = VersionedFile::<OsRecordFile>::new(dir.path());
    file.store(&record(0), &DefaultPlacement::default()).unwrap();

    let (store_errors, loads, torn) = while_loading(&file, || {
        (1..=STORES)
            .filter_map(|n| file.store(&record(n), &DefaultPlacement::default()).err())
            .map(|e| format!("{e:?}"))
            .collect::<Vec<_>>()
    });

    assert!(loads > 0, "guard: the loader ran");
    assert!(
        store_errors.is_empty(),
        "{} of {STORES} stores failed while a load was running; first: {}",
        store_errors.len(),
        store_errors[0]
    );
    assert!(
        torn.is_empty(),
        "{} loads were neither Current nor Absent; first: {}",
        torn.len(),
        torn[0]
    );
}

#[skuld::test]
fn an_unlocked_reader_never_makes_a_move_aside_fail() {
    let dir = dir();
    let file = VersionedFile::<OsRecordFile>::new(dir.path());

    let (move_errors, loads, torn) = while_loading(&file, || {
        let mut errors = Vec::new();
        for n in 1..=MOVES {
            file.store(&record(n), &DefaultPlacement::default()).unwrap();
            match file.move_aside() {
                Ok(Some(_)) => {}
                other => errors.push(format!("{other:?}")),
            }
        }
        errors
    });

    assert!(loads > 0, "guard: the loader ran");
    assert!(
        move_errors.is_empty(),
        "{} of {MOVES} move_asides failed while a load was running; first: {}",
        move_errors.len(),
        move_errors[0]
    );
    assert!(
        torn.is_empty(),
        "{} loads were not Current or Absent; first: {}",
        torn.len(),
        torn[0]
    );
}
