//! `load` takes no exclusion: a reader that has the file open never makes a
//! `store` or a `move_aside` fail.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use super::{DefaultPlacement, Loaded, VersionedFile};
use crate::versioned_file::fixtures::{dir, OsRecordFile};

/// The writer's whole workload; the loader runs until the writer is done.
const STORES: usize = 1000;

/// `move_aside` claims the first free backup name by trying each in turn, so
/// its cost grows with the backups made: keep the workload small.
const MOVES: usize = 100;

fn record(n: usize) -> OsRecordFile {
    OsRecordFile { value: format!("v{n}") }
}

/// Runs `write` once per step of `steps` on this thread while another thread
/// loads the file in a loop, until `write` is done. Returns what `write`
/// collected, the number of loads, and the loads that were not `Current`.
fn while_loading<T>(file: &VersionedFile<OsRecordFile>, write: impl FnOnce() -> T) -> (T, usize, Vec<String>) {
    let written = AtomicBool::new(false);
    let (loading, loaded_once) = mpsc::channel();

    std::thread::scope(|scope| {
        let loader = scope.spawn(|| {
            let (mut loads, mut torn) = (0usize, Vec::new());
            while !written.load(Ordering::Acquire) {
                match file.load() {
                    Loaded::Current { .. } | Loaded::Absent => {}
                    other => torn.push(format!("{other:?}")),
                }
                loads += 1;
                // Only the first send is read; later ones find the receiver gone.
                let _ = loading.send(());
            }
            (loads, torn)
        });

        loaded_once.recv().expect("the loader has read once");
        let out = write();
        written.store(true, Ordering::Release);

        let (loads, torn) = loader.join().expect("the loader did not panic");
        (out, loads, torn)
    })
}

#[skuld::test]
fn a_concurrent_load_never_makes_a_store_fail() {
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
        "{} loads were not Current; first: {}",
        torn.len(),
        torn[0]
    );
}

#[skuld::test]
fn a_concurrent_load_never_makes_a_move_aside_fail() {
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
