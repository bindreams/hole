use std::sync::Barrier;

use super::{Fs, Lock};
use crate::versioned_file::fixtures::{dir, put};

/// Every call is the real one.
struct Real;

impl Fs for Real {}

#[skuld::test]
fn a_lock_is_open_for_writing_whether_it_was_created_or_found() {
    let dir = dir();
    let state = put(&dir, "state.json", b"{}");
    let lock_path = dir.path().join("state.json.lock");

    let created = Lock::acquire(&Real, &lock_path, &state).unwrap();
    created.file.set_len(0).expect("a created lock is writable");
    drop(created);
    let found = Lock::acquire(&Real, &lock_path, &state).unwrap();
    found.file.set_len(0).expect("a found lock is writable");
}

#[skuld::test]
fn writers_racing_to_create_the_lock_all_get_it_and_leave_one_file() {
    const WRITERS: usize = 8;
    let dir = dir();
    let state = put(&dir, "state.json", b"{}");
    let lock_path = dir.path().join("state.json.lock");
    let start = Barrier::new(WRITERS);

    std::thread::scope(|scope| {
        let writers: Vec<_> = (0..WRITERS)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    drop(Lock::acquire(&Real, &lock_path, &state).unwrap());
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
    });

    let mut names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["state.json", "state.json.lock"], "no temp lock is left behind");
}
