//! The generation and the path lock: what `observe` pairs, what moves the generation, and where a failed read failed.

use std::ffi::OsStr;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::is_locked;
use crate::dir::ReadDir;
use crate::versioned_file::fixtures::{dir, put, ClaimFile, DecisionFile};
use crate::versioned_file::store::Fs;
use crate::versioned_file::{Change, DefaultPlacement, Loaded, StoreError, UnreadableKind, VersionedFile};

fn plain() -> DefaultPlacement {
    DefaultPlacement::default()
}

fn store(file: &VersionedFile<DecisionFile>, value: &str) -> Result<(), StoreError> {
    file.update(&plain(), |_| (Change::Store(DecisionFile { value: value.into() }), ()))
        .map(|_| ())
}

/// The publish never happens, as a rename that fails.
struct FailsPublish;

impl Fs for FailsPublish {
    fn publish(&self, _staged: crate::dir::Staged<'_>) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

#[skuld::test]
fn generation_moves_before_the_write_even_when_the_write_fails() {
    let dir = dir();
    let file = VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(FailsPublish));
    let before = file.observe().generation;

    assert!(store(&file, "v").is_err(), "guard: the write fails");

    assert_ne!(file.observe().generation, before);
}

#[skuld::test]
fn generation_moves_with_every_successful_write() {
    let dir = dir();
    let file = VersionedFile::<DecisionFile>::new(dir.path());
    let first = file.observe().generation;

    store(&file, "a").unwrap();
    let second = file.observe().generation;
    store(&file, "b").unwrap();
    let third = file.observe().generation;

    assert_ne!(first, second);
    assert_ne!(second, third);
    assert_ne!(first, third);
}

#[skuld::test]
fn generation_moves_for_a_remove_and_for_a_move_aside() {
    let dir = dir();
    let file = VersionedFile::<DecisionFile>::new(dir.path());
    store(&file, "a").unwrap();
    let stored = file.observe().generation;

    file.update(&plain(), |_| (Change::MoveAside, ())).unwrap();
    let moved = file.observe().generation;
    file.update(&plain(), |_| (Change::Remove, ())).unwrap();
    let removed = file.observe().generation;

    assert_ne!(stored, moved);
    assert_ne!(moved, removed);
}

#[skuld::test]
fn generation_is_unchanged_by_keep_and_by_a_refusal() {
    let dir = dir();
    put(&dir, "claim.json", br#"{"version":99,"value":"theirs"}"#);
    let file = VersionedFile::<ClaimFile>::new(dir.path());
    let before = file.observe().generation;

    file.update(&plain(), |_| (Change::Keep, ())).unwrap();
    let refused = file.update(&plain(), |_| (Change::Store(ClaimFile { value: "v".into() }), ()));

    assert!(matches!(refused, Err(StoreError::Unreadable { .. })), "{refused:?}");
    assert_eq!(file.observe().generation, before);
}

#[skuld::test]
fn two_handles_on_one_path_share_one_generation() {
    let dir = dir();
    let one = VersionedFile::<DecisionFile>::new(dir.path());
    let other = VersionedFile::<DecisionFile>::new(dir.path());
    let before = other.observe().generation;

    store(&one, "v").unwrap();

    assert_ne!(other.observe().generation, before);
    assert_eq!(other.observe().generation, one.observe().generation);
}

#[skuld::test]
fn two_paths_do_not_share_a_generation() {
    let (first, second) = (dir(), dir());
    let one = VersionedFile::<DecisionFile>::new(first.path());
    let other = VersionedFile::<DecisionFile>::new(second.path());
    let before = other.observe().generation;

    store(&one, "v").unwrap();

    assert_eq!(other.observe().generation, before);
}

/// Reads through the real vouched read, and records whether the path's lock was held at that moment.
struct ChecksLock {
    path: PathBuf,
    held: Arc<AtomicBool>,
}

impl Fs for ChecksLock {
    fn read(&self, dir: &ReadDir, name: &OsStr) -> io::Result<Vec<u8>> {
        self.held.store(is_locked(&self.path), Ordering::SeqCst);
        dir.read_vouched(name)
    }
}

/// A read outside the lock could pair old bytes with a generation bumped for a write not yet published.
#[skuld::test]
fn observe_reads_under_the_path_lock() {
    let dir = dir();
    let held = Arc::new(AtomicBool::new(false));
    let fs = ChecksLock {
        path: dir.path().join("decision.json"),
        held: held.clone(),
    };
    let file = VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(fs));
    store(&file, "v").unwrap();

    let observed = file.observe();

    assert!(
        matches!(observed.loaded, Loaded::Current { .. }),
        "guard: the read happened"
    );
    assert!(held.load(Ordering::SeqCst), "the file was read without its lock");
}

#[skuld::test]
fn update_reads_under_the_path_lock() {
    let dir = dir();
    let held = Arc::new(AtomicBool::new(false));
    let fs = ChecksLock {
        path: dir.path().join("decision.json"),
        held: held.clone(),
    };
    let file = VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(fs));
    store(&file, "v").unwrap();
    held.store(false, Ordering::SeqCst);

    file.update(&plain(), |_| (Change::Keep, ())).unwrap();

    assert!(held.load(Ordering::SeqCst), "the file was read without its lock");
}

#[cfg(debug_assertions)]
#[skuld::test]
fn a_reentrant_update_panics_in_debug() {
    let dir = dir();
    let file = VersionedFile::<DecisionFile>::new(dir.path());

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = file.update(&plain(), |_| {
            let _ = file.observe();
            (Change::Keep, ())
        });
    }));

    assert!(outcome.is_err(), "a decide that calls back in did not panic");
    // The panic poisoned the lock; the next user recovers it.
    store(&file, "after").unwrap();
}

#[skuld::test]
fn a_panicking_decide_leaves_the_file_usable() {
    let dir = dir();
    let file = VersionedFile::<DecisionFile>::new(dir.path());
    store(&file, "before").unwrap();

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = file.update(&plain(), |_| -> (Change<DecisionFile>, ()) { panic!("decide failed") });
    }));

    assert!(outcome.is_err(), "guard: decide panicked");
    assert!(matches!(
        file.observe().loaded,
        Loaded::Current { value: DecisionFile { ref value }, .. } if value == "before"
    ));
}

// Where a read failed -------------------------------------------------------------------------------------------------

fn unreadable_kind(loaded: &Loaded<DecisionFile>) -> UnreadableKind {
    match loaded {
        Loaded::Unreadable { kind, .. } => *kind,
        other => panic!("not an unreadable read: {other:?}"),
    }
}

#[skuld::test]
fn observe_says_the_directory_did_not_open() {
    let root = dir();
    let state = crate::dir::testing::state_dir_linked_to_a_system_folder(root.path());

    let observed = VersionedFile::<DecisionFile>::new(&state).observe();

    assert_eq!(unreadable_kind(&observed.loaded), UnreadableKind::Directory);
}

struct DeniedRead;

impl Fs for DeniedRead {
    fn read(&self, _dir: &ReadDir, _name: &OsStr) -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

#[skuld::test]
fn observe_says_a_regular_file_failed_to_read() {
    let dir = dir();
    put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);

    let observed = VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(DeniedRead)).observe();

    assert_eq!(unreadable_kind(&observed.loaded), UnreadableKind::File);
}

#[skuld::test]
fn observe_says_the_name_holds_something_that_is_not_a_file() {
    let dir = dir();
    std::fs::create_dir(dir.path().join("decision.json")).unwrap();

    let observed = VersionedFile::<DecisionFile>::new(dir.path()).observe();

    assert_eq!(unreadable_kind(&observed.loaded), UnreadableKind::NotAFile);
}

#[cfg(unix)]
#[skuld::test]
fn observe_says_a_fifo_at_the_name_is_not_a_file_and_does_not_wait() {
    use std::os::unix::ffi::OsStrExt;
    let dir = dir();
    let fifo = std::ffi::CString::new(dir.path().join("decision.json").as_os_str().as_bytes()).unwrap();
    // SAFETY: `fifo` is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let observed = VersionedFile::<DecisionFile>::new(dir.path()).observe();

    assert_eq!(unreadable_kind(&observed.loaded), UnreadableKind::NotAFile);
}

#[skuld::test]
fn observe_says_a_missing_directory_is_an_absent_file() {
    let root = dir();
    let file = VersionedFile::<DecisionFile>::new(&root.path().join("not-there"));

    assert!(matches!(file.observe().loaded, Loaded::Absent));
    assert!(!root.path().join("not-there").exists(), "a read made the directory");
}
