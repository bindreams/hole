//! The generation and the path lock: what `observe` pairs, that every write attempt moves the generation exactly once, and where a failed read failed.

use std::ffi::OsStr;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::is_locked;
use crate::dir::ReadDir;
use crate::versioned_file::fixtures::{dir, names, put, ClaimFile, CoverFile, DecisionFile};
use crate::versioned_file::store::Fs;
use crate::versioned_file::{
    Change, DefaultPlacement, Loaded, StoreError, UnreadableKind, UpdateOutcome, VersionedFile,
};

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
fn generation_is_unchanged_by_keep() {
    let dir = dir();
    put(&dir, "claim.json", br#"{"version":99,"value":"theirs"}"#);
    let file = VersionedFile::<ClaimFile>::new(dir.path());
    let before = file.observe().generation;

    file.update(&plain(), |_| (Change::Keep, ())).unwrap();

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

// Moves once per write attempt ----------------------------------------------------------------------------------------

/// Each input moves the generation by exactly one, measured by two reads around the write.
fn moves_once<S: crate::versioned_file::VersionedState, R>(
    file: &VersionedFile<S>,
    place: &dyn crate::versioned_file::Placement,
    decide: impl FnOnce(&crate::versioned_file::Observed<S>) -> (Change<S>, R),
) -> Result<(R, crate::versioned_file::UpdateOutcome), StoreError> {
    let before = file.observe().generation;
    let result = file.update(place, decide);
    assert_eq!(file.observe().generation, before.next(), "{:?}", result.as_ref().err());
    result
}

#[skuld::test]
fn next_is_the_generation_after_one_write() {
    // A Store over an absent file.
    let absent = dir();
    let file = VersionedFile::<CoverFile>::new(absent.path());
    moves_once(&file, &plain(), |_| {
        (Change::Store(CoverFile { value: "v".into() }), ())
    })
    .unwrap();

    // A Store over a newer and over a corrupt record: the backup path, which links before it publishes.
    for bytes in [&br#"{"version":99,"value":"theirs"}"#[..], &b"{ not json"[..]] {
        let dir = dir();
        put(&dir, "cover.json", bytes);
        let file = VersionedFile::<CoverFile>::new(dir.path());
        moves_once(&file, &plain(), |_| {
            (Change::Store(CoverFile { value: "v".into() }), ())
        })
        .unwrap();
        assert!(
            names(&dir).iter().any(|n| n.ends_with(".bak")),
            "guard: the backup path ran"
        );
    }

    // A Remove over a current file.
    let current = dir();
    let file = VersionedFile::<DecisionFile>::new(current.path());
    store(&file, "a").unwrap();
    moves_once(&file, &plain(), |_| (Change::Remove, ())).unwrap();
}

#[skuld::test]
fn a_directory_that_cannot_be_opened_still_moves_the_generation() {
    let root = dir();
    let state = crate::dir::testing::state_dir_linked_to_a_system_folder(root.path());
    let file = VersionedFile::<DecisionFile>::new(&state);

    let result = moves_once(&file, &plain(), |_| (Change::Keep, ()));

    assert!(result.is_err(), "guard: the open failed");
}

#[skuld::test]
fn a_refused_store_moves_the_generation() {
    let dir = dir();
    put(&dir, "claim.json", br#"{"version":99,"value":"theirs"}"#);
    let file = VersionedFile::<ClaimFile>::new(dir.path());

    let refused = moves_once(&file, &plain(), |_| {
        (Change::Store(ClaimFile { value: "v".into() }), ())
    });

    assert!(matches!(refused, Err(StoreError::Unreadable { .. })), "{refused:?}");
}

#[skuld::test]
fn a_remove_over_a_missing_directory_moves_the_generation() {
    let root = dir();
    let file = VersionedFile::<DecisionFile>::new(&root.path().join("not-there"));

    let outcome = moves_once(&file, &plain(), |_| (Change::Remove, ())).unwrap();

    assert_eq!(outcome.1, UpdateOutcome::Absent);
}

#[skuld::test]
fn a_remove_the_role_keeps_moves_the_generation() {
    let dir = dir();
    put(&dir, "cover.json", br#"{"version":1,"value":"v"}"#);
    let file = VersionedFile::<CoverFile>::with_fs(dir.path(), Arc::new(DeniedRead));

    let outcome = moves_once(&file, &plain(), |_| (Change::Remove, ())).unwrap();

    assert_eq!(outcome.1, UpdateOutcome::Kept);
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

/// A read that fails and a name that is gone by the time it is examined: the file is not there.
struct VanishesAfterFailedRead {
    path: PathBuf,
}

impl Fs for VanishesAfterFailedRead {
    fn read(&self, _dir: &ReadDir, _name: &OsStr) -> io::Result<Vec<u8>> {
        std::fs::remove_file(&self.path).unwrap();
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

#[skuld::test]
fn observe_says_a_name_that_vanished_after_a_failed_read_is_absent() {
    let dir = dir();
    let path = put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);

    let observed =
        VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(VanishesAfterFailedRead { path })).observe();

    assert!(matches!(observed.loaded, Loaded::Absent), "{:?}", observed.loaded);
}

/// A read that fails and a name that cannot be examined.
struct CannotBeProbed;

impl Fs for CannotBeProbed {
    fn read(&self, _dir: &ReadDir, _name: &OsStr) -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }

    fn kind_of(&self, _dir: &ReadDir, _name: &OsStr) -> io::Result<Option<crate::dir::EntryKind>> {
        Err(io::Error::from(io::ErrorKind::TimedOut))
    }
}

#[skuld::test]
fn observe_says_a_name_that_cannot_be_examined_after_a_failed_read_is_unprobed() {
    let dir = dir();
    put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);

    let observed = VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(CannotBeProbed)).observe();

    assert_eq!(unreadable_kind(&observed.loaded), UnreadableKind::Unprobed);
}

#[skuld::test]
fn a_failed_probe_of_the_name_is_logged_with_its_kind() {
    let writer = garter::test_utils::WaitableWriter::new();
    let _guard = garter::tracing_test::set_default_in_current_thread(
        tracing_subscriber::fmt()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    );
    let dir = dir();
    put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);

    VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(CannotBeProbed)).observe();

    let log = writer.snapshot();
    assert_eq!(log.matches("DEBUG").count(), 1, "{log}");
    assert!(log.contains("TimedOut"), "{log}");
    assert!(log.contains("decision.json"), "{log}");
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
