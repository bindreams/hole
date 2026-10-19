//! The lock around every decision `store`, `remove` and `move_aside` make, and
//! the backups they leave: each guard is proven with a real lock held from a
//! second handle, never with a delay.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};

use garter::test_utils::WaitableWriter;
use garter::tracing_test::set_default_in_current_thread;
use tempfile::{NamedTempFile, TempDir};

use super::{DefaultPlacement, Fs, Removal, StoreError, VersionedFile};
use crate::versioned_file::fixtures::{dir, names, put, unreadable_bytes, DecisionFile, OsRecordFile};
use crate::versioned_file::lock::Lock;
use crate::versioned_file::{sys, CannotRead, Loaded};

fn plain() -> DefaultPlacement {
    DefaultPlacement::default()
}

fn decision(value: &str) -> DecisionFile {
    DecisionFile {
        value: value.to_string(),
    }
}

/// Every call is the real one.
struct Real;

impl Fs for Real {}

fn lock_path(dir: &TempDir, state_file: &str) -> PathBuf {
    dir.path().join(format!("{state_file}.lock"))
}

fn read(dir: &TempDir, name: &str) -> Vec<u8> {
    std::fs::read(dir.path().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Everything in `dir`, lock files included.
fn all_names(dir: &TempDir) -> Vec<String> {
    let mut all: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    all.sort();
    all
}

// The lock is held across probe and act ===============================================================================

/// Records, at each call, whether the lock file is held by someone else's
/// handle: it is exactly when the caller holds it.
struct Probe {
    lock: PathBuf,
    sites: Mutex<Vec<(&'static str, bool)>>,
}

impl Probe {
    fn new(dir: &TempDir, state_file: &str) -> Arc<Self> {
        Arc::new(Self {
            lock: lock_path(dir, state_file),
            sites: Mutex::new(Vec::new()),
        })
    }

    fn visit(&self, site: &'static str) {
        let held = match File::open(&self.lock) {
            Ok(other_handle) => !sys::try_lock_exclusive(&other_handle).unwrap(),
            Err(_) => false,
        };
        self.sites.lock().unwrap().push((site, held));
    }

    fn sites(&self) -> Vec<(&'static str, bool)> {
        self.sites.lock().unwrap().clone()
    }
}

impl Fs for Probe {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.visit("read");
        std::fs::read(path)
    }

    fn hard_link(&self, original: &Path, link: &Path) -> io::Result<()> {
        self.visit("hard_link");
        std::fs::hard_link(original, link)
    }

    fn publish(&self, tmp: NamedTempFile, dest: &Path) -> io::Result<()> {
        self.visit("publish");
        sys::publish(tmp, dest)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        self.visit("remove_file");
        std::fs::remove_file(path)
    }

    fn rename_noreplace(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.visit("rename_noreplace");
        sys::rename_noreplace(from, to)
    }
}

#[skuld::test]
fn store_holds_the_lock_from_the_probe_to_the_publish() {
    let dir = dir();
    put(&dir, "decision.json", unreadable_bytes(CannotRead::Newer));
    let probe = Probe::new(&dir, "decision.json");

    VersionedFile::<DecisionFile>::with_fs(dir.path(), probe.clone())
        .store(&decision("new"), &plain())
        .unwrap();

    assert_eq!(
        probe.sites(),
        [("read", true), ("hard_link", true), ("publish", true)],
        "every step runs under the lock"
    );
}

#[skuld::test]
fn remove_holds_the_lock_from_the_probe_to_the_delete() {
    let dir = dir();
    put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);
    let probe = Probe::new(&dir, "decision.json");

    let removal = VersionedFile::<DecisionFile>::with_fs(dir.path(), probe.clone())
        .remove()
        .unwrap();

    assert_eq!(removal, Removal::Removed);
    assert_eq!(probe.sites(), [("read", true), ("remove_file", true)]);
}

#[skuld::test]
fn remove_that_moves_aside_holds_the_lock_throughout() {
    let dir = dir();
    put(&dir, "decision.json", unreadable_bytes(CannotRead::Corrupt));
    let probe = Probe::new(&dir, "decision.json");

    let removal = VersionedFile::<DecisionFile>::with_fs(dir.path(), probe.clone())
        .remove()
        .unwrap();

    assert!(matches!(removal, Removal::MovedAside(_)), "{removal:?}");
    assert_eq!(probe.sites(), [("read", true), ("rename_noreplace", true)]);
}

#[skuld::test]
fn move_aside_renames_under_the_lock_and_makes_no_link() {
    let dir = dir();
    put(&dir, "decision.json", unreadable_bytes(CannotRead::Newer));
    let probe = Probe::new(&dir, "decision.json");

    VersionedFile::<DecisionFile>::with_fs(dir.path(), probe.clone())
        .move_aside()
        .unwrap();

    assert_eq!(probe.sites(), [("rename_noreplace", true)]);
}

// A writer waits for the holder, then decides from what it left =======================================================

/// Tells the test the writer is about to wait for the lock, then really waits.
/// A writer that never asks for the lock drops the sender instead.
struct SignalsBeforeLocking(Mutex<Sender<()>>);

impl Fs for SignalsBeforeLocking {
    fn lock(&self, file: &File) -> io::Result<()> {
        self.0.lock().unwrap().send(()).unwrap();
        sys::lock_exclusive(file)
    }
}

/// Holds `state_file`'s lock, runs `op` on another thread, and once `op` has
/// asked for the lock calls `while_held` and releases it. What `op` returns
/// was therefore decided after `while_held`.
fn run_behind_the_lock<R: Send>(
    dir: &TempDir,
    state_file: &str,
    while_held: impl FnOnce(),
    op: impl FnOnce(Arc<dyn Fs>) -> R + Send,
) -> R {
    // The lock takes its access from a file that exists: any will do here.
    let reference_dir = crate::versioned_file::fixtures::dir();
    let reference = put(&reference_dir, "reference", b"");
    let held = Lock::acquire(&Real, &lock_path(dir, state_file), &reference).unwrap();
    std::thread::scope(|scope| {
        let (asked, waiting) = channel();
        let writer = scope.spawn(move || op(Arc::new(SignalsBeforeLocking(Mutex::new(asked)))));
        waiting.recv().expect("the writer finished without taking the lock");
        while_held();
        drop(held);
        writer.join().unwrap()
    })
}

#[skuld::test]
fn store_decides_from_the_file_the_lock_holder_left() {
    let dir = dir();
    let newer = unreadable_bytes(CannotRead::Newer);

    let result = run_behind_the_lock(
        &dir,
        "os-record.json",
        || {
            put(&dir, "os-record.json", newer);
        },
        |fs| {
            VersionedFile::<OsRecordFile>::with_fs(dir.path(), fs).store(
                &OsRecordFile {
                    value: "mine".to_string(),
                },
                &plain(),
            )
        },
    );

    assert!(
        matches!(
            result,
            Err(StoreError::Unreadable {
                cause: CannotRead::Newer,
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(
        read(&dir, "os-record.json"),
        newer,
        "a newer record is never overwritten"
    );
}

#[skuld::test]
fn remove_decides_from_the_file_the_lock_holder_left() {
    let dir = dir();
    let corrupt = unreadable_bytes(CannotRead::Corrupt);
    // There is a file when `remove` starts: it is what makes it wait.
    put(&dir, "os-record.json", br#"{"version":1,"value":"before"}"#);

    let result = run_behind_the_lock(
        &dir,
        "os-record.json",
        || {
            put(&dir, "os-record.json", corrupt);
        },
        |fs| VersionedFile::<OsRecordFile>::with_fs(dir.path(), fs).remove(),
    );

    assert_eq!(result.unwrap(), Removal::Kept);
    assert_eq!(
        read(&dir, "os-record.json"),
        corrupt,
        "a corrupt record is never deleted"
    );
}

#[skuld::test]
fn move_aside_moves_the_file_the_lock_holder_left() {
    let dir = dir();
    // There is a file when `move_aside` starts: it is what makes it wait.
    put(&dir, "decision.json", b"before");

    let result = run_behind_the_lock(
        &dir,
        "decision.json",
        || {
            put(&dir, "decision.json", b"written while the lock was held");
        },
        |fs| VersionedFile::<DecisionFile>::with_fs(dir.path(), fs).move_aside(),
    );

    let backup = result.unwrap().expect("a file to move");
    assert_eq!(std::fs::read(backup).unwrap(), b"written while the lock was held");
    assert!(matches!(
        VersionedFile::<DecisionFile>::new(dir.path()).load(),
        Loaded::Absent
    ));
}

// The lock file =======================================================================================================

#[skuld::test]
fn store_creates_the_lock_file_and_nothing_removes_it() {
    let dir = dir();
    let file = VersionedFile::<DecisionFile>::new(dir.path());

    file.store(&decision("v"), &plain()).unwrap();
    assert_eq!(all_names(&dir), ["decision.json", "decision.json.lock"]);
    assert_eq!(read(&dir, "decision.json.lock"), b"", "only ever locked");

    file.remove().unwrap();
    assert_eq!(all_names(&dir), ["decision.json.lock"]);

    file.store(&decision("again"), &plain()).unwrap();
    file.move_aside().unwrap();
    assert_eq!(
        all_names(&dir),
        ["decision.json.lock", "decision.json.unreadable.bak"],
        "move_aside leaves the lock file too"
    );
}

#[skuld::test]
fn remove_and_move_aside_take_an_existing_lock_without_a_placement() {
    // A file from before the lock existed: no lock file yet.
    let dir = dir();
    put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);

    assert_eq!(
        VersionedFile::<DecisionFile>::new(dir.path()).remove().unwrap(),
        Removal::Removed
    );
    assert_eq!(all_names(&dir), ["decision.json.lock"]);
}

#[skuld::test]
fn remove_and_move_aside_in_a_missing_directory_find_nothing_and_create_nothing() {
    let dir = dir();
    let missing = dir.path().join("not-there");
    let file = VersionedFile::<DecisionFile>::new(&missing);

    assert_eq!(file.remove().unwrap(), Removal::Absent);
    assert_eq!(file.move_aside().unwrap(), None);
    assert!(!missing.exists(), "a removal must not create the directory");
}

// Backups =============================================================================================================

fn capture() -> (impl tracing::Subscriber + Send + Sync, WaitableWriter) {
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .finish();
    (subscriber, writer)
}

struct FailsPublish;

impl Fs for FailsPublish {
    fn publish(&self, _tmp: NamedTempFile, _dest: &Path) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

/// A platform without a no-clobber rename, whose `remove_file` then fails.
struct NoRenameAndNoDelete;

impl Fs for NoRenameAndNoDelete {
    fn rename_noreplace(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn remove_file(&self, _path: &Path) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

struct NoRename;

impl Fs for NoRename {
    fn rename_noreplace(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[skuld::test]
fn a_backup_is_logged_even_when_the_publish_after_it_fails() {
    let (subscriber, log) = capture();
    let _guard = set_default_in_current_thread(subscriber);
    let dir = dir();
    put(&dir, "decision.json", unreadable_bytes(CannotRead::Newer));

    let result =
        VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(FailsPublish)).store(&decision("new"), &plain());

    assert!(result.is_err());
    let log = log.snapshot();
    assert_eq!(log.matches("backed up a state file").count(), 1, "{log}");
    assert!(log.contains("decision.json.unreadable.bak"), "{log}");
    assert!(
        names(&dir).contains(&"decision.json.unreadable.bak".to_string()),
        "a logged backup is kept, not cleaned up"
    );
}

#[skuld::test]
fn move_aside_logs_the_backup_it_makes() {
    let (subscriber, log) = capture();
    let _guard = set_default_in_current_thread(subscriber);
    let dir = dir();
    put(&dir, "decision.json", unreadable_bytes(CannotRead::Newer));

    VersionedFile::<DecisionFile>::new(dir.path()).move_aside().unwrap();

    let log = log.snapshot();
    assert_eq!(log.matches("moved a state file aside").count(), 1, "{log}");
    assert!(log.contains("decision.json.unreadable.bak"), "{log}");
}

#[skuld::test]
fn without_a_no_clobber_rename_move_aside_links_then_removes() {
    let dir = dir();
    let original = unreadable_bytes(CannotRead::Newer);
    put(&dir, "decision.json", original);

    let moved = VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(NoRename))
        .move_aside()
        .unwrap();

    let backup = moved.expect("a file to move");
    assert_eq!(backup, dir.path().join("decision.json.unreadable.bak"));
    assert_eq!(std::fs::read(&backup).unwrap(), original);
    assert_eq!(names(&dir), ["decision.json.unreadable.bak"]);
}

#[skuld::test]
fn a_failed_delete_after_the_link_leaves_a_logged_backup() {
    let (subscriber, log) = capture();
    let _guard = set_default_in_current_thread(subscriber);
    let dir = dir();
    let original = unreadable_bytes(CannotRead::Newer);
    put(&dir, "decision.json", original);

    let err = VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(NoRenameAndNoDelete))
        .move_aside()
        .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(read(&dir, "decision.json"), original, "the original is still there");
    assert_eq!(read(&dir, "decision.json.unreadable.bak"), original);
    assert!(
        log.snapshot().contains("decision.json.unreadable.bak"),
        "{}",
        log.snapshot()
    );
}
