//! The backups `store`, `remove` and `move_aside` leave, and what they do when
//! a rename or a delete is refused.

use std::io;
use std::path::Path;
use std::sync::Arc;

use garter::test_utils::WaitableWriter;
use garter::tracing_test::set_default_in_current_thread;
use tempfile::NamedTempFile;

use super::{DefaultPlacement, Fs, Removal, VersionedFile};
use crate::versioned_file::fixtures::{dir, names, put, unreadable_bytes, DecisionFile};
use crate::versioned_file::CannotRead;

fn plain() -> DefaultPlacement {
    DefaultPlacement::default()
}

fn decision(value: &str) -> DecisionFile {
    DecisionFile {
        value: value.to_string(),
    }
}

fn read(dir: &tempfile::TempDir, name: &str) -> Vec<u8> {
    std::fs::read(dir.path().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
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

/// A refusal of the rename itself, as a sticky directory or a security module
/// answers it. Not "unavailable": a link made instead would be allowed where
/// the rename was not, and would leave a backup beside a file that stays.
struct RenameRefused;

impl Fs for RenameRefused {
    fn rename_noreplace(&self, _from: &Path, _to: &Path) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

#[skuld::test]
fn a_refused_rename_fails_move_aside_and_leaves_no_backup() {
    let dir = dir();
    let original = unreadable_bytes(CannotRead::Newer);
    put(&dir, "decision.json", original);

    let err = VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(RenameRefused))
        .move_aside()
        .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(read(&dir, "decision.json"), original, "the original is still there");
    assert_eq!(names(&dir), ["decision.json"], "no backup");
}

#[skuld::test]
fn a_refused_rename_fails_remove_and_leaves_no_backup() {
    let dir = dir();
    let original = unreadable_bytes(CannotRead::Newer);
    put(&dir, "decision.json", original);

    let err = VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(RenameRefused))
        .remove()
        .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(read(&dir, "decision.json"), original, "the original is still there");
    assert_eq!(names(&dir), ["decision.json"], "no backup");
}
