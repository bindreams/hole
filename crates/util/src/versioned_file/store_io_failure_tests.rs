//! `store` and `remove` over a file whose read failed with an I/O error. The
//! bytes were never seen, so nothing may destroy them: a role that keeps a
//! file it cannot read refuses or keeps, and one that replaces it links the old
//! bytes aside first. The seam fails the read while the file stays readable on
//! disk, so each test can compare what is left with what was there.

use std::io;
use std::sync::Arc;

use garter::test_utils::WaitableWriter;
use garter::tracing_test::set_default_in_current_thread;

use super::{DefaultPlacement, Fs, Removal, StoreError, VersionedFile};
use crate::versioned_file::fixtures::{dir, names, put, ConfigFile, DecisionFile, LegacyRecordFile, OsRecordFile};
use crate::versioned_file::VersionedState;

const ORIGINAL: &[u8] = b"bytes nobody could read: hunter2";

/// Every read fails, as a file the caller may not open.
struct DeniedRead;

impl Fs for DeniedRead {
    fn read(&self, _dir: &crate::dir::Dir, _name: &std::ffi::OsStr) -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

/// Every read and every backup link fails.
struct DeniedReadAndLink;

impl Fs for DeniedReadAndLink {
    fn read(&self, _dir: &crate::dir::Dir, _name: &std::ffi::OsStr) -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }

    fn hard_link(
        &self,
        _dir: &crate::dir::Dir,
        _original: &std::ffi::OsStr,
        _link: &std::ffi::OsStr,
    ) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

fn plain() -> DefaultPlacement {
    DefaultPlacement::default()
}

fn capture() -> (impl tracing::Subscriber + Send + Sync, WaitableWriter) {
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .finish();
    (subscriber, writer)
}

/// A file of `S` holding `ORIGINAL` that `fs` cannot read.
fn unreadable<S: VersionedState>(fs: Arc<dyn Fs>) -> (tempfile::TempDir, VersionedFile<S>) {
    let dir = dir();
    put(&dir, S::FILE_NAME, ORIGINAL);
    let file = VersionedFile::<S>::with_fs(dir.path(), fs);
    (dir, file)
}

fn bytes_of(dir: &tempfile::TempDir, name: &str) -> Vec<u8> {
    std::fs::read(dir.path().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

// A role that keeps what it cannot read ===============================================================================

fn store_refuses<S: VersionedState>(value: S) {
    let (dir, file) = unreadable::<S>(Arc::new(DeniedRead));

    let err = file.store(&value, &plain()).unwrap_err();

    match &err {
        StoreError::ReadFailed { path, kind } => {
            assert_eq!(path, file.path(), "{}", S::FILE_NAME);
            assert_eq!(*kind, io::ErrorKind::PermissionDenied);
        }
        other => panic!("{}: {other:?}", S::FILE_NAME),
    }
    assert!(err.to_string().contains("could not be read"), "{err}");
    assert_eq!(bytes_of(&dir, S::FILE_NAME), ORIGINAL, "the file is untouched");
    assert_eq!(names(&dir), [S::FILE_NAME], "no temp file, no backup");
}

#[skuld::test]
fn an_os_record_store_refuses_over_an_io_failed_probe() {
    store_refuses(OsRecordFile { value: "v".into() });
}

#[skuld::test]
fn a_legacy_record_store_refuses_over_an_io_failed_probe() {
    store_refuses(LegacyRecordFile { value: "v".into() });
}

fn remove_keeps<S: VersionedState>() {
    let (dir, file) = unreadable::<S>(Arc::new(DeniedRead));

    assert_eq!(file.remove().unwrap(), Removal::Kept, "{}", S::FILE_NAME);

    assert_eq!(bytes_of(&dir, S::FILE_NAME), ORIGINAL);
    assert_eq!(names(&dir), [S::FILE_NAME]);
}

#[skuld::test]
fn an_os_record_remove_keeps_an_io_failed_file() {
    remove_keeps::<OsRecordFile>();
}

#[skuld::test]
fn a_legacy_record_remove_keeps_an_io_failed_file() {
    remove_keeps::<LegacyRecordFile>();
}

// A role that replaces it, after a backup =============================================================================

fn store_links_aside_then_writes<S: VersionedState>(value: S) {
    let (subscriber, log) = capture();
    let _guard = set_default_in_current_thread(subscriber);
    let (dir, file) = unreadable::<S>(Arc::new(DeniedRead));
    let backup = format!("{}.unreadable.bak", S::FILE_NAME);

    file.store(&value, &plain()).unwrap();

    assert_eq!(
        bytes_of(&dir, &backup),
        ORIGINAL,
        "{}: the old bytes are kept",
        S::FILE_NAME
    );
    let written = String::from_utf8(bytes_of(&dir, S::FILE_NAME)).unwrap();
    assert!(written.contains("\"new\""), "{written}");
    assert_eq!(names(&dir), [S::FILE_NAME.to_string(), backup.clone()]);
    let log = log.snapshot();
    assert_eq!(log.matches("backed up a state file").count(), 1, "{log}");
    assert!(log.contains(&backup), "{log}");
}

#[skuld::test]
fn a_decision_store_links_an_io_failed_file_aside_then_writes() {
    store_links_aside_then_writes(DecisionFile { value: "new".into() });
}

#[skuld::test]
fn a_config_store_links_an_io_failed_file_aside_then_writes() {
    store_links_aside_then_writes(ConfigFile { value: "new".into() });
}

fn store_fails_when_the_backup_link_fails<S: VersionedState>(value: S) {
    let (dir, file) = unreadable::<S>(Arc::new(DeniedReadAndLink));

    let err = file.store(&value, &plain()).unwrap_err();

    assert!(matches!(err, StoreError::Io(_)), "{}: {err:?}", S::FILE_NAME);
    assert_eq!(bytes_of(&dir, S::FILE_NAME), ORIGINAL, "the original stays");
    assert_eq!(names(&dir), [S::FILE_NAME], "no temp file, no backup");
}

#[skuld::test]
fn a_decision_store_fails_and_keeps_the_file_when_the_backup_link_fails() {
    store_fails_when_the_backup_link_fails(DecisionFile { value: "new".into() });
}

#[skuld::test]
fn a_config_store_fails_and_keeps_the_file_when_the_backup_link_fails() {
    store_fails_when_the_backup_link_fails(ConfigFile { value: "new".into() });
}

fn remove_moves_aside<S: VersionedState>() {
    let (subscriber, log) = capture();
    let _guard = set_default_in_current_thread(subscriber);
    let (dir, file) = unreadable::<S>(Arc::new(DeniedRead));
    let backup = format!("{}.unreadable.bak", S::FILE_NAME);

    assert_eq!(
        file.remove().unwrap(),
        Removal::MovedAside(dir.path().join(&backup)),
        "{}",
        S::FILE_NAME
    );

    assert_eq!(bytes_of(&dir, &backup), ORIGINAL);
    assert_eq!(names(&dir), std::slice::from_ref(&backup), "moved, not deleted");
    let log = log.snapshot();
    assert_eq!(log.matches("moved a state file aside").count(), 1, "{log}");
    assert!(log.contains(&backup), "{log}");
}

#[skuld::test]
fn a_decision_remove_moves_an_io_failed_file_aside() {
    remove_moves_aside::<DecisionFile>();
}

#[skuld::test]
fn a_config_remove_moves_an_io_failed_file_aside() {
    remove_moves_aside::<ConfigFile>();
}
