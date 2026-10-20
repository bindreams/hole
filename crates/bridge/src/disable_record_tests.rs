use std::path::Path;

use super::*;

/// The record's file name, written out so that renaming it in the type is a
/// decision a test notices: an installed release reads it by this name.
const FILE: &str = "bridge-service-disabled.json";

fn write_bytes(dir: &Path, bytes: &[u8]) {
    std::fs::write(dir.join(FILE), bytes).expect("write the record by hand");
}

fn backups(dir: &Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .expect("read the state dir")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            name.starts_with(FILE) && name.ends_with(".bak")
        })
        .collect()
}

#[skuld::test]
fn a_written_record_reads_present_and_a_cleared_one_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert_eq!(record_state(dir.path()), RecordState::Absent);

    write(dir.path()).expect("write");
    assert_eq!(record_state(dir.path()), RecordState::Present);
    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join(FILE)).expect("the file")).expect("JSON");
    assert_eq!(on_disk, serde_json::json!({"version": 1}));

    clear(dir.path()).expect("clear");
    assert_eq!(record_state(dir.path()), RecordState::Absent);
    assert!(!dir.path().join(FILE).exists());
}

#[skuld::test]
fn clearing_an_absent_record_is_ok() {
    let dir = tempfile::tempdir().expect("tempdir");
    clear(dir.path()).expect("nothing to clear is not a failure");
    assert_eq!(record_state(dir.path()), RecordState::Absent);
}

/// Only a Hole release writes the state dir, so a file that is there but not
/// readable is still the record: reading it as absent would word a service
/// the uninstall disabled as an administrator's.
#[skuld::test]
fn a_corrupt_or_newer_record_reads_present() {
    for bytes in [
        &b"this is not json"[..],
        &b""[..],
        &br#"{"version": 2}"#[..],
        &br#"{"version": 99999999999999}"#[..],
        &br#"{"version": 0}"#[..],
        &br#"["version", 1]"#[..],
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        write_bytes(dir.path(), bytes);
        assert_eq!(
            record_state(dir.path()),
            RecordState::Present,
            "{}",
            String::from_utf8_lossy(bytes)
        );
    }
}

/// A directory at the file's path fails the read with an OS error. Like a file
/// that cannot be interpreted, it is the record's place and counts as present,
/// so no elevated path fails on it: the write that follows replaces it.
#[skuld::test]
fn a_read_that_fails_with_an_io_error_reads_present() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join(FILE)).expect("a directory where the file goes");
    assert_eq!(record_state(dir.path()), RecordState::Present);
}

#[skuld::test]
fn writing_over_a_corrupt_record_backs_it_up_and_replaces_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_bytes(dir.path(), b"this is not json");

    write(dir.path()).expect("a corrupt record never blocks a write");

    let saved = backups(dir.path());
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert_eq!(std::fs::read(&saved[0]).expect("the backup"), b"this is not json");
    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join(FILE)).expect("the file")).expect("JSON");
    assert_eq!(on_disk, serde_json::json!({"version": 1}));
}

#[skuld::test]
fn clearing_a_corrupt_record_moves_it_aside_and_reads_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_bytes(dir.path(), br#"{"version": 2}"#);

    clear(dir.path()).expect("a newer record never blocks a clear");

    assert_eq!(record_state(dir.path()), RecordState::Absent);
    let saved = backups(dir.path());
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert_eq!(std::fs::read(&saved[0]).expect("the backup"), br#"{"version": 2}"#);
}

#[skuld::test]
fn disabled_by_is_decided_on_the_record_alone() {
    assert_eq!(DisabledBy::of(RecordState::Present), DisabledBy::InterruptedUninstall);
    assert_eq!(DisabledBy::of(RecordState::Absent), DisabledBy::Elsewhere);
}
