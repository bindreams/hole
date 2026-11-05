use super::*;
use std::path::PathBuf;
use util::versioned_file::UpdateOutcome;

use super::super::StateFile;

fn sample(token: &str) -> FailClosedState {
    FailClosedState {
        pf_token: token.into(),
        pf_was_enabled: true,
    }
}

fn write_raw(dir: &Path, bytes: &[u8]) {
    std::fs::write(dir.join(STATE_FILE_NAME), bytes).unwrap();
}

fn backup_of(dir: &Path) -> PathBuf {
    dir.join(format!("{STATE_FILE_NAME}.unreadable.bak"))
}

#[skuld::test]
fn save_then_load_roundtrips() {
    let tmp = tempfile::tempdir().unwrap();
    let st = sample("1234567890");
    save(tmp.path(), &st, None).unwrap();
    assert_eq!(load(tmp.path()), Some(st));
}

/// The bytes a save leaves are what the previous release reads: its `version` first, the same two fields, and
/// nothing else.
#[skuld::test]
fn what_a_save_writes_has_the_previous_releases_shape() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample("5"), None).unwrap();

    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tmp.path().join(STATE_FILE_NAME)).unwrap()).unwrap();

    assert_eq!(
        written,
        serde_json::json!({"version": 1, "pf_token": "5", "pf_was_enabled": true})
    );
}

/// A file written by the previous release, whose `pf_was_enabled` was a bare
/// `bool`, reads unchanged.
///
/// Driven from BYTES, not from `save`, and the version is the LITERAL `1`: the claim is about files already on disk,
/// which carry the version they were written at. The opposite direction (what this binary writes, read by the
/// previous release) is `macos_tests::what_an_engage_persists_parses_under_the_previous_releases_schema`.
#[skuld::test]
fn load_reads_an_older_files_bare_bool_pf_was_enabled() {
    for written in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let older = format!(r#"{{"version":1,"pf_token":"5","pf_was_enabled":{written}}}"#);
        write_raw(tmp.path(), older.as_bytes());
        assert_eq!(
            load(tmp.path()),
            Some(FailClosedState {
                pf_token: "5".into(),
                pf_was_enabled: written,
            }),
            "a record already on disk at schema 1 must read unchanged: {older}"
        );
    }
}

#[skuld::test]
fn load_absent_is_none() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(load(tmp.path()), None);
}

#[skuld::test]
fn load_rejects_schema_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(tmp.path(), br#"{"version":2,"pf_token":"1","pf_was_enabled":false}"#);
    assert_eq!(load(tmp.path()), None, "future schema must be discarded");
}

/// A record from a newer release is unusable to this one, and its token is the only copy of the `pfctl -E` ticket.
#[skuld::test]
fn a_stateless_unusable_record_salvages_its_token_from_a_newer_record() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(
        tmp.path(),
        br#"{"version":2,"pf_token":"7","pf_was_enabled":false,"later":{"a":1}}"#,
    );

    let found = load_presence(tmp.path());

    assert!(
        matches!(&found, StateFile::Unusable { pf_token: Some(t) } if t == "7"),
        "{found:?}"
    );
}

#[skuld::test]
fn an_unknown_field_does_not_make_the_record_unusable() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(
        tmp.path(),
        br#"{"version":1,"pf_token":"7","pf_was_enabled":false,"stray":true}"#,
    );

    assert_eq!(
        load(tmp.path()),
        Some(FailClosedState {
            pf_token: "7".into(),
            pf_was_enabled: false,
        })
    );
}

#[skuld::test]
fn save_over_a_corrupt_pf_record_keeps_a_backup() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(tmp.path(), b"{not json");

    save(tmp.path(), &sample("9"), None).unwrap();

    assert_eq!(load(tmp.path()), Some(sample("9")));
    assert_eq!(std::fs::read(backup_of(tmp.path())).unwrap(), b"{not json");
}

#[skuld::test]
fn save_over_a_newer_pf_record_keeps_a_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let newer: &[u8] = br#"{"version":2,"pf_token":"3","pf_was_enabled":true}"#;
    write_raw(tmp.path(), newer);

    save(tmp.path(), &sample("9"), None).unwrap();

    assert_eq!(load(tmp.path()), Some(sample("9")));
    assert_eq!(std::fs::read(backup_of(tmp.path())).unwrap(), newer);
}

#[skuld::test]
fn clear_moves_a_corrupt_or_newer_pf_record_aside() {
    let cases: [(&str, &[u8]); 2] = [
        ("corrupt", b"{not json"),
        ("newer", br#"{"version":2,"pf_token":"3","pf_was_enabled":true}"#),
    ];
    for (what, bytes) in cases {
        let tmp = tempfile::tempdir().unwrap();
        write_raw(tmp.path(), bytes);

        let outcome = clear(tmp.path()).unwrap();

        assert!(matches!(outcome, UpdateOutcome::MovedAside(_)), "{what}: {outcome:?}");
        assert!(!tmp.path().join(STATE_FILE_NAME).exists(), "{what}");
        assert_eq!(std::fs::read(backup_of(tmp.path())).unwrap(), bytes, "{what}");
    }
}

#[skuld::test]
fn clear_keeps_a_pf_record_whose_read_failed() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join(STATE_FILE_NAME)).unwrap();

    let outcome = clear(tmp.path()).unwrap();

    assert!(matches!(outcome, UpdateOutcome::Kept), "{outcome:?}");
    assert!(tmp.path().join(STATE_FILE_NAME).is_dir());
    assert!(!backup_of(tmp.path()).exists());
}

#[skuld::test]
fn clear_refuses_a_state_dir_that_is_a_users_link_to_a_system_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let state = util::dir::testing::state_dir_linked_to_a_system_folder(tmp.path());

    let err = clear(&state).unwrap_err();

    let util::versioned_file::StoreError::Io(err) = err else {
        panic!("expected an I/O refusal, got {err:?}");
    };
    assert_eq!(util::dir::Refusal::from_error(&err), Some(&util::dir::Refusal::Symlink));
}

#[skuld::test]
fn clear_removes_file_and_tolerates_absence() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample("9"), None).unwrap();
    assert!(tmp.path().join(STATE_FILE_NAME).exists());

    assert!(matches!(clear(tmp.path()).unwrap(), UpdateOutcome::Removed));
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    assert!(matches!(clear(tmp.path()).unwrap(), UpdateOutcome::Absent)); // a second clear is a no-op
}
