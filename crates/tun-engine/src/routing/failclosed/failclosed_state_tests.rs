use super::*;

#[skuld::test]
fn save_then_load_roundtrips() {
    let tmp = tempfile::tempdir().unwrap();
    let st = FailClosedState {
        version: SCHEMA_VERSION,
        pf_token: "1234567890".into(),
        pf_was_enabled: true,
    };
    save(tmp.path(), &st, None).unwrap();
    assert_eq!(load(tmp.path()), Some(st));
}

/// A file written by the previous release, whose `pf_was_enabled` was a bare
/// `bool`, reads unchanged.
///
/// Driven from BYTES, not from `save`, and the version is the LITERAL `1`, never
/// `{SCHEMA_VERSION}`: the claim is about files already on disk, which carry the
/// version they were written at. The opposite direction (what this binary
/// writes, read by the previous release) is
/// `macos_tests::what_an_engage_persists_parses_under_the_previous_releases_schema`.
#[skuld::test]
fn load_reads_an_older_files_bare_bool_pf_was_enabled() {
    for written in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let older = format!(r#"{{"version":1,"pf_token":"5","pf_was_enabled":{written}}}"#);
        std::fs::write(tmp.path().join(STATE_FILE_NAME), &older).unwrap();
        assert_eq!(
            load(tmp.path()),
            Some(FailClosedState {
                version: 1,
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
    let st = FailClosedState {
        version: SCHEMA_VERSION + 1,
        pf_token: "1".into(),
        pf_was_enabled: false,
    };
    // `save` writes whatever version the struct carries, so this fabricates a
    // future-version file on disk.
    save(tmp.path(), &st, None).unwrap();
    assert_eq!(load(tmp.path()), None, "future schema must be discarded");
}

#[skuld::test]
fn clear_refuses_a_state_dir_that_is_a_users_link_to_a_system_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let state = util::dir::testing::state_dir_linked_to_a_system_folder(tmp.path());

    let err = clear(&state).unwrap_err();

    assert_eq!(util::dir::Refusal::from_error(&err), Some(&util::dir::Refusal::Symlink));
}

#[skuld::test]
fn clear_removes_file_and_tolerates_absence() {
    let tmp = tempfile::tempdir().unwrap();
    let st = FailClosedState {
        version: SCHEMA_VERSION,
        pf_token: "9".into(),
        pf_was_enabled: false,
    };
    save(tmp.path(), &st, None).unwrap();
    assert!(tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap(); // second clear is a no-op, not an error
}
