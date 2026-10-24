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
fn clear_removes_file_and_tolerates_absence() {
    let tmp = tempfile::tempdir().unwrap();
    let st = FailClosedState {
        version: SCHEMA_VERSION,
        pf_token: "9".into(),
        pf_was_enabled: false,
    };
    save(tmp.path(), &st, None).unwrap();
    assert!(tmp.path().join(STATE_FILE_NAME).exists());
    remove_file(tmp.path()).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    remove_file(tmp.path()).unwrap(); // second clear is a no-op, not an error
}

// Concurrent release: swap / clear_if_token / holds ===================================================================

fn with_token(token: &str) -> FailClosedState {
    FailClosedState {
        version: SCHEMA_VERSION,
        pf_token: token.into(),
        pf_was_enabled: false,
    }
}

#[skuld::test]
fn swap_applies_over_an_absent_record_when_absence_was_expected() {
    let tmp = tempfile::tempdir().unwrap();
    let swap = swap(tmp.path(), &StateFile::Absent, &with_token("1"), None).unwrap();
    assert_eq!(swap, Swap::Applied);
    assert_eq!(load(tmp.path()), Some(with_token("1")));
}

#[skuld::test]
fn swap_is_superseded_by_a_changed_token() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("old"), None).unwrap();
    let expected = load_presence(tmp.path());
    save(tmp.path(), &with_token("newer"), None).unwrap();

    let swap = swap(tmp.path(), &expected, &with_token("mine"), None).unwrap();

    assert_eq!(swap, Swap::Superseded);
    assert_eq!(
        load(tmp.path()),
        Some(with_token("newer")),
        "a superseded swap writes nothing"
    );
}

#[skuld::test]
fn swap_is_superseded_when_the_expected_record_was_cleared() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("old"), None).unwrap();
    let expected = load_presence(tmp.path());
    clear_if_token(tmp.path(), Some("old")).unwrap();

    let swap = swap(tmp.path(), &expected, &with_token("mine"), None).unwrap();

    assert_eq!(swap, Swap::Superseded);
    assert!(
        !tmp.path().join(STATE_FILE_NAME).exists(),
        "a release that cleared the record is not undone"
    );
}

#[skuld::test]
fn swap_applies_over_an_equal_unusable_file() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join(STATE_FILE_NAME),
        br#"{"version":99,"pf_token":"salvaged","pf_was_enabled":true}"#,
    )
    .unwrap();
    let expected = load_presence(tmp.path());
    assert!(matches!(&expected, StateFile::Unusable { pf_token: Some(t) } if t == "salvaged"));

    assert_eq!(
        swap(tmp.path(), &expected, &with_token("mine"), None).unwrap(),
        Swap::Applied
    );
    assert_eq!(load(tmp.path()), Some(with_token("mine")));
}

#[skuld::test]
fn swap_holds_the_record_lock_while_comparing_and_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut held_inside = false;
    swap_with(tmp.path(), &StateFile::Absent, &with_token("1"), None, || {
        held_inside = LOCK.try_acquire().is_none();
    })
    .unwrap();
    assert!(held_inside, "the compare and the write must be one critical section");
    assert!(LOCK.try_acquire().is_some());
}

#[skuld::test]
fn clear_if_token_clears_the_record_that_carries_the_token_and_only_that() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("newer"), None).unwrap();
    clear_if_token(tmp.path(), Some("old")).unwrap();
    assert_eq!(
        load(tmp.path()),
        Some(with_token("newer")),
        "a newer record is not the caller's"
    );

    clear_if_token(tmp.path(), Some("newer")).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    clear_if_token(tmp.path(), Some("newer")).unwrap();
}

#[skuld::test]
fn clear_if_token_none_clears_only_a_record_that_names_no_token() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &with_token("7"), None).unwrap();
    clear_if_token(tmp.path(), None).unwrap();
    assert_eq!(load(tmp.path()), Some(with_token("7")));

    std::fs::write(tmp.path().join(STATE_FILE_NAME), b"not json").unwrap();
    clear_if_token(tmp.path(), None).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn holds_is_true_only_for_a_present_record_carrying_the_token() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(!holds(tmp.path(), "1"), "no record holds nothing");
    save(tmp.path(), &with_token("1"), None).unwrap();
    assert!(holds(tmp.path(), "1"));
    assert!(!holds(tmp.path(), "2"));
}
