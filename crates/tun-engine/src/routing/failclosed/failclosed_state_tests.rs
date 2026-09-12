use super::*;

#[skuld::test]
fn save_then_load_roundtrips() {
    let tmp = tempfile::tempdir().unwrap();
    let st = FailClosedState {
        version: SCHEMA_VERSION,
        pf_token: "1234567890".into(),
        pf_was_enabled: Some(true),
    };
    save(tmp.path(), &st, None).unwrap();
    assert_eq!(load(tmp.path()), Some(st));
}

/// The compatibility direction [`FailClosedState::pf_was_enabled`]'s doc claims
/// and nothing else asserted: an OLDER file, written by a binary whose field
/// was a bare `bool`, read by this one.
///
/// That is why [`SCHEMA_VERSION`] was not bumped when the field became
/// `Option<bool>` — so the claim is load-bearing, not cosmetic: if it were
/// false, every pre-upgrade record would read as `Unusable`, and recovery
/// would fall back to that arm — a `warn` per start, the record's
/// `pf_was_enabled` gone, and only what [`super::StateFile::unusable`] can
/// scrape back out of the bytes standing in for it. The opposite direction
/// (this binary's `null` against an older `bool` schema) is pinned next door by
/// `macos_tests::a_rolled_back_bridges_sweep_reads_a_newer_record_as_a_cover_to_clear`.
///
/// Driven from BYTES, not from `save`: `save` writes what this binary's schema
/// emits, which is the shape already covered by `save_then_load_roundtrips`.
///
/// The fixture's version is the LITERAL `1`, never `{SCHEMA_VERSION}`. The
/// claim is about files already sitting on disk, and those carry the version
/// they were written at; interpolating the constant would make the fixture
/// follow a bump, so the one edit that breaks the claim for every such file
/// would leave this test green.
#[skuld::test]
fn load_reads_an_older_files_bare_bool_pf_was_enabled() {
    for (written, want) in [("true", Some(true)), ("false", Some(false))] {
        let tmp = tempfile::tempdir().unwrap();
        let older = format!(r#"{{"version":1,"pf_token":"5","pf_was_enabled":{written}}}"#);
        std::fs::write(tmp.path().join(STATE_FILE_NAME), &older).unwrap();
        assert_eq!(
            load(tmp.path()),
            Some(FailClosedState {
                version: 1,
                pf_token: "5".into(),
                pf_was_enabled: want,
            }),
            "a record already on disk at schema 1, carrying an older binary's bare `{written}`, \
             must read unchanged — anything else makes every pre-upgrade record `Unusable`: \
             {older}"
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
        pf_was_enabled: Some(false),
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
        pf_was_enabled: Some(false),
    };
    save(tmp.path(), &st, None).unwrap();
    assert!(tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap(); // second clear is a no-op, not an error
}
