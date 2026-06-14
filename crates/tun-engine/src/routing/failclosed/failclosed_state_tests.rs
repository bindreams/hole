use super::*;

#[skuld::test]
fn save_then_load_roundtrips() {
    let tmp = tempfile::tempdir().unwrap();
    let st = FailClosedState {
        version: SCHEMA_VERSION,
        pf_token: "1234567890".into(),
        pf_was_enabled: true,
    };
    save(tmp.path(), &st).unwrap();
    assert_eq!(load(tmp.path()), Some(st));
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
    save(tmp.path(), &st).unwrap();
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
    save(tmp.path(), &st).unwrap();
    assert!(tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap(); // second clear is a no-op, not an error
}
