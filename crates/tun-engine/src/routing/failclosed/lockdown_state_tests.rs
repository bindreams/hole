use super::*;

#[skuld::test]
fn save_then_load_roundtrips() {
    let tmp = tempfile::tempdir().unwrap();
    let st = LockdownState {
        version: SCHEMA_VERSION,
        enabled: true,
    };
    save(tmp.path(), &st).unwrap();
    assert_eq!(load(tmp.path()), Some(st));
}

#[skuld::test]
fn load_absent_is_none_and_load_enabled_is_false() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(load(tmp.path()), None);
    assert!(!load_enabled(tmp.path()), "absent file => default-off");
}

#[skuld::test]
fn load_rejects_schema_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let st = LockdownState {
        version: SCHEMA_VERSION + 1,
        enabled: true,
    };
    save(tmp.path(), &st).unwrap();
    assert_eq!(load(tmp.path()), None, "future schema must be discarded");
}

#[skuld::test]
fn set_enabled_is_last_writer_wins() {
    let tmp = tempfile::tempdir().unwrap();
    set_enabled(tmp.path(), true).unwrap();
    assert!(load_enabled(tmp.path()));
    set_enabled(tmp.path(), false).unwrap();
    assert!(!load_enabled(tmp.path()), "second writer wins");
}

#[skuld::test]
fn clear_removes_file_and_tolerates_absence() {
    let tmp = tempfile::tempdir().unwrap();
    set_enabled(tmp.path(), true).unwrap();
    assert!(tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap(); // second clear is a no-op
}
