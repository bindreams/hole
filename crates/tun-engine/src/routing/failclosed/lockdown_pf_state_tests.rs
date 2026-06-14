use super::*;

fn sample() -> LockdownPfState {
    LockdownPfState {
        version: SCHEMA_VERSION,
        pf_token: "12345678901234567890".into(),
        main_snapshot: "scrub-anchor \"com.apple/*\" all fragment reassemble\n".into(),
    }
}

#[skuld::test]
fn save_then_load_roundtrips() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample()).unwrap();
    assert_eq!(load(tmp.path()), Some(sample()));
}

#[skuld::test]
fn load_absent_is_none() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(load(tmp.path()), None);
}

#[skuld::test]
fn load_rejects_schema_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let mut st = sample();
    st.version = SCHEMA_VERSION + 1;
    save(tmp.path(), &st).unwrap();
    assert_eq!(load(tmp.path()), None, "future schema must be discarded");
}

#[skuld::test]
fn clear_removes_file_and_tolerates_absence() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample()).unwrap();
    assert!(tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap();
}
