use super::*;

fn sample() -> LockdownPfState {
    LockdownPfState {
        version: SCHEMA_VERSION,
        pf_token: "12345678901234567890".into(),
        main_snapshot: "scrub-anchor \"com.apple/*\" all fragment reassemble\n".into(),
        nat_snapshot: "nat-anchor \"com.apple/*\" all\n".into(),
        main_snapshot_captured: true,
    }
}

#[skuld::test]
fn save_then_load_roundtrips() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample(), None).unwrap();
    assert_eq!(load(tmp.path()), Some(sample()));
}

#[skuld::test]
fn roundtrip_preserves_nat_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample(), None).unwrap();
    assert_eq!(load(tmp.path()).unwrap().nat_snapshot, sample().nat_snapshot);
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
    save(tmp.path(), &st, None).unwrap();
    assert_eq!(load(tmp.path()), None, "future schema must be discarded");
}

#[skuld::test]
fn load_rejects_unknown_field() {
    // `deny_unknown_fields` guards against a half-written/foreign file silently
    // round-tripping as a valid state.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join(STATE_FILE_NAME),
        br#"{"version":1,"pf_token":"x","main_snapshot":"","nat_snapshot":"","stray":true}"#,
    )
    .unwrap();
    assert_eq!(load(tmp.path()), None, "unknown field must be rejected");
}

#[skuld::test]
fn clear_removes_file_and_tolerates_absence() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample(), None).unwrap();
    assert!(tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap(); // second clear is a no-op, not an error
}

// main_snapshot_captured ==============================================================================================

#[skuld::test]
fn state_roundtrips_the_captured_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let mut st = sample();
    st.main_snapshot_captured = false;
    st.main_snapshot = String::new();
    save(tmp.path(), &st, None).unwrap();
    assert_eq!(load(tmp.path()), Some(st));
}

#[skuld::test]
fn a_file_without_the_flag_reads_as_captured() {
    // The upgrade path. A v1 file carries a real captured baseline, so a
    // missing field must read `true`. Bumping SCHEMA_VERSION instead would make
    // every existing file Unusable, collapse `load` to None, early-return
    // `disengage_lockdown` Ok over a still-blocked host, and drop both escapes
    // (`hole bridge unlock` and the tray's Unblock item) on the ordinary macOS
    // upgrade.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join(STATE_FILE_NAME),
        br#"{"version":1,"pf_token":"x","main_snapshot":"pass out all\n","nat_snapshot":""}"#,
    )
    .unwrap();
    let st = load(tmp.path()).expect("a v1 file must still parse");
    assert!(
        st.main_snapshot_captured,
        "a file written before the flag existed carries the captured baseline it was"
    );
    assert_eq!(st.main_snapshot, "pass out all\n");
}
