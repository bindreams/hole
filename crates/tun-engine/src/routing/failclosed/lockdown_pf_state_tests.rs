use super::*;
use std::path::PathBuf;
use util::versioned_file::UpdateOutcome;

use super::super::StateFile;

fn sample() -> LockdownPfState {
    LockdownPfState {
        pf_token: "12345678901234567890".into(),
        main_snapshot: "scrub-anchor \"com.apple/*\" all fragment reassemble\n".into(),
        nat_snapshot: "nat-anchor \"com.apple/*\" all\n".into(),
        main_snapshot_captured: true,
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
    save(tmp.path(), &sample(), None).unwrap();
    assert_eq!(load(tmp.path()), Some(sample()));
}

#[skuld::test]
fn roundtrip_preserves_nat_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample(), None).unwrap();
    assert_eq!(load(tmp.path()).unwrap().nat_snapshot, sample().nat_snapshot);
}

/// The bytes a save leaves are what the previous release reads: its `version` first and the same four fields.
#[skuld::test]
fn what_a_save_writes_has_the_previous_releases_shape() {
    let tmp = tempfile::tempdir().unwrap();
    save(tmp.path(), &sample(), None).unwrap();

    let written: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tmp.path().join(STATE_FILE_NAME)).unwrap()).unwrap();

    assert_eq!(
        written,
        serde_json::json!({
            "version": 1,
            "pf_token": "12345678901234567890",
            "main_snapshot": "scrub-anchor \"com.apple/*\" all fragment reassemble\n",
            "nat_snapshot": "nat-anchor \"com.apple/*\" all\n",
            "main_snapshot_captured": true,
        })
    );
}

#[skuld::test]
fn load_absent_is_none() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(load(tmp.path()), None);
}

#[skuld::test]
fn load_rejects_schema_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(
        tmp.path(),
        br#"{"version":2,"pf_token":"x","main_snapshot":"","nat_snapshot":"","main_snapshot_captured":true}"#,
    );
    assert_eq!(load(tmp.path()), None, "future schema must be discarded");
}

/// A record from a newer release is unusable to this one, and its token is the only copy of the `pfctl -E` ticket.
#[skuld::test]
fn a_newer_record_is_unusable_and_gives_up_its_token() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(
        tmp.path(),
        br#"{"version":2,"pf_token":"7","main_snapshot":"","nat_snapshot":"","later":1}"#,
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
        br#"{"version":1,"pf_token":"x","main_snapshot":"","nat_snapshot":"","stray":true}"#,
    );

    assert!(load(tmp.path()).is_some(), "an unknown field is ignored");
}

#[skuld::test]
fn save_over_a_corrupt_pf_record_keeps_a_backup() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(tmp.path(), b"{not json");

    save(tmp.path(), &sample(), None).unwrap();

    assert_eq!(load(tmp.path()), Some(sample()));
    assert_eq!(std::fs::read(backup_of(tmp.path())).unwrap(), b"{not json");
}

#[skuld::test]
fn save_over_a_newer_pf_record_keeps_a_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let newer: &[u8] = br#"{"version":2,"pf_token":"3","main_snapshot":"","nat_snapshot":""}"#;
    write_raw(tmp.path(), newer);

    save(tmp.path(), &sample(), None).unwrap();

    assert_eq!(load(tmp.path()), Some(sample()));
    assert_eq!(std::fs::read(backup_of(tmp.path())).unwrap(), newer);
}

#[skuld::test]
fn clear_moves_a_corrupt_or_newer_pf_record_aside() {
    let cases: [(&str, &[u8]); 2] = [
        ("corrupt", b"{not json"),
        (
            "newer",
            br#"{"version":2,"pf_token":"3","main_snapshot":"","nat_snapshot":""}"#,
        ),
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
    save(tmp.path(), &sample(), None).unwrap();
    assert!(tmp.path().join(STATE_FILE_NAME).exists());

    assert!(matches!(clear(tmp.path()).unwrap(), UpdateOutcome::Removed));
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    assert!(matches!(clear(tmp.path()).unwrap(), UpdateOutcome::Absent)); // a second clear is a no-op
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
    // missing field must read `true`. Bumping the schema version instead would make
    // every existing file Unusable, collapse `load` to None, early-return
    // `disengage_lockdown` Ok over a still-blocked host, and drop both escapes
    // (`hole bridge unlock` and the tray's Unblock item) on the ordinary macOS
    // upgrade.
    let tmp = tempfile::tempdir().unwrap();
    write_raw(
        tmp.path(),
        br#"{"version":1,"pf_token":"x","main_snapshot":"pass out all\n","nat_snapshot":""}"#,
    );
    let st = load(tmp.path()).expect("a v1 file must still parse");
    assert!(
        st.main_snapshot_captured,
        "a file written before the flag existed carries the captured baseline it was"
    );
    assert_eq!(st.main_snapshot, "pass out all\n");
}

/// `main_snapshot` is a captured `pfctl -sr` ruleset, so whenever the ruleset
/// it captured was Hole's own cover it contains the server IP in a permit
/// rule — and `serde_json::Error`'s `Display` quotes the offending bytes
/// back. Same class as `routing::state`'s two arms.
#[skuld::test]
fn a_corrupt_pf_state_never_echoes_its_contents_into_the_log() {
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    const SECRET_ADDR: &str = "203.0.113.42";

    // The record frames, and the flag is a string where a bool belongs: the payload parse is what fails.
    let json = format!(
        r#"{{"version":1,"pf_token":"1","main_snapshot":"","nat_snapshot":"","main_snapshot_captured":"{SECRET_ADDR}"}}"#
    );

    // Guard: without it this passes against a serde_json that stopped echoing.
    let raw = serde_json::from_str::<LockdownPfState>(&json)
        .expect_err("must not parse")
        .to_string();
    assert!(raw.contains(SECRET_ADDR), "guard: serde_json echoes the value: {raw}");

    let tmp = tempfile::tempdir().unwrap();
    write_raw(tmp.path(), json.as_bytes());

    let writer = garter::test_utils::WaitableWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    let loaded = {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        load(tmp.path())
    };
    let logs = writer.snapshot();

    assert_eq!(loaded, None, "a corrupt record must not be acted on");
    assert!(!logs.contains(SECRET_ADDR), "the address reached bridge.log: {logs}");
    assert!(
        logs.contains("line 1"),
        "position must survive so the warning stays actionable: {logs}"
    );
}
