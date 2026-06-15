use super::*;

#[skuld::test]
fn roundtrip_write_read_clear() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read(dir.path()).is_none(), "absent -> None");

    let info = MarkerInfo {
        version: MARKER_VERSION,
        from_version: "0.2.0".into(),
        to_version: "0.3.0".into(),
        pid: 4242,
        started_at_unix: 1_700_000_000,
    };
    write(dir.path(), &info).unwrap();

    let got = read(dir.path()).expect("present -> Some");
    assert_eq!(got, info);

    clear(dir.path()).unwrap();
    assert!(read(dir.path()).is_none(), "cleared -> None");
    // clear is idempotent (remove-by-path, not parse-then-clear).
    clear(dir.path()).unwrap();
}

#[skuld::test]
fn schema_mismatch_reads_none() {
    let dir = tempfile::tempdir().unwrap();
    // A FULLY VALID, same-shape marker with an unknown version — this exercises
    // the version gate (`info.version == MARKER_VERSION`), not the deserialize
    // step. The real scenario: a future bridge writes a v2 marker, an old GUI
    // reads it. (A garbage/wrong-shape body would fail at deserialize and never
    // reach the gate, so it would test the wrong mechanism.)
    let future = serde_json::json!({
        "version": MARKER_VERSION + 1,
        "from_version": "0.3.0",
        "to_version": "0.4.0",
        "pid": 7,
        "started_at_unix": 1,
    });
    std::fs::write(dir.path().join(MARKER_FILE), serde_json::to_vec(&future).unwrap()).unwrap();
    assert!(read(dir.path()).is_none(), "unknown schema version -> None");
    // But clear still removes it (remove-by-path), proving clear does NOT route
    // through read() — a schema bump must never strand the marker.
    clear(dir.path()).unwrap();
    assert!(!dir.path().join(MARKER_FILE).exists());
}

#[cfg(unix)]
#[skuld::test]
fn marker_mode_is_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let info = MarkerInfo {
        version: MARKER_VERSION,
        from_version: "a".into(),
        to_version: "b".into(),
        pid: 1,
        started_at_unix: 0,
    };
    write(dir.path(), &info).unwrap();
    let mode = std::fs::metadata(dir.path().join(MARKER_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644, "root bridge must write a GUI-readable marker");
}

#[skuld::test]
fn service_log_dir_matches_log_collector_constants() {
    // Pins the dedup: the resolver must equal the dirs the GUI's log_collector
    // hardcodes (so the GUI reads the same place the bridge writes).
    let d = service_log_dir();
    #[cfg(target_os = "windows")]
    assert!(d.ends_with("hole\\logs") || d.ends_with("hole/logs"), "{d:?}");
    #[cfg(target_os = "macos")]
    assert_eq!(d, std::path::PathBuf::from("/var/log/hole"));
}
