use super::*;

/// The marker's payload, or a failure naming which arm answered instead.
fn present(dir: &std::path::Path) -> MarkerInfo {
    match read(dir) {
        Marker::Present(info) => info,
        other => panic!("expected a readable marker, got {other:?}"),
    }
}

#[skuld::test]
fn absent_reads_as_absent() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(read(dir.path()), Marker::Absent));
    assert!(!is_present(dir.path()));
}

#[skuld::test]
fn valid_reads_as_present() {
    let dir = tempfile::tempdir().unwrap();
    let info = MarkerInfo {
        version: MARKER_VERSION,
        from_version: "0.2.0".into(),
        to_version: "0.3.0".into(),
        driver_pid: 4242,
        started_at_unix: 1_700_000_000,
        driver_start_unix_ms: 0,
    };
    write(dir.path(), &info, None).unwrap();

    let Marker::Present(got) = read(dir.path()) else {
        panic!("a marker written at the current version must read as Present");
    };
    assert_eq!(got, info);
    assert!(is_present(dir.path()));

    clear(dir.path()).unwrap();
    assert!(matches!(read(dir.path()), Marker::Absent));
    // clear is idempotent (remove-by-path, not parse-then-clear).
    clear(dir.path()).unwrap();
}

#[skuld::test]
fn an_unparseable_marker_reads_as_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(MARKER_FILE), b"not json").unwrap();
    assert!(matches!(read(dir.path()), Marker::Unreadable));
}

#[skuld::test]
fn is_present_is_true_for_an_unreadable_marker() {
    // Presence derived from a successful parse answers `false` here, which is
    // the fail-open the post-sweep re-check exists to catch.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(MARKER_FILE), b"not json").unwrap();
    assert!(is_present(dir.path()));
}

#[skuld::test]
fn an_unknown_version_marker_reads_as_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    // The CURRENT shape with an unknown version, so it parses and the version
    // guard is what rejects it. A body of the OTHER schema's field set would be
    // refused by `deny_unknown_fields` first and would test nothing.
    let future = serde_json::json!({
        "version": 99,
        "from_version": "0.3.0",
        "to_version": "0.4.0",
        "driver_pid": 7,
        "started_at_unix": 1,
        "driver_start_unix_ms": 0,
    });
    std::fs::write(dir.path().join(MARKER_FILE), serde_json::to_vec(&future).unwrap()).unwrap();
    assert!(matches!(read(dir.path()), Marker::Unreadable));
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
        driver_pid: 1,
        started_at_unix: 0,
        driver_start_unix_ms: 0,
    };
    write(dir.path(), &info, None).unwrap();
    let mode = std::fs::metadata(dir.path().join(MARKER_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644, "root bridge must write a GUI-readable marker");
}

#[skuld::test]
fn write_new_is_an_atomic_single_occupancy_claim() {
    let dir = tempfile::tempdir().unwrap();
    let info = MarkerInfo {
        version: MARKER_VERSION,
        from_version: "0.2.0".into(),
        to_version: "0.3.0".into(),
        driver_pid: 1,
        started_at_unix: 0,
        driver_start_unix_ms: 0,
    };
    // First claim wins and the full content is readable (never a partial file).
    write_new(dir.path(), &info, None).unwrap();
    assert_eq!(present(dir.path()), info);

    // A second claim loses with AlreadyExists (the race-free 409 guard) and does
    // not overwrite the first claim's content.
    let other = MarkerInfo {
        to_version: "9.9.9".into(),
        ..info.clone()
    };
    let err = write_new(dir.path(), &other, None).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(present(dir.path()).to_version, "0.3.0");

    // No leftover temp file from either the win or the lost claim.
    let leftover = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
    assert!(!leftover, "no stray .tmp after write_new");

    // After a clear, the claim is available again.
    clear(dir.path()).unwrap();
    write_new(dir.path(), &other, None).unwrap();
    assert_eq!(present(dir.path()).to_version, "9.9.9");
}

#[cfg(unix)]
#[skuld::test]
fn write_new_marker_mode_is_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let info = MarkerInfo {
        version: MARKER_VERSION,
        from_version: "a".into(),
        to_version: "b".into(),
        driver_pid: 1,
        started_at_unix: 0,
        driver_start_unix_ms: 0,
    };
    write_new(dir.path(), &info, None).unwrap();
    let mode = std::fs::metadata(dir.path().join(MARKER_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644, "the claimed marker must be GUI-readable too");
}

// The cross-uid proof that `owner` reaches the PUBLISHED marker inode (through
// rename for `write` and hard_link for `write_new`) needs real root to give the
// file to another uid; a self-chown here would be vacuous (the temp is already
// self-owned). It rides the root lane in
// `crates/hole/tests/elevated_ownership_privileged.rs`.

#[skuld::test]
fn stamp_driver_overwrites_only_driver_fields() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        &MarkerInfo {
            version: MARKER_VERSION,
            from_version: "0.2.0".into(),
            to_version: "0.3.0".into(),
            driver_pid: 111,
            started_at_unix: 1_700_000_000,
            driver_start_unix_ms: 0,
        },
        None,
    )
    .unwrap();
    stamp_driver(dir.path(), 222, 1_700_000_123_456).unwrap();
    let Marker::Present(got) = read(dir.path()) else {
        panic!("a stamped marker must stay readable");
    };
    assert_eq!((got.driver_pid, got.driver_start_unix_ms), (222, 1_700_000_123_456));
    assert_eq!(
        (got.from_version.as_str(), got.started_at_unix),
        ("0.2.0", 1_700_000_000)
    );
}

#[skuld::test]
fn stamp_driver_errs_when_the_marker_is_absent() {
    // A stamp that warns and succeeds leaves the marker naming the INITIATOR,
    // which the cutover then stops — so the GUI resolves that identity as dead
    // and reports a failed update on a successful one.
    let dir = tempfile::tempdir().unwrap();
    let result = stamp_driver(dir.path(), 1, 1);
    assert!(
        result.is_err(),
        "a marker that could not be read must fail the stamp, not be warned past"
    );
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
