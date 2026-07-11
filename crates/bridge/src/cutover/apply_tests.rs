use super::*;

fn sample_marker() -> hole_common::update_marker::MarkerInfo {
    hole_common::update_marker::MarkerInfo {
        version: hole_common::update_marker::MARKER_VERSION,
        from_version: "0.2.0".into(),
        to_version: "0.3.0".into(),
        driver_pid: 4242,
        started_at_unix: 1_700_000_000,
        driver_start_unix_ms: 0,
    }
}

#[skuld::test]
fn lockdown_off_without_consent_is_refused() {
    // Under lockdown-off, consent=false must be refused; under lockdown-on,
    // consent is irrelevant (the standing cover holds the gap).
    assert_eq!(consent_gate(false, false), Err(ConsentError::Required));
    assert_eq!(consent_gate(false, true), Ok(()));
    assert_eq!(consent_gate(true, false), Ok(()));
    assert_eq!(consent_gate(true, true), Ok(()));
}

#[skuld::test]
fn concurrent_cutover_detected_via_existing_marker() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!cutover_in_progress(dir.path()), "no marker -> not in progress");
    hole_common::update_marker::write(dir.path(), &sample_marker(), None).unwrap();
    assert!(cutover_in_progress(dir.path()), "marker present -> in progress (409)");
}

#[cfg(target_os = "macos")]
fn make_bundle_in(dir: &std::path::Path, name: &str, id: &str) -> std::path::PathBuf {
    let app = dir.join(name);
    std::fs::create_dir_all(app.join("Contents").join("MacOS")).unwrap();
    std::fs::write(
        app.join("Contents").join("Info.plist"),
        format!("<plist><dict>\n<key>CFBundleIdentifier</key>\n<string>{id}</string>\n</dict></plist>"),
    )
    .unwrap();
    app
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn preflight_app_dest_anchors_to_the_hole_identity() {
    // An absent hint is rejected; a foreign bundle identity is rejected; a genuine
    // `com.hole.app` passes — all before any marker. The path is a hint, the
    // identity is the trust anchor.
    let dir = tempfile::tempdir().unwrap();
    assert!(preflight_app_dest(None).is_err(), "an absent app_dest must be rejected");

    let evil = make_bundle_in(dir.path(), "Evil.app", "com.evil.app");
    assert!(
        preflight_app_dest(Some(&evil)).is_err(),
        "a foreign bundle identity must be rejected"
    );

    let genuine = make_bundle_in(dir.path(), "Hole.app", "com.hole.app");
    preflight_app_dest(Some(&genuine)).expect("a genuine com.hole.app bundle must pass");
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_actor_failure_clears_the_injected_log_dir() {
    // The macOS inline actor SIGTERMs its own process on success, so the only
    // way past `run_cutover` is a swap failure before the SIGTERM. That failure
    // path must clear the marker in the handler-supplied `log_dir` (next to
    // bridge.log), NOT re-resolve `service_log_dir()` — a marker stranded in the
    // wrong dir would make the GUI mask Disconnected forever.
    let dir = tempfile::tempdir().unwrap();
    hole_common::update_marker::write(dir.path(), &sample_marker(), None).unwrap();
    macos::clear_marker_on_actor_failure(Err(std::io::Error::other("swap failed")), dir.path());
    assert!(
        hole_common::update_marker::read(dir.path()).is_none(),
        "the injected log_dir's marker must be cleared on actor failure"
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn breakaway_only_when_in_job_and_job_permits() {
    // Unconditional CREATE_BREAKAWAY_FROM_JOB fails the spawn when the job
    // forbids it, so request it ONLY when both hold.
    assert!(breakaway_decision(true, true));
    assert!(!breakaway_decision(true, false), "job forbids breakaway");
    assert!(
        !breakaway_decision(false, true),
        "not in a job -> nothing to break out of"
    );
    assert!(!breakaway_decision(false, false));
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn record_spawned_driver_stamps_when_alive() {
    let dir = tempfile::tempdir().unwrap();
    hole_common::update_marker::write(dir.path(), &sample_marker(), None).unwrap();
    windows::record_spawned_driver(dir.path(), 4242, Some(1_700_000_000_123)).unwrap();
    let got = hole_common::update_marker::read(dir.path()).unwrap();
    assert_eq!((got.driver_pid, got.driver_start_unix_ms), (4242, 1_700_000_000_123));
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn record_spawned_driver_fails_when_child_vanished_or_zero() {
    let dir = tempfile::tempdir().unwrap();
    hole_common::update_marker::write(dir.path(), &sample_marker(), None).unwrap();
    assert!(windows::record_spawned_driver(dir.path(), 4242, None).is_err());
    assert!(
        windows::record_spawned_driver(dir.path(), 4242, Some(0)).is_err(),
        "a poisoned 0 start time is rejected"
    );
}

// The suspend->resume ordering primitive, asserted POSITIVELY: a suspended child
// does not run (its sentinel is absent) until resumed, then it runs (sentinel
// appears). Driven through the `spawn_suspended_command` inner seam so the
// ordering is testable with an arbitrary observable command.
#[cfg(target_os = "windows")]
#[skuld::test]
fn spawn_suspended_child_is_frozen_until_resumed() {
    let dir = tempfile::tempdir().unwrap();
    let sentinel = dir.path().join("ran.txt");
    let mut child = windows::spawn_suspended_command(&format!("cmd /c echo x > \"{}\"", sentinel.display())).unwrap();
    let pid = child.id();
    assert!(!sentinel.exists(), "a suspended child must not run before resume");
    windows::resume_main_thread(pid).unwrap();
    // Sanctioned external-event wait: a broken resume leaves the child suspended
    // forever, which the test harness surfaces as a timeout, not a hang here.
    child.wait().unwrap();
    assert!(sentinel.exists(), "the child ran only after resume");
}
