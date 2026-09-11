use super::*;

#[skuld::test]
fn plist_contains_label() {
    let plist = generate_plist("/usr/local/bin/hole");
    assert!(plist.contains("com.hole.bridge"), "missing label in plist");
}

#[skuld::test]
fn plist_contains_binary_path() {
    let plist = generate_plist("/opt/hole/hole");
    assert!(plist.contains("/opt/hole/hole"), "missing binary path in plist");
}

#[skuld::test]
fn plist_has_bridge_run_args() {
    let plist = generate_plist("/usr/local/bin/hole");
    // ProgramArguments should include "bridge" and "run" as separate entries
    assert!(plist.contains("<string>bridge</string>"), "missing 'bridge' arg");
    assert!(plist.contains("<string>run</string>"), "missing 'run' arg");
}

#[skuld::test]
fn plist_has_run_at_load() {
    let plist = generate_plist("/usr/local/bin/hole");
    assert!(plist.contains("<key>RunAtLoad</key>"), "missing RunAtLoad");
    assert!(plist.contains("<true/>"), "RunAtLoad should be true");
}

#[skuld::test]
fn plist_has_keep_alive() {
    let plist = generate_plist("/usr/local/bin/hole");
    assert!(plist.contains("<key>KeepAlive</key>"), "missing KeepAlive");
}

#[skuld::test]
fn helper_path_is_stable() {
    assert_eq!(HELPER_PATH, "/Library/PrivilegedHelperTools/com.hole.bridge");
}

#[skuld::test]
fn service_log_dir_const_matches_shared_resolver() {
    // The const is referenced widely here, but the marker lives at the same
    // cross-privilege dir the GUI reads. Pin them equal so they cannot drift.
    assert_eq!(
        std::path::Path::new(SERVICE_LOG_DIR),
        hole_common::update_marker::service_log_dir()
    );
}

#[skuld::test]
async fn serve_until_signal_returns_when_signal_fires() {
    // A server future that never completes, and a shutdown future we control.
    // Firing the shutdown must return control so the daemon's pm.stop()
    // teardown runs — the SIGTERM-graceful behavior under test.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = std::future::pending::<std::io::Result<()>>();
    let shutdown = async move {
        let _ = rx.await;
    };
    let join = tokio::spawn(serve_until_signal(server, shutdown));
    tx.send(()).unwrap();
    join.await.unwrap();
}

// `ensure_stopped`'s absent-job classification ========================================================================
//
// The macOS half of #1003's "stop, then deregister" rule, and the mirror of
// windows.rs's `open_error_is_absent`. Both platforms answer the same question
// — does the service manager still have a job for this label? — and both must
// answer it BY CAUSE. The old body answered it by re-probing with
// `is_running()`, whose `.unwrap_or(false)` turned "launchd could not be asked"
// into "nothing is running", so an `ensure_stopped` that stopped nothing
// reported success and `uninstall_bridge_with` went on to deregister.

#[skuld::test]
fn launchd_answers_no_such_service_for_a_label_it_does_not_know() {
    // Measures the constant against the running OS rather than asserting it
    // from memory: `LAUNCHD_NO_SUCH_SERVICE` is what the classification of
    // "there is no job to stop" hangs on, and a wrong value turns every clean
    // uninstall into a failure (or, if it collided with success, a silent one).
    let status = std::process::Command::new("launchctl")
        .args(["print", "system/com.hole.bridge.absent-by-construction"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("launchctl is present on every macOS host");
    assert_eq!(
        status.code(),
        Some(LAUNCHD_NO_SUCH_SERVICE),
        "launchctl print must report `no such service` for a label launchd cannot know"
    );
}

#[skuld::test]
fn a_registration_probe_classifies_by_cause() {
    assert_eq!(classify_registration(Ok(Some(0))), Registration::Loaded);
    assert_eq!(
        classify_registration(Ok(Some(LAUNCHD_NO_SUCH_SERVICE))),
        Registration::Absent
    );
    // Anything else is an answer about launchctl, not about the job. Neither
    // an unexpected exit code, a signal, nor a failure to spawn says the
    // bridge is stopped.
    for unusable in [Some(1), Some(37), None] {
        assert!(
            matches!(classify_registration(Ok(unusable)), Registration::Unknown(_)),
            "{unusable:?}"
        );
    }
    assert!(matches!(
        classify_registration(Err(std::io::Error::other("launchctl not found"))),
        Registration::Unknown(_)
    ));
}

#[skuld::test]
fn an_unanswerable_probe_is_never_a_stopped_bridge() {
    // The silent-success hole itself. `uninstall_bridge_with` gates
    // deregistration on this returning Ok, and deleting the plist over a
    // still-loaded job is the macOS dead end #1003 is about: `is_installed()`
    // then reads false and no later uninstall ever tries to stop it again.
    let err = ensure_stopped_verdict(Registration::Unknown("launchctl not found".into()))
        .expect_err("an unanswerable probe must fail loud");
    assert!(format!("{err}").contains("launchctl not found"), "{err}");

    assert!(
        ensure_stopped_verdict(Registration::Absent).is_ok(),
        "a label launchd does not know is a label that is not running"
    );

    // Total over `Registration`, not merely over what its one caller passes:
    // a still-loaded job is never a stopped bridge either, whoever asks.
    assert!(ensure_stopped_verdict(Registration::Loaded).is_err());
}

#[skuld::test]
fn post_bind_sweep_clears_marker() {
    let dir = tempfile::tempdir().unwrap();
    hole_common::update_marker::write(dir.path(), &super::test_marker(), None).unwrap();
    sweep_marker(dir.path());
    assert!(!hole_common::update_marker::is_present(dir.path()));
    sweep_marker(dir.path()); // idempotent: absent marker is a no-op
}

#[skuld::test]
fn plist_does_not_set_standard_paths() {
    // The FD-level stdio redirect in hole_common::logging::init captures
    // stdout/stderr into bridge.log; a launchd-side capture would only
    // produce duplicate files. If StandardOutPath or StandardErrorPath is
    // reintroduced, this test fails and catches the regression.
    let plist = generate_plist("/usr/local/bin/hole");
    assert!(
        !plist.contains("StandardErrorPath"),
        "plist must not set StandardErrorPath — the FD redirect already captures stderr",
    );
    assert!(
        !plist.contains("StandardOutPath"),
        "plist must not set StandardOutPath — the FD redirect already captures stdout",
    );
}
