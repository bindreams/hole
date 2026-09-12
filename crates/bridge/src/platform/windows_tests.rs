use super::*;

#[skuld::test]
fn service_name_is_hole_bridge() {
    assert_eq!(SERVICE_NAME, "HoleBridge");
}

#[skuld::test]
fn service_display_name_is_set() {
    assert!(!SERVICE_DISPLAY_NAME.is_empty());
}

#[skuld::test]
fn service_description_is_set() {
    assert!(!SERVICE_DESCRIPTION.is_empty());
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
fn sweep_marker_then_ready_sweeps_before_reporting() {
    let dir = tempfile::tempdir().unwrap();
    hole_common::update_marker::write(dir.path(), &super::test_marker(), None).unwrap();
    let marker_gone_when_reported = std::cell::Cell::new(false);
    super::sweep_marker_then_ready(dir.path(), || {
        marker_gone_when_reported.set(!hole_common::update_marker::is_present(dir.path()));
        Ok(())
    })
    .unwrap();
    assert!(
        marker_gone_when_reported.get(),
        "the marker must be swept before Running is reported"
    );
}

#[skuld::test]
fn sweep_marker_then_ready_errs_when_marker_survives_sweep() {
    // An external holder can leave the marker present after the sweep attempt.
    // Inject a no-op sweep so the marker survives: the helper must return Err and
    // NEVER report Running (which would false-fail a healthy update).
    let dir = tempfile::tempdir().unwrap();
    hole_common::update_marker::write(dir.path(), &super::test_marker(), None).unwrap();
    let reported = std::cell::Cell::new(false);
    let out = super::sweep_marker_then_ready_with(
        || {}, // no-op sweep: the marker is NOT removed
        dir.path(),
        || {
            reported.set(true);
            Ok(())
        },
    );
    assert!(out.is_err(), "a surviving marker must fail the start");
    assert!(!reported.get(), "Running must never be reported with a stale marker");
}

#[skuld::test]
fn restart_failure_actions_configures_restart_on_failure() {
    use windows_service::service::{ServiceActionType, ServiceFailureResetPeriod};
    let fa = super::restart_failure_actions();
    assert!(fa
        .actions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|a| a.action_type == ServiceActionType::Restart));
    assert!(matches!(fa.reset_period, ServiceFailureResetPeriod::After(d) if !d.is_zero()));
}

#[skuld::test]
fn sweep_old_binaries_removes_old_suffixed_and_spares_live() {
    let dir = tempfile::tempdir().unwrap();
    let old1 = dir.path().join("hole.exe.old-0.0.0");
    let old2 = dir.path().join("hole.exe.old-0.2.1");
    let live = dir.path().join("hole.exe");
    let other = dir.path().join("config.json");
    for p in [&old1, &old2, &live, &other] {
        std::fs::write(p, b"x").unwrap();
    }
    sweep_old_binaries(dir.path());
    assert!(!old1.exists(), "rename-away leftover must be swept");
    assert!(!old2.exists(), "rename-away leftover must be swept");
    assert!(live.exists(), "the live binary must be spared");
    assert!(other.exists(), "unrelated files must be spared");
    sweep_old_binaries(dir.path()); // idempotent on a clean dir
}

/// A log dir whose marker path can be neither opened nor probed: `*` is not a
/// legal Windows path character, so both calls fail ERROR_INVALID_NAME rather
/// than ERROR_FILE_NOT_FOUND. No ACL surgery, so it is deterministic and not
/// defeated by running as SYSTEM.
fn unprobeable_log_dir(base: &Path) -> std::path::PathBuf {
    base.join("in*valid")
}

#[skuld::test]
fn sweep_recheck_admits_an_indeterminate_marker_path() {
    // The re-check must fail CLOSED only on a marker it established EXISTS.
    // An undetermined presence refuses every start forever: the sweep's own
    // `clear` fails on the same path for the same reason, so nothing ends it.
    let base = tempfile::tempdir().unwrap();
    let dir = unprobeable_log_dir(base.path());
    let reported = std::cell::Cell::new(false);
    super::sweep_marker_then_ready_with(
        || {}, // the real sweep cannot clear this path either
        &dir,
        || {
            reported.set(true);
            Ok(())
        },
    )
    .expect("an undetermined marker presence must not fail the start");
    assert!(
        reported.get(),
        "Running must be reported: no marker was ever established"
    );
}

#[skuld::test]
fn shutdown_reason_treats_an_indeterminate_marker_as_a_process_exit_not_a_user_stop() {
    // Reporting CutoverRestart here would misattribute the shutdown to an
    // update cutover that never happened; reporting UserStopped would wrongly
    // move the target to `Off` on a plain machine shutdown. `ProcessExiting`
    // leaves the target unchanged either way, so an indeterminate marker
    // reads the same as an absent one: a clean exit, not a disarm-or-drop
    // decision either kind of stop would make.
    use crate::target::SessionEvent;
    let base = tempfile::tempdir().unwrap();
    let dir = unprobeable_log_dir(base.path());
    assert_eq!(
        crate::foreground::shutdown_reason(hole_common::update_marker::is_present(&dir)),
        SessionEvent::ProcessExiting
    );
}

#[skuld::test]
fn sweep_recheck_uses_presence_not_schema() {
    // The re-check exists to catch an external holder keeping the marker open.
    // Deriving presence from a successful parse fails OPEN on exactly that case.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(hole_common::update_marker::MARKER_FILE), b"not json").unwrap();
    let reported = std::cell::Cell::new(false);
    let out = super::sweep_marker_then_ready_with(
        || {}, // no-op sweep: the marker is NOT removed
        dir.path(),
        || {
            reported.set(true);
            Ok(())
        },
    );
    assert!(out.is_err(), "the marker survived the sweep; Running must be refused");
    assert!(
        !reported.get(),
        "Running must not be reported while a marker is present"
    );
}

// `ensure_stopped`'s absent-service classification ====================================================================
//
// This is what makes the stop independent of a registration record (#1003).
// `ERROR_SERVICE_MARKED_FOR_DELETE` is the one that matters: it is the state a
// `DeleteService` over a live service leaves behind, and mis-reading it as a
// real failure would make an uninstall unrunnable on a host that merely has a
// stale row with an open handle. Anything else is a genuine SCM error and must
// stay one.

fn winapi_error(code: u32) -> windows_service::Error {
    windows_service::Error::Winapi(std::io::Error::from_raw_os_error(code as i32))
}

/// The same Win32 status as the `windows` bindings raise it — an `HRESULT`,
/// not an OS code. This is what `scm_wait`'s `OpenServiceW` failure carries.
fn hresult_error(code: u32) -> windows::core::Error {
    windows::core::Error::from_hresult(HRESULT::from_win32(code))
}

#[skuld::test]
fn an_unregistered_or_deleted_service_has_nothing_to_stop() {
    assert!(open_error_is_absent(&winapi_error(ERROR_SERVICE_DOES_NOT_EXIST.0)));
    assert!(open_error_is_absent(&winapi_error(ERROR_SERVICE_MARKED_FOR_DELETE.0)));
}

#[skuld::test]
fn a_real_scm_failure_is_not_an_absent_service() {
    // Access denied: the caller is unprivileged, the service is very much there.
    assert!(!open_error_is_absent(&winapi_error(5)));
    assert!(!open_error_is_absent(
        &windows_service::Error::LaunchArgumentsNotSupported
    ));
}

#[skuld::test]
fn a_stop_that_failed_over_a_row_that_is_gone_is_a_stopped_service() {
    // `ensure_stopped` classifies the STOP's own error, and the stop reaches
    // SCM through three layers that each report an absent row differently. A
    // classifier that read only the first would answer for whichever layer
    // happened to speak: the uninstall then refuses to deregister over a
    // service provably not running, and every later attempt skips its teardown
    // (#1003).
    for code in [ERROR_SERVICE_DOES_NOT_EXIST.0, ERROR_SERVICE_MARKED_FOR_DELETE.0] {
        assert!(stop_error_is_absent(&winapi_error(code)), "windows_service: {code}");
        assert!(
            stop_error_is_absent(&hresult_error(code)),
            "the `windows` bindings' HRESULT: {code}"
        );
        assert!(
            stop_error_is_absent(&std::io::Error::other(hresult_error(code))),
            "scm_wait's io::Error::other wrapping of it: {code}"
        );
        assert!(
            stop_error_is_absent(&std::io::Error::other(winapi_error(code))),
            "a windows_service error wrapped the same way: {code}"
        );
        assert!(
            stop_error_is_absent(&std::io::Error::from_raw_os_error(code as i32)),
            "NotifyServiceStatusChangeW's bare OS code: {code}"
        );
    }
}

#[skuld::test]
fn a_real_stop_failure_is_never_a_stopped_service() {
    // Access denied at every layer, and a failure carrying no OS code at all.
    // Reporting any of these stopped is the silent half of #1003: the plist
    // equivalent is deleted over a service still running.
    assert!(!stop_error_is_absent(&winapi_error(5)));
    assert!(!stop_error_is_absent(&hresult_error(5)));
    assert!(!stop_error_is_absent(&std::io::Error::other(hresult_error(5))));
    assert!(!stop_error_is_absent(&std::io::Error::other(winapi_error(5))));
    assert!(!stop_error_is_absent(&std::io::Error::from_raw_os_error(5)));
    assert!(!stop_error_is_absent(
        &windows_service::Error::LaunchArgumentsNotSupported
    ));
    assert!(!stop_error_is_absent(&std::io::Error::other(
        "the service did not accept the control"
    )));
}
