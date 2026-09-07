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
