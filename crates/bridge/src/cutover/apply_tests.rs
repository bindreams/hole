use super::*;

fn sample_marker() -> hole_common::update_marker::MarkerInfo {
    hole_common::update_marker::MarkerInfo {
        version: hole_common::update_marker::MARKER_VERSION,
        from_version: "0.2.0".into(),
        to_version: "0.3.0".into(),
        pid: 4242,
        started_at_unix: 1_700_000_000,
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
    hole_common::update_marker::write(dir.path(), &sample_marker()).unwrap();
    assert!(cutover_in_progress(dir.path()), "marker present -> in progress (409)");
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
