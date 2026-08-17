//! Platform-neutral tests for the cover-state vocabulary shared by both
//! platform probes.

use super::*;

#[skuld::test]
fn verify_disengaged_rejects_anything_but_a_confirmed_absence() {
    // `disengage_lockdown`'s Ok must mean "the host is open", not "the call
    // returned". Unknown is a failure: a probe that cannot answer is no basis
    // for telling the user their network is back.
    assert!(verify_disengaged(CoverState::Absent).is_ok());
    assert!(verify_disengaged(CoverState::Engaged).is_err());
    assert!(verify_disengaged(CoverState::Unknown).is_err());
}

#[skuld::test]
fn unknown_counts_as_present_for_recovery() {
    // Reconciliation is idempotent either way, so an unanswerable probe must
    // reconcile rather than skip: a real cover that read Unknown would otherwise
    // survive a Sweep the user asked for.
    assert!(CoverState::Engaged.is_present());
    assert!(CoverState::Unknown.is_present());
    assert!(!CoverState::Absent.is_present());
}

#[skuld::test]
fn unknown_counts_as_engaged_for_the_status_surface() {
    // The escape affordance keys on this. Reporting "not engaged" for a probe
    // that failed would hide a genuinely blocked host.
    assert!(CoverState::Engaged.is_engaged_or_unknown());
    assert!(CoverState::Unknown.is_engaged_or_unknown());
    assert!(!CoverState::Absent.is_engaged_or_unknown());
}
