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
fn only_a_confirmed_absence_is_absent() {
    // Both consumers hang off this one predicate: recovery must reconcile a cover
    // it cannot rule out, and the escape affordance must stay offered for the
    // same reason. Reporting "not engaged" for a probe that failed would hide a
    // genuinely blocked host.
    assert!(CoverState::Engaged.is_present());
    assert!(CoverState::Unknown.is_present());
    assert!(!CoverState::Absent.is_present());
}
