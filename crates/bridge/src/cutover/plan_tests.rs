use super::*;

#[skuld::test]
fn plan_cutover_table() {
    // lockdown ON -> the persistent standing cover already holds the gap;
    // the cutover engages NOTHING.
    assert_eq!(plan_cutover(true), CutoverPlan::StandingCoverHolds);
    // lockdown OFF -> plain restart, brief leak accepted (consent-gated upstream).
    assert_eq!(plan_cutover(false), CutoverPlan::PlainRestart);
}

#[skuld::test]
fn plan_cutover_never_engages_transient_cover() {
    // Structural never-co-engage invariant: neither plan is a transient cover.
    for lockdown in [true, false] {
        match plan_cutover(lockdown) {
            CutoverPlan::StandingCoverHolds | CutoverPlan::PlainRestart => {}
        }
    }
}

#[skuld::test]
fn cover_needed_table() {
    assert!(cover_needed(true, true)); // lockdown on + running -> cover must hold
    assert!(!cover_needed(true, false)); // not running -> nothing to cover
    assert!(!cover_needed(false, true)); // lockdown off -> no cover
    assert!(!cover_needed(false, false));
}
