use super::*;

#[skuld::test]
fn plan_engages_only_a_covered_start_with_no_standing_cover() {
    let covered = Coverage::Covered { unblock_snapshot: 7 };
    let table = [
        (covered, false, CoverPlan::Engage { unblock_snapshot: 7 }),
        (covered, true, CoverPlan::HandToLockdown),
        (Coverage::Uncovered, false, CoverPlan::FailOpen),
        (Coverage::Uncovered, true, CoverPlan::FailOpen),
    ];
    for (coverage, standing, expected) in table {
        assert_eq!(
            coverage.plan(standing),
            expected,
            "coverage={coverage:?} standing_cover_expected={standing}"
        );
    }
}
