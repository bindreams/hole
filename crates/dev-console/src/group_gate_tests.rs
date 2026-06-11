use std::collections::BTreeSet;

use crate::group_gate::missing_hole_group;

#[skuld::test]
fn absent_group_means_nothing_to_check() {
    assert!(!missing_hole_group(None, &BTreeSet::from([20, 501])));
}

#[skuld::test]
fn member_passes() {
    assert!(!missing_hole_group(Some(601), &BTreeSet::from([20, 601])));
}

/// The union with {getgid, getegid} matters: os.getgroups may omit the
/// primary gid on some systems — a user whose PRIMARY group is hole must
/// not be reported missing. The caller builds the union; this pin documents
/// why the predicate takes the full set.
#[skuld::test]
fn non_member_is_missing() {
    assert!(missing_hole_group(Some(601), &BTreeSet::from([20, 501])));
}
