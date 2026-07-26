use super::*;

#[skuld::test]
fn no_windows_means_no_dashboard() {
    assert!(!dashboard_is_open(std::iter::empty()));
}

#[skuld::test]
fn a_dashboard_window_means_open() {
    assert!(dashboard_is_open(["dashboard-0"].into_iter()));
    assert!(dashboard_is_open(["dashboard-7", "dashboard-8"].into_iter()));
}
