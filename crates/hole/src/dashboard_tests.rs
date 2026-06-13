use super::*;

#[skuld::test]
fn dashboard_none_initially() {
    let dash = DashboardWindow::new();
    assert_eq!(dash.current_label(), None);
}

#[skuld::test]
fn dashboard_allocate_marks_current_and_labels_from_zero() {
    let dash = DashboardWindow::new();
    let (generation, label) = dash.allocate();
    assert_eq!(generation, 0);
    assert_eq!(label, "dashboard-0");
    assert_eq!(dash.current_label(), Some("dashboard-0".to_string()));
}

#[skuld::test]
fn dashboard_allocate_hands_out_unique_generations() {
    let dash = DashboardWindow::new();
    let (g0, l0) = dash.allocate();
    let (g1, l1) = dash.allocate();
    assert_ne!(g0, g1);
    assert_ne!(l0, l1);
    assert_eq!(l1, "dashboard-1");
    // `current` tracks the latest allocation.
    assert_eq!(dash.current_label(), Some("dashboard-1".to_string()));
}

#[skuld::test]
fn dashboard_forget_current_clears_it() {
    let dash = DashboardWindow::new();
    let (generation, _) = dash.allocate();
    dash.forget(generation);
    assert_eq!(dash.current_label(), None);
}

#[skuld::test]
fn dashboard_forget_stale_generation_leaves_current_intact() {
    let dash = DashboardWindow::new();
    let (g0, _) = dash.allocate(); // generation 0 becomes current
    dash.forget(g0); // 0 closes -> current None
    let _ = dash.allocate(); // generation 1 becomes current

    // A late close for the already-gone generation 0 must not touch gen 1.
    dash.forget(g0);
    assert_eq!(dash.current_label(), Some("dashboard-1".to_string()));
}

#[skuld::test]
fn dashboard_close_then_reopen_during_teardown_keeps_new_window() {
    // The race: close A (forget its generation), then a concurrent open()
    // builds B with a fresh label while A is still tearing down. B must win.
    let dash = DashboardWindow::new();
    let (a, _) = dash.allocate(); // A live
    dash.forget(a); // user clicks X on A -> current None
    let (_b, b_label) = dash.allocate(); // open() during A's teardown builds B
    assert_eq!(b_label, "dashboard-1");
    assert_eq!(dash.current_label(), Some("dashboard-1".to_string()));
}

#[skuld::test]
fn dashboard_forget_unallocated_generation_is_noop() {
    let dash = DashboardWindow::new();
    dash.forget(0);
    assert_eq!(dash.current_label(), None);
}

#[skuld::test]
fn dashboard_double_forget_current_is_idempotent() {
    let dash = DashboardWindow::new();
    let (g, _) = dash.allocate();
    dash.forget(g);
    dash.forget(g);
    assert_eq!(dash.current_label(), None);
}

#[skuld::test]
fn dashboard_label_matches_capability_glob_prefix() {
    // Labels must match the `dashboard-*` glob in capabilities/default.json.
    assert_eq!(label_for(0), "dashboard-0");
    assert_eq!(label_for(42), "dashboard-42");
    assert!(label_for(7).starts_with("dashboard-"));
}
