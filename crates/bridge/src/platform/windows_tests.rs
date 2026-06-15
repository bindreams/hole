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
fn shutdown_reason_keys_on_marker() {
    use crate::proxy_manager::StopReason;
    assert_eq!(shutdown_reason(true), StopReason::Cutover);
    assert_eq!(shutdown_reason(false), StopReason::UserStop);
}

#[skuld::test]
fn post_bind_sweep_clears_marker() {
    let dir = tempfile::tempdir().unwrap();
    hole_common::update_marker::write(dir.path(), &super::test_marker()).unwrap();
    sweep_marker(dir.path());
    assert!(hole_common::update_marker::read(dir.path()).is_none());
    sweep_marker(dir.path()); // idempotent: absent marker is a no-op
}
