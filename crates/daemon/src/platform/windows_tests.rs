use super::*;

#[skuld::test]
fn service_name_is_hole_daemon() {
    assert_eq!(SERVICE_NAME, "HoleDaemon");
}

#[skuld::test]
fn service_display_name_is_set() {
    assert!(!SERVICE_DISPLAY_NAME.is_empty());
}

#[skuld::test]
fn service_description_is_set() {
    assert!(!SERVICE_DESCRIPTION.is_empty());
}
