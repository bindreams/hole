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
    hole_common::update_marker::write(dir.path(), &super::test_marker(), None).unwrap();
    sweep_marker(dir.path());
    assert!(hole_common::update_marker::read(dir.path()).is_none());
    sweep_marker(dir.path()); // idempotent: absent marker is a no-op
}

#[skuld::test]
fn sweep_old_binaries_removes_old_suffixed_and_spares_live() {
    let dir = tempfile::tempdir().unwrap();
    let old1 = dir.path().join("hole.exe.old-0.0.0");
    let old2 = dir.path().join("hole.exe.old-0.2.1");
    let live = dir.path().join("hole.exe");
    let other = dir.path().join("config.json");
    for p in [&old1, &old2, &live, &other] {
        std::fs::write(p, b"x").unwrap();
    }
    sweep_old_binaries(dir.path());
    assert!(!old1.exists(), "rename-away leftover must be swept");
    assert!(!old2.exists(), "rename-away leftover must be swept");
    assert!(live.exists(), "the live binary must be spared");
    assert!(other.exists(), "unrelated files must be spared");
    sweep_old_binaries(dir.path()); // idempotent on a clean dir
}
