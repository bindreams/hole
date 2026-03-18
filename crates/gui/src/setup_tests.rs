use super::*;

#[skuld::test]
fn daemon_install_status_returns_a_value() {
    // On a dev machine the daemon is typically not installed,
    // but we just verify the function runs without panicking.
    let status = daemon_install_status();
    // Should be one of the three variants
    assert!(matches!(
        status,
        DaemonInstallStatus::Running | DaemonInstallStatus::Installed | DaemonInstallStatus::NotInstalled
    ));
}

#[skuld::test]
fn daemon_binary_path_resolves() {
    let path = daemon_binary_path().expect("should resolve current exe");
    assert!(path.exists(), "resolved path should exist: {path:?}");
}
