use super::remove_adapter;

/// **#388**: calling `remove_adapter` with a name that doesn't match any
/// real adapter must complete cleanly (no panic, no hang). PowerShell's
/// `Get-NetAdapter -ErrorAction SilentlyContinue` swallows the
/// not-found error, so the pipe exits 0 and the function logs at
/// `debug!` level.
///
/// **Privilege caveat**: `Remove-NetAdapter` requires elevation. When the
/// test process is unprivileged, the inner Remove-NetAdapter step would
/// fail with access-denied — but `Get-NetAdapter` returns nothing on
/// our test name, so `ForEach-Object` runs zero iterations and we never
/// hit the elevation check. So the test passes regardless of elevation.
#[skuld::test]
#[cfg(target_os = "windows")]
fn remove_adapter_for_absent_name_is_silent_noop() {
    remove_adapter("hole-tun-test-does-not-exist-987654321");
}

/// macOS no-op variant — should not error.
#[skuld::test]
#[cfg(not(target_os = "windows"))]
fn remove_adapter_is_noop_on_non_windows() {
    remove_adapter("any-name");
}
