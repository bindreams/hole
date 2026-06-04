use super::remove_adapter;

/// `remove_adapter` with a name matching no real adapter completes
/// cleanly (no panic, no hang): `Get-NetAdapter -ErrorAction
/// SilentlyContinue` swallows the not-found error, the pipe exits 0,
/// and the function logs at `debug!`.
///
/// `Remove-NetAdapter` needs elevation, but `ForEach-Object` runs zero
/// iterations on a non-matching name, so the test passes regardless of
/// privilege.
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
