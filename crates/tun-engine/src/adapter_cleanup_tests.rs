use std::time::Duration;
// `Instant` is only used by the Windows-gated detach-timing tests below.
#[cfg(target_os = "windows")]
use std::time::Instant;

use super::{await_adapter_detached, remove_adapter};

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

/// A LUID that resolves to no live interface must short-circuit immediately
/// (the NSI lookup fails → "detached"), NOT wait out the deadline. The huge
/// 30s deadline vs the <10s assertion catches a broken success predicate (a
/// predicate that never fires would burn the full deadline). No adapter is
/// created, so this is non-privileged and can't race the `hole-tun` e2e lock.
#[skuld::test]
#[cfg(target_os = "windows")]
async fn await_adapter_detached_short_circuits_for_absent_luid() {
    let start = Instant::now();
    await_adapter_detached(0xDEAD_BEEF_DEAD_BEEF, Duration::from_secs(30)).await;
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "absent LUID must short-circuit via the NSI lookup, not wait the deadline"
    );
}

/// The `luid == 0` sentinel ("no LUID") returns without touching the table.
#[skuld::test]
#[cfg(target_os = "windows")]
async fn await_adapter_detached_returns_for_zero_luid() {
    let start = Instant::now();
    await_adapter_detached(0, Duration::from_secs(30)).await;
    assert!(start.elapsed() < Duration::from_secs(1), "luid 0 must early-return");
}

/// Non-Windows is a no-op (utun detaches on FD close).
#[skuld::test]
#[cfg(not(target_os = "windows"))]
async fn await_adapter_detached_is_noop_on_non_windows() {
    await_adapter_detached(123, Duration::from_secs(30)).await;
}
