//! Best-effort post-teardown wintun adapter cleanup.
//!
//! A safety net for paths where [`Dispatcher::drop`](../../bridge/src/dispatcher.rs)
//! does not get to drain the engine task and let wintun's own Drop
//! release the adapter:
//!
//! - **Panic / SIGKILL** paths where Drops don't run at all.
//! - **Current-thread runtime** test paths where `block_in_place` would
//!   panic, so `Dispatcher::drop` takes the abort-only fallback.
//!
//! Idempotent: no-op if the adapter is already gone. Requires admin
//! privileges (the bridge runs elevated; in dev mode, dev-console requires
//! an already-elevated shell). PowerShell cold-start adds ~500-2000ms to
//! teardown — acceptable tax for crash-recovery safety. On macOS the
//! utun adapter auto-cleans on FD close (no equivalent leak), so this
//! is a no-op there.

/// Build the PowerShell script [`remove_adapter`] executes. Extracted so the
/// escaping is unit-testable without spawning PowerShell or touching a real
/// adapter. `cfg`-gated to Windows-or-test rather than bare `windows`:
/// production has exactly one caller, [`remove_adapter`] (Windows-only), but
/// the escaping is also exercised directly by `adapter_cleanup_tests.rs` on
/// every platform — same convention as `identity::classify_incumbent`.
///
/// `tun_name` reaches a **single-quoted** PowerShell string, where a literal
/// `'` is the one character still given meaning (everything else, including
/// a space or a newline, is literal content): it must be doubled (`''`) to
/// escape it, or it would terminate the string early and let the remainder
/// be evaluated as PowerShell. A space is passed straight through, never
/// refused: `hole-tun 2` (#936's disambiguated alias) is real production
/// input, and refusing it would skip cleanup and leak the adapter — worse
/// than the injection this guards against.
#[cfg(any(target_os = "windows", test))]
fn build_remove_adapter_script(tun_name: &str) -> String {
    let escaped = tun_name.replace('\'', "''");
    // `-ErrorAction SilentlyContinue` on Get-NetAdapter swallows the
    // "no MSFT_NetAdapter objects found" error so the pipe's overall
    // exit code is 0 when nothing matches (the dominant case after a
    // clean stop — `Dispatcher::drop` already released the adapter).
    format!(
        "Get-NetAdapter -Name '{tun}*' -ErrorAction SilentlyContinue | \
         ForEach-Object {{ Remove-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue }}",
        tun = escaped,
    )
}

#[cfg(target_os = "windows")]
pub fn remove_adapter(tun_name: &str) {
    use std::process::Command;
    use tracing::{debug, warn};

    // Provenance canary, not a charset filter — `build_remove_adapter_script`
    // itself now escapes any `'` safely, so this is not standing in for that,
    // and a prefix/charset check on `tun_name` was tried and reverted: this
    // function's callers are not only production's `TUN_DEVICE_NAME`/its
    // #936-disambiguated siblings (`"hole-tun 2"`, ...) but also the
    // privileged tests in `device::ipv6_addr_privileged_tests` and
    // `net::metric_privileged_tests`, whose device names are deliberately
    // `"ipv6t-hole"`/`"metrict-hole"` — chosen specifically to NOT match
    // `hole-tun*`, so a live production sweep can't delete them out from
    // under a concurrent test (see those modules' docs). No shared prefix or
    // charset exists across every legitimate caller, so the one invariant
    // actually true of all of them — and the one whose violation is
    // genuinely dangerous — is checked instead: an empty name turns the glob
    // at `'{tun}*'` below into `'*'`, matching and deleting *every* adapter
    // on the machine, not just Hole's own. A caller reaching here with no
    // real device identity is exactly "provenance drifted".
    debug_assert!(
        !tun_name.is_empty(),
        "adapter_cleanup's provenance assumption drifted: an empty tun_name \
         would glob-match and delete every adapter on the machine"
    );

    let ps = build_remove_adapter_script(tun_name);

    let result = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .output();

    match result {
        Ok(out) if out.status.success() => {
            debug!(tun = tun_name, "post-teardown adapter cleanup done");
        }
        Ok(out) => {
            warn!(
                tun = tun_name,
                exit = ?out.status.code(),
                stderr = %String::from_utf8_lossy(&out.stderr),
                "Remove-NetAdapter returned non-zero — adapter may be leaked; \
                 run `scripts/network-reset.py` if connectivity is broken"
            );
        }
        Err(e) => {
            warn!(
                tun = tun_name,
                error = %e,
                "failed to spawn Remove-NetAdapter; adapter may be leaked"
            );
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn remove_adapter(_tun_name: &str) {
    // macOS utun adapters are torn down by the kernel when their FD is
    // closed. The `tun::AsyncDevice` Drop on engine task exit handles
    // it. No defensive shell-out needed.
}

#[cfg(test)]
#[path = "adapter_cleanup_tests.rs"]
mod adapter_cleanup_tests;
