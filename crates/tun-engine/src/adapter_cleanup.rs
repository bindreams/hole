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
//! an already-elevated shell). It starts a PowerShell, so it adds that
//! process's cold-start time to teardown. On macOS the utun adapter is
//! released when its file descriptor closes, so this is a no-op there.

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
/// refused: a name such as `hole-tun 2` is real production input.
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

/// Remove every adapter whose name starts with `tun_name`: the script globs
/// `'<tun_name>*'`, so `hole-tun` also matches `hole-tun 2` and any other
/// adapter that merely shares the prefix, including a sibling bridge's
/// (bindreams/hole#1314). Failures are logged, never returned: the caller is
/// already tearing down.
#[cfg(target_os = "windows")]
pub fn remove_adapter(tun_name: &str) {
    use tracing::{debug, warn};
    use util::system_tool::SystemPowershell;

    // The callers' names share no prefix (production's `hole-tun`/`hole-tun 2`,
    // and the privileged tests' deliberately non-matching names), so the one
    // checkable invariant is a non-empty name: an empty one turns the glob
    // below into `'*'` and deletes every adapter on the machine.
    debug_assert!(
        !tun_name.is_empty(),
        "adapter_cleanup's provenance assumption drifted: an empty tun_name \
         would glob-match and delete every adapter on the machine"
    );

    let ps = build_remove_adapter_script(tun_name);

    let result = SystemPowershell::command(&ps).and_then(|mut c| c.output());

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
                error = &e as &dyn std::error::Error,
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
