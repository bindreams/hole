//! Best-effort post-teardown wintun adapter cleanup.
//!
//! Belt-and-suspenders for the [`Dispatcher::drop`](../../bridge/src/dispatcher.rs)
//! architectural fix added in bindreams/hole#388 — covers:
//!
//! - **Panic / SIGKILL** paths where Drops don't run at all.
//! - **Current-thread runtime** test paths where `block_in_place` would
//!   panic, so `Dispatcher::drop` takes the abort-only fallback.
//! - **Drop timeout** (2s budget in `Dispatcher::drop`) — a wedged engine
//!   future eventually surrenders the adapter on process exit; this layer
//!   makes sure the next start finds a clean machine.
//!
//! Idempotent: no-op if the adapter is already gone. Requires admin
//! privileges (the bridge runs elevated; in dev mode, `scripts/dev.py`
//! requests UAC elevation). PowerShell cold-start adds ~500-2000ms to
//! teardown — acceptable tax for crash-recovery safety. On macOS the
//! utun adapter auto-cleans on FD close (no equivalent leak), so this
//! is a no-op there.

#[cfg(target_os = "windows")]
pub fn remove_adapter(tun_name: &str) {
    use std::process::Command;
    use tracing::{debug, warn};

    // Guard against PowerShell injection. The only production caller
    // passes the const `TUN_DEVICE_NAME = "hole-tun"`, so this assert
    // never fires in practice — it's a structural guarantee against a
    // future caller that interpolates user input. PowerShell uses
    // single-quote strings (no expansion) but a literal `'` would
    // terminate the string and the rest would be evaluated as PowerShell.
    debug_assert!(
        tun_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "tun_name must be alphanumeric/-/_; got {tun_name:?}"
    );

    // `-ErrorAction SilentlyContinue` on Get-NetAdapter swallows the
    // "no MSFT_NetAdapter objects found" error so the pipe's overall
    // exit code is 0 when nothing matches (the dominant case after a
    // clean stop — `Dispatcher::drop` already released the adapter).
    let ps = format!(
        "Get-NetAdapter -Name '{tun}*' -ErrorAction SilentlyContinue | \
         ForEach-Object {{ Remove-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue }}",
        tun = tun_name,
    );

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
