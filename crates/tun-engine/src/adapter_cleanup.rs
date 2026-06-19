//! Best-effort post-teardown wintun adapter cleanup.
//!
//! A safety net for paths where [`Dispatcher::drop`](../../bridge/src/dispatcher.rs)
//! does not get to drain the engine task and let wintun's own Drop
//! release the adapter:
//!
//! - **Panic / SIGKILL** paths where Drops don't run at all.
//! - **Current-thread runtime** test paths where `block_in_place` would
//!   panic, so `Dispatcher::drop` takes the abort-only fallback.
//! - **Drop timeout** (2s budget in `Dispatcher::drop`) — a wedged engine
//!   future eventually surrenders the adapter on process exit; this layer
//!   makes sure the next start finds a clean machine.
//!
//! Idempotent: no-op if the adapter is already gone. Requires admin
//! privileges (the bridge runs elevated; in dev mode, dev-console requires
//! an already-elevated shell). PowerShell cold-start adds ~500-2000ms to
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

/// Wait until the wintun adapter identified by `luid` is fully removed from
/// the kernel interface table, or `deadline` elapses.
///
/// `WintunCloseAdapter` (run when the engine task's `tun::AsyncDevice` drops)
/// tears down the userspace adapter and signals the driver, but the kernel
/// NDIS miniport/LWF detach is **asynchronous** and continues after the call
/// returns. That lingering detach transiently stalls the host network stack
/// (loopback `connect`, v2ray-core startup) for the NEXT operation — the
/// bindreams/hole#541 hang (a co-located galoshes-server fixture's readiness)
/// and a real disconnect→reconnect race (re-creating `hole-tun` by name while
/// the prior instance is mid-detach). Awaiting the detach makes teardown leave
/// the host quiescent.
///
/// `ConvertInterfaceLuidToIndex` is a synchronous NSI table lookup keyed by the
/// 64-bit LUID — NOT a WMI/CIM enumeration like `Get-NetAdapter` (the documented
/// hang vector), so polling it cannot hang. While the interface exists (even
/// mid-detach) it returns `NO_ERROR`; once the kernel has removed it the lookup
/// fails (`ERROR_FILE_NOT_FOUND`). That transition is the genuine external OS
/// event we wait on; `deadline` is the failure-to-human bound (logged, then we
/// proceed — never hang) and the inter-poll sleep only avoids a busy loop.
#[cfg(target_os = "windows")]
pub async fn await_adapter_detached(luid: u64, deadline: std::time::Duration) {
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToIndex;
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    // luid 0 is the "no LUID" sentinel (`Device::tun_luid` on platforms/paths
    // without one). Never query the table for it.
    if luid == 0 {
        return;
    }

    let net_luid = NET_LUID_LH { Value: luid };
    let start = Instant::now();
    loop {
        let mut index = 0u32;
        // SAFETY: `net_luid` is an initialized LUID; `index` is a valid out-ptr.
        let err = unsafe { ConvertInterfaceLuidToIndex(&net_luid, &mut index) };
        if err != NO_ERROR {
            // Any non-success means the LUID no longer resolves to a live
            // interface — the detach has completed (or the interface is
            // otherwise gone). Either way the host is quiescent for `luid`.
            tracing::debug!(
                luid,
                win32_error = err.0,
                elapsed_ms = start.elapsed().as_millis() as u64,
                "wintun adapter NDIS detach complete"
            );
            return;
        }
        if start.elapsed() >= deadline {
            tracing::warn!(
                luid,
                deadline_ms = deadline.as_millis() as u64,
                "wintun adapter NDIS detach did not complete within deadline; \
                 next TUN start or host network op may transiently stall"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// macOS/Unix utun adapters detach synchronously on FD close, so there is no
/// async detach to await.
#[cfg(not(target_os = "windows"))]
pub async fn await_adapter_detached(_luid: u64, _deadline: std::time::Duration) {}

#[cfg(test)]
#[path = "adapter_cleanup_tests.rs"]
mod adapter_cleanup_tests;
