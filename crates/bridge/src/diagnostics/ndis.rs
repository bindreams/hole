//! NDIS / driver / Hyper-V vSwitch snapshot diagnostic.
//!
//! Complements [`super::wfp`]. WFP sits near the top of the Windows
//! networking stack; this module probes the layers *below* WFP that
//! could still hold references to a torn-down wintun adapter:
//!
//! - [`Get-NetAdapter -IncludeHidden`] — reveals phantom adapters
//!   that Windows keeps in the device tree after the visible device
//!   is gone. Wintun has known cases where a hidden adapter survives
//!   incomplete cleanup.
//! - [`Get-NetAdapterBinding -AllBindings`] — the per-adapter binding
//!   inventory, including NDIS Lightweight Filters (LWFs). A wintun
//!   LWF still bound to the loopback pseudo-interface or to a
//!   Hyper-V vSwitch adapter after wintun.sys unloads is exactly the
//!   kind of below-WFP breakage #200 points at.
//! - [`Get-VMSwitchExtension`] — Hyper-V vSwitch extensions. The CI
//!   runner exposes a `vEthernet (nat)` switch; an extension registered
//!   by wintun and not deregistered on adapter teardown would also
//!   break loopback routing through that switch.
//! - [`pnputil /enum-drivers`] — driver-store inventory. If a wintun
//!   driver entry remains after the adapter is gone, the driver stack
//!   may be in a half-torn state.
//!
//! ## Output shape
//!
//! Same three-tier pattern as [`super::wfp`]: one-line `info!` summary
//! with per-source match counts, `warn!` if any source has a match
//! post-teardown, `debug!` with truncated per-source stdout.
//!
//! ## Why PowerShell, not the `windows` crate
//!
//! The probed data is spread across DISM (Get-WindowsDriver), NDIS
//! (Get-NetAdapter*), Hyper-V WMI (Get-VMSwitchExtension), and PnP
//! (pnputil). Direct Win32 bindings would require pulling in multiple
//! COM / WMI / IOCTL surfaces. Shelling PowerShell is ~40 lines and
//! gives us structured string output that's easy to grep for the
//! watch-list strings. Performance is not a concern — snapshots fire
//! once per bridge lifecycle event, not in a hot path.
//!
//! [`Get-NetAdapter -IncludeHidden`]: https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapter
//! [`Get-NetAdapterBinding -AllBindings`]: https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapterbinding
//! [`Get-VMSwitchExtension`]: https://learn.microsoft.com/en-us/powershell/module/hyper-v/get-vmswitchextension
//! [`pnputil /enum-drivers`]: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax

use super::{truncate_utf8, watched_matches, DEBUG_OUTPUT_CAP_BYTES};
use std::process::Command;
use tracing::{debug, info, warn};

/// Emit an NDIS / driver / Hyper-V snapshot.
///
/// See module docs for probe list and tier layout. `phase` conventions
/// match [`super::wfp::log_snapshot`] — typically `"startup"` or
/// `"post-teardown"`.
pub fn log_snapshot(phase: &'static str) {
    let adapters = run_probe(
        "Get-NetAdapter",
        "Get-NetAdapter -IncludeHidden | Format-Table -AutoSize -Wrap",
    );
    let bindings = run_probe(
        "Get-NetAdapterBinding",
        // Filter down to fields we actually scan — AllBindings includes
        // disabled and hidden-adapter bindings too. Keeping the output
        // line-oriented rather than Format-List means the truncation
        // ceiling holds more rows.
        "Get-NetAdapterBinding -AllBindings | \
         Format-Table -AutoSize -Wrap -Property Name,DisplayName,ComponentID,Enabled",
    );
    let vmswext = run_probe(
        "Get-VMSwitchExtension",
        // Iterate switches so we don't depend on having a specific
        // named switch available. SilentlyContinue swallows the
        // "Hyper-V PowerShell not installed" error on machines
        // without the role (our CI runner does have it).
        "Get-VMSwitch -ErrorAction SilentlyContinue | \
         ForEach-Object { Get-VMSwitchExtension -VMSwitchName $_.Name } | \
         Format-Table -AutoSize -Wrap",
    );
    let drivers = run_probe("pnputil", "pnputil /enum-drivers");

    let adapter_matches = watched_matches(&adapters);
    let binding_matches = watched_matches(&bindings);
    let vmswext_matches = watched_matches(&vmswext);
    let driver_matches = watched_matches(&drivers);
    // "Live" matches are residue visible at layers that indicate an
    // active / half-uninstalled component: a hidden adapter, a stuck
    // NDIS binding, a stuck vSwitch extension. These should be absent
    // on a clean machine with wintun not currently loaded.
    //
    // `driver_matches` (pnputil enum-drivers) is separate and does NOT
    // count toward the warn criterion — wintun's driver package stays
    // in the driver store for as long as Hole has been installed,
    // independent of whether any wintun adapter is currently active.
    // On a user's machine `driver_matches > 0` is the expected baseline;
    // warning on it would be noise.
    let live_matches = adapter_matches.len() + binding_matches.len() + vmswext_matches.len();
    let total_matches: u32 = live_matches as u32 + driver_matches.len() as u32;

    info!(
        phase,
        total_matches,
        live_matches = live_matches as u32,
        adapter_matches = ?adapter_matches,
        binding_matches = ?binding_matches,
        vmswext_matches = ?vmswext_matches,
        driver_matches = ?driver_matches,
        "ndis snapshot"
    );

    if live_matches > 0 {
        warn!(
            phase,
            live_matches = live_matches as u32,
            adapter_matches = ?adapter_matches,
            binding_matches = ?binding_matches,
            vmswext_matches = ?vmswext_matches,
            "ndis snapshot: wintun-related live residue detected at adapter/binding/vmswext layer — possible TUN teardown leak"
        );
    }

    // Emit each probe source's full output at debug level. Per-source
    // truncation — not one big concatenated blob — so callers reading
    // the log can tell which source contributed which lines even when
    // the 16 KB cap hits.
    emit_debug_source(phase, "Get-NetAdapter -IncludeHidden", &adapters);
    emit_debug_source(phase, "Get-NetAdapterBinding -AllBindings", &bindings);
    emit_debug_source(phase, "Get-VMSwitchExtension", &vmswext);
    emit_debug_source(phase, "pnputil /enum-drivers", &drivers);
}

/// Run a PowerShell expression and return its stdout as a UTF-8 string.
///
/// On any failure — spawn error, non-zero exit, stderr contents — the
/// return value is an error marker string (`<probe '...' failed: ...>`)
/// rather than an `Err` return. Rationale: callers unconditionally log
/// the output and scan it for watch-list substrings; a failure string
/// survives that path intact and surfaces as a debug-level log entry
/// the operator can see in context. Returning `Err` and propagating
/// would force every probe to fail the whole snapshot, which is worse
/// than "one probe says nothing, three others proceed."
fn run_probe(label: &'static str, ps_command: &str) -> String {
    match Command::new("powershell")
        .args(["-NoProfile", "-Command", ps_command])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        Ok(o) => format!(
            "<probe '{label}' exited {:?}; stderr: {}>",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("<probe '{label}' failed to spawn: {e}>"),
    }
}

/// Emit a debug-level log line carrying `source`'s output, truncated.
/// Split out because four call sites with identical shape would
/// otherwise get unwieldy.
fn emit_debug_source(phase: &'static str, source: &'static str, output: &str) {
    let truncated = truncate_utf8(output, DEBUG_OUTPUT_CAP_BYTES);
    let was_truncated = output.len() > truncated.len();
    debug!(
        phase,
        source,
        truncated = was_truncated,
        full_len = output.len() as u64,
        output = %truncated,
        "ndis snapshot source"
    );
}
