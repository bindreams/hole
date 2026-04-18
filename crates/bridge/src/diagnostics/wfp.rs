//! Windows Filtering Platform (WFP) snapshot diagnostic.
//!
//! `log_snapshot(phase)` runs `netsh wfp show filters` for the loopback
//! outbound path and emits a three-tier structured trace:
//!
//! - **info** — one-liner with `phase`, matched-substring list, and
//!   output byte count. Always emitted so every bug report contains
//!   the verdict without needing debug logs.
//! - **warn** — when `phase == "post-teardown"` and we still see
//!   wintun-related filter references. Turns the known-bad case into
//!   something greppable by severity in an incoming user log.
//! - **debug** — full `netsh` stdout, truncated to
//!   [`DEBUG_OUTPUT_CAP_BYTES`]. Captures the specific filter name/GUID
//!   that's implicated, only when the caller has turned debug on.
//!
//! See the sibling `ndis` module for a parallel diagnostic covering the
//! NDIS / driver / Hyper-V vSwitch layers.

use super::{truncate_utf8, watched_matches, DEBUG_OUTPUT_CAP_BYTES};
use std::process::Command;
use tracing::{debug, info, warn};

/// Emit a WFP filter snapshot for the loopback outbound path.
///
/// See module docs for `phase` conventions and the three-tier output.
pub fn log_snapshot(phase: &'static str) {
    let output = match run_netsh() {
        Ok(o) => o,
        Err(e) => {
            warn!(phase, error = %e, "wfp snapshot: netsh invocation failed");
            return;
        }
    };

    let matches = watched_matches(&output);

    info!(
        phase,
        total_matches = matches.len() as u32,
        watched = ?matches,
        output_bytes = output.len() as u64,
        "wfp snapshot"
    );

    if phase == "post-teardown" && !matches.is_empty() {
        warn!(
            phase,
            watched = ?matches,
            "wfp snapshot: wintun-related filter references still present after teardown — suspected WFP leak"
        );
    }

    let debug_output = truncate_utf8(&output, DEBUG_OUTPUT_CAP_BYTES);
    let truncated = output.len() > debug_output.len();
    debug!(
        phase,
        truncated,
        full_len = output.len() as u64,
        output = %debug_output,
        "wfp snapshot: netsh stdout"
    );
}

/// Run `netsh wfp show filters` scoped to the loopback outbound path
/// and return stdout as a UTF-8 string (lossy where invalid).
///
/// `file=-` writes to stdout instead of `filters.xml` in CWD.
/// `localaddr=127.0.0.1 dir=OUT` narrows to filters that could affect
/// outbound connects to localhost — the exact direction hanging in
/// #200. `verbose=on` includes the provider key GUID per filter so the
/// debug-level output has enough information to trace a leaked filter
/// back to its provider without needing a second `show providers` call.
fn run_netsh() -> std::io::Result<String> {
    let output = Command::new("netsh")
        .args([
            "wfp",
            "show",
            "filters",
            "localaddr=127.0.0.1",
            "dir=OUT",
            "verbose=on",
            "file=-",
        ])
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "netsh wfp show filters exited with {:?}; stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
