//! Windows Filtering Platform (WFP) snapshot diagnostic.
//!
//! `log_snapshot(phase)` runs `netsh wfp show filters` for the loopback
//! outbound path and emits a three-tier structured trace:
//!
//! - **info** — one-liner with `phase`, match counts, and a boolean
//!   `wintun_related` flag. Always emitted so every bug report contains
//!   the verdict without needing debug logs.
//! - **warn** — when `phase == "post-teardown"` and we still see wintun-
//!   related filter references. Turns the known-bad case into something
//!   greppable by severity in an incoming user log.
//! - **debug** — full `netsh` stdout, truncated to 16 KB. Captures the
//!   specific filter name/GUID/layer that's implicated, only when the
//!   caller has turned debug on. No budget impact in production.
//!
//! # Why `netsh` and not `FwpmFilterEnum0` via the `windows` crate
//!
//! `netsh wfp show filters file=-` writes plaintext to stdout and, with
//! the `localaddr=127.0.0.1 dir=OUT` constraints, returns only filters
//! that could affect outbound loopback connects — exactly the set we
//! care about for #200. A Win32-API walk would be typed and cheaper but
//! requires wiring up `FwpmEngineOpen0` / `FwpmFilterEnum0` / handle
//! management, which is more code than the diagnostic warrants for the
//! first iteration. If the per-call cost or output-parsing fragility
//! becomes a problem, swap in the typed API without changing the log
//! schema — callers only see the `info!` / `warn!` / `debug!` output.
//!
//! # Elevation
//!
//! `show filters` requires Administrator on Windows. The bridge runs
//! elevated on Windows (needs admin for TUN + routes), so this call
//! always succeeds inside the bridge. If invoked from a non-elevated
//! context (shouldn't happen in production), `netsh` prints an error
//! and exits non-zero — we catch this and log a `warn!` instead of
//! panicking. See [`run_netsh`].

use std::process::Command;
use tracing::{debug, info, warn};

/// Case-insensitive substrings we scan for in the `netsh` output to
/// flag a likely wintun/WireGuard-owned filter still in the table.
/// Match list is intentionally broad — false positives are cheap
/// (one `info!` field), false negatives are the bug we're hunting.
const WATCH_SUBSTRINGS: &[&str] = &["wintun", "wireguard", "hole-tun"];

/// Truncation ceiling for the debug-level full-output field. 16 KB is
/// large enough to include a few dozen filter blocks (each is typically
/// 200-400 chars), small enough not to blow the size-rotated bridge log.
const DEBUG_OUTPUT_CAP_BYTES: usize = 16 * 1024;

/// Emit a WFP filter snapshot for the loopback outbound path.
///
/// `phase` is a static tag threaded through every log field so a log
/// scanner can correlate snapshots across the bridge lifecycle:
///
/// - `"startup"` — call once after crash-recovery completes but before
///   IPC serves its first request. Catches state left behind by a
///   prior bridge run that crashed before it could tear down.
/// - `"post-teardown"` — call from `SystemRoutes::drop` after
///   `teardown_routes` returns. Proves teardown removed everything it
///   installed. A post-teardown snapshot that still shows wintun
///   references is the #200 smoking gun (warn-level).
///
/// Callers pass the phase as `&'static str` — the value is cheap,
/// never user-controlled, and structured logging tags it as a
/// categorical field.
pub fn log_snapshot(phase: &'static str) {
    let output = match run_netsh() {
        Ok(o) => o,
        Err(e) => {
            warn!(phase, error = %e, "wfp snapshot: netsh invocation failed");
            return;
        }
    };

    let total_matches = WATCH_SUBSTRINGS
        .iter()
        .filter(|needle| output.to_lowercase().contains(**needle))
        .count() as u32;

    let matches: Vec<&&str> = WATCH_SUBSTRINGS
        .iter()
        .filter(|needle| output.to_lowercase().contains(**needle))
        .collect();

    info!(
        phase,
        total_matches,
        watched = ?matches,
        output_bytes = output.len() as u64,
        "wfp snapshot"
    );

    if phase == "post-teardown" && total_matches > 0 {
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

/// Truncate a string to at most `max_bytes` bytes without splitting a
/// UTF-8 code point. Walks back from `max_bytes` to the nearest char
/// boundary using `str::is_char_boundary`, so the returned slice is
/// always valid UTF-8 and callers can format it with `%` without risk
/// of malformed output.
fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

#[cfg(test)]
#[path = "wfp_tests.rs"]
mod wfp_tests;
