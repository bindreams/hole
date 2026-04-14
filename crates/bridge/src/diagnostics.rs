// Bridge runtime diagnostics — cross-cutting observability helpers.
//
// Modules here emit through the standard `tracing` subscriber so whatever
// shows up in CI also shows up in user bug reports via `hole bridge log`.
// Nothing here owns state beyond the single-call execution; these are
// "take a snapshot and log it" helpers, not long-lived subsystems.
//
// # Shared conventions
//
// - Every submodule exposes `log_snapshot(phase: &'static str)` that
//   runs its probe(s) and emits `info!` / `warn!` / `debug!` tiered
//   output. See `wfp.rs` for the canonical shape.
// - `WATCH_SUBSTRINGS` is the case-insensitive set of strings we treat
//   as "possible wintun/hole residue" across all probes. Kept here so
//   adding a new watch word (e.g. a different TUN driver someday)
//   updates every probe at once.
// - `DEBUG_OUTPUT_CAP_BYTES` caps debug-level output sizes per probe
//   source so the bridge's size-rotated log file cannot be blown out
//   by a single snapshot even when a probe produces multi-MB output.

#[cfg(target_os = "windows")]
pub mod etw;
#[cfg(target_os = "windows")]
pub mod ndis;
#[cfg(target_os = "windows")]
pub mod wfp;

/// Case-insensitive substrings used across probes to flag residue from
/// wintun / WireGuard-derived TUN drivers / our own adapter name.
/// Match list is intentionally broad — false positives are cheap (one
/// structured field in a log line), false negatives are the bug we are
/// hunting.
#[cfg(target_os = "windows")]
pub(crate) const WATCH_SUBSTRINGS: &[&str] = &["wintun", "wireguard", "hole-tun"];

/// Truncation ceiling for debug-level per-probe output. 16 KB is large
/// enough to include a few dozen filter / binding / driver blocks (each
/// is typically 200-400 chars), small enough not to blow the size-
/// rotated bridge log file when multiple snapshots fire in one run.
#[cfg(target_os = "windows")]
pub(crate) const DEBUG_OUTPUT_CAP_BYTES: usize = 16 * 1024;

/// Return how many of `WATCH_SUBSTRINGS` appear in `text` (case-insensitive)
/// and the list of the matched substrings. The count is the length of
/// the returned `Vec` — returned separately so info-level structured
/// logs can include both as discrete fields without re-computing.
#[cfg(target_os = "windows")]
pub(crate) fn watched_matches(text: &str) -> Vec<&'static str> {
    let lower = text.to_lowercase();
    WATCH_SUBSTRINGS
        .iter()
        .filter(|needle| lower.contains(**needle))
        .copied()
        .collect()
}

/// Truncate a string to at most `max_bytes` bytes without splitting a
/// UTF-8 code point. Walks back from `max_bytes` to the nearest char
/// boundary using `str::is_char_boundary`, so the returned slice is
/// always valid UTF-8 and callers can format it with `%` without risk
/// of malformed output in the tracing subscriber's file layer.
#[cfg(target_os = "windows")]
pub(crate) fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

#[cfg(all(test, target_os = "windows"))]
#[path = "diagnostics_tests.rs"]
mod diagnostics_tests;
