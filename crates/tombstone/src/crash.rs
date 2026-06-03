use std::path::Path;

/// Install the process-global native-crash handler. Idempotent. Best-effort:
/// on failure logs a `tracing::warn!` and returns — never panics. `kind`
/// labels the marker ("gui", "bridge", "gui-cli", "galoshes", "test").
/// `log_dir` must be user-readable even for the elevated bridge (the marker
/// inherits its perms).
pub fn attach(kind: &'static str, log_dir: &Path) {
    let _ = (kind, log_dir);
    // Implemented in the attach task.
}

/// Scan `log_dir` for `crash-*.marker`, emit one
/// `tracing::error!(target: "crash", …)` breadcrumb per marker, then delete
/// the marker (leaving any sibling `.dmp`). Best-effort; tolerant of
/// malformed/partial markers.
pub fn sweep(log_dir: &Path) {
    let _ = log_dir;
    // Implemented in the sweep task.
}

#[cfg(test)]
#[path = "crash_tests.rs"]
mod crash_tests;
