// GUI logging — delegates to shared logging in hole-common.

use hole_common::logging::LogGuard;
use std::path::Path;

/// Initialize GUI logging (stderr + size-rotated file).
pub fn init(log_dir: &Path) -> LogGuard {
    // The GUI runs unprivileged, so `gui.log` is already user-owned: `owner` is
    // `None` (no chown).
    let (file, stderr) = hole_common::logging::resolve_sink_directives("hole=info", None);
    hole_common::logging::init_dual(log_dir, "gui", "gui.log", &file, &stderr, None)
}

#[cfg(test)]
#[path = "logging_tests.rs"]
mod logging_tests;
