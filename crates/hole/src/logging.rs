// GUI logging — delegates to shared logging in hole-common.

use hole_common::logging::LogGuard;
use std::path::Path;

/// Initialize GUI logging (stderr + size-rotated file).
pub fn init(log_dir: &Path) -> LogGuard {
    // The GUI runs unprivileged, so `gui.log` is already user-owned: no chown.
    hole_common::logging::init(log_dir, "gui", "gui.log", "hole=info", None)
}

#[cfg(test)]
#[path = "logging_tests.rs"]
mod logging_tests;
