// GUI logging — delegates to shared logging in hole-common.

use hole_common::logging::LogGuard;
use std::path::Path;

/// Initialize GUI logging (stderr + rolling daily file).
pub fn init(log_dir: &Path) -> LogGuard {
    hole_common::logging::init(log_dir, "gui.log", "hole_gui=info")
}

#[cfg(test)]
#[path = "logging_tests.rs"]
mod logging_tests;
