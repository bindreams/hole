// GUI logging — delegates to shared logging in hole-common.

use hole_common::logging::LogGuard;
use std::path::Path;

/// Initialize GUI logging (stderr + size-rotated file). `owner` is the person
/// `gui.log` is handed to when the process runs as root on their behalf; `None`
/// for a GUI that is already running as them.
pub fn init(log_dir: &Path, owner: Option<(u32, u32)>) -> LogGuard {
    let (file, stderr) = hole_common::logging::resolve_sink_directives("hole=info", None);
    hole_common::logging::init_dual(log_dir, "gui", "gui.log", &file, &stderr, owner)
}

#[cfg(test)]
#[path = "logging_tests.rs"]
mod logging_tests;
