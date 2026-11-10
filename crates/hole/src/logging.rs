// GUI logging — delegates to shared logging in hole-common.

use hole_common::logging::LogGuard;
use std::path::Path;
use util::dir::Principal;

/// Initialize GUI logging (stderr + size-rotated file). `principal` is the running process's privilege
/// (`stepstool::principal`): a GUI run under `sudo` is privileged and walks the user's folder as the system.
pub fn init(log_dir: &Path, principal: Principal) -> LogGuard {
    // The GUI writes its own `gui.log`, so `owner` is `None` (no chown).
    let (file, stderr) = hole_common::logging::resolve_sink_directives("hole=info", None);
    hole_common::logging::init_dual(log_dir, "gui", "gui.log", &file, &stderr, None, principal)
}

#[cfg(test)]
#[path = "logging_tests.rs"]
mod logging_tests;
