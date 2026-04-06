// Bridge logging — delegates to shared logging in hole-common.

use hole_common::logging::LogGuard;
use std::path::Path;

/// Initialize bridge logging (stderr + rolling daily file).
pub fn init(log_dir: &Path) -> LogGuard {
    hole_common::logging::init(log_dir, "bridge.log", "hole_bridge=info")
}
