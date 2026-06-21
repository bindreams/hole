//! Bridge logging — delegates to shared logging in hole-common.

use hole_common::logging::LogGuard;
use std::path::Path;

/// Initialize bridge logging (stderr + size-rotated file).
///
/// File sink: `HOLE_BRIDGE_LOG` (comma-separated directives), else `HOLE_LOG`,
/// else the default `hole_bridge=info`. Stderr sink: `HOLE_LOG_STDERR` if set,
/// else mirrors the file sink — so an unset environment behaves exactly as
/// before. `RUST_LOG` is honored upstream of both via `from_env_lossy`.
///
/// `owner` (the real user's `(uid, gid)` on macOS) is threaded into
/// [`hole_common::logging::init_dual`] so the elevated bridge hands `bridge.log`
/// and its log dir back to the user; `None` off-macOS / for the unprivileged GUI.
pub fn init(log_dir: &Path, owner: Option<(u32, u32)>) -> LogGuard {
    let (file, stderr) = hole_common::logging::resolve_sink_directives("hole_bridge=info", Some("HOLE_BRIDGE_LOG"));
    hole_common::logging::init_dual(log_dir, "bridge", "bridge.log", &file, &stderr, owner)
}
