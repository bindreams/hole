// Bridge logging — delegates to shared logging in hole-common.

use hole_common::logging::LogGuard;
use std::path::Path;

/// Initialize bridge logging (stderr + size-rotated file).
///
/// The default directive is `hole_bridge=info`. Set `HOLE_BRIDGE_LOG` to
/// override — e.g. `hole_bridge=debug,shadowsocks_service=debug` for
/// diagnostic runs. We pass the value through `add_directive` in
/// `hole_common::logging::init` and deliberately rely on leaving `RUST_LOG`
/// unset so `from_env_lossy()` yields an empty filter that does not
/// compete with our directive at equal specificity.
pub fn init(log_dir: &Path) -> LogGuard {
    let directive = std::env::var("HOLE_BRIDGE_LOG").unwrap_or_else(|_| "hole_bridge=info".to_string());
    hole_common::logging::init(log_dir, "bridge.log", &directive)
}
