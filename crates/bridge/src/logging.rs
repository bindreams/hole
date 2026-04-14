// Bridge logging — delegates to shared logging in hole-common.

use hole_common::logging::LogGuard;
use std::path::Path;

/// Initialize bridge logging (stderr + size-rotated file).
///
/// The default directive is `hole_bridge=info`. Set `HOLE_BRIDGE_LOG` to
/// override — a single directive (`hole_bridge=debug`) or a comma-separated
/// list (`hole_bridge=debug,shadowsocks_service=debug`).
///
/// `hole_common::logging::init` accepts only a single directive string, so
/// when the env var contains commas we split here and pass through the
/// first directive (the one most likely to be the "interesting" one for
/// the bridge crate). Additional directives are dropped — callers that
/// need multi-crate filtering should set `RUST_LOG` instead, which is read
/// by `from_env_lossy()` upstream.
///
/// We deliberately rely on leaving `RUST_LOG` unset (when only
/// `HOLE_BRIDGE_LOG` is set) so `from_env_lossy()` yields an empty filter
/// that does not compete with our directive at equal specificity.
pub fn init(log_dir: &Path) -> LogGuard {
    let raw = std::env::var("HOLE_BRIDGE_LOG").unwrap_or_else(|_| "hole_bridge=info".to_string());
    // `add_directive` parses ONE directive. Split on commas and pass each
    // through; any well-formed prefix wins. To avoid changing the common
    // init signature, we forward the first directive and let callers union
    // additional ones via RUST_LOG (read by `from_env_lossy`). For our
    // primary use case (bridge debug only), one directive is enough.
    let primary = raw.split(',').next().unwrap_or("hole_bridge=info").trim();
    hole_common::logging::init(log_dir, "bridge.log", primary)
}
