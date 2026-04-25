// Bridge logging — delegates to shared logging in hole-common.

use hole_common::logging::LogGuard;
use std::path::Path;

/// Initialize bridge logging (stderr + size-rotated file).
///
/// The default directive is `hole_bridge=info`. Set `HOLE_BRIDGE_LOG` to
/// override — a single directive (`hole_bridge=debug`) or a comma-separated
/// list (`hole_bridge=debug,shadowsocks_service=trace`).
///
/// All comma-separated directives are honored: the env var is split, each
/// piece is trimmed, blanks are dropped, and the rest are passed to
/// `EnvFilter::add_directive` in order via [`hole_common::logging::init_multi`].
/// Pre-#267 only the first directive made it through, which silently hid
/// shadowsocks-service's relay byte-count TRACE logs (`L2R N bytes, R2L M
/// bytes`) — the load-bearing diagnostic for #248.
///
/// `RUST_LOG` is also still honored upstream of the directive list (via
/// `EnvFilter::from_env_lossy` inside `init_multi`), so e.g.
/// `RUST_LOG=shadowsocks_service=trace HOLE_BRIDGE_LOG=hole_bridge=debug`
/// composes the same way.
pub fn init(log_dir: &Path) -> LogGuard {
    let raw = std::env::var("HOLE_BRIDGE_LOG").unwrap_or_else(|_| "hole_bridge=info".to_string());
    let directives = parse_directives(&raw);
    // Empty / whitespace-only env var falls back to the default rather than
    // passing zero directives to `init_multi` (which would let the global
    // INFO default win without any bridge-specific override).
    if directives.is_empty() {
        hole_common::logging::init_multi(log_dir, "bridge.log", ["hole_bridge=info"])
    } else {
        hole_common::logging::init_multi(log_dir, "bridge.log", directives)
    }
}

/// Split a comma-separated `HOLE_BRIDGE_LOG`-style value into its
/// component directives. Trims whitespace around each piece and drops
/// blanks (so trailing commas / `a,, b` don't produce empty filters).
///
/// Pulled into a named function so the splitting rules are unit-testable
/// without standing up the global subscriber.
fn parse_directives(raw: &str) -> Vec<&str> {
    raw.split(',').map(str::trim).filter(|s| !s.is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::parse_directives;

    #[skuld::test]
    fn single_directive_yields_one_element() {
        assert_eq!(parse_directives("hole_bridge=debug"), vec!["hole_bridge=debug"]);
    }

    #[skuld::test]
    fn comma_separated_yields_each_directive_in_order() {
        assert_eq!(
            parse_directives("hole_bridge=debug,shadowsocks_service=trace"),
            vec!["hole_bridge=debug", "shadowsocks_service=trace"],
        );
    }

    #[skuld::test]
    fn whitespace_around_directives_is_trimmed() {
        assert_eq!(
            parse_directives("  hole_bridge=debug ,\tshadowsocks_service=trace  "),
            vec!["hole_bridge=debug", "shadowsocks_service=trace"],
        );
    }

    #[skuld::test]
    fn empty_string_yields_no_directives() {
        assert!(parse_directives("").is_empty());
    }

    #[skuld::test]
    fn whitespace_only_yields_no_directives() {
        assert!(parse_directives("   \t  ").is_empty());
    }

    #[skuld::test]
    fn trailing_and_doubled_commas_drop_blanks() {
        assert_eq!(
            parse_directives("hole_bridge=debug,,shadowsocks_service=trace,"),
            vec!["hole_bridge=debug", "shadowsocks_service=trace"],
        );
    }

    #[skuld::test]
    fn three_directives_preserved() {
        assert_eq!(
            parse_directives("hole_bridge=debug,shadowsocks_service=trace,hyper=warn"),
            vec!["hole_bridge=debug", "shadowsocks_service=trace", "hyper=warn"],
        );
    }
}
