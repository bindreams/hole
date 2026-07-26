//! Launch vocabulary shared between the bin's clap definition and the lib.
//!
//! `cli.rs` is bin-only, so `relaunch` cannot name the flags it passes to a
//! successor. `cli_tests` asserts the flag constants still parse.

/// Opens the dashboard on launch. Accepted by every shipped build, so it is
/// safe to pass to a successor that may be an older image.
pub const SHOW_DASHBOARD: &str = "--show-dashboard";

/// Suppresses the dashboard on launch. Carried by the OS autostart
/// registration and by a successor inheriting a tray-only predecessor.
pub const NO_SHOW_DASHBOARD: &str = "--no-show-dashboard";

/// Set by a relaunching predecessor to suppress the successor's dashboard.
///
/// An env var rather than a flag because the successor may be an older build:
/// an unknown variable is inert, where an unknown flag is a parse error that
/// would stop the successor ever arming its exit-wait.
pub const NO_DASHBOARD_ENV: &str = "HOLE_NO_DASHBOARD";
