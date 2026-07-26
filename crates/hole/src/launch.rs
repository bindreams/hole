//! Launch vocabulary shared between the bin's clap definition and the lib.
//!
//! `cli.rs` and `dashboard.rs` are bin-only, so `relaunch` and `selfheal`
//! cannot name the flags they pass to a successor or the window labels they
//! inspect. `cli_tests` asserts the flag constants still parse.

/// Opens the dashboard on launch. Accepted by every shipped build, so it is
/// safe to pass to a successor that may be an older image.
pub const SHOW_DASHBOARD: &str = "--show-dashboard";

/// Suppresses the dashboard on launch. Carried by the OS autostart
/// registration and by a successor inheriting a tray-only predecessor.
pub const NO_SHOW_DASHBOARD: &str = "--no-show-dashboard";

/// Every dashboard window's label starts with this. Must match the capability
/// glob `dashboard-*` in `capabilities/default.json`.
pub const DASHBOARD_LABEL_PREFIX: &str = "dashboard-";

/// Whether any live window means the user had the dashboard open.
///
/// Only dashboards are ever built (`tauri.conf.json` declares no static
/// windows). The assertion fires in dev and tests if a second window kind is
/// ever added, because callers use window presence as a proxy for "dashboard
/// open" and that proxy would silently start lying.
pub fn dashboard_is_open<'a>(labels: impl Iterator<Item = &'a str>) -> bool {
    let mut open = false;
    for label in labels {
        debug_assert!(
            label.starts_with(DASHBOARD_LABEL_PREFIX),
            "window label {label:?} is not a dashboard; window presence no longer implies a dashboard"
        );
        open = true;
    }
    open
}

#[cfg(test)]
#[path = "launch_tests.rs"]
mod launch_tests;
