// Self-alias so modules compiled in BOTH the lib and the bin (e.g.
// `bridge_client`, `state`) can name this crate uniformly as `hole::`:
// `crate::version` breaks in the bin (no `mod version` there), `hole::version`
// breaks in the lib without this alias.
extern crate self as hole;

pub mod bridge_client;
#[macro_use]
pub mod cli_log;
pub mod commands;
pub mod config_recovery;
pub mod elevation;
pub mod logging;
pub mod path_management;
pub mod relaunch;
pub mod selfheal;
pub mod setup;
pub mod state;
pub mod tray_icons;
pub mod ui_ready;
pub mod ui_settings;
pub mod update;
pub mod version;

// Install the workspace test subscriber + panic hook. The dev-dep
// is gated on cfg(test) because it isn't linked in non-test builds.
// See `crates/test-observability/` and bindreams/hole#301.
#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    skuld::run_all();
}

#[cfg(test)]
#[path = "build_assets_tests.rs"]
mod build_assets_tests;

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
#[skuld::test]
fn debug_assertions_enabled() {
    assert!(
        cfg!(debug_assertions),
        "tests must be compiled with debug assertions enabled"
    );
}
