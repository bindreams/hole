//! Helper crate shared by `xtask` (the workspace task runner), the build.rs
//! version stamps, and the bridge update-cutover. Lives outside `xtask/` so
//! consumers can depend on it without dragging in `xtask`'s clap/glob/ureq
//! machinery.
//!
//! Modules are split by weight: `bindir` (the BINDIR name set + `Os`) and
//! `repo_root` need only `anyhow`, so the SYSTEM/root bridge cutover can use
//! `bindir` without linking a TOML parser. Group-aware version computation
//! (`version`/`ex_ray_version`) pulls `toml` + `semver` and is gated behind the
//! `version` feature.

pub mod asset;
pub mod bindir;
pub mod repo_root;

#[cfg(feature = "version")]
pub mod ex_ray_version;
#[cfg(feature = "version")]
pub mod version;

#[cfg(all(test, feature = "version"))]
mod test_support;

#[cfg(all(test, feature = "version"))]
#[path = "version_tests.rs"]
mod version_tests;

#[cfg(all(test, feature = "version"))]
#[path = "ex_ray_version_tests.rs"]
mod ex_ray_version_tests;

#[cfg(test)]
#[path = "asset_tests.rs"]
mod asset_tests;

#[cfg(test)]
#[path = "repo_root_tests.rs"]
mod repo_root_tests;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
