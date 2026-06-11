//! Helper crate shared by `xtask` (the workspace task runner) and
//! `crates/hole/build.rs`. Lives outside `xtask/` so that `crates/hole/build.rs`
//! can depend on it as a build-dependency without dragging in `xtask`'s
//! clap/glob/ureq machinery.
//!
//! This crate is the single source of truth for group-aware version
//! computation, shared by `crates/hole/build.rs` and `xtask` (`cargo xtask
//! version`) instead of being reimplemented per consumer — so the logic
//! stays testable in one place.

pub mod ex_ray_version;
pub mod repo_root;
pub mod version;

#[cfg(test)]
mod test_support;

#[cfg(test)]
#[path = "version_tests.rs"]
mod version_tests;

#[cfg(test)]
#[path = "ex_ray_version_tests.rs"]
mod ex_ray_version_tests;

#[cfg(test)]
#[path = "repo_root_tests.rs"]
mod repo_root_tests;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
