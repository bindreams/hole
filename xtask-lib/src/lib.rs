//! Helper crate shared by `xtask` (the workspace task runner) and
//! `crates/gui/build.rs`. Lives outside `xtask/` so that `crates/gui/build.rs`
//! can depend on it as a build-dependency without dragging in `xtask`'s
//! clap/glob/ureq machinery.
//!
//! See issue #143 for the motivation: version computation was previously
//! duplicated across `crates/gui/build.rs::compute_git_version`,
//! `msi-installer/src/msi_installer/__init__.py::get_version`, and
//! `scripts/check-version.py`. This crate is the single source of truth.

pub mod version;

#[cfg(test)]
#[path = "version_tests.rs"]
mod version_tests;

#[cfg(test)]
fn main() {
    skuld::run_all();
}
