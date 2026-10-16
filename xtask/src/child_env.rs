//! The environment `cargo run` hands to xtask, and why no child may inherit it.
//!
//! `cargo xtask <cmd>` is `cargo run -p xtask`, so xtask runs with the package
//! environment of the xtask crate (`CARGO_MANIFEST_DIR`, `CARGO_PKG_*`, ...).
//! Every cargo xtask then spawns inherits it. Cargo records an environment
//! variable in a build script's fingerprint when the script prints
//! `rerun-if-env-changed` for it, and `ring`'s does so for `CARGO_MANIFEST_DIR`.
//! A build made through xtask and a later plain `cargo nextest run` therefore
//! disagree about that variable: `ring`'s build script reruns, and everything
//! that depends on `ring` (the whole shadowsocks and quinn stack) recompiles.
//! Children are launched without the injected variables so both spellings of a
//! build share one set of fingerprints.

use std::ffi::OsStr;
use std::process::Command;

/// Is `name` one of the variables `cargo run` sets for the program it launches?
///
/// Prefix rules rather than a fixed list: cargo adds `CARGO_PKG_*` fields over
/// time. The settings a caller chooses for every cargo they run (`CARGO_HOME`,
/// `CARGO_INCREMENTAL`, `CARGO_TARGET_DIR`, ...) match neither prefix.
pub fn is_run_injected(name: &str) -> bool {
    name.starts_with("CARGO_PKG_") || name.starts_with("CARGO_MANIFEST_")
}

/// Stop `cmd` from inheriting the variables `cargo run` injected into this process.
pub fn scrub(cmd: &mut Command) -> &mut Command {
    scrub_names(cmd, std::env::vars_os().map(|(name, _)| name))
}

/// [`scrub`] over an explicit list of inherited variable names.
pub(crate) fn scrub_names<S: AsRef<OsStr>>(cmd: &mut Command, inherited: impl IntoIterator<Item = S>) -> &mut Command {
    for name in inherited {
        if name.as_ref().to_str().is_some_and(is_run_injected) {
            cmd.env_remove(name);
        }
    }
    cmd
}

#[cfg(test)]
#[path = "child_env_tests.rs"]
mod child_env_tests;
