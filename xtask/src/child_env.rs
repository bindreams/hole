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
//! [`strip_run_injected`] removes the variables from xtask's own environment
//! once, at startup, so no spawn can inherit them and both spellings of a build
//! share one set of fingerprints.

use std::ffi::OsString;

/// Is `name` one of the variables `cargo run` sets for the program it launches?
///
/// Prefix rules rather than a fixed list: cargo adds `CARGO_PKG_*` fields over
/// time. The settings a caller chooses for every cargo they run (`CARGO_HOME`,
/// `CARGO_INCREMENTAL`, `CARGO_TARGET_DIR`, ...) match neither prefix.
pub fn is_run_injected(name: &str) -> bool {
    name.starts_with("CARGO_PKG_") || name.starts_with("CARGO_MANIFEST_")
}

/// Remove the variables `cargo run` injected from this process's environment.
///
/// Call it first thing in `main`, before any thread exists: `remove_var` races
/// with every concurrent environment read.
pub fn strip_run_injected() {
    let injected: Vec<OsString> = std::env::vars_os()
        .map(|(name, _)| name)
        .filter(|name| name.to_str().is_some_and(is_run_injected))
        .collect();
    for name in injected {
        // SAFETY: single-threaded by the caller's contract (see above), so no other
        // thread can be reading or writing the environment. In `xtask`'s `main`
        // nothing precedes the call but std's runtime start, which spawns no thread.
        std::env::remove_var(name);
    }
}

#[cfg(test)]
#[path = "child_env_tests.rs"]
mod child_env_tests;
