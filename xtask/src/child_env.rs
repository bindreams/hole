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
//! share one set of fingerprints. It first records the names it was launched with
//! ([`launch_env_names`]), which `verify-run-injected-env` checks against a real
//! `cargo run` (see `run_injected_env`).
//!
//! `CARGO_MANIFEST_DIR` is also how [`xtask_lib::repo_root::repo_root`] finds
//! the workspace when the binary does not live under it (a `CARGO_TARGET_DIR`
//! or `build.target-dir` elsewhere). The strip therefore resolves the root
//! first and [`repo_root`] answers from that, so no caller has to know the
//! variable is gone.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::Result;

/// The workspace root, or why there is none, as resolved by
/// [`strip_run_injected`] before it removed the variables the lookup reads. The
/// failure is kept (as text: `anyhow::Error` is not `Clone`) because a lookup
/// repeated after the strip cannot see a bad `CARGO_MANIFEST_DIR` and would
/// answer from the executable's location instead.
static WORKSPACE_ROOT: OnceLock<std::result::Result<PathBuf, String>> = OnceLock::new();

/// The names this process was launched with, recorded by [`strip_run_injected`]
/// before it removed any.
static LAUNCH_ENV_NAMES: OnceLock<Vec<OsString>> = OnceLock::new();

/// The workspace root. After [`strip_run_injected`] this is what it resolved at
/// startup; before it (tests, library callers) it is looked up now.
pub fn repo_root() -> Result<PathBuf> {
    match WORKSPACE_ROOT.get() {
        Some(Ok(root)) => Ok(root.clone()),
        Some(Err(why)) => Err(anyhow::anyhow!("{why}")),
        None => xtask_lib::repo_root::repo_root(),
    }
}

/// The names this process was launched with, as [`strip_run_injected`] saw them
/// before it removed any; `None` until it has run.
pub fn launch_env_names() -> Option<&'static [OsString]> {
    LAUNCH_ENV_NAMES.get().map(Vec::as_slice)
}

/// Is `name` one of the variables `cargo run` sets for the program it launches?
///
/// Prefix rules rather than a fixed list: cargo adds `CARGO_PKG_*` fields over
/// time. The settings a caller chooses for every cargo they run (`CARGO_HOME`,
/// `CARGO_INCREMENTAL`, `CARGO_TARGET_DIR`, ...) match neither prefix.
pub fn is_run_injected(name: &str) -> bool {
    name.starts_with("CARGO_PKG_") || name.starts_with("CARGO_MANIFEST_")
}

/// Remove the variables `cargo run` injected from this process's environment,
/// after resolving the workspace root from them (see the module doc). A root
/// that cannot be found here is not an error yet: [`repo_root`] reports it to
/// the subcommand that needs it.
///
/// Call it first thing in `main`, before any thread exists: `remove_var` races
/// with every concurrent environment read.
pub fn strip_run_injected() {
    let _ = WORKSPACE_ROOT.set(xtask_lib::repo_root::repo_root().map_err(|e| format!("{e:#}")));
    let launch: Vec<OsString> = std::env::vars_os().map(|(name, _)| name).collect();
    let injected: Vec<OsString> = launch
        .iter()
        .filter(|name| name.to_str().is_some_and(is_run_injected))
        .cloned()
        .collect();
    let _ = LAUNCH_ENV_NAMES.set(launch);
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
