//! Process-scoped skuld fixture that stages the dist directory.
//!
//! Calls `xtask::run_stage(Profile::Debug, &dist_bin)` exactly once per
//! test binary invocation. Hardlinks are idempotent and cheap — the
//! staging cost is dominated by `create_dir_all` + file metadata probes,
//! ~10ms total.
//!
//! The staged directory lives at `target/debug/dist/bin/` inside the
//! workspace root. Paths:
//!
//! - `target/debug/dist/bin/hole[.exe]` — the bridge/GUI binary
//! - `target/debug/dist/bin/v2ray-plugin[.exe]` — the Go plugin sidecar
//! - `target/debug/dist/bin/wintun.dll` (Windows only)
//!
//! Each `DistHarness::spawn()` call runs `hole bridge run` from that
//! directory, which means `current_exe()` is `dist/bin/hole` and
//! `resolve_plugin_path` finds `v2ray-plugin` next to it — the same
//! resolution path production uses.
//!
//! ## Concurrency
//!
//! Skuld's process-scoped fixture implementation has a race: the setup
//! function can be invoked concurrently from multiple threads because
//! the "not in cache" check and the `(setup)()` call happen under
//! different lock acquisitions in
//! `skuld::fixture::ensure_process_fixture`. Two parallel `run_stage`
//! calls would race on the same destination files (`remove_file` by one
//! thread + `hard_link` by another → `os error 32` on Windows).
//!
//! Mitigation: guard the actual staging behind a `OnceLock` inside this
//! module. Skuld may call `dist_dir()` twice, but only the first caller
//! runs `xtask::run_stage`; the rest observe the already-staged path.

use std::path::PathBuf;
use std::sync::OnceLock;
use xtask::Profile;

/// Singleton guarding the actual `run_stage` call. Skuld's process
/// fixture cache can race; this enforces one-and-only-one staging.
static STAGED_DIST_BIN: OnceLock<Result<PathBuf, String>> = OnceLock::new();

/// Stage the dist directory and return its absolute `bin/` path.
///
/// Process-scoped so the staging work happens at most once per test
/// binary. The return value is reused by every `DistHarness::spawn`
/// call — tests only borrow the path; they never mutate the directory.
///
/// `deref` lets tests request the fixture as `&Path` (via `Deref::Target`)
/// instead of `&PathBuf`.
#[skuld::fixture(scope = process, deref)]
pub(crate) fn dist_dir() -> Result<PathBuf, String> {
    STAGED_DIST_BIN
        .get_or_init(|| {
            let repo_root = xtask::repo_root().map_err(|e| format!("locate workspace root: {e}"))?;
            let dist_bin = repo_root.join("target").join("debug").join("dist").join("bin");

            xtask::run_stage(Profile::Debug, &dist_bin).map_err(|e| {
                format!(
                    "xtask::run_stage into {dist_bin:?} failed: {e}\n\
                     (did you forget `cargo xtask deps && cargo build --workspace`?)"
                )
            })?;
            Ok(dist_bin)
        })
        .clone()
}
