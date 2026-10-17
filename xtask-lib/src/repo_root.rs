//! Workspace-root discovery shared by xtask and dev-console.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Locate the workspace root: walk up from `CARGO_MANIFEST_DIR` (set by
/// `cargo run` at runtime for the binary's own crate dir) and, failing that,
/// from the executable's location, until a `Cargo.toml` containing
/// `[workspace]` is found.
///
/// Deliberately no `git rev-parse --show-toplevel` — this must work where
/// git is unavailable (CI minimal images, source tarballs).
pub fn repo_root() -> Result<PathBuf> {
    if let Some(manifest_dir) = std::env::var_os("CARGO_MANIFEST_DIR") {
        if let Ok(root) = repo_root_from(Path::new(&manifest_dir)) {
            return Ok(root);
        }
    }
    let exe = std::env::current_exe().context("current_exe")?;
    repo_root_from(exe.parent().unwrap_or(Path::new("/")))
}

/// The hole checkout a binary a build driver launched belongs to: the first of
/// `CARGO_MANIFEST_DIR`, the executable's location and the working directory
/// whose enclosing workspace is a hole root (has `crates/hole`).
///
/// Only a hole root is accepted, so a launch from inside some other workspace
/// (or another hole checkout, when the executable is in this one) cannot
/// redirect the lookup. The executable comes before the working directory,
/// which is the fallback for a `target/` symlinked out of the tree (on Linux
/// `current_exe` is then canonical and its walk-up misses the checkout):
/// `cargo xtask run hole` launches dev-console with the root it pinned as the
/// working directory and strips `CARGO_MANIFEST_DIR` from the environment.
///
/// Errors name each location tried.
pub fn repo_root_from_launch_dir() -> Result<PathBuf> {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from);
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let cwd = std::env::current_dir().ok();
    hole_root_for_launch(manifest_dir.as_deref(), exe_dir.as_deref(), cwd.as_deref())
}

/// [`repo_root_from_launch_dir`] over explicit locations (`None`: unavailable),
/// so tests need not touch the process environment. The parameter order is the
/// lookup order.
pub(crate) fn hole_root_for_launch(
    manifest_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    cwd: Option<&Path>,
) -> Result<PathBuf> {
    let candidates = [
        ("CARGO_MANIFEST_DIR", manifest_dir),
        ("executable", exe_dir),
        ("working directory", cwd),
    ];
    let mut tried = Vec::new();
    for (what, start) in candidates {
        let Some(start) = start else {
            tried.push(format!("{what}: unavailable"));
            continue;
        };
        match repo_root_from(start) {
            Ok(root) if root.join("crates").join("hole").is_dir() => return Ok(root),
            Ok(root) => tried.push(format!(
                "{what} {}: workspace {} is not the hole root (no crates/hole)",
                start.display(),
                root.display()
            )),
            Err(_) => tried.push(format!("{what} {}: no workspace above it", start.display())),
        }
    }
    anyhow::bail!("could not locate the hole root; tried {}", tried.join("; "))
}

/// Walk-up core, separated for tests.
pub fn repo_root_from(start: &Path) -> Result<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join("Cargo.toml");
        if candidate.is_file() {
            // Naive [workspace] substring check; the alternative would pull
            // in `toml` parsing for one read. (Same trade as the original
            // xtask fn this generalizes.)
            if let Ok(s) = std::fs::read_to_string(&candidate) {
                if s.contains("[workspace]") {
                    return Ok(dir);
                }
            }
        }
        if !dir.pop() {
            anyhow::bail!(
                "could not locate the workspace root walking up from {}",
                start.display()
            );
        }
    }
}
