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
