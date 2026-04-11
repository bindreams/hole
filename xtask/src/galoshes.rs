//! Build the galoshes sidecar from `external/galoshes/`.
//!
//! Galoshes embeds its own v2ray-plugin at compile time, so we first build
//! v2ray-plugin inside the galoshes workspace, then build galoshes itself.
//!
//! Output: `external/galoshes/target/release/galoshes{.exe}`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

/// Build (or rebuild) the galoshes binary.
///
/// Steps:
/// 1. Build galoshes' embedded v2ray-plugin via its own xtask.
/// 2. Build the galoshes binary in release mode.
pub fn build(repo_root: &Path) -> Result<PathBuf> {
    let galoshes_root = repo_root.join("external").join("galoshes");
    if !galoshes_root.join("Cargo.toml").is_file() {
        bail!(
            "galoshes workspace not found at {}. Did `git subrepo clone` run?",
            galoshes_root.display()
        );
    }

    build_embedded_v2ray_plugin(&galoshes_root)?;
    build_galoshes_binary(&galoshes_root)
}

/// Build v2ray-plugin inside the galoshes workspace using its own xtask.
fn build_embedded_v2ray_plugin(galoshes_root: &Path) -> Result<()> {
    let status = Command::new("cargo")
        .args(["xtask", "v2ray-plugin"])
        .current_dir(galoshes_root)
        .status()
        .context("failed to run `cargo xtask v2ray-plugin` in galoshes workspace")?;

    if !status.success() {
        bail!(
            "`cargo xtask v2ray-plugin` in galoshes failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

/// Build the galoshes binary in release mode.
fn build_galoshes_binary(galoshes_root: &Path) -> Result<PathBuf> {
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "galoshes"])
        .current_dir(galoshes_root)
        .status()
        .context("failed to run `cargo build -p galoshes` in galoshes workspace")?;

    if !status.success() {
        bail!(
            "`cargo build -p galoshes` failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }

    let exe_suffix = if cfg!(windows) { ".exe" } else { "" };
    let binary = galoshes_root
        .join("target")
        .join("release")
        .join(format!("galoshes{exe_suffix}"));

    if !binary.is_file() {
        return Err(anyhow!("galoshes binary not found at {} after build", binary.display()));
    }

    Ok(binary)
}
