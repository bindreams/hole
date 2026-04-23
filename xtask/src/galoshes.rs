//! Build the galoshes sidecar. Post-monorepo-merge, galoshes is a
//! regular workspace member at `crates/galoshes/`; it embeds the
//! v2ray-plugin binary produced by [`super::v2ray_plugin::build`]
//! (which writes to `<repo>/.cache/v2ray-plugin/`, where galoshes's
//! `build.rs` picks it up).
//!
//! Output: `<repo>/target/release/galoshes{.exe}`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

/// Build (or rebuild) the galoshes binary in release mode. Assumes the
/// v2ray-plugin binary has already been produced at
/// `<repo>/.cache/v2ray-plugin/` by [`super::v2ray_plugin::build`] (which
/// is what `cargo xtask deps` does just before calling this).
pub fn build(repo_root: &Path) -> Result<PathBuf> {
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "galoshes"])
        .current_dir(repo_root)
        .status()
        .context("failed to run `cargo build -p galoshes`")?;

    if !status.success() {
        bail!(
            "`cargo build -p galoshes` failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }

    let exe_suffix = if cfg!(windows) { ".exe" } else { "" };
    let binary = repo_root
        .join("target")
        .join("release")
        .join(format!("galoshes{exe_suffix}"));

    if !binary.is_file() {
        return Err(anyhow!("galoshes binary not found at {} after build", binary.display()));
    }

    Ok(binary)
}
