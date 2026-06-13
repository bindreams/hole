//! Build the galoshes sidecar (workspace member `crates/galoshes/`). It
//! embeds the ex-ray binary produced by [`super::ex_ray::build`]
//! (written to `<repo>/.cache/ex-ray/`, where galoshes's `build.rs` picks
//! it up).
//!
//! Output: `<repo>/target/release/galoshes{.exe}`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

/// Build (or rebuild) the galoshes binary in release mode. Assumes the
/// ex-ray binary has already been produced at
/// `<repo>/.cache/ex-ray/` by [`super::ex_ray::build`] (which
/// is what `cargo xtask deps` does just before calling this).
pub fn build(repo_root: &Path) -> Result<PathBuf> {
    // Dev-only minidump opt-in (bindreams/hole#438). dev-console sets
    // HOLE_CRASH_DUMPS=1; release / standalone galoshes builds do not, so
    // minidump-writer never links into the windows-arm64 galoshes matrix.
    let mut args: Vec<&str> = vec!["build", "--release", "-p", "galoshes"];
    if std::env::var_os("HOLE_CRASH_DUMPS").is_some() {
        args.push("--features");
        args.push("galoshes/crash-dumps");
    }
    let status = Command::new("cargo")
        .args(&args)
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
