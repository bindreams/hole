//! Build the galoshes sidecar (workspace member `crates/galoshes/`). It
//! embeds the ex-ray binary produced by [`super::ex_ray::build`]
//! (written to `<repo>/.cache/ex-ray/`, where galoshes's `build.rs` picks
//! it up).
//!
//! Output: `<repo>/target/release/galoshes{.exe}`, plus a Tauri-sidecar copy
//! at `<repo>/.cache/galoshes/galoshes-<triple>{.exe}` for the macOS DMG.

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

    // Also stage a Tauri-sidecar copy at `.cache/galoshes/galoshes-<triple>`.
    // `npx tauri build` (the macOS DMG path) bundles `externalBin` entries by
    // appending the host triple, mirroring how ex-ray lands in `.cache/ex-ray/`.
    let cache_dir = repo_root.join(".cache").join("galoshes");
    std::fs::create_dir_all(&cache_dir).with_context(|| format!("failed to create {}", cache_dir.display()))?;
    let sidecar = cache_dir.join(cache_sidecar_name());
    std::fs::copy(&binary, &sidecar)
        .with_context(|| format!("failed to stage galoshes sidecar to {}", sidecar.display()))?;

    Ok(binary)
}

/// Tauri-sidecar filename: `galoshes-<triple>{.exe}`. Tauri's bundler appends
/// the host triple to each `externalBin` path, so the macOS DMG needs galoshes
/// at `.cache/galoshes/galoshes-<triple>` to bundle it into `Contents/MacOS/`.
pub fn cache_sidecar_name() -> String {
    let exe = if cfg!(target_os = "windows") { ".exe" } else { "" };
    format!("galoshes-{}{exe}", crate::target::host_target_triple())
}
