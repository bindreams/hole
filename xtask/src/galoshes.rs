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
    let args = build_args(std::env::var_os("HOLE_CRASH_DUMPS").is_some(), cfg!(windows));
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

/// Cargo args for the galoshes release build.
///
/// `crash_dumps` is the `HOLE_CRASH_DUMPS` opt-in, set only by the `hole`
/// target's run: step — run-only, so `--all` and the release installers
/// never link `minidump-writer` (#438). `windows_host` gates it further,
/// because `.dmp` is a Windows-only branch: `minidump-writer` is declared
/// under `cfg(windows)` and the macOS `on_crash` has had no dump branch
/// since #842. Off Windows the opt-in must not even change the command
/// line — a different feature set is a different cargo fingerprint, which
/// bought a full release rebuild of galoshes and tombstone for nothing.
pub(crate) fn build_args(crash_dumps: bool, windows_host: bool) -> Vec<&'static str> {
    let mut args = vec!["build", "--release", "-p", "galoshes"];
    if crash_dumps && windows_host {
        args.push("--features");
        args.push("galoshes/crash-dumps");
    }
    args
}

/// Tauri-sidecar filename: `galoshes-<triple>{.exe}`. Tauri's bundler appends
/// the host triple to each `externalBin` path, so the macOS DMG needs galoshes
/// at `.cache/galoshes/galoshes-<triple>` to bundle it into `Contents/MacOS/`.
pub fn cache_sidecar_name() -> String {
    let exe = if cfg!(target_os = "windows") { ".exe" } else { "" };
    format!("galoshes-{}{exe}", crate::target::host_target_triple())
}
