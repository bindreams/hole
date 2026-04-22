//! Build the v2ray-plugin sidecar from `external/v2ray-plugin/` (Go source).
//!
//! This was previously [`crates/hole/build.rs::build_v2ray_plugin`] — moved
//! into xtask in Commit 4 because the v2ray-plugin binary is a runtime
//! dependency of the bridge, not a compile-time input to any Rust crate.
//! See issue #143.
//!
//! Output: `<repo>/.cache/v2ray-plugin/v2ray-plugin-<target-triple>{.exe}`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

/// Returns the platform-specific output filename matching what shadowsocks-rust
/// expects and what `crates/galoshes/build.rs` reads via
/// `v2ray-plugin-{TARGET}{ext}`. The trailing `.exe` is included on Windows.
///
/// Supports every target triple in the workspace CI matrix (Hole's
/// Windows/macOS release set plus the ex-Galoshes Linux / Windows-arm64
/// test matrix).
pub fn output_name() -> &'static str {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "v2ray-plugin-x86_64-pc-windows-msvc.exe"
    }
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        "v2ray-plugin-aarch64-pc-windows-msvc.exe"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "v2ray-plugin-aarch64-apple-darwin"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "v2ray-plugin-x86_64-apple-darwin"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "v2ray-plugin-x86_64-unknown-linux-gnu"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "v2ray-plugin-aarch64-unknown-linux-gnu"
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
    )))]
    compile_error!("unsupported platform for v2ray-plugin sidecar");
}

/// Build (or rebuild) the v2ray-plugin binary for the host platform.
///
/// Go's own build cache makes this near-instant if nothing changed; we
/// deliberately don't add our own freshness check on top.
pub fn build(repo_root: &Path) -> Result<PathBuf> {
    let source_dir = repo_root.join("external").join("v2ray-plugin");
    let output_dir = repo_root.join(".cache").join("v2ray-plugin");
    let output_path = output_dir.join(output_name());

    std::fs::create_dir_all(&output_dir).with_context(|| format!("failed to create {}", output_dir.display()))?;

    let status = Command::new("go")
        .args(["build", "-trimpath", "-ldflags=-s -w", "-o"])
        .arg(&output_path)
        .arg(".")
        .current_dir(&source_dir)
        .env("CGO_ENABLED", "0")
        .status();

    match status {
        Ok(s) if s.success() => Ok(output_path),
        Ok(s) => bail!("go build failed with exit code {}", s.code().unwrap_or(-1)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(anyhow!("Go toolchain not found. Install from https://go.dev/dl/"))
        }
        Err(e) => Err(anyhow!("failed to run go build: {e}")),
    }
}
