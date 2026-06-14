//! Build the ex-ray sidecar from `crates/ex-ray/` (Go source).
//!
//! The plugin binary is a runtime dependency of the bridge, not a
//! compile-time input to any Rust crate, so it lives in xtask rather than a
//! build.rs.
//!
//! Output: `<repo>/.cache/ex-ray/ex-ray-<target-triple>{.exe}`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

/// Returns the platform-specific output filename matching what shadowsocks-rust
/// expects and what `crates/galoshes/build.rs` reads via
/// `ex-ray-{TARGET}{ext}`. The trailing `.exe` is included on Windows.
pub fn output_name() -> String {
    let exe = if cfg!(target_os = "windows") { ".exe" } else { "" };
    format!("ex-ray-{}{exe}", crate::target::host_target_triple())
}

/// Build (or rebuild) the ex-ray binary for the host platform.
///
/// Go's own build cache makes this near-instant if nothing changed; we
/// deliberately don't add our own freshness check on top.
pub fn build(repo_root: &Path) -> Result<PathBuf> {
    let source_dir = repo_root.join("crates").join("ex-ray");
    let output_dir = repo_root.join(".cache").join("ex-ray");
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
