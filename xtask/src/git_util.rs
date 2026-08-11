//! Small shared helpers for xtask modules that shell out to `git`.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Run `git <args>` in `cwd`, returning trimmed stdout on success and a
/// descriptive error (including stderr) on failure.
pub fn run_git(cwd: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to run git {args:?}"))?;
    if !output.status.success() {
        bail!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
