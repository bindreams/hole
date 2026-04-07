//! The canonical list of files that comprise a runnable hole BINDIR.
//!
//! **This is the single source of truth.** Adding a new file that must sit
//! next to `hole.exe` is one line in `bindir_files()` below — both
//! `scripts/dev.py` and `msi-installer/__init__.py:stage_files()` call into
//! this via `cargo xtask stage`, so they pick it up automatically.
//!
//! See issue #143 for the motivation.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::Profile;

/// One file that must end up in BINDIR alongside the bridge binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindirFile {
    /// Absolute source path on disk.
    pub source: PathBuf,
    /// Filename to use in the destination directory (no path components).
    pub dest_name: String,
}

impl BindirFile {
    pub fn new(source: PathBuf, dest_name: impl Into<String>) -> Self {
        Self {
            source,
            dest_name: dest_name.into(),
        }
    }
}

/// Return the canonical BINDIR file list for the host platform and given profile.
///
/// **Edit this function to add or remove BINDIR files.** The accompanying
/// regression test in `bindir_tests.rs` asserts the exact filenames per
/// platform — it will fail loudly if this list changes, forcing the change
/// to be acknowledged.
pub fn bindir_files(profile: Profile, repo_root: &Path) -> Result<Vec<BindirFile>> {
    let mut files = Vec::new();
    let exe_suffix = if cfg!(windows) { ".exe" } else { "" };

    // 1. hole binary — this IS the bridge + GUI executable. Built by `cargo build`.
    let hole_name = format!("hole{exe_suffix}");
    let hole_src = repo_root.join("target").join(profile.dir_name()).join(&hole_name);
    files.push(BindirFile::new(hole_src, hole_name));

    // 2. v2ray-plugin sidecar. Built by `cargo xtask v2ray-plugin` into
    //    `.cache/v2ray-plugin/v2ray-plugin-<target-triple>{.exe}`. The
    //    target-triple varies (`x86_64-pc-windows-msvc`, `aarch64-apple-darwin`,
    //    etc.) so we glob and assert exactly one match.
    let v2ray_glob_pattern = if cfg!(windows) {
        ".cache/v2ray-plugin/v2ray-plugin-*.exe"
    } else {
        ".cache/v2ray-plugin/v2ray-plugin-*"
    };
    let v2ray_src = unique_glob_match(repo_root, v2ray_glob_pattern)?;
    let v2ray_dest = format!("v2ray-plugin{exe_suffix}");
    files.push(BindirFile::new(v2ray_src, v2ray_dest));

    // 3. wintun.dll — Windows-only. Downloaded by `cargo xtask wintun` into
    //    `.cache/wintun/wintun.dll`. Not a sidecar binary; loaded as a DLL by
    //    the bridge's TUN code path. See crates/bridge/src/wintun.rs.
    #[cfg(target_os = "windows")]
    {
        let wintun_src = repo_root.join(".cache").join("wintun").join("wintun.dll");
        files.push(BindirFile::new(wintun_src, "wintun.dll".to_string()));
    }

    Ok(files)
}

/// Find exactly one file matching `pattern` (a glob relative to `repo_root`).
/// Returns the absolute path. Errors if zero or more than one match.
fn unique_glob_match(repo_root: &Path, pattern: &str) -> Result<PathBuf> {
    let abs_pattern = repo_root.join(pattern);
    let pattern_str = abs_pattern
        .to_str()
        .ok_or_else(|| anyhow!("glob pattern is not valid UTF-8: {abs_pattern:?}"))?;

    let mut matches = Vec::new();
    for entry in glob::glob(pattern_str).with_context(|| format!("invalid glob pattern: {pattern_str}"))? {
        matches.push(entry?);
    }

    match matches.len() {
        0 => Err(anyhow!(
            "no files matched glob {pattern_str}. Did `cargo xtask deps` run?"
        )),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => Err(anyhow!(
            "expected exactly 1 file matching {pattern_str}, found {n}: {matches:?}"
        )),
    }
}
