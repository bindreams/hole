//! Resolve the canonical BINDIR file *set* to host source paths.
//!
//! The set itself — [`bindir_dest_names`] + the [`Os`] it keys on — is the
//! single source of truth and lives in `xtask-lib` (shared with the bridge
//! cutover + build.rs). This module re-exports it and adds the disk-resolving
//! [`bindir_files`]. dev-console and
//! `msi-installer/src/msi_installer/__init__.py:stage_files()` stage via
//! `cargo xtask stage`; the installer-manifest conformance tests derive their
//! expected payload from `bindir_dest_names` (via `cargo xtask bindir-names`)
//! so the manifests cannot silently drift.
//!
//! See issue #143 for the motivation.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::manifest::Os;
use crate::Profile;

pub use xtask_lib::bindir::{bindir_dest_names, plugin_sidecar_names};

/// Source kind for a BINDIR entry. Files use hard-link-then-copy;
/// directory bundles (macOS `.dSYM`) recurse a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindirSource {
    /// Single regular file. Staged via hard-link with copy fallback.
    File(PathBuf),
    /// Directory bundle. Staged via recursive copy. Used for macOS
    /// `.dSYM` bundles; hard-link doesn't apply at the directory
    /// level, and even if it did, Finder/Spotlight expect a real
    /// directory tree.
    Directory(PathBuf),
}

impl BindirSource {
    pub fn path(&self) -> &Path {
        match self {
            BindirSource::File(p) | BindirSource::Directory(p) => p,
        }
    }
}

/// One file or bundle that must end up in BINDIR alongside the bridge
/// binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindirFile {
    /// Absolute source path on disk and its kind.
    pub source: BindirSource,
    /// Filename to use in the destination directory (no path components).
    pub dest_name: String,
}

impl BindirFile {
    /// Construct a file entry — the common case. Equivalent to
    /// `BindirSource::File(source)`.
    pub fn new(source: PathBuf, dest_name: impl Into<String>) -> Self {
        Self {
            source: BindirSource::File(source),
            dest_name: dest_name.into(),
        }
    }

    /// Construct a directory-bundle entry (macOS `.dSYM`, etc.).
    pub fn directory(source: PathBuf, dest_name: impl Into<String>) -> Self {
        Self {
            source: BindirSource::Directory(source),
            dest_name: dest_name.into(),
        }
    }
}

/// The host OS as a manifest [`Os`], or an error on a host outside the
/// supported set (windows/darwin/linux) — the same platforms `bindir_files`
/// already supports.
fn host_os() -> Result<Os> {
    Os::host().ok_or_else(|| anyhow!("host OS is not one of windows/darwin/linux; cannot resolve BINDIR"))
}

/// Resolve the canonical BINDIR file list for the host platform and given
/// profile. The *set* and order come from [`bindir_dest_names`]; this fn maps
/// each name to its host source path.
pub fn bindir_files(profile: Profile, repo_root: &Path) -> Result<Vec<BindirFile>> {
    let host = host_os()?;
    let target_dir = repo_root.join("target").join(profile.dir_name());

    // ex-ray is built per-target-triple into `.cache/ex-ray/ex-ray-<triple>{.exe}`;
    // the triple varies, so glob + assert exactly one match.
    let ex_ray_glob = if host == Os::Windows {
        ".cache/ex-ray/ex-ray-*.exe"
    } else {
        ".cache/ex-ray/ex-ray-*"
    };

    let mut files = Vec::new();
    for name in bindir_dest_names(host) {
        let file = match name.as_str() {
            // hole binary — the bridge + GUI executable, built by `cargo build`.
            "hole" | "hole.exe" => BindirFile::new(target_dir.join(&name), name),
            // MSVC emits the PDB next to the .exe.
            "hole.pdb" => BindirFile::new(target_dir.join("hole.pdb"), name),
            // macOS `split-debuginfo = "packed"` emits a self-contained `.dSYM` bundle.
            "hole.dSYM" => BindirFile::directory(target_dir.join("hole.dSYM"), name),
            "ex-ray" | "ex-ray.exe" => BindirFile::new(unique_glob_match(repo_root, ex_ray_glob)?, name),
            // galoshes is a workspace member, built into the unified `target/release/`.
            "galoshes" | "galoshes.exe" => BindirFile::new(repo_root.join("target").join("release").join(&name), name),
            // wintun.dll — downloaded by `cargo xtask wintun` into `.cache/wintun/`.
            "wintun.dll" => BindirFile::new(repo_root.join(".cache").join("wintun").join("wintun.dll"), name),
            "NOTICES.md" => BindirFile::new(repo_root.join("NOTICES.md"), name),
            other => return Err(anyhow!("BINDIR name {other:?} has no source mapping in bindir_files")),
        };
        files.push(file);
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
