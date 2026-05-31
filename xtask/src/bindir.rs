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

/// Source kind for a BINDIR entry. Files use hard-link-then-copy;
/// directory bundles (macOS `.dSYM`) recurse a copy. Introduced for
/// bindreams/hole#393 so panic-backtrace symbols ship on both
/// platforms.
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

    // 1a. Debug symbols for `hole` — staged alongside the binary so panic
    //     backtraces in dev (`scripts/dev.py`) and production (the MSI)
    //     resolve frame names and line numbers. Without these, the panic
    //     hook at `crates/common/src/logging.rs::install_panic_hook` renders
    //     every frame as `<unknown>`. See bindreams/hole#393.
    //
    //     The workspace `[profile.release].debug = "limited"` guarantees the
    //     PDB/dSYM exists for release builds (cargo's default is `false`).
    //     Debug builds already emit full debug info.
    #[cfg(target_os = "windows")]
    {
        // MSVC emits the binary's PDB next to the .exe.
        let pdb_src = repo_root.join("target").join(profile.dir_name()).join("hole.pdb");
        files.push(BindirFile::new(pdb_src, "hole.pdb".to_string()));
    }
    #[cfg(target_os = "macos")]
    {
        // Cargo's macOS `split-debuginfo = "unpacked"` (release default)
        // emits a `.dSYM` bundle at the same level as the binary.
        let dsym_src = repo_root.join("target").join(profile.dir_name()).join("hole.dSYM");
        files.push(BindirFile::directory(dsym_src, "hole.dSYM".to_string()));
    }

    // 2. ex-ray sidecar. Built by `cargo xtask ex-ray` into
    //    `.cache/ex-ray/ex-ray-<target-triple>{.exe}`. The
    //    target-triple varies (`x86_64-pc-windows-msvc`, `aarch64-apple-darwin`,
    //    etc.) so we glob and assert exactly one match.
    let ex_ray_glob_pattern = if cfg!(windows) {
        ".cache/ex-ray/ex-ray-*.exe"
    } else {
        ".cache/ex-ray/ex-ray-*"
    };
    let ex_ray_src = unique_glob_match(repo_root, ex_ray_glob_pattern)?;
    let ex_ray_dest = format!("ex-ray{exe_suffix}");
    files.push(BindirFile::new(ex_ray_src, ex_ray_dest));

    // 3. galoshes sidecar. Built by `cargo xtask galoshes` into
    //    `target/release/galoshes{.exe}` (the unified workspace target dir
    //    now that galoshes is a regular workspace member at `crates/galoshes/`).
    let galoshes_name = format!("galoshes{exe_suffix}");
    let galoshes_src = repo_root.join("target").join("release").join(&galoshes_name);
    files.push(BindirFile::new(galoshes_src, galoshes_name));

    // 4. wintun.dll — Windows-only. Downloaded by `cargo xtask wintun` into
    //    `.cache/wintun/wintun.dll`. Not a sidecar binary; loaded as a DLL by
    //    the bridge's TUN code path. See crates/bridge/src/wintun.rs.
    #[cfg(target_os = "windows")]
    {
        let wintun_src = repo_root.join(".cache").join("wintun").join("wintun.dll");
        files.push(BindirFile::new(wintun_src, "wintun.dll".to_string()));
    }

    // 5. NOTICES.md — Apache-2.0 attribution for galoshes/garter components
    //    that the GPL-3.0 binary distribution bundles. Apache-2.0 §4(d)
    //    requires the NOTICE file to be preserved in derivative works; since
    //    the installer's license dialog only shows GPL-3.0 text, the file
    //    must accompany the binaries on disk. See bindreams/hole#363 review.
    let notices_src = repo_root.join("NOTICES.md");
    files.push(BindirFile::new(notices_src, "NOTICES.md".to_string()));

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
