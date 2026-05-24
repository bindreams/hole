//! Stage BINDIR files into a destination directory.
//!
//! For each [`crate::bindir::BindirFile`], try a hard link first, fall back to
//! a copy if hardlinking fails (cross-device, permissions, file already exists
//! at the destination, etc.). The hardlink path is faster and saves disk for
//! release builds; the copy fallback keeps things working in dev temp dirs
//! that may be on a different volume.
//!
//! This logic was previously duplicated in
//! `msi-installer/src/msi_installer/__init__.py:link_or_copy()` and (via
//! `shutil.copy2`) in `scripts/dev.py`. See issue #143.

use std::path::Path;

use anyhow::{anyhow, Context, Result};

use crate::bindir::{BindirFile, BindirSource};

/// Stage `files` into `out_dir`. Creates `out_dir` if missing.
pub fn stage(out_dir: &Path, files: &[BindirFile]) -> Result<()> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("failed to create out_dir {}", out_dir.display()))?;

    for f in files {
        // Reject any dest_name with path separators — defense against future
        // edits to bindir_files() introducing nested layouts that the consumers
        // wouldn't handle.
        if f.dest_name.contains('/') || f.dest_name.contains('\\') {
            return Err(anyhow!(
                "BINDIR dest_name must not contain path separators: {}",
                f.dest_name
            ));
        }

        let dest = out_dir.join(&f.dest_name);

        match &f.source {
            BindirSource::File(src) => stage_file(src, &dest)?,
            BindirSource::Directory(src) => stage_directory(src, &dest)?,
        }
    }

    Ok(())
}

fn stage_file(src: &Path, dest: &Path) -> Result<()> {
    // Validate the source exists with a clear error message — much more
    // useful than the cryptic "No such file or directory" you'd get
    // from std::fs::hard_link.
    if !src.is_file() {
        return Err(anyhow!(
            "BINDIR source file does not exist: {}\n\
             Run `cargo build` (and `cargo xtask deps`) first.",
            src.display()
        ));
    }

    // Remove any pre-existing file at the destination so hard_link can
    // succeed (it errors if the destination exists). This matches what
    // shutil.copy2 and the existing link_or_copy helper do implicitly.
    if dest.exists() {
        std::fs::remove_file(dest).with_context(|| format!("failed to remove pre-existing dest {}", dest.display()))?;
    }

    match std::fs::hard_link(src, dest) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Hardlink failed (cross-device, permissions, etc.). Fall back
            // to a copy. We deliberately do not log the hardlink error —
            // it's expected on a fresh dev temp dir on a different volume.
            std::fs::copy(src, dest)
                .map(|_| ())
                .with_context(|| format!("failed to copy {} to {}", src.display(), dest.display()))
        }
    }
}

/// Recursively copy `src` directory into `dest`. Used for macOS `.dSYM`
/// bundles. Hard-link is not attempted — these bundles are needed as
/// real directory trees for Spotlight/Finder/lldb.
///
/// The recursion is depth-first, idempotent (pre-existing `dest` is
/// removed first), and propagates the first I/O error encountered.
fn stage_directory(src: &Path, dest: &Path) -> Result<()> {
    if !src.is_dir() {
        return Err(anyhow!(
            "BINDIR source directory does not exist: {}\n\
             Run `cargo build` (and `cargo xtask deps`) first.",
            src.display()
        ));
    }

    if dest.exists() {
        std::fs::remove_dir_all(dest)
            .with_context(|| format!("failed to remove pre-existing dest {}", dest.display()))?;
    }

    copy_dir_recursive(src, dest)
        .with_context(|| format!("failed to copy directory {} to {}", src.display(), dest.display()))
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if file_type.is_symlink() {
            // Preserve symlinks within the bundle (rare but possible
            // inside dSYM/Versions/). On Windows symlinks may fail
            // without elevation; fall back to a regular copy of the
            // target so we still produce a usable bundle.
            let target = std::fs::read_link(&from)?;
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&target, &to)?;
            }
            #[cfg(not(unix))]
            {
                // Resolve the symlink and copy its target as a regular file.
                let resolved = if target.is_absolute() {
                    target
                } else {
                    from.parent().unwrap_or(src).join(&target)
                };
                std::fs::copy(&resolved, &to)?;
            }
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}
