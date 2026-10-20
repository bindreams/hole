//! Stage BINDIR files into a destination directory.
//!
//! For each [`crate::bindir::BindirFile`], try a hard link first, fall back to
//! a copy if hardlinking fails (cross-device, permissions, etc.). The hardlink
//! path is faster and saves disk for release builds; the copy fallback keeps
//! things working in dev temp dirs that may be on a different volume.
//!
//! Every entry is built under a unique scratch directory beside the destination
//! and renamed into place, so concurrent stagers never write through each
//! other's (or the source's) inode and a file destination is never absent.
//!
//! This logic was previously duplicated in
//! `msi-installer/src/msi_installer/__init__.py:link_or_copy()` and (via
//! `shutil.copy2`) in the late `scripts/dev.py`. See issue #143.

use std::io::{self, ErrorKind};
use std::path::Path;

use anyhow::{anyhow, Context, Result};

use crate::bindir::{BindirFile, BindirSource};

/// Makes `staged` a hard link of `src`. An `Err` sends the entry down the copy fallback.
pub(crate) type LinkFn<'a> = &'a (dyn Fn(&Path, &Path) -> io::Result<()> + Sync);

/// Stage `files` into `out_dir`. Creates `out_dir` if missing.
pub fn stage(out_dir: &Path, files: &[BindirFile]) -> Result<()> {
    stage_with(out_dir, files, &|src, staged| std::fs::hard_link(src, staged))
}

/// [`stage`] with the link step injectable, so tests can drive the copy fallback.
pub(crate) fn stage_with(out_dir: &Path, files: &[BindirFile], link: LinkFn<'_>) -> Result<()> {
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
            BindirSource::File(src) => stage_file(src, &dest, link)?,
            BindirSource::Directory(src) => stage_directory(src, &dest)?,
        }
    }

    Ok(())
}

fn stage_file(src: &Path, dest: &Path, link: LinkFn<'_>) -> Result<()> {
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

    let scratch = scratch_dir_beside(dest)?;
    let staged = scratch.path().join(dest_file_name(dest)?);

    // `staged` is a fresh path, so the copy fallback can never write through a
    // hard link of `src`.
    if link(src, &staged).is_err() {
        // Link errors are expected (e.g. cross-volume dev temp dirs) and deliberately not logged.
        std::fs::copy(src, &staged)
            .with_context(|| format!("failed to copy {} to {}", src.display(), staged.display()))?;
    }

    // Atomic replace: `dest` is present with complete content at every instant.
    std::fs::rename(&staged, dest)
        .with_context(|| format!("failed to move {} over {}", staged.display(), dest.display()))
}

/// Recursively copy `src` directory into `dest`. Used for macOS `.dSYM`
/// bundles. Hard-link is not attempted — these bundles are needed as
/// real directory trees for Spotlight/Finder/lldb.
///
/// The tree is built under a unique scratch directory beside `dest`, then the
/// old `dest` is renamed aside and the new tree renamed into place. A directory
/// cannot be renamed over a non-empty one, so there is a gap with no `dest`;
/// bundles are debug symbols, never executed. On Windows, concurrent stagers of
/// one directory can fail with access denied; only macOS stages a bundle.
fn stage_directory(src: &Path, dest: &Path) -> Result<()> {
    if !src.is_dir() {
        return Err(anyhow!(
            "BINDIR source directory does not exist: {}\n\
             Run `cargo build` (and `cargo xtask deps`) first.",
            src.display()
        ));
    }

    // `new/` holds the tree being built and `old` the bundle moved aside, so no `dest` name
    // can make the two collide.
    let scratch = scratch_dir_beside(dest)?;
    let new_dir = scratch.path().join("new");
    std::fs::create_dir(&new_dir).with_context(|| format!("failed to create {}", new_dir.display()))?;
    let staged = new_dir.join(dest_file_name(dest)?);
    copy_dir_recursive(src, &staged)
        .with_context(|| format!("failed to copy directory {} to {}", src.display(), staged.display()))?;

    // Move any pre-existing bundle aside (the scratch dir's drop deletes it). NotFound:
    // there is none, or a concurrent stager moved it first.
    match std::fs::rename(dest, scratch.path().join("old")) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("failed to move pre-existing dest {} aside", dest.display())),
    }

    match std::fs::rename(&staged, dest) {
        Ok(()) => Ok(()),
        // `dest` only ever appears by a complete rename, so a non-empty or existing `dest` is a
        // concurrent stager's finished bundle of the same source.
        Err(e) if matches!(e.kind(), ErrorKind::DirectoryNotEmpty | ErrorKind::AlreadyExists) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to move {} to {}", staged.display(), dest.display())),
    }
}

/// A uniquely named (created exclusively) scratch directory in `dest`'s parent,
/// so a staged entry can be renamed onto `dest` within one filesystem. Removed on
/// drop, together with whatever was moved into it.
fn scratch_dir_beside(dest: &Path) -> Result<tempfile::TempDir> {
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow!("BINDIR dest has no parent directory: {}", dest.display()))?;
    tempfile::Builder::new()
        .prefix(".stage-")
        .tempdir_in(parent)
        .with_context(|| format!("failed to create a scratch directory in {}", parent.display()))
}

fn dest_file_name(dest: &Path) -> Result<&std::ffi::OsStr> {
    dest.file_name()
        .ok_or_else(|| anyhow!("BINDIR dest has no file name: {}", dest.display()))
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
