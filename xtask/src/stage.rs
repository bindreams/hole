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

use crate::bindir::BindirFile;

/// Stage `files` into `out_dir`. Creates `out_dir` if missing.
pub fn stage(out_dir: &Path, files: &[BindirFile]) -> Result<()> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("failed to create out_dir {}", out_dir.display()))?;

    for f in files {
        // Validate the source exists with a clear error message — much more
        // useful than the cryptic "No such file or directory" you'd get
        // from std::fs::hard_link.
        if !f.source.is_file() {
            return Err(anyhow!(
                "BINDIR source file does not exist: {}\n\
                 Run `cargo build` (and, post-Commit-4, `cargo xtask deps`) first.",
                f.source.display()
            ));
        }

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

        // Remove any pre-existing file at the destination so hard_link can
        // succeed (it errors if the destination exists). This matches what
        // shutil.copy2 and the existing link_or_copy helper do implicitly.
        if dest.exists() {
            std::fs::remove_file(&dest)
                .with_context(|| format!("failed to remove pre-existing dest {}", dest.display()))?;
        }

        match std::fs::hard_link(&f.source, &dest) {
            Ok(()) => {}
            Err(_) => {
                // Hardlink failed (cross-device, permissions, etc.). Fall back
                // to a copy. We deliberately do not log the hardlink error —
                // it's expected on a fresh dev temp dir on a different volume.
                std::fs::copy(&f.source, &dest)
                    .with_context(|| format!("failed to copy {} to {}", f.source.display(), dest.display()))?;
            }
        }
    }

    Ok(())
}
