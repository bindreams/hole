use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Expand variables in a source path:
/// - `{target}` → the cargo target directory (e.g., `target/release`)
/// - `{arch}` → the Rust target triple (e.g., `x86_64-pc-windows-msvc`)
pub(crate) fn expand_vars(source: &str, target_dir: &Path, target_triple: &str) -> String {
    source
        .replace("{target}", &target_dir.to_string_lossy())
        .replace("{arch}", target_triple)
}

/// Stage files into a temporary directory according to the `files` config.
///
/// Returns the temp directory handle (must be kept alive) and a map of
/// bindpath name to staging subdirectory path.
pub fn stage(
    files: &BTreeMap<String, BTreeMap<String, String>>,
    workspace_root: &Path,
    target_dir: &Path,
    target_triple: &str,
) -> Result<(tempfile::TempDir, BTreeMap<String, PathBuf>)> {
    let staging_dir = tempfile::tempdir()?;
    let mut bindpaths = BTreeMap::new();

    for (bindpath_name, file_map) in files {
        let bp_dir = staging_dir.path().join(bindpath_name);
        std::fs::create_dir_all(&bp_dir)?;

        for (dest_name, source_pattern) in file_map {
            let expanded = expand_vars(source_pattern, target_dir, target_triple);
            let source_path = workspace_root.join(&expanded);

            if !source_path.exists() {
                return Err(Error::StagingFailed(format!(
                    "source file not found: {} (resolved to {})",
                    source_pattern,
                    source_path.display()
                )));
            }

            let dest_path = bp_dir.join(dest_name);
            std::fs::copy(&source_path, &dest_path).map_err(|e| {
                Error::StagingFailed(format!(
                    "failed to copy {} to {}: {e}",
                    source_path.display(),
                    dest_path.display()
                ))
            })?;
        }

        bindpaths.insert(bindpath_name.clone(), bp_dir);
    }

    Ok((staging_dir, bindpaths))
}

#[cfg(test)]
#[path = "staging_tests.rs"]
mod staging_tests;
