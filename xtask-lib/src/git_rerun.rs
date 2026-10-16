//! The git state a build script's version stamp depends on, as `cargo:rerun-if-changed`
//! paths.
//!
//! Cargo treats a `rerun-if-changed` path that does not exist as changed on every
//! invocation, so a build script that names `.git/packed-refs` or a packed branch
//! ref reruns — and recompiles its crate and everything downstream — each time cargo
//! runs, in any worktree where that file is absent. A linked worktree has no
//! `.git/HEAD` at all (`.git` is a file), so the same happens there. [`rerun_paths`]
//! therefore resolves every path through git and reports only paths that exist.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Paths whose change can change the version stamp: `HEAD`, the branch ref it
/// points to, the tags, and `packed-refs`. Every returned path exists.
pub fn rerun_paths(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let refs = git_path(repo_root, "refs")?;
    let mut out = Vec::new();

    let head = git_path(repo_root, "HEAD")?;
    if let Ok(head_text) = std::fs::read_to_string(&head) {
        out.push(head);
        if let Some(branch) = head_text.trim().strip_prefix("ref: ") {
            out.extend(tracked_or_nearest_ancestor(&git_path(repo_root, branch)?, &refs));
        }
    }
    out.extend(tracked_or_nearest_ancestor(&git_path(repo_root, "refs/tags")?, &refs));

    // Absent until something packs refs; a pack removes loose refs, which
    // changes the directories tracked above.
    let packed = git_path(repo_root, "packed-refs")?;
    if packed.exists() {
        out.push(packed);
    }
    out.dedup();
    Ok(out)
}

/// Print a `cargo:rerun-if-changed` line per [`rerun_paths`] entry. A failure to
/// ask git is a warning, not an error: the version stamp itself degrades the
/// same way (`display_version`), and a build script must not panic over it.
pub fn emit_rerun_if_changed(repo_root: &Path) {
    match rerun_paths(repo_root) {
        Ok(paths) => {
            for p in paths {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
        Err(e) => println!("cargo:warning=cannot resolve git paths for the version stamp: {e:#}"),
    }
}

/// `path` if it exists, else its nearest existing ancestor that is `floor` or
/// below it. A file created later under a missing path lands in that ancestor,
/// whose change cargo sees. `None` when not even `floor` exists.
pub fn tracked_or_nearest_ancestor(path: &Path, floor: &Path) -> Option<PathBuf> {
    path.ancestors()
        .take_while(|a| a.starts_with(floor))
        .find(|a| a.exists())
        .map(Path::to_path_buf)
}

fn git_path(repo_root: &Path, name: &str) -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-path", name])
        .current_dir(repo_root)
        .output()
        .context("running `git rev-parse --git-path` (is git installed?)")?;
    if !output.status.success() {
        bail!(
            "`git rev-parse --git-path {name}` failed in {}: {}",
            repo_root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}
