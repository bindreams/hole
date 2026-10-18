//! The git state a build script's version stamp depends on, as `cargo:rerun-if-changed`
//! paths.
//!
//! Cargo treats a `rerun-if-changed` path that does not exist as changed on every
//! invocation, so a build script that names `.git/packed-refs` or a packed branch
//! ref reruns — and recompiles its crate and everything downstream — each time cargo
//! runs, in any worktree where that file is absent. A linked worktree has no
//! `.git/HEAD` at all (`.git` is a file), so the same happens there. [`rerun_paths`]
//! therefore resolves every path through git and reports only paths that exist.

#![allow(clippy::disallowed_methods)] // build-script helper: runs as the invoking developer or CI user, never privileged

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Paths whose change can change the version stamp: `HEAD`, the branch ref it
/// points to, the tags, and `packed-refs`. Every returned path exists.
pub fn rerun_paths(repo_root: &Path) -> Result<Vec<PathBuf>> {
    rerun_paths_with(repo_root, &|_| {})
}

/// Adjusts the `git` command before it runs, e.g. to isolate it from the
/// ambient `GIT_*` environment.
pub(crate) type ConfigureGit<'a> = &'a dyn Fn(&mut Command);

/// [`rerun_paths`] with `configure` applied to every `git` it starts, so tests
/// can pin the environment git sees without touching the process's own.
pub(crate) fn rerun_paths_with(repo_root: &Path, configure: ConfigureGit) -> Result<Vec<PathBuf>> {
    let refs = git_path(repo_root, "refs", configure)?;
    let mut out = Vec::new();

    let head = git_path(repo_root, "HEAD", configure)?;
    if let Some(head_text) = read_head(&head)? {
        out.push(head);
        if let Some(branch) = head_text.trim().strip_prefix("ref: ") {
            out.extend(tracked_or_nearest_ancestor(
                &git_path(repo_root, branch, configure)?,
                &refs,
            ));
        }
    }
    out.extend(tracked_or_nearest_ancestor(
        &git_path(repo_root, "refs/tags", configure)?,
        &refs,
    ));

    // Absent until something packs refs; a pack removes loose refs, which
    // changes the directories tracked above.
    let packed = git_path(repo_root, "packed-refs", configure)?;
    if packed.exists() {
        out.push(packed);
    }
    out.dedup();
    Ok(out)
}

/// The text of the `HEAD` file at `path`; `None` only when it does not exist.
/// Any other failure is an error: swallowing it would drop HEAD and the branch
/// ref from the tracked paths with nothing to say so.
pub(crate) fn read_head(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Print a `cargo:rerun-if-changed` line per [`rerun_paths`] entry. A failure to
/// ask git is a warning, not an error: the version stamp itself degrades the
/// same way (`display_version`), and a build script must not panic over it.
pub fn emit_rerun_if_changed(repo_root: &Path) {
    write_rerun_if_changed(repo_root, &mut std::io::stdout().lock(), &|_| {})
        .expect("writing cargo directives to stdout");
}

/// [`emit_rerun_if_changed`] into `out`.
pub(crate) fn write_rerun_if_changed(
    repo_root: &Path,
    out: &mut impl std::io::Write,
    configure: ConfigureGit,
) -> std::io::Result<()> {
    match rerun_paths_with(repo_root, configure) {
        Ok(paths) => {
            for p in paths {
                writeln!(out, "cargo:rerun-if-changed={}", p.display())?;
            }
        }
        Err(e) => writeln!(
            out,
            "cargo:warning=cannot resolve git paths for the version stamp: {e:#}"
        )?,
    }
    Ok(())
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

fn git_path(repo_root: &Path, name: &str, configure: ConfigureGit) -> Result<PathBuf> {
    let mut git = Command::new("git");
    git.args(["rev-parse", "--path-format=absolute", "--git-path", name])
        .current_dir(repo_root);
    configure(&mut git);
    let output = git
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
