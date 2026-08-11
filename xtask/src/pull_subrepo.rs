//! `cargo xtask pull-subrepo <path> <tag>` — a thin, honest wrapper around
//! `git subrepo pull` that fixes the one squash-merge gotcha this repo
//! hits on every pull (see crates/ex-ray/third_party/VENDORING.md) and
//! otherwise behaves exactly like `git pull`: a real conflict stops here,
//! uncommitted, for a human to resolve. No Renovate/CI awareness — the
//! caller decides `tag`, and the "commit anyway despite conflicts"
//! CI-only policy is `force_commit_conflicted`, a separate function `run`
//! never calls.

use std::path::{Path, PathBuf};

use anyhow::Result;

pub enum Outcome {
    /// Pull succeeded (cleanly, or after auto-resolving only the
    /// documented-safe allowlist); a new commit updating `<subdir>` now
    /// sits on HEAD.
    Clean,
    /// A conflict remains outside the safe allowlist. The pull attempt
    /// itself committed nothing — the temp merge worktree `git subrepo
    /// pull` created is left exactly as `git merge` would leave a
    /// conflicted tree, for a human to resolve. (A prior, independent
    /// `.gitrepo`-parent-realignment commit may already be on the branch
    /// if that fixup ran first — see `fix_stale_parent`.)
    Conflicted { worktree: PathBuf, unresolved: Vec<String> },
}

pub fn run(_repo_root: &Path, _subdir: &str, _tag: &str) -> Result<Outcome> {
    unimplemented!("Task 3/4")
}

pub fn force_commit_conflicted(_repo_root: &Path, _subdir: &str, _tag: &str) -> Result<()> {
    unimplemented!("Task 4")
}

// Only exercised by tests until Task 4 wires it into `run`/`force_commit_conflicted`.
#[allow(dead_code)]
pub(crate) fn is_auto_resolvable(_path: &str) -> bool {
    unimplemented!("Task 4")
}
