//! `cargo xtask pull-subrepo <path> <tag>` — a thin, honest wrapper around
//! `git subrepo pull` that fixes the one squash-merge gotcha this repo
//! hits on every pull (see crates/ex-ray/third_party/VENDORING.md) and
//! otherwise behaves exactly like `git pull`: a real conflict stops here,
//! uncommitted, for a human to resolve. No Renovate/CI awareness — the
//! caller decides `tag`, and the "commit anyway despite conflicts"
//! CI-only policy is `force_commit_conflicted`, a separate function `run`
//! never calls.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};

use crate::git_util::run_git;

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

pub fn run(repo_root: &Path, subdir: &str, tag: &str) -> Result<Outcome> {
    ensure_clean_tree(repo_root)?;
    ensure_no_in_progress_conflict_resolution(repo_root, subdir)?;

    let first = attempt_pull(repo_root, subdir, tag)?;
    if first.status.success() {
        best_effort_clean(repo_root, subdir);
        return Ok(Outcome::Clean);
    }

    let stderr = String::from_utf8_lossy(&first.stderr);
    if stderr.contains("is not an ancestor") {
        fix_stale_parent(repo_root, subdir)?;
        let second = attempt_pull(repo_root, subdir, tag)?;
        if second.status.success() {
            best_effort_clean(repo_root, subdir);
            return Ok(Outcome::Clean);
        }
        return handle_conflict(repo_root, subdir, tag, &second);
    }

    handle_conflict(repo_root, subdir, tag, &first)
}

fn ensure_clean_tree(repo_root: &Path) -> Result<()> {
    let status = run_git(repo_root, &["status", "--porcelain"])?;
    if !status.is_empty() {
        bail!("working tree is dirty; `git subrepo pull` refuses to run against a dirty tree:\n{status}");
    }
    Ok(())
}

/// `attempt_pull`'s defensive pre-clean (below) would otherwise silently
/// `rm -rf` a worktree a human is actively resolving a real conflict in —
/// `git subrepo clean` is the one git-subrepo subcommand that skips the
/// tool's own working-copy-clean guard, so it deletes an in-progress
/// resolution with no confirmation. Called once at the very start of
/// `run`, before any cleaning happens: refuses whenever a leftover
/// worktree from a *previous* invocation exists at all, regardless of
/// whether `git status --porcelain` inside it is empty. A dirtiness check
/// is not sufficient: git-subrepo's own documented recovery steps (`cd
/// <worktree>`, resolve, `git add`, `git commit`) have the human commit
/// *inside* the temp worktree before the outer `git subrepo commit
/// <subdir>` step folds it back in — so a worktree sitting in exactly
/// that "resolved and committed, not yet folded in" state has an empty
/// porcelain status but still represents real, valuable, unfinished work
/// (the commit itself, and the `refs/heads/subrepo/<subdir>` branch
/// pointing to it) that a dirtiness-only check would wrongly treat as
/// stale-and-safe-to-discard.
fn ensure_no_in_progress_conflict_resolution(repo_root: &Path, subdir: &str) -> Result<()> {
    let common_dir = git_common_dir(repo_root)?;
    let worktree = common_dir.join("tmp").join("subrepo").join(subdir);
    if worktree.exists() {
        bail!(
            "a conflict-resolution worktree already exists at {} — if you're resolving a \
             conflict there, finish it (see the earlier `pull-subrepo` output for the exact \
             steps); if it's stale (e.g. left over from an interrupted run), run \
             `git subrepo clean {subdir}` yourself first to discard it",
            worktree.display()
        );
    }
    Ok(())
}

/// Runs `git subrepo pull`, first defensively cleaning any worktree/branch
/// left over from a previous attempt *within this same `run` call* (the
/// stale-parent-fixup retry can follow a first attempt that failed before
/// ever creating a worktree — see `fix_stale_parent`'s doc comment — so
/// this is always safe to call unconditionally here — safe here, since a
/// prior, separate invocation's in-progress work is guarded separately by
/// `ensure_no_in_progress_conflict_resolution`). A leftover
/// `subrepo/<subdir>` worktree/branch makes the next `git subrepo pull`
/// fail immediately with "There is already a worktree with branch
/// subrepo/<subdir>", masking the real outcome of this attempt.
fn attempt_pull(repo_root: &Path, subdir: &str, tag: &str) -> Result<Output> {
    best_effort_clean(repo_root, subdir);
    Command::new("git")
        .args(["subrepo", "pull", subdir, "-b", tag])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to run `git subrepo pull {subdir} -b {tag}`"))
}

/// `git subrepo clean` is a safe no-op when there's nothing to clean. If it
/// fails for a real reason, a debug trace is left so a subsequent
/// "already a worktree" pull failure is correlatable back to it — every
/// call site in this module uses this helper rather than a bare `.ok()`,
/// so none of them silently swallow a genuine clean failure.
fn best_effort_clean(repo_root: &Path, subdir: &str) {
    if let Err(e) = run_git(repo_root, &["subrepo", "clean", subdir]) {
        eprintln!("xtask: debug: `git subrepo clean {subdir}` failed (may be benign): {e}");
    }
}

fn git_common_dir(repo_root: &Path) -> Result<PathBuf> {
    let raw = run_git(repo_root, &["rev-parse", "--git-common-dir"])?;
    let path = PathBuf::from(raw);
    Ok(if path.is_absolute() { path } else { repo_root.join(path) })
}

/// Replicates git-subrepo's own recovery formula for a squash-merge-stale
/// `.gitrepo` `parent` (its own error message suggests exactly this SHA):
/// the last commit that touched the `.gitrepo` file's `commit =` line,
/// walked back one parent. This candidate is always an ancestor of HEAD by
/// construction (it comes from `git log` starting at HEAD). The is-ancestor
/// check below is still a real, always-on `bail!` rather than a
/// `debug_assert!` despite that guarantee: it's the sole guard immediately
/// before an irreversible committed write in unattended CI, where a
/// silently compiled-away check (debug_assert! is a no-op in release
/// builds) is the wrong trade. The two earlier `bail!`s (no commit found;
/// root commit with no parent) are real defensive checks but effectively
/// unreachable through any real `git subrepo` lifecycle — confirmed live:
/// `git subrepo clone` refuses outright ("You can't clone into an empty
/// repository") in a repo with zero prior commits, so the sync commit this
/// function walks back from always has at least one parent to find, and a
/// `.gitrepo` file only ever exists because some commit introduced its
/// `commit =` line in the first place. No test fabricates either
/// condition for the same reason no test fabricates a non-ancestor
/// candidate for the check below — doing so would require hand-corrupting
/// the git object graph outside any real git-subrepo operation, testing
/// the fabrication rather than the code.
fn fix_stale_parent(repo_root: &Path, subdir: &str) -> Result<()> {
    let gitrepo_rel = format!("{subdir}/.gitrepo");

    let last_sync_commit = run_git(
        repo_root,
        &["log", "-1", "-G", "commit =", "--format=%H", "--", &gitrepo_rel],
    )?;
    if last_sync_commit.is_empty() {
        bail!("could not find a commit that touched `{gitrepo_rel}`'s `commit =` line; cannot compute a replacement `parent`");
    }

    let parent_ref = format!("{last_sync_commit}^");
    let candidate = run_git(repo_root, &["log", "-1", "--format=%H", &parent_ref]).with_context(|| {
        format!("the last sync commit {last_sync_commit} has no parent (it's a root commit) — cannot compute a replacement `.gitrepo` parent")
    })?;

    let is_ancestor = Command::new("git")
        .args(["merge-base", "--is-ancestor", &candidate, "HEAD"])
        .current_dir(repo_root)
        .status()
        .context("git merge-base --is-ancestor failed to run")?;
    if !is_ancestor.success() {
        bail!(
            "computed replacement parent {candidate} is not an ancestor of HEAD — \
             this should never happen (the last-sync-commit formula guarantees it by \
             construction); something is deeply wrong with this repo's history"
        );
    }

    let gitrepo_path = repo_root.join(subdir).join(".gitrepo");
    let contents =
        std::fs::read_to_string(&gitrepo_path).with_context(|| format!("failed to read {}", gitrepo_path.display()))?;
    std::fs::write(&gitrepo_path, replace_gitrepo_field(&contents, "parent", &candidate)?)
        .with_context(|| format!("failed to write {}", gitrepo_path.display()))?;

    run_git(repo_root, &["add", &gitrepo_rel])?;
    run_git(
        repo_root,
        &[
            "commit",
            "-m",
            &format!("fix: realign {subdir} subrepo parent after squash-merge"),
        ],
    )?;
    Ok(())
}

fn replace_gitrepo_field(contents: &str, field: &str, value: &str) -> Result<String> {
    let prefix = format!("{field} =");
    let mut found = false;
    let lines: Vec<String> = contents
        .lines()
        .map(|line| {
            if line.trim_start().starts_with(&prefix) {
                found = true;
                format!("\t{field} = {value}")
            } else {
                line.to_string()
            }
        })
        .collect();
    if !found {
        bail!("`.gitrepo` has no `{field} = ` line to replace");
    }
    Ok(lines.join("\n") + "\n")
}

fn handle_conflict(_repo_root: &Path, _subdir: &str, _tag: &str, output: &Output) -> Result<Outcome> {
    bail!(
        "git subrepo pull failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn force_commit_conflicted(_repo_root: &Path, _subdir: &str, _tag: &str) -> Result<()> {
    unimplemented!("Task 4")
}

// Only exercised by tests until Task 4 wires it into `run`/`force_commit_conflicted`.
#[allow(dead_code)]
pub(crate) fn is_auto_resolvable(_path: &str) -> bool {
    unimplemented!("Task 4")
}
