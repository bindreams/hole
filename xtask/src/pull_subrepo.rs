//! `cargo xtask pull-subrepo <path> <tag>` — a thin, honest wrapper around
//! `git subrepo pull` that fixes the one squash-merge gotcha this repo
//! hits on every pull (see crates/ex-ray/third_party/VENDORING.md) and
//! otherwise behaves exactly like `git pull`: a real conflict stops here
//! for a human to resolve. The one exception to "uncommitted": if the
//! squash-merge fixup ran and a *later* step in the same attempt still
//! fails, the fixup commit already landed — every such error path discloses
//! that commit's SHA rather than leaving it a silent side effect. No
//! Renovate/CI awareness — the caller decides `tag`, and the "commit anyway
//! despite conflicts" CI-only policy is `force_commit_conflicted`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};

use crate::git_util::run_git;

pub enum Outcome {
    /// Pull succeeded (cleanly, or after auto-resolving only the
    /// documented-safe allowlist). Usually a new commit updating `<subdir>`
    /// now sits on HEAD; if `<subdir>` was already at `tag`, `git subrepo
    /// pull` is a no-op and HEAD is unchanged instead.
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
    assert_subdir_is_ref_safe(repo_root, subdir)?;
    ensure_clean_tree(repo_root)?;
    ensure_no_in_progress_conflict_resolution(repo_root, subdir)?;

    let first = attempt_pull(repo_root, subdir, tag)?;
    if first.status.success() {
        best_effort_clean(repo_root, subdir);
        return Ok(Outcome::Clean);
    }

    let stderr = String::from_utf8_lossy(&first.stderr);
    if stderr.contains("is not an ancestor") {
        let fixup_commit = fix_stale_parent(repo_root, subdir)?;
        let second = attempt_pull(repo_root, subdir, tag)?;
        if second.status.success() {
            best_effort_clean(repo_root, subdir);
            return Ok(Outcome::Clean);
        }
        return handle_conflict(repo_root, subdir, tag, &second).with_context(|| {
            format!(
                "a `.gitrepo` parent-realignment commit ({fixup_commit}) was already created \
                 on this branch before this failure; `git reset --hard HEAD~1` undoes it if \
                 you want to retry from a clean state"
            )
        });
    }

    handle_conflict(repo_root, subdir, tag, &first)
}

/// git-subrepo's own `encode-subdir` percent-encodes `subdir` into a
/// distinct `subref` whenever `subdir` isn't already a valid git ref
/// component (spaces, `~`, `^`, `:`, leading dots, etc.) — but leaves
/// `subref == subdir` unchanged for every subdir already valid as one
/// (confirmed in the installed `git-subrepo` lib: it early-returns before
/// encoding whenever `git check-ref-format "subrepo/$subref"` succeeds).
/// This module builds worktree/branch paths straight from the raw
/// `subdir`, which only matches what git-subrepo itself uses when no
/// encoding was needed — so refuse up front rather than silently guarding
/// (and later cleaning) the wrong path for a `subdir` that would encode.
fn assert_subdir_is_ref_safe(repo_root: &Path, subdir: &str) -> Result<()> {
    let ref_name = format!("subrepo/{subdir}");
    let ok = Command::new("git")
        .args(["check-ref-format", &ref_name])
        .current_dir(repo_root)
        .status()
        .context("git check-ref-format failed to run")?
        .success();
    if !ok {
        bail!(
            "`{subdir}` is not directly usable as a git ref component (`{ref_name}` fails \
             `git check-ref-format`); git-subrepo's own `encode-subdir` would percent-encode it \
             before naming its worktree/branch, which this tool does not replicate, so it can't \
             safely locate the worktree/branch git-subrepo would create — rename the subdir"
        );
    }
    Ok(())
}

/// Untracked files are deliberately excluded: `fix_stale_parent`'s commit
/// below only ever `git add`s the `.gitrepo` pathspec, so an untracked file
/// elsewhere can never be swept into it, and (unlike this check's earlier
/// wording claimed) `git subrepo pull` itself doesn't refuse on them either
/// — its own working-copy-clean assertion checks tracked changes only.
fn ensure_clean_tree(repo_root: &Path) -> Result<()> {
    let status = run_git(repo_root, &["status", "--porcelain", "--untracked-files=no"])?;
    if !status.is_empty() {
        bail!("working tree has uncommitted changes; refusing to run against it:\n{status}");
    }
    Ok(())
}

/// `best_effort_clean` runs `git subrepo clean`, the one git-subrepo
/// subcommand that skips the tool's own working-copy-clean guard — it would
/// silently discard a worktree a human is actively resolving a real
/// conflict in. Existence, not dirtiness, is the right test: after the
/// human resolves and commits *inside* the temp worktree (per git-subrepo's
/// own recovery steps), porcelain status is clean again even though the
/// outer `git subrepo commit <subdir>` fold-in hasn't happened yet — that
/// state must still be refused, not discarded. Checked once at the very
/// start of `run`. Both the worktree directory AND the
/// `refs/heads/subrepo/<subdir>` branch are checked, not just the
/// directory: `git worktree remove`/`prune` (including git-subrepo's own
/// documented recovery steps for a *stale* worktree) can leave the
/// directory gone while the branch — and the human's resolution commit on
/// it — still exists, which `git subrepo clean` would then delete.
fn ensure_no_in_progress_conflict_resolution(repo_root: &Path, subdir: &str) -> Result<()> {
    let common_dir = git_common_dir(repo_root)?;
    let worktree = common_dir.join("tmp").join("subrepo").join(subdir);
    let branch_ref = format!("refs/heads/subrepo/{subdir}");
    let branch_exists = Command::new("git")
        .args(["show-ref", "--verify", "--quiet", &branch_ref])
        .current_dir(repo_root)
        .status()
        .context("git show-ref failed to run")?
        .success();
    if worktree.exists() || branch_exists {
        bail!(
            "a conflict-resolution worktree ({}) or branch ({branch_ref}) already exists — if \
             you're resolving a conflict there, finish it (see the earlier `pull-subrepo` \
             output for the exact steps); if it's stale (e.g. left over from an interrupted \
             run), run `git subrepo clean {subdir}` yourself first to discard it",
            worktree.display()
        );
    }
    Ok(())
}

/// Runs `git subrepo pull`. Called up to twice per `run` (the
/// stale-parent-fixup retry) without cleaning in between: `fix_stale_parent`
/// only runs after a failure containing "is not an ancestor", which
/// git-subrepo raises during its up-front ancestry check, before it ever
/// creates a worktree — so there is nothing left over to clean before the
/// retry. Deliberately does *not* pre-clean unconditionally: doing so would
/// destroy a leftover `subrepo/<subdir>` worktree/branch that
/// `ensure_no_in_progress_conflict_resolution` already decided, once, at
/// the top of `run`, to leave alone (re-checking and re-cleaning here would
/// also race a concurrent, separate `git subrepo pull` invocation).
fn attempt_pull(repo_root: &Path, subdir: &str, tag: &str) -> Result<Output> {
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
/// root commit with no parent) are unreachable through any real `git
/// subrepo` lifecycle — `git subrepo clone` refuses cloning into an empty
/// repo, and `.gitrepo` only exists once a commit introduced its `commit =`
/// line — so no test fabricates them.
///
/// Returns the SHA of the fixup commit it creates, so a caller whose
/// subsequent retry still fails can disclose that this commit already
/// landed on the branch rather than leaving it a silent side effect.
fn fix_stale_parent(repo_root: &Path, subdir: &str) -> Result<String> {
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
    run_git(repo_root, &["rev-parse", "HEAD"])
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
