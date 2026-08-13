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
    /// itself committed nothing to the caller's branch. `unresolved`'s
    /// paths are left in the temp merge worktree exactly as `git merge`
    /// would leave them, with real conflict markers, for a human to
    /// resolve — but paths on the documented-safe allowlist are NOT left
    /// that way even though the outcome as a whole is `Conflicted`:
    /// `handle_conflict` already resolved and staged them to upstream's
    /// content before returning, and their paths are disclosed in
    /// `auto_resolved` rather than silently mutating the worktree with no
    /// record of it. `fixup_commit` is `Some(sha)` when a prior,
    /// independent `.gitrepo`-parent-realignment commit already landed on
    /// the branch before this conflict was hit (see `fix_stale_parent`) —
    /// carried in the value, not just an error path, so a real (non-`Err`)
    /// `Conflicted` result still discloses it.
    Conflicted {
        worktree: PathBuf,
        unresolved: Vec<String>,
        auto_resolved: Vec<String>,
        fixup_commit: Option<String>,
    },
}

pub fn run(repo_root: &Path, subdir: &str, tag: &str) -> Result<Outcome> {
    let subdir = &normalize_subdir(subdir);
    assert_subdir_is_ref_safe(repo_root, subdir)?;
    ensure_clean_tree(repo_root, subdir)?;
    ensure_no_in_progress_conflict_resolution(repo_root, subdir)?;

    let first = attempt_pull(repo_root, subdir, tag)?;
    if first.status.success() {
        best_effort_clean(repo_root, subdir);
        // `git subrepo pull` has, in the usual (non-no-op) case, already
        // committed real vendored content to HEAD by this point — if the
        // tag-pin fixup below fails, say so, rather than leaving that
        // already-landed commit an undisclosed side effect.
        ensure_tag_pin_matches(repo_root, subdir, tag).with_context(|| {
            "git subrepo pull already succeeded and (usually) committed to this branch before \
             this failure — check `git log -1` before assuming nothing happened"
                .to_string()
        })?;
        return Ok(Outcome::Clean);
    }

    let stderr = String::from_utf8_lossy(&first.stderr);
    if stderr.contains("is not an ancestor") {
        let fixup_commit = fix_stale_parent(repo_root, subdir)?;
        return retry_after_stale_parent_fixup(repo_root, subdir, tag, &fixup_commit);
    }

    handle_conflict(repo_root, subdir, tag, &first, None)
}

/// Every fallible step after `fix_stale_parent` lands its `.gitrepo`
/// parent-realignment commit is wrapped with the same disclosure context —
/// a real, irreversible commit already exists on the branch by this point,
/// and the module's contract (see the module doc) promises no error path
/// after that leaves it a silent side effect. One shared closure, applied
/// to every fallible call in this retry, so a future added step can't
/// reintroduce the gap by omission.
fn retry_after_stale_parent_fixup(repo_root: &Path, subdir: &str, tag: &str, fixup_commit: &str) -> Result<Outcome> {
    // `{fixup_commit}~1` (not `HEAD~1`) is deliberate: by the time
    // `ensure_tag_pin_matches` below runs, a successful `second` pull has
    // already added its own content commit on top of `fixup_commit`, so
    // `HEAD~1` would only undo *that* commit, not the fixup. Naming the
    // fixup commit's own parent directly stays correct regardless of how
    // many commits landed after it.
    let disclose = || {
        format!(
            "a `.gitrepo` parent-realignment commit ({fixup_commit}) was already created on \
             this branch before this failure; `git reset --hard {fixup_commit}~1` undoes it \
             (and anything committed after it) if you want to retry from a clean state"
        )
    };

    let second = attempt_pull(repo_root, subdir, tag).with_context(disclose)?;
    if second.status.success() {
        best_effort_clean(repo_root, subdir);
        ensure_tag_pin_matches(repo_root, subdir, tag).with_context(disclose)?;
        return Ok(Outcome::Clean);
    }
    handle_conflict(repo_root, subdir, tag, &second, Some(fixup_commit)).with_context(disclose)
}

/// Mirrors git-subrepo's own `check-and-normalize-subdir`: strips a leading
/// `./`, a trailing `/`, and collapses repeated `/`. git-subrepo applies
/// this to its own `$subdir` argument before doing anything else, so a
/// caller passing e.g. a shell-tab-completed `vendor/` still works from
/// git-subrepo's point of view — every check and path this module builds
/// from `subdir` needs the same normalized value, not the raw argument, to
/// stay consistent with what git-subrepo actually operates on.
fn normalize_subdir(subdir: &str) -> String {
    let s = subdir.strip_prefix("./").unwrap_or(subdir);
    let s = s.strip_suffix('/').unwrap_or(s);
    if !s.contains("//") {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut prev_slash = false;
    for c in s.chars() {
        if c == '/' {
            if !prev_slash {
                out.push(c);
            }
            prev_slash = true;
        } else {
            out.push(c);
            prev_slash = false;
        }
    }
    out
}

/// git-subrepo's own `encode-subdir` percent-encodes `subdir` into a
/// distinct `subref` whenever `subdir` isn't already a valid git ref
/// component (spaces, `~`, `^`, `:`, leading dots, etc.) — but leaves
/// `subref == subdir` unchanged for every subdir already valid as one
/// (confirmed in the installed `git-subrepo` lib: it early-returns before
/// encoding whenever `git check-ref-format "subrepo/$subref"` succeeds).
/// This module builds worktree/branch paths straight from `subdir`, which
/// only matches what git-subrepo itself uses when no encoding was needed —
/// so refuse up front rather than silently guarding (and later cleaning)
/// the wrong path for a `subdir` that would encode. Must run on the
/// already-`normalize_subdir`-ed value, since normalization (not encoding)
/// is what git-subrepo applies first.
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

/// Untracked files outside `<subdir>` are deliberately allowed:
/// `fix_stale_parent`'s commit only ever `git add`s the `.gitrepo`
/// pathspec, so one elsewhere can never be swept into it, and `git subrepo
/// pull` itself doesn't refuse on them either — its own working-copy-clean
/// assertion checks tracked changes only.
///
/// An untracked file *inside* `<subdir>` is a different, real hazard:
/// git-subrepo's fold-in step does `git rm -r <subdir>` and only then
/// `git read-tree --prefix=<subdir> -u <upstream>` — if the untracked file
/// collides with a path the new upstream tree introduces, `read-tree`
/// aborts after the `rm` already deleted and staged the whole subtree,
/// leaving `<subdir>` half-destroyed. That failure's stderr doesn't
/// contain "is not an ancestor", so it routes to `handle_conflict`'s raw
/// bail with no mention that `<subdir>` was just wiped.
fn ensure_clean_tree(repo_root: &Path, subdir: &str) -> Result<()> {
    let status = run_git(repo_root, &["status", "--porcelain", "--untracked-files=no"])?;
    if !status.is_empty() {
        bail!("working tree has uncommitted changes; refusing to run against it:\n{status}");
    }

    // `--untracked-files=normal` is explicit rather than relying on the
    // default: a user/CI image with `status.showUntrackedFiles=no` set
    // would otherwise make this check silently see nothing to reject.
    let subdir_status = run_git(
        repo_root,
        &["status", "--porcelain", "--untracked-files=normal", "--", subdir],
    )?;
    let untracked_in_subdir: Vec<&str> = subdir_status.lines().filter(|line| line.starts_with("??")).collect();
    if !untracked_in_subdir.is_empty() {
        bail!(
            "untracked files exist under `{subdir}` — git-subrepo's pull step deletes and \
             re-populates this whole subtree, and an untracked file colliding with a path in \
             the new upstream tree aborts mid-way, leaving `{subdir}` half-destroyed:\n{}",
            untracked_in_subdir.join("\n")
        );
    }
    Ok(())
}

/// `best_effort_clean` runs `git subrepo clean`, the one git-subrepo
/// subcommand that skips the tool's own working-copy-clean guard — it would
/// silently discard a worktree a human is actively resolving a real
/// conflict in. Existence, not dirtiness, is the right test for the
/// worktree: after the human resolves and commits *inside* it (per
/// git-subrepo's own recovery steps), porcelain status is clean again even
/// though the outer `git subrepo commit <subdir>` fold-in hasn't happened
/// yet — that state must still be refused, not discarded.
///
/// The `subrepo/<subdir>` branch needs a different test, not mere
/// existence: git-subrepo leaves this branch behind after *every*
/// successful pull too (`subrepo:pull` only deletes+recreates it on the
/// *next* pull; nothing at the end of a successful one removes it), so a
/// branch-existence-only check would permanently refuse to run wherever
/// the documented manual flow was ever used. What distinguishes
/// "benign leftover from a completed pull" from "a human's resolution
/// commit that was never folded in" (e.g. after a manual `rm -rf` of the
/// worktree, bypassing `git subrepo commit <subdir>`) is
/// `refs/subrepo/<subdir>/commit`: git-subrepo's own `subrepo:commit` step
/// — reached only on completion, auto-merged or manually folded in — always
/// updates it to the branch's exact tip at that moment. So the branch is
/// safe exactly when it matches that ref; anything else means unfolded
/// work sits on it.
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

    let branch_ref = format!("refs/heads/subrepo/{subdir}");
    if let Some(branch_sha) = rev_parse_if_exists(repo_root, &branch_ref)? {
        let commit_ref = format!("refs/subrepo/{subdir}/commit");
        let folded_in = rev_parse_if_exists(repo_root, &commit_ref)?.as_deref() == Some(branch_sha.as_str());
        if !folded_in {
            bail!(
                "the `{branch_ref}` branch carries commits never folded in via `git subrepo \
                 commit {subdir}` (its tip doesn't match `{commit_ref}`) — if you're resolving \
                 a conflict there, finish it (see the earlier `pull-subrepo` output for the \
                 exact steps); if it's stale, run `git subrepo clean {subdir}` yourself first \
                 to discard it"
            );
        }
    }
    Ok(())
}

/// `git rev-parse --verify --quiet <ref>`: `Some(sha)` if `ref` resolves,
/// `None` if it doesn't exist — as opposed to `run_git`, which treats a
/// nonzero exit as an error. `--quiet` only suppresses git's message for
/// the "not a valid object" case (confirmed: a missing ref and a malformed
/// one both exit 1 with empty stderr); any *other* stderr output on a
/// nonzero exit means something else genuinely failed and must not be
/// silently folded into "the ref doesn't exist".
fn rev_parse_if_exists(repo_root: &Path, ref_name: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", ref_name])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to run `git rev-parse --verify {ref_name}`"))?;
    if output.status.success() {
        return Ok(Some(String::from_utf8_lossy(&output.stdout).trim().to_string()));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        bail!("git rev-parse --verify --quiet {ref_name} failed: {}", stderr.trim());
    }
    Ok(None)
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
/// construction (it comes from `git log` starting at HEAD).
///
/// Verified against only HEAD, not also against `.gitrepo`'s recorded
/// `commit` field: read the installed git-subrepo's own `subrepo:branch()`
/// (the function that raises the "is not an ancestor" error this fixup
/// exists to satisfy) — it performs exactly the same single
/// `merge-base --is-ancestor $subrepo_parent HEAD` check before proceeding,
/// never one against the `.gitrepo` `commit` field. Matching what
/// git-subrepo itself actually validates is correct and sufficient for the
/// retry to succeed; a second check against a field with no established
/// operational meaning in this comparison would validate a requirement
/// git-subrepo doesn't have.
///
/// The is-ancestor check below is still a real, always-on `bail!` rather than a
/// `debug_assert!` despite that guarantee: it's the sole guard immediately
/// before an irreversible committed write in unattended CI, where a
/// silently compiled-away check (debug_assert! is a no-op in release
/// builds) is the wrong trade. The two earlier `bail!`s (no commit found;
/// root commit with no parent) are unreachable through any real `git
/// subrepo` lifecycle — `git subrepo clone` refuses cloning into an empty
/// repo, and `.gitrepo` only exists once a commit introduced its `commit =`
/// line.
///
/// Returns the SHA of the fixup commit it creates.
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
        .output()
        .context("git merge-base --is-ancestor failed to run")?;
    if !is_ancestor.status.success() {
        // Confirmed: "not an ancestor" is exit 1 with empty stderr; a
        // genuinely malformed/invalid commit-ish exits 128 with a real
        // stderr message — don't conflate the two under one canned message.
        let stderr = String::from_utf8_lossy(&is_ancestor.stderr);
        if !stderr.trim().is_empty() {
            bail!(
                "git merge-base --is-ancestor {candidate} HEAD failed: {}",
                stderr.trim()
            );
        }
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

    run_git(repo_root, &["add", &gitrepo_rel]).with_context(|| {
        format!("`{gitrepo_rel}` was already modified on disk to realign `parent` before this failure")
    })?;
    run_git(
        repo_root,
        &[
            "commit",
            "-m",
            &format!("fix: realign {subdir} subrepo parent after squash-merge"),
        ],
    )
    .with_context(|| {
        format!("`{gitrepo_rel}` was already modified and staged to realign `parent` before this failure")
    })?;
    run_git(repo_root, &["rev-parse", "HEAD"])
        .context("the .gitrepo parent-realignment commit was created but its SHA could not be read back")
}

/// `git subrepo pull` exits 0 and returns `Outcome::Clean` for a genuine
/// no-op too ("already up to date": `tag` resolves to the commit already
/// recorded), and that path leaves `.gitrepo` completely untouched —
/// including its `branch` field, which keeps naming the *old* tag. Every
/// real merge already sets `branch` correctly (git-subrepo's own
/// `update-gitrepo-file` step), so this is a no-op there; it only acts on
/// the no-op-pull gap, keeping `Outcome::Clean`'s contract (the tag pin is
/// current) true unconditionally rather than true only when git-subrepo
/// happened to do real work.
fn ensure_tag_pin_matches(repo_root: &Path, subdir: &str, tag: &str) -> Result<()> {
    let gitrepo_path = repo_root.join(subdir).join(".gitrepo");
    let contents =
        std::fs::read_to_string(&gitrepo_path).with_context(|| format!("failed to read {}", gitrepo_path.display()))?;
    if gitrepo_field(&contents, "branch").as_deref() == Some(tag) {
        return Ok(());
    }

    let gitrepo_rel = format!("{subdir}/.gitrepo");
    std::fs::write(&gitrepo_path, replace_gitrepo_field(&contents, "branch", tag)?)
        .with_context(|| format!("failed to write {}", gitrepo_path.display()))?;
    run_git(repo_root, &["add", &gitrepo_rel]).with_context(|| {
        format!("`{gitrepo_rel}` was already modified on disk to realign `branch` before this failure")
    })?;
    run_git(
        repo_root,
        &[
            "commit",
            "-m",
            &format!("fix: realign {subdir} subrepo branch pin to {tag}"),
        ],
    )
    .with_context(|| {
        format!("`{gitrepo_rel}` was already modified and staged to realign `branch` before this failure")
    })?;
    Ok(())
}

fn gitrepo_field(contents: &str, field: &str) -> Option<String> {
    let prefix = format!("{field} =");
    contents.lines().find_map(|line| {
        line.trim_start()
            .strip_prefix(&prefix)
            .map(|rest| rest.trim().to_string())
    })
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

// See `Outcome::Conflicted`'s own doc for what `fixup_commit` carries and why.
fn handle_conflict(
    repo_root: &Path,
    subdir: &str,
    tag: &str,
    pull_output: &Output,
    fixup_commit: Option<&str>,
) -> Result<Outcome> {
    // A real merge conflict is detected by the state git-subrepo actually
    // leaves behind — a temp worktree with unmerged paths — not by
    // matching a substring of its human-facing recovery prose in stdout.
    // That prose is printed via git-subrepo's own `say()`, which is a
    // silent no-op whenever the ambient `GIT_SUBREPO_QUIET` env var is
    // set (confirmed against the installed git-subrepo 0.4.9 source;
    // this module doesn't control that var — a CI runner or a
    // developer's shell profile could set it), so string-matching stdout
    // is not a reliable signal.
    let unexpected_failure = |extra: Option<String>| {
        // `git subrepo pull` runs its own internal fold-in commit in
        // `repo_root` as part of a conflict-free merge — if that specific
        // commit is what failed (e.g. a rejecting hook), the `<subdir>`
        // swap it staged (`git rm -r` + `git read-tree --prefix`) is left
        // staged and uncommitted in the caller's repo with nothing else in
        // this module aware of it. Surface it here rather than leaving it
        // an undisclosed side effect discovered later as an unrelated
        // "working tree has uncommitted changes" on the next run.
        // `--untracked-files=no`, matching `ensure_clean_tree`'s own
        // tracked-changes-only definition of "dirty" — an untracked
        // scratch file elsewhere in the repo is not evidence git-subrepo's
        // fold-in partially ran, and would otherwise trigger a false
        // "run `git reset --hard`" warning on an unrelated failure.
        let staged_note = match run_git(repo_root, &["status", "--porcelain", "--untracked-files=no"]) {
            Ok(status) if status.is_empty() => String::new(),
            Ok(status) => format!(
                "\n\nthe repo also has staged/uncommitted changes right now — git-subrepo's own \
                 fold-in step may have partially run before failing; inspect before retrying \
                 (`git reset --hard` undoes it if so):\n{status}"
            ),
            Err(e) => {
                eprintln!("xtask: debug: `git status --porcelain` failed while building diagnostics: {e}");
                String::new()
            }
        };
        anyhow::anyhow!(
            "git subrepo pull failed in an unexpected way{}:\nstdout:\n{}\nstderr:\n{}{staged_note}",
            extra.map(|e| format!(" ({e})")).unwrap_or_default(),
            String::from_utf8_lossy(&pull_output.stdout),
            String::from_utf8_lossy(&pull_output.stderr)
        )
    };
    let worktree = conflict_worktree(repo_root, subdir)
        .map_err(|e| unexpected_failure(Some(format!("no conflict worktree found: {e:#}"))))?;
    let conflicted = unmerged_paths(&worktree)
        .map_err(|e| unexpected_failure(Some(format!("failed to list unmerged paths: {e:#}"))))?;
    if conflicted.is_empty() {
        return Err(unexpected_failure(Some(format!(
            "a conflict worktree exists at {} but has no unmerged paths",
            worktree.display()
        ))));
    }

    // Only checked once a real conflict is confirmed, so a non-conflict
    // failure (e.g. `<subdir>/.gitrepo` missing entirely) still surfaces
    // through `unexpected_failure` with the pull's real stdout/stderr,
    // rather than this check's own unrelated read error discarding it.
    assert_join_method_is_merge(repo_root, subdir)?;

    let mut unresolved = Vec::new();
    let mut auto_resolved = Vec::new();

    // Resolve go.mod first (independent of `unmerged_paths`'s own
    // ordering) so go.sum's own coupling check inside `resolve_to_theirs`,
    // which reads go.mod's *current* worktree state, sees the result of
    // this resolution rather than a still-conflicted go.mod.
    if conflicted.iter().any(|p| p.as_str() == "go.mod") {
        let resolved = resolve_to_theirs(&worktree, subdir, "go.mod").with_context(|| {
            format!(
                "failed to resolve go.mod in the subrepo temp worktree {}",
                worktree.display()
            )
        })?;
        if resolved {
            auto_resolved.push("go.mod".to_string());
        } else {
            unresolved.push("go.mod".to_string());
        }
    }

    for path in conflicted.iter().filter(|p| p.as_str() != "go.mod") {
        if is_auto_resolvable(path) {
            let resolved = resolve_to_theirs(&worktree, subdir, path).with_context(|| {
                format!(
                    "failed to resolve {path} in the subrepo temp worktree {} — other allowlisted \
                     paths in this same run may already be resolved and staged there; inspect \
                     with `git status` before assuming nothing happened",
                    worktree.display()
                )
            })?;
            if resolved {
                auto_resolved.push(path.clone());
                continue;
            }
        }
        unresolved.push(path.clone());
    }

    // Final safety net for a go.sum that never itself appeared in
    // `conflicted` at all — `resolve_to_theirs`'s own go.sum/go.mod
    // coupling check (inside the loop above) only runs when go.sum is
    // itself a conflict this module resolves. If go.mod WAS a conflict
    // this run and this module explicitly resolved it to upstream's exact
    // content (`auto_resolved`, not merely "happens to match upstream" —
    // a go.mod this run never touched at all is not this module's
    // business to second-guess), while go.sum never conflicted at all
    // (git's own clean 3-way merge silently kept downstream's now-stale
    // content) and no longer matches upstream, nothing else here would
    // catch the resulting inconsistent pair. Unlike go.mod's `replace`
    // directives, go.sum has no independently meaningful downstream
    // content to preserve — it's purely a derived artifact of go.mod's
    // requirements — so it's realigned to upstream directly (the same
    // "take theirs" resolution a real conflict on it would get) rather
    // than reported as `unresolved` — there's no conflict-marker state for
    // a human to act on, and `force_commit_conflicted`'s own hard guard
    // (real unmerged paths required) would refuse a worktree whose only
    // flagged problem is this.
    if auto_resolved.iter().any(|p| p.as_str() == "go.mod")
        && !auto_resolved.iter().any(|p| p.as_str() == "go.sum")
        && !unresolved.iter().any(|p| p.as_str() == "go.sum")
    {
        // No filesystem `.exists()` gate here — a downstream-only deletion
        // of go.sum (never conflicted, git's clean merge just kept the
        // deletion) is exactly one of the inconsistent-pair shapes this
        // net exists to catch, and the `ours_go_sum != upstream_go_sum`
        // comparison below already handles every presence combination
        // correctly (including both-absent, which correctly no-ops).
        let already_staged_note = || {
            format!(
                "go.mod is already resolved and staged to upstream's content in the subrepo temp \
                 worktree {} — this failure is only in checking/realigning the now-possibly-stale \
                 go.sum alongside it",
                worktree.display()
            )
        };
        let upstream_go_sum = read_blob_if_exists(&worktree, &format!("refs/subrepo/{subdir}/fetch:go.sum"))
            .with_context(already_staged_note)?;
        let ours_go_sum = read_blob_if_exists(&worktree, ":go.sum").with_context(already_staged_note)?;
        if ours_go_sum != upstream_go_sum {
            // Mirrors `resolve_to_theirs`'s own `!theirs_present` branch:
            // if upstream has no go.sum at the pulled tag at all, "realign
            // to upstream" means removing it — `git checkout <fetch-ref>
            // -- go.sum` would otherwise fail outright on a pathspec that
            // matches nothing in that tree (confirmed against git 2.53.0).
            if upstream_go_sum.is_some() {
                run_git(
                    &worktree,
                    &[
                        "checkout",
                        &format!("refs/subrepo/{subdir}/fetch"),
                        "--",
                        ":(literal)go.sum",
                    ],
                )
                .with_context(already_staged_note)?;
                run_git(&worktree, &["add", "--", ":(literal)go.sum"]).with_context(already_staged_note)?;
            } else {
                run_git(&worktree, &["rm", "--", ":(literal)go.sum"]).with_context(already_staged_note)?;
            }
            auto_resolved.push("go.sum".to_string());
        }
    }

    if !unresolved.is_empty() {
        return Ok(Outcome::Conflicted {
            worktree,
            unresolved,
            auto_resolved,
            fixup_commit: fixup_commit.map(str::to_string),
        });
    }

    // Every conflict was on the documented-safe allowlist — finish the
    // merge exactly as git-subrepo's own instructions tell a human to.
    // PREK_ALLOW_NO_CONFIG=1 (not --no-verify): this temp worktree is a
    // standalone checkout of just the subrepo content, with no
    // prek.toml of its own.
    let already_staged_note = || {
        format!(
            "the allowlisted conflicts ({}) are already resolved and staged in the subrepo temp \
             worktree {} — only the commit itself needs retrying, not the resolution",
            auto_resolved.join(", "),
            worktree.display()
        )
    };
    let status = Command::new("git")
        .args(["commit", "--no-edit"])
        .current_dir(&worktree)
        .env("PREK_ALLOW_NO_CONFIG", "1")
        .status()
        .with_context(already_staged_note)?;
    if !status.success() {
        bail!(
            "git commit failed in the subrepo temp worktree {}: {}",
            worktree.display(),
            already_staged_note()
        );
    }

    finish_conflict_fold_in(repo_root, subdir, tag)?;
    Ok(Outcome::Clean)
}

/// Whether `path` (as it currently sits in the worktree — resolved via
/// the allowlist, left via git's own clean 3-way merge for non-overlapping
/// edits that never get flagged as a conflict at all, or still conflicted)
/// is byte-identical to upstream's version at the pulled tag. Reads
/// "ours" from the worktree's current index (stage 0: absent while `path`
/// is still an unmerged conflict, since only stages 1/2/3 exist then) and
/// "theirs" from git-subrepo's own `refs/subrepo/<subdir>/fetch` ref,
/// which always points at the raw fetched upstream commit at the pulled
/// tag, independent of whether any individual file conflicted (confirmed
/// against the installed git-subrepo 0.4.9 source and a live worktree).
/// Both reads go through `read_blob_if_exists`, not a blanket `.ok()`: a
/// path legitimately absent from one side (deleted, or never conflicted
/// and simply doesn't exist there) must compare as `None`, but a genuine
/// git error on either side (a malformed ref, an unrelated failure) must
/// propagate as `Err` rather than silently read as "absent" — collapsing
/// both into `None` would let two *different* real failures agree with
/// each other and register as a false "matches". An unmerged `path` gets
/// an explicit, separate check rather than falling into that same `None`
/// bucket: its stage-0 read fails the exact same way a *deleted* path's
/// would, so if upstream also happens to lack `path` (e.g. it deleted it
/// too), both sides would otherwise read `None` and register as a false
/// "matches" while `path`'s real fate is still undecided.
fn blob_matches_upstream(worktree: &Path, subdir: &str, path: &str) -> Result<bool> {
    let pathspec = format!(":(literal){path}");
    if !run_git(worktree, &["ls-files", "-u", "--", &pathspec])?.is_empty() {
        return Ok(false);
    }
    let ours = read_blob_if_exists(worktree, &format!(":{path}"))?;
    let theirs = read_blob_if_exists(worktree, &format!("refs/subrepo/{subdir}/fetch:{path}"))?;
    Ok(ours == theirs)
}

/// `git show <revision-spec>`, returning `Ok(None)` when the failure is
/// git's own wording for "this specific path doesn't exist here" (checked
/// against every wording confirmed live on git 2.53.0: absent from a
/// tree-ish, absent from the index with or without an on-disk copy, and
/// present-but-unmerged for the bare `:path` index form) — any other
/// failure (a malformed revision, a corrupt ref, etc.) propagates as a
/// real `Err` instead of being folded into the same "absent" bucket.
fn read_blob_if_exists(worktree: &Path, revision_spec: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["show", revision_spec])
        .current_dir(worktree)
        // `LC_ALL=C`: git's `fatal:` messages this function pattern-matches
        // are gettext-translated — a git install with locale data present
        // under a non-English `LANG`/`LC_ALL` would otherwise emit wording
        // this match can't recognize, turning every legitimate "path
        // absent" case into a false `bail!`.
        .env("LC_ALL", "C")
        .output()
        .with_context(|| format!("failed to run `git show {revision_spec}`"))?;
    if output.status.success() {
        return Ok(Some(String::from_utf8_lossy(&output.stdout).trim().to_string()));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let path_absent = stderr.contains("does not exist in")
        || stderr.contains("does not exist (neither on disk nor in the index)")
        || stderr.contains("exists on disk, but not in")
        || stderr.contains("is in the index, but not at stage");
    if path_absent {
        return Ok(None);
    }
    bail!("git show {revision_spec} failed: {}", stderr.trim());
}

/// `.gitrepo`'s `method` field selects `git subrepo`'s join strategy —
/// `merge` (the default, and the only value this repo's own vendored
/// subrepos actually use) or `rebase`. Under `rebase`, git-subrepo swaps
/// which side is stage 2 vs stage 3 (`git rebase <upstream> <ours>`, not
/// `git merge`), inverting every "theirs"/"ours" assumption this module's
/// conflict-resolution logic makes (`checkout --theirs`, the go.mod
/// replace-directive check, `blob_matches_upstream`'s stage-0 read) — a
/// hard, always-on guard rather than silently resolving the wrong side,
/// since this repo's own `.gitrepo` files are checked-in and the
/// consequence of getting it wrong is a corrupted vendor commit.
fn assert_join_method_is_merge(repo_root: &Path, subdir: &str) -> Result<()> {
    let gitrepo_path = repo_root.join(subdir).join(".gitrepo");
    let contents =
        std::fs::read_to_string(&gitrepo_path).with_context(|| format!("failed to read {}", gitrepo_path.display()))?;
    match gitrepo_field(&contents, "method").as_deref() {
        None | Some("merge") => Ok(()),
        Some(other) => bail!(
            "`{subdir}/.gitrepo` has `method = {other}` — this module's conflict-resolution \
             logic (checkout --theirs, the go.mod replace-directive preservation check, the \
             go.mod/go.sum consistency check) assumes git-subrepo's default `merge` join \
             strategy; under `rebase`, git-subrepo swaps which side is \"ours\" vs \"theirs\", \
             which would silently invert every one of those checks. Resolve this conflict by \
             hand instead."
        ),
    }
}

/// The CI-only "commit despite conflicts" policy — deliberately NOT
/// reachable from `run`/`handle_conflict`, so `pull-subrepo` itself never
/// commits a conflicted tree. Kept in Rust (not reimplemented in the
/// calling workflow's YAML/bash) so the worktree-path derivation and
/// branch-field fixup stay the same tested code path as everything else
/// in this module, instead of a second, untested implementation drifting
/// from the first.
pub fn force_commit_conflicted(repo_root: &Path, subdir: &str, tag: &str) -> Result<()> {
    // Same normalization/ref-safety guards `run` applies before deriving
    // any worktree/branch path from `subdir` — without them, a
    // ref-unsafe or unnormalized `subdir` (e.g. one needing git-subrepo's
    // own `encode-subdir` percent-encoding) would make `conflict_worktree`
    // below look in the wrong place and fail with its generic "no
    // conflicted subrepo temp worktree found" message instead of
    // `assert_subdir_is_ref_safe`'s specific, actionable one.
    let subdir = &normalize_subdir(subdir);
    assert_subdir_is_ref_safe(repo_root, subdir)?;
    // Same guard `run` applies before ever touching a subrepo: git-subrepo's
    // fold-in (`git rm -r -- <subdir>` then `git read-tree --prefix=<subdir>
    // -u`, run inside `finish_conflict_fold_in` below) doesn't check for
    // untracked files itself, so one colliding with a path in the merged
    // tree aborts `read-tree` after `rm` already deleted and staged the
    // entire vendored subtree — confirmed live: `<subdir>` ends up entirely
    // deleted-and-staged with no disclosure beyond the raw git-subrepo error.
    ensure_clean_tree(repo_root, subdir)?;
    let worktree = conflict_worktree(repo_root, subdir)?;
    // A hard guard, not a debug_assert — this is immediately before an
    // irreversible commit in unattended CI (the same class of risk
    // fix_stale_parent's is-ancestor check guards against).
    if unmerged_paths(&worktree)?.is_empty() {
        bail!(
            "the subrepo temp worktree at {} has no unmerged paths — refusing to force-commit \
             what isn't actually a conflicted pull; if it's a stale worktree from an unrelated \
             run, resolve it with `git subrepo commit {subdir}` or discard it with `git subrepo \
             clean {subdir}` instead",
            worktree.display()
        );
    }
    run_git(&worktree, &["add", "-A"])?;
    let already_staged_note = || {
        format!(
            "`git add -A` already staged the entire (conflict-marker-laden) tree in the subrepo \
             temp worktree {} — only the commit itself needs retrying, not another `git add`",
            worktree.display()
        )
    };
    let status = Command::new("git")
        .args([
            "commit",
            "-m",
            &format!("vendor: conflicted pull of {subdir} {tag} — needs manual resolution"),
        ])
        .current_dir(&worktree)
        .env("PREK_ALLOW_NO_CONFIG", "1")
        .status()
        .with_context(already_staged_note)?;
    if !status.success() {
        bail!(
            "git commit failed in the subrepo temp worktree {}: {}",
            worktree.display(),
            already_staged_note()
        );
    }
    finish_conflict_fold_in(repo_root, subdir, tag)
}

/// Folds the resolved temp worktree into the caller's branch
/// (`git subrepo commit`, a real irreversible commit) and realigns the tag
/// pin — shared by `handle_conflict`'s auto-resolved-clean path and
/// `force_commit_conflicted` so both stay on the same tested disclosure
/// path instead of two copies silently drifting apart. Both calls are
/// disclosure-wrapped like the rest of this module's post-commit steps
/// (see `run`'s own `ensure_tag_pin_matches` call): a real commit already
/// exists on the branch by the time either could fail.
fn finish_conflict_fold_in(repo_root: &Path, subdir: &str, tag: &str) -> Result<()> {
    run_git(repo_root, &["subrepo", "commit", subdir]).with_context(|| {
        format!(
            "a commit was already made in the subrepo temp worktree before this failure — run \
             `git subrepo commit {subdir}` yourself to retry the fold-in once fixed, or `git \
             subrepo clean {subdir}` to discard it"
        )
    })?;
    // Cleaned up before the fallible `ensure_tag_pin_matches` below — same
    // ordering as `run`'s own plain-success path — so a tag-pin failure
    // here never leaves the now-folded-in temp worktree behind blocking
    // `ensure_no_in_progress_conflict_resolution` on the next run.
    best_effort_clean(repo_root, subdir);
    ensure_tag_pin_matches(repo_root, subdir, tag).with_context(|| {
        format!(
            "`git subrepo commit {subdir}` already succeeded and committed real vendored content \
             to this branch before this failure — check `git log -1` before assuming nothing \
             happened"
        )
    })?;
    Ok(())
}

fn conflict_worktree(repo_root: &Path, subdir: &str) -> Result<PathBuf> {
    let common_dir = git_common_dir(repo_root)?;
    let worktree = common_dir.join("tmp").join("subrepo").join(subdir);
    if !worktree.exists() {
        bail!(
            "no conflicted subrepo temp worktree found at {} — its internal layout may have \
             changed since git-subrepo 0.4.9, or there's nothing to commit",
            worktree.display()
        );
    }
    Ok(worktree)
}

/// Resolves a conflicted path to upstream's ("theirs") version. Returns
/// `Ok(true)` if resolved, `Ok(false)` if it declined — for `go.mod`,
/// where taking theirs (or, on a delete/modify conflict, deleting our
/// version outright) would drop a downstream-only `replace` line; for
/// `go.sum`, where taking theirs would pair upstream's checksums with a
/// go.mod that isn't upstream's, see below — the caller treats a decline
/// as a real, unresolved conflict rather than silently losing or
/// corrupting content.
///
/// The `go.mod` check runs before the delete/modify (`!theirs_present`)
/// branch, and covers both directions of that conflict: if upstream
/// deleted `go.mod` while we modified it, "their" directives are treated
/// as empty (deleting the file loses every directive we carry, same as
/// checking out an upstream version with none of them); if we deleted
/// `go.mod` (`!ours_present`) there is nothing of ours to lose, so the
/// check is skipped and resolving to theirs (resurrecting the file) is
/// correct. Compares whole directives, not just the replaced module's
/// path, so upstream rewriting a directive's target while keeping the
/// same left-hand path (e.g. `=> ../utls` becoming `=> some-fork`) is
/// still caught as a loss.
///
/// The `go.sum` check similarly runs before `!theirs_present`, but is
/// scoped to the content-*taking* branch only (`theirs_present`): go.sum
/// is a checksum lockfile whose only valid content matches its paired
/// go.mod exactly, so taking upstream's go.sum content is only safe when
/// go.mod's current worktree state (whatever it is right now — resolved
/// above if it also conflicted, or however git's own clean 3-way merge
/// left it if it never conflicted at all) is byte-identical to upstream's
/// go.mod. A go.sum *deletion* (`!theirs_present`, upstream removed the
/// file) carries no such hazard — an absent file has no checksums to
/// mismatch — so it's exempt from this check.
fn resolve_to_theirs(worktree: &Path, subdir: &str, path: &str) -> Result<bool> {
    // `:(literal)` disables git's default glob-pathspec matching — a
    // conflicted filename containing `[`, `]`, `*`, or `?` (all legal,
    // including on Windows) would otherwise also match unrelated sibling
    // files in every pathspec-taking call below, e.g. `git rm --
    // 'x[12].yml'` deleting the literal file AND `x1.yml`/`x2.yml`
    // (confirmed against git 2.53.0).
    let pathspec = format!(":(literal){path}");
    let staged = run_git(worktree, &["ls-files", "-u", "--", &pathspec])?;
    let has_stage = |stage_num: &str| {
        staged.lines().any(|line| {
            line.split_whitespace()
                .nth(2)
                .map(|stage| stage == stage_num)
                .unwrap_or(false)
        })
    };
    let ours_present = has_stage("2");
    let theirs_present = has_stage("3");

    if path == "go.mod" && ours_present {
        let ours = run_git(worktree, &["show", ":2:go.mod"])?;
        let our_directives = go_mod_replace_directives(&ours)?;
        let their_directives = if theirs_present {
            let theirs = run_git(worktree, &["show", ":3:go.mod"])?;
            go_mod_replace_directives(&theirs)?
        } else {
            Vec::new()
        };
        let lost_a_replace = our_directives.iter().any(|d| !their_directives.contains(d));
        if lost_a_replace {
            return Ok(false);
        }
    }

    if path == "go.sum" && theirs_present && !blob_matches_upstream(worktree, subdir, "go.mod")? {
        return Ok(false);
    }

    if !theirs_present {
        run_git(worktree, &["rm", "--", &pathspec])?;
        return Ok(true);
    }

    run_git(worktree, &["checkout", "--theirs", "--", &pathspec])?;
    run_git(worktree, &["add", "--", &pathspec])?;
    Ok(true)
}

/// Extracts every `replace` directive from a go.mod's content as raw JSON
/// objects, via `go mod edit -json` (the Go toolchain's own parser)
/// rather than line-prefix matching — go.mod's block syntax
/// (`replace (\n\tmod => path\n)`) has individual entries that don't start
/// with the literal text `"replace "`, so a naive per-line filter misses
/// them and would silently pass a downstream-only replace hiding inside a
/// block straight through to `checkout --theirs`.
fn go_mod_replace_directives(content: &str) -> Result<Vec<serde_json::Value>> {
    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for go mod edit")?;
    let tmp_path = tmp_dir.path().join("go.mod");
    std::fs::write(&tmp_path, content).context("failed to write temp go.mod")?;
    // `current_dir` + `GOTOOLCHAIN=local`: Go's toolchain selection reads
    // the *cwd's* module, not the file argument's — without pinning both,
    // this parse's success depends on wherever the caller's shell happened
    // to be standing (e.g. inside a subrepo declaring a newer `go`
    // directive triggers a network toolchain download attempt; confirmed
    // empirically) rather than depending only on `content`.
    let output = Command::new("go")
        .args(["mod", "edit", "-json"])
        .arg(&tmp_path)
        .current_dir(tmp_dir.path())
        .env("GOTOOLCHAIN", "local")
        .output()
        .context("failed to run `go mod edit -json`")?;
    if !output.status.success() {
        bail!("go mod edit -json failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("failed to parse go mod edit -json output")?;
    Ok(parsed["Replace"].as_array().cloned().unwrap_or_default())
}

pub(crate) fn is_auto_resolvable(path: &str) -> bool {
    path == "go.mod" || path == "go.sum" || path.starts_with(".github/workflows/")
}

/// `-z` (NUL-delimited, unquoted paths) avoids git's default
/// `core.quotePath` C-quoting of non-ASCII path bytes — a conflicted
/// `café.yml` would otherwise come back as the literal string
/// `"caf\303\251.yml"` (confirmed against git 2.53.0), breaking
/// `is_auto_resolvable`'s prefix match and every pathspec built from these
/// paths downstream.
fn unmerged_paths(worktree: &Path) -> Result<Vec<String>> {
    let output = run_git(worktree, &["diff", "-z", "--name-only", "--diff-filter=U"])?;
    Ok(output
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect())
}
