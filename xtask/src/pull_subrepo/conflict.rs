//! Conflict-handling half of `pull_subrepo`: auto-resolves the
//! documented-safe allowlist (go.mod/go.sum/.github/workflows/*), leaves
//! everything else as real conflict markers for a human, and the
//! CI-only "commit anyway despite conflicts" policy. Split out from
//! `pull_subrepo.rs`, which keeps the clean-pull/stale-parent-fixup
//! concern and the shared `Outcome`/`run` entry point.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};

use crate::git_util::{hash_object_or_deleted, run_git, run_git_raw, run_git_with_env};

use super::Outcome;

// See `Outcome::Conflicted`'s own doc for what `fixup_commit` carries and why.
pub(super) fn handle_conflict(
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
            stage_upstream_or_remove(&worktree, &format!("refs/subrepo/{subdir}/fetch"), "go.sum")
                .with_context(already_staged_note)?;
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
    commit_in_worktree(&worktree, &["commit", "--no-edit"], already_staged_note)?;

    finish_conflict_fold_in(repo_root, subdir, tag)?;
    Ok(Outcome::Clean)
}

/// An unmerged `path` gets an explicit, separate check rather than falling
/// into `read_blob_if_exists`'s `None` bucket: its stage-0 read fails the
/// exact same way a *deleted* path's would, so if upstream also happens to
/// lack `path` (e.g. it deleted it too), both sides would otherwise read
/// `None` and register as a false "matches" while `path`'s real fate is
/// still undecided.
fn blob_matches_upstream(worktree: &Path, subdir: &str, path: &str) -> Result<bool> {
    let pathspec = format!(":(literal){path}");
    if !run_git(worktree, &["ls-files", "-u", "--", &pathspec])?.is_empty() {
        return Ok(false);
    }
    let ours = read_blob_if_exists(worktree, &format!(":{path}"))?;
    let theirs = read_blob_if_exists(worktree, &format!("refs/subrepo/{subdir}/fetch:{path}"))?;
    Ok(ours == theirs)
}

/// `git cat-file -p <revision-spec>` (not `git show`: confirmed against git
/// 2.53.0 that `show` has an undocumented revision/pathspec-ambiguity
/// fallback that silently returns an *empty success* — not an error — for
/// a nonexistent `<tree>:<path>` whose path contains pathspec-magic
/// characters like `[`/`]`, e.g. a real conflicted `.github/workflows/
/// x[1].yml`; `cat-file` is plumbing with no such fallback and gives the
/// exact same error wording `show` does for every genuinely-absent case).
/// Returns `Ok(None)` when the failure is git's own wording for "this
/// specific path doesn't exist here" (checked against every wording
/// confirmed live on git 2.53.0: absent from a tree-ish, absent from the
/// index with or without an on-disk copy, and present-but-unmerged for the
/// bare `:path` index form) — any other failure (a malformed revision, a
/// corrupt ref, etc.) propagates as a real `Err` instead of being folded
/// into the same "absent" bucket.
fn read_blob_if_exists(worktree: &Path, revision_spec: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["cat-file", "-p", revision_spec])
        .current_dir(worktree)
        // `LC_ALL=C`: git's `fatal:` messages this function pattern-matches
        // are gettext-translated — a git install with locale data present
        // under a non-English `LANG`/`LC_ALL` would otherwise emit wording
        // this match can't recognize, turning every legitimate "path
        // absent" case into a false `bail!`.
        .env("LC_ALL", "C")
        .output()
        .with_context(|| format!("failed to run `git cat-file -p {revision_spec}`"))?;
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
    bail!("git cat-file -p {revision_spec} failed: {}", stderr.trim());
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
    match super::gitrepo_field(&contents, "method").as_deref() {
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
    let subdir = &super::normalize_subdir(subdir);
    super::assert_subdir_is_ref_safe(repo_root, subdir)?;
    // Same guard `run` applies before ever touching a subrepo — see
    // `ensure_clean_tree`'s own doc for the untracked-file hazard it exists
    // to catch.
    super::ensure_clean_tree(repo_root, subdir)?;
    // Guards this path's own irreversible commit exactly as `handle_conflict`
    // guards its clean-resolve commit: under `method = rebase`,
    // `conflict_worktree` below sits on a detached HEAD mid-rebase, and
    // committing there would land a commit `refs/heads/subrepo/<subdir>`
    // never points at — `git subrepo commit`'s own worktree lookup then
    // fails with an unrelated "no worktree available" error, after the
    // commit already happened.
    assert_join_method_is_merge(repo_root, subdir)?;
    let worktree = conflict_worktree(repo_root, subdir)?;
    // A hard guard, not a debug_assert — this is immediately before an
    // irreversible commit in unattended CI (the same class of risk
    // fix_stale_parent's is-ancestor check guards against).
    let unmerged = unmerged_paths(&worktree)?;
    if unmerged.is_empty() {
        bail!(
            "the subrepo temp worktree at {} has no unmerged paths — refusing to force-commit \
             what isn't actually a conflicted pull; if it's a stale worktree from an unrelated \
             run, resolve it with `git subrepo commit {subdir}` or discard it with `git subrepo \
             clean {subdir}` instead",
            worktree.display()
        );
    }
    // The unresolved-conflict sentinel: check-vendoring-integrity's own
    // marker scan can only see conflicts git represents as text — a
    // delete/modify or binary-content conflict never gets markers at all
    // (git just leaves "ours"/"theirs" on disk, unmerged in the index, with
    // zero textual trace). The index-stage signal `unmerged_paths` just
    // read is the only place every conflict shape shows up uniformly, and
    // it only exists transiently — captured here, before `git add -A`
    // commits the tree and it's gone.
    write_vendor_conflict_sentinel(&worktree, &unmerged)?;
    run_git(&worktree, &["add", "-A"])?;
    let already_staged_note = || {
        format!(
            "`git add -A` already staged the entire (conflict-marker-laden) tree in the subrepo \
             temp worktree {} — only the commit itself needs retrying, not another `git add`",
            worktree.display()
        )
    };
    let message = format!("vendor: conflicted pull of {subdir} {tag} — needs manual resolution");
    commit_in_worktree(&worktree, &["commit", "-m", &message], already_staged_note)?;
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
    // `run_git_with_env`, not `run_git`: `git subrepo commit` is a
    // repo-root commit that lands the fold-in tree (real content, but not
    // yet `ensure_tag_pin_matches`'s own `.gitrepo` `branch` realignment
    // below) — the same intermediate-inconsistent-tree shape
    // `pull_subrepo::skip_check_vendoring_integrity`'s own doc comment
    // explains.
    run_git_with_env(
        repo_root,
        &["subrepo", "commit", subdir],
        &[("SKIP", &super::skip_check_vendoring_integrity())],
    )
    .with_context(|| {
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
    super::best_effort_clean(repo_root, subdir);
    super::ensure_tag_pin_matches(repo_root, subdir, tag).with_context(|| {
        format!(
            "`git subrepo commit {subdir}` already succeeded and committed real vendored content \
             to this branch before this failure — check `git log -1` before assuming nothing \
             happened"
        )
    })?;
    Ok(())
}

/// Runs `git <args>` (a commit, in practice) in `worktree` with
/// `PREK_ALLOW_NO_CONFIG=1` — this temp worktree is a standalone checkout
/// of just the subrepo content, with no prek.toml of its own, so the flag
/// (not `--no-verify`) is what lets a hookless environment through while
/// still running any hooks that do exist. Shared by `handle_conflict`'s
/// allowlist-resolved-clean commit and `force_commit_conflicted`'s
/// literal-conflict-markers commit so the two stay on one tested
/// disclosure path instead of two copies silently drifting apart. On
/// failure, the error carries git's own stdout+stderr (`run_git`'s own
/// pattern in `git_util.rs`, for the same reason: some git commands,
/// notably `commit`, report the real failure reason on stdout, not
/// stderr) alongside `already_staged_note`'s call-site-specific context
/// that the target content is already staged and only the commit itself
/// needs retrying.
fn commit_in_worktree(worktree: &Path, args: &[&str], already_staged_note: impl Fn() -> String) -> Result<()> {
    let output = Command::new("git")
        .args(args)
        .current_dir(worktree)
        .env("PREK_ALLOW_NO_CONFIG", "1")
        .output()
        .with_context(&already_staged_note)?;
    if !output.status.success() {
        bail!(
            "git commit failed in the subrepo temp worktree {}:\nstdout:\n{}\nstderr:\n{}\n\n{}",
            worktree.display(),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim(),
            already_staged_note()
        );
    }
    Ok(())
}

fn conflict_worktree(repo_root: &Path, subdir: &str) -> Result<PathBuf> {
    let common_dir = super::git_common_dir(repo_root)?;
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

    // Runs before the delete/modify (`!theirs_present`) branch below, and
    // covers both directions of that conflict: if upstream deleted go.mod
    // while we modified it, "their" directives are treated as empty (same
    // loss as checking out an upstream version with none of them); if we
    // deleted go.mod (`!ours_present`) there's nothing of ours to lose, so
    // this check is skipped and resurrecting the file from theirs is
    // correct. Compares whole directives, not just the replaced module's
    // path, so upstream retargeting a directive we also carry (e.g.
    // `=> ../utls` becoming `=> some-fork`) is still caught as a loss.
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

    // Scoped to the content-*taking* branch only (`theirs_present`):
    // go.sum's only valid content matches its paired go.mod exactly, so
    // taking upstream's is safe only when go.mod's current worktree state
    // is byte-identical to upstream's. A go.sum *deletion* carries no such
    // hazard (an absent file has no checksums to mismatch), so it's exempt.
    if path == "go.sum" && theirs_present && !blob_matches_upstream(worktree, subdir, "go.mod")? {
        return Ok(false);
    }

    stage_upstream_or_remove(worktree, &format!("refs/subrepo/{subdir}/fetch"), path)?;
    Ok(true)
}

/// Stages `upstream_ref`'s content for `path` in `worktree`, or removes
/// `path` if `upstream_ref` doesn't have it — the "take theirs, or delete"
/// resolution every allowlisted path in this module ultimately gets,
/// whether reached through an active merge conflict (`resolve_to_theirs`)
/// or a direct blob comparison with no conflict state at all
/// (`handle_conflict`'s go.sum safety net) — one primitive so the two
/// callers can't drift apart.
fn stage_upstream_or_remove(worktree: &Path, upstream_ref: &str, path: &str) -> Result<()> {
    let pathspec = format!(":(literal){path}");
    if read_blob_if_exists(worktree, &format!("{upstream_ref}:{path}"))?.is_none() {
        run_git(worktree, &["rm", "--", &pathspec])?;
        return Ok(());
    }
    run_git(worktree, &["checkout", upstream_ref, "--", &pathspec])?;
    run_git(worktree, &["add", "--", &pathspec])?;
    Ok(())
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

pub(super) fn is_auto_resolvable(path: &str) -> bool {
    path == "go.mod" || path == "go.sum" || path.starts_with(".github/workflows/")
}

/// `-z` (NUL-delimited, unquoted paths) avoids git's default
/// `core.quotePath` C-quoting of non-ASCII path bytes — a conflicted
/// `café.yml` would otherwise come back as the literal string
/// `"caf\303\251.yml"` (confirmed against git 2.53.0), breaking
/// `is_auto_resolvable`'s prefix match and every pathspec built from these
/// paths downstream.
fn unmerged_paths(worktree: &Path) -> Result<Vec<String>> {
    // `run_git_raw`, not `run_git`: a path can legitimately start with a
    // space, and `run_git`'s `.trim()` would silently strip it off the
    // first entry (`\0` isn't Unicode whitespace, so only the very first
    // and last bytes of the whole joined string are at risk — but the
    // first path's leading byte sits exactly there).
    let output = run_git_raw(worktree, &["diff", "-z", "--name-only", "--diff-filter=U"])?;
    Ok(output
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect())
}

/// Writes one `<path>\t<hash>` line per entry in `unmerged` to
/// `.vendor-conflict` at `worktree`'s root — `hash` is `<deleted>` if
/// `path` doesn't currently exist on disk in `worktree`, otherwise its
/// `git hash-object` blob hash. Written to the worktree root (not
/// `repo_root`) so it's swept into the same `git add -A` + commit as the
/// rest of the conflicted tree, landing at
/// `crates/ex-ray/third_party/<dep>/.vendor-conflict` once
/// `finish_conflict_fold_in` folds the worktree onto the branch — the same
/// per-dep path `check_vendoring_integrity` scans.
fn write_vendor_conflict_sentinel(worktree: &Path, unmerged: &[String]) -> Result<()> {
    let mut contents = String::new();
    for path in unmerged {
        let hash = hash_object_or_deleted(worktree, path)?;
        contents.push_str(&format!("{path}\t{hash}\n"));
    }
    let sentinel_path = worktree.join(".vendor-conflict");
    std::fs::write(&sentinel_path, contents).with_context(|| format!("failed to write {}", sentinel_path.display()))
}
