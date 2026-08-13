use std::path::{Path, PathBuf};
use std::process::Command;

use super::pull_subrepo::{self, Outcome};

/// Which upstream file(s) v2 changes, matched against what our local
/// downstream patch also touches.
enum ConflictKind {
    /// v2 changes only `other.txt`, which nothing downstream touches — a
    /// genuinely clean pull.
    None,
    /// v2 rewrites `go.mod`/`go.sum` (no downstream-only `replace` line
    /// involved), which our downstream commit also edits — exercises the
    /// documented "resolve to theirs" allowlist.
    Allowlisted,
    /// v2 rewrites `go.mod`, but our downstream version carries a
    /// single-line `replace` directive theirs doesn't — resolving to
    /// theirs would silently drop it. Must NOT auto-resolve.
    AllowlistedWithReplace,
    /// Same as `AllowlistedWithReplace`, but the downstream-only `replace`
    /// is written in go.mod's block form (`replace (\n\t...\n)`) instead
    /// of a single line — the exact syntax a naive line-prefix filter
    /// would miss.
    AllowlistedWithBlockReplace,
    /// v2's go.mod carries a `replace` directive for the SAME left-hand
    /// module path our downstream version has, but retargeted to a
    /// different right-hand side — proving the comparison is over whole
    /// directives (old+new path), not just the replaced module's path: a
    /// path-only comparison would wrongly treat this as "theirs already
    /// has it" and silently drop our retargeting. Must NOT auto-resolve.
    AllowlistedWithRetargetedReplace,
    /// v2's go.mod carries the EXACT SAME `replace` directive our
    /// downstream version has (nothing would actually be lost) — the
    /// auto-resolve happy path for a go.mod that carries a `replace` line
    /// at all. Must auto-resolve.
    AllowlistedWithMatchingReplace,
    /// v2 DELETES `go.sum` entirely while our downstream commit still has
    /// local edits to it — a delete/modify conflict.
    AllowlistedDelete,
    /// v2 changes ONLY `go.sum` (not `go.mod`) — go.mod merges cleanly via
    /// git's own 3-way merge (never flagged as a conflict at all, since
    /// only our side touched it), but ends up textually different from
    /// upstream's go.mod. go.sum's conflict must decline rather than pair
    /// upstream's checksums with a go.mod that isn't upstream's.
    GoSumConflictsAloneWithMismatchedGoMod,
    /// v2 DELETES `go.mod` entirely while our downstream version carries a
    /// downstream-only `replace` directive (the delete/modify direction of
    /// the replace-preservation guard: deleting our go.mod outright would
    /// lose the directive just as surely as `checkout --theirs` would —
    /// must NOT auto-resolve) AND ALSO rewrites `go.sum` (a real, separate
    /// conflict, since our downstream commit always patches go.sum too).
    /// Exercises `blob_matches_upstream`'s "an unmerged path is a hard
    /// non-match" branch: go.mod stays unmerged (declined), so go.sum's
    /// own coupling check must decline it too rather than treating
    /// go.mod's coincidentally-`None` stage-0 read as "matches upstream's
    /// (also `None`, since upstream deleted go.mod)" content.
    AllowlistedDeleteWithReplace,
    /// Our downstream commit DELETES `go.mod` entirely while v2 modifies
    /// it normally — the reverse delete/modify direction, with nothing of
    /// ours to lose. Must auto-resolve to upstream's content.
    DownstreamDeletesGoMod,
    /// v2 rewrites a `.github/workflows/` file, which our downstream
    /// commit also edits — exercises the workflows branch of the allowlist
    /// through a real conflict end-to-end, not just the bare predicate.
    AllowlistedWorkflow,
    /// v2 DELETES `.github/workflows/x[1].yml` (a filename containing
    /// glob-metacharacters) while our downstream commit modifies it — a
    /// delete/modify conflict on a path that would collide with the
    /// sibling `x1.yml` under naive (non-literal) pathspec glob matching.
    /// Must resolve `x[1].yml` only, leaving `x1.yml` untouched.
    AllowlistedGlobMetacharacterFilename,
    /// v2 rewrites `.github/workflows/café.yml` (a non-ASCII filename),
    /// which our downstream commit also edits — exercises
    /// `unmerged_paths`'s NUL-delimited parsing against git's default
    /// C-quoting of non-ASCII path bytes. Must auto-resolve to upstream.
    AllowlistedWorkflowNonAscii,
    /// v2 changes ONLY `go.sum`; go.mod is untouched on both sides (still
    /// exactly the cloned v1 content, so it trivially matches upstream
    /// without ever being flagged as a conflict at all) — the positive
    /// mirror of `GoSumConflictsAloneWithMismatchedGoMod`. Must
    /// auto-resolve go.sum to upstream's content.
    GoSumConflictsAloneWithMatchingGoMod,
    /// v2 changes go.mod (ONLY upstream touches it — our downstream commit
    /// never edits it at all) AND a `.github/workflows/` file (which both
    /// sides edit, a real conflict on the allowlist). go.mod's clean
    /// 3-way merge lands upstream's exact content but is NEVER flagged as
    /// a conflict and NEVER goes through `resolve_to_theirs` — the
    /// go.mod/go.sum consistency safety net must not fire here even
    /// though go.mod ends up byte-identical to upstream, because THIS
    /// module never touched it. Must auto-resolve cleanly.
    UpstreamOnlyGoModChangeWithConflictingWorkflow,
    /// v2 changes ONLY go.mod (both sides edit it, no replace directive
    /// involved — auto-resolves to upstream); go.sum is touched ONLY
    /// downstream, so it merges cleanly to stale downstream content
    /// without ever being flagged as a conflict, and nothing else
    /// conflicts. The go.mod/go.sum consistency safety net must silently
    /// realign go.sum to upstream too — the standalone, no-other-conflict
    /// case (see `Mixed` for the same interaction alongside a real,
    /// unresolvable conflict).
    GoModConflictsAloneLeavingGoSumStale,
    /// Upstream never ships a go.sum at all (absent at v1 and v2); our
    /// downstream commit adds one anyway (a downstream-only file, never
    /// present upstream at any point). go.mod conflicts (both sides edit
    /// it, no replace directive) and auto-resolves. The go.mod/go.sum
    /// consistency safety net must realign go.sum by REMOVING it (there's
    /// no upstream content to check out) rather than failing on a
    /// pathspec that matches nothing in the fetch ref's tree.
    GoModConflictsAloneWithGoSumNeverUpstream,
    /// Our downstream commit DELETES go.sum entirely; upstream keeps it
    /// unchanged from v1 (only go.mod is bumped). go.sum never conflicts
    /// (only our side touched it, by removing it), so git's clean 3-way
    /// merge just keeps the deletion — a filesystem `.exists()`-based
    /// gate on the go.mod/go.sum consistency safety net would miss this
    /// entirely, silently committing a go.mod with no go.sum at all. Must
    /// resurrect go.sum from upstream's unchanged content.
    DownstreamDeletesGoSumWhileUpstreamKeepsIt,
    /// Neither side ever has go.sum, at v1 or v2 — go.mod is the only
    /// conflict (both sides edit it, no replace directive) and
    /// auto-resolves. Exercises the go.mod/go.sum consistency safety
    /// net's both-absent no-op path: `ours_go_sum` and `upstream_go_sum`
    /// both read `None`, comparing equal, so the net must stay silent
    /// (no `git rm` on a path that was never staged, nothing added to
    /// `auto_resolved`).
    GoModConflictsAloneWithGoSumAbsentEverywhere,
    /// v2 rewrites `patched.txt`, which our local ECH-style patch also
    /// edits — a real conflict outside the allowlist.
    Real,
    /// v2 rewrites BOTH `go.mod` (allowlisted) and `patched.txt` (real).
    Mixed,
    /// v2 rewrites both `patched.txt` and a second file, `also_patched.txt`
    /// — two real conflicts in the same pull.
    TwoReal,
}

struct Fixture {
    dir: tempfile::TempDir,
    downstream: PathBuf,
}

impl Fixture {
    fn build(conflict: ConflictKind) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let upstream = dir.path().join("upstream");
        let downstream = dir.path().join("downstream");

        git_init(&upstream);
        std::fs::write(upstream.join("patched.txt"), "upstream line one\n").unwrap();
        std::fs::write(upstream.join("also_patched.txt"), "upstream other line\n").unwrap();
        std::fs::write(upstream.join("go.mod"), "module fixture\n\ngo 1.25\n").unwrap();
        // Every ConflictKind except these two ships a v1 go.sum — both
        // need upstream to never have go.sum at all, at v1 or v2.
        if !matches!(
            conflict,
            ConflictKind::GoModConflictsAloneWithGoSumNeverUpstream
                | ConflictKind::GoModConflictsAloneWithGoSumAbsentEverywhere
        ) {
            std::fs::write(upstream.join("go.sum"), "fixture v1.0.0 h1:abc=\n").unwrap();
        }
        std::fs::write(upstream.join("other.txt"), "unrelated\n").unwrap();
        std::fs::create_dir_all(upstream.join(".github/workflows")).unwrap();
        std::fs::write(upstream.join(".github/workflows/ci.yml"), "name: ci\non: [push]\n").unwrap();
        // `x[1].yml` (glob-metacharacter filename) + `x1.yml` (unrelated
        // sibling a naive glob pathspec would also match) and `café.yml`
        // (non-ASCII filename) — present in every fixture, but only
        // exercised as conflicts by the ConflictKinds that name them.
        std::fs::write(upstream.join(".github/workflows/x[1].yml"), "base\n").unwrap();
        std::fs::write(upstream.join(".github/workflows/x1.yml"), "sibling, do not touch\n").unwrap();
        std::fs::write(upstream.join(".github/workflows/café.yml"), "base\n").unwrap();
        git(&upstream, &["add", "."]);
        git(&upstream, &["commit", "-m", "v1"]);
        git(&upstream, &["tag", "v1"]);

        match conflict {
            ConflictKind::None => {
                std::fs::write(upstream.join("other.txt"), "unrelated changed\n").unwrap();
            }
            ConflictKind::Allowlisted
            | ConflictKind::AllowlistedWithReplace
            | ConflictKind::AllowlistedWithBlockReplace
            | ConflictKind::DownstreamDeletesGoMod => {
                std::fs::write(
                    upstream.join("go.mod"),
                    "module fixture\n\ngo 1.26\n\nrequire upstream/newdep v1.0.0\n",
                )
                .unwrap();
                std::fs::write(upstream.join("go.sum"), "fixture v2.0.0 h1:xyz=\n").unwrap();
            }
            ConflictKind::AllowlistedDelete => {
                std::fs::remove_file(upstream.join("go.sum")).unwrap();
                git(&upstream, &["add", "-A"]);
            }
            ConflictKind::GoSumConflictsAloneWithMismatchedGoMod => {
                std::fs::write(upstream.join("go.sum"), "fixture v2.0.0 h1:xyz=\n").unwrap();
            }
            ConflictKind::GoModConflictsAloneLeavingGoSumStale
            | ConflictKind::GoModConflictsAloneWithGoSumNeverUpstream
            | ConflictKind::DownstreamDeletesGoSumWhileUpstreamKeepsIt
            | ConflictKind::GoModConflictsAloneWithGoSumAbsentEverywhere => {
                std::fs::write(
                    upstream.join("go.mod"),
                    "module fixture\n\ngo 1.26\n\nrequire upstream/newdep v1.0.0\n",
                )
                .unwrap();
            }
            ConflictKind::UpstreamOnlyGoModChangeWithConflictingWorkflow => {
                std::fs::write(
                    upstream.join("go.mod"),
                    "module fixture\n\ngo 1.26\n\nrequire upstream/newdep v1.0.0\n",
                )
                .unwrap();
                std::fs::write(
                    upstream.join(".github/workflows/ci.yml"),
                    "name: ci\non: [push]\njobs:\n  upstream-changed: {}\n",
                )
                .unwrap();
            }
            ConflictKind::AllowlistedDeleteWithReplace => {
                std::fs::remove_file(upstream.join("go.mod")).unwrap();
                std::fs::write(upstream.join("go.sum"), "fixture v2.0.0 h1:xyz=\n").unwrap();
                git(&upstream, &["add", "-A"]);
            }
            ConflictKind::AllowlistedWithRetargetedReplace => {
                std::fs::write(
                    upstream.join("go.mod"),
                    "module fixture\n\ngo 1.26\n\nrequire upstream/newdep v1.0.0\n\nreplace ourdownstream/loadbearing => ../different-target\n",
                )
                .unwrap();
                std::fs::write(upstream.join("go.sum"), "fixture v2.0.0 h1:xyz=\n").unwrap();
            }
            ConflictKind::AllowlistedWithMatchingReplace => {
                std::fs::write(
                    upstream.join("go.mod"),
                    "module fixture\n\ngo 1.26\n\nrequire upstream/newdep v1.0.0\n\nreplace ourdownstream/loadbearing => ../loadbearing\n",
                )
                .unwrap();
                std::fs::write(upstream.join("go.sum"), "fixture v2.0.0 h1:xyz=\n").unwrap();
            }
            ConflictKind::AllowlistedWorkflow => {
                std::fs::write(
                    upstream.join(".github/workflows/ci.yml"),
                    "name: ci\non: [push]\njobs:\n  upstream-changed: {}\n",
                )
                .unwrap();
            }
            ConflictKind::AllowlistedGlobMetacharacterFilename => {
                std::fs::remove_file(upstream.join(".github/workflows/x[1].yml")).unwrap();
                git(&upstream, &["add", "-A"]);
            }
            ConflictKind::AllowlistedWorkflowNonAscii => {
                std::fs::write(upstream.join(".github/workflows/café.yml"), "upstream-changed\n").unwrap();
            }
            ConflictKind::GoSumConflictsAloneWithMatchingGoMod => {
                std::fs::write(upstream.join("go.sum"), "fixture v2.0.0 h1:xyz=\n").unwrap();
            }
            ConflictKind::Real => {
                std::fs::write(upstream.join("patched.txt"), "upstream line one CHANGED\n").unwrap();
            }
            ConflictKind::Mixed => {
                std::fs::write(
                    upstream.join("go.mod"),
                    "module fixture\n\ngo 1.26\n\nrequire upstream/newdep v1.0.0\n",
                )
                .unwrap();
                std::fs::write(upstream.join("patched.txt"), "upstream line one CHANGED\n").unwrap();
            }
            ConflictKind::TwoReal => {
                std::fs::write(upstream.join("patched.txt"), "upstream line one CHANGED\n").unwrap();
                std::fs::write(upstream.join("also_patched.txt"), "upstream other line CHANGED\n").unwrap();
            }
        }
        git(&upstream, &["commit", "-am", "v2"]);
        git(&upstream, &["tag", "v2"]);

        git_init(&downstream);
        std::fs::write(downstream.join("README.md"), "downstream\n").unwrap();
        git(&downstream, &["add", "."]);
        git(&downstream, &["commit", "-m", "initial"]);

        git(&downstream, &["checkout", "-b", "feature"]);
        git(
            &downstream,
            &["subrepo", "clone", upstream.to_str().unwrap(), "vendor", "-b", "v1"],
        );
        std::fs::write(
            downstream.join("vendor/patched.txt"),
            "upstream line one\nour local patch\n",
        )
        .unwrap();
        std::fs::write(
            downstream.join("vendor/also_patched.txt"),
            "upstream other line\nour other local patch\n",
        )
        .unwrap();

        if matches!(conflict, ConflictKind::DownstreamDeletesGoMod) {
            std::fs::remove_file(downstream.join("vendor/go.mod")).unwrap();
        } else if matches!(
            conflict,
            ConflictKind::GoSumConflictsAloneWithMatchingGoMod
                | ConflictKind::UpstreamOnlyGoModChangeWithConflictingWorkflow
        ) {
            // Leave go.mod completely untouched — still exactly the cloned
            // v1 content, so it merges cleanly (taking upstream's changed
            // content wholesale, for kinds where upstream touches it)
            // without ever being flagged as a conflict at all.
        } else {
            let go_mod_content = if matches!(
                conflict,
                ConflictKind::AllowlistedWithReplace
                    | ConflictKind::AllowlistedDeleteWithReplace
                    | ConflictKind::AllowlistedWithRetargetedReplace
                    | ConflictKind::AllowlistedWithMatchingReplace
            ) {
                "module fixture\n\ngo 1.25\n\nrequire ourdownstream/patchdep v1.0.0\n\nreplace ourdownstream/loadbearing => ../loadbearing\n"
            } else if matches!(conflict, ConflictKind::AllowlistedWithBlockReplace) {
                "module fixture\n\ngo 1.25\n\nrequire ourdownstream/patchdep v1.0.0\n\nreplace (\n\tourdownstream/loadbearing => ../loadbearing\n)\n"
            } else {
                "module fixture\n\ngo 1.25\n\nrequire ourdownstream/patchdep v1.0.0\n"
            };
            std::fs::write(downstream.join("vendor/go.mod"), go_mod_content).unwrap();
        }
        if matches!(conflict, ConflictKind::DownstreamDeletesGoSumWhileUpstreamKeepsIt) {
            std::fs::remove_file(downstream.join("vendor/go.sum")).unwrap();
        } else if matches!(conflict, ConflictKind::GoModConflictsAloneWithGoSumAbsentEverywhere) {
            // Never present upstream at v1 (skipped above) and never
            // written downstream either — go.sum simply never exists.
        } else {
            std::fs::write(downstream.join("vendor/go.sum"), "fixture v1.0.0-patched h1:def=\n").unwrap();
        }
        if matches!(
            conflict,
            ConflictKind::AllowlistedWorkflow | ConflictKind::UpstreamOnlyGoModChangeWithConflictingWorkflow
        ) {
            std::fs::write(
                downstream.join("vendor/.github/workflows/ci.yml"),
                "name: ci\non: [push]\njobs:\n  downstream-changed: {}\n",
            )
            .unwrap();
        }
        if matches!(conflict, ConflictKind::AllowlistedGlobMetacharacterFilename) {
            std::fs::write(
                downstream.join("vendor/.github/workflows/x[1].yml"),
                "downstream-changed\n",
            )
            .unwrap();
        }
        if matches!(conflict, ConflictKind::AllowlistedWorkflowNonAscii) {
            std::fs::write(
                downstream.join("vendor/.github/workflows/café.yml"),
                "downstream-changed\n",
            )
            .unwrap();
        }
        git(&downstream, &["add", "-A"]);
        git(&downstream, &["commit", "-m", "patch: our local addition"]);

        git(&downstream, &["checkout", "main"]);
        git(&downstream, &["merge", "--squash", "feature"]);
        git(&downstream, &["commit", "-m", "vendor: import + patch (squashed)"]);
        git(&downstream, &["branch", "-D", "feature"]);

        Fixture { dir, downstream }
    }

    /// Rewrites `.gitrepo`'s `parent` to a commit that exists but is not an
    /// ancestor of HEAD — the same symptom `Fixture::build`'s
    /// clone+patch+squash-merge sequence already produces naturally (see
    /// `clean_pull_after_squash_merge_auto_fixes_stale_parent`), just
    /// forced directly so other tests that only need this precondition
    /// don't have to repeat that whole dance.
    fn corrupt_parent(&self) {
        git(&self.downstream, &["checkout", "-b", "throwaway"]);
        std::fs::write(self.downstream.join("README.md"), "throwaway\n").unwrap();
        git(&self.downstream, &["commit", "-am", "throwaway"]);
        let unreachable = git_output(&self.downstream, &["rev-parse", "HEAD"]).trim().to_string();
        git(&self.downstream, &["checkout", "main"]);
        git(&self.downstream, &["branch", "-D", "throwaway"]);

        let gitrepo_path = self.downstream.join("vendor/.gitrepo");
        let contents = std::fs::read_to_string(&gitrepo_path).unwrap();
        let corrupted: String = contents
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("parent =") {
                    format!("\tparent = {unreachable}")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&gitrepo_path, corrupted).unwrap();
        git(&self.downstream, &["add", "-A"]);
        git(&self.downstream, &["commit", "-m", "test: artificially stale parent"]);
    }

    /// Rewrites `.gitrepo`'s `method` field to `rebase` — confirmed
    /// against the installed git-subrepo 0.4.9 source (`update-gitrepo-
    /// file`'s `git config --file="$gitrepo" subrepo.method`) that a
    /// pull reads this field directly, so a manually-edited value on disk
    /// genuinely switches the join strategy on the next pull, the same as
    /// having originally cloned with `-M rebase`.
    fn set_join_method_rebase(&self) {
        let gitrepo_path = self.downstream.join("vendor/.gitrepo");
        let contents = std::fs::read_to_string(&gitrepo_path).unwrap();
        let rewritten: String = contents
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("method =") {
                    "\tmethod = rebase".to_string()
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&gitrepo_path, rewritten).unwrap();
        git(&self.downstream, &["add", "-A"]);
        git(&self.downstream, &["commit", "-m", "test: force method=rebase"]);
    }
}

fn git_init(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    git(path, &["init", "--initial-branch=main", "--quiet"]);
    git(path, &["config", "user.email", "fixture@example.com"]);
    git(path, &["config", "user.name", "fixture"]);
}

fn git(cwd: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| panic!("failed to run git {args:?} in {}: {e}", cwd.display()));
    assert!(status.success(), "git {args:?} failed in {}", cwd.display());
}

fn git_output(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git").args(args).current_dir(cwd).output().unwrap();
    assert!(output.status.success(), "git {args:?} failed in {}", cwd.display());
    String::from_utf8(output.stdout).unwrap()
}

/// Installs a `pre-commit` hook that unconditionally rejects the commit —
/// a deterministic, cross-platform way to force a `git commit` to fail
/// after its preceding `git add` already succeeded, for tests exercising
/// the disclosure wrapped around exactly that gap.
fn install_rejecting_pre_commit_hook(repo: &Path) {
    let hooks_dir = repo.join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    let hook_path = hooks_dir.join("pre-commit");
    std::fs::write(&hook_path, "#!/bin/sh\nexit 1\n").unwrap();
    // On POSIX (core.fileMode defaults to true), git silently skips a
    // non-executable hook instead of running it — without the exec bit
    // this hook never fires and the commit it's supposed to block
    // succeeds instead, on every unix CI runner.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[skuld::test]
fn clean_pull_on_the_very_first_attempt_from_a_plain_checkout() {
    // The most common real-world case (no staleness, no dirty tree, no
    // worktree) has no other direct test — every other ConflictKind::None
    // test also corrupts the parent or dirties the tree first.
    let fx = Fixture::build(ConflictKind::None);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));
}

#[skuld::test]
fn clean_pull_after_squash_merge_auto_fixes_stale_parent() {
    let fx = Fixture::build(ConflictKind::None);
    fx.corrupt_parent();

    // Sanity check: this reproduces the exact stale-parent failure the
    // fixup exists to recover from (stdout/stderr distinction is
    // documented in pull_subrepo.rs's handle_conflict).
    let raw = Command::new("git")
        .args(["subrepo", "pull", "vendor", "-b", "v2"])
        .current_dir(&fx.downstream)
        .output()
        .unwrap();
    assert!(
        !raw.status.success(),
        "fixture should reproduce the stale-parent failure before any fixup"
    );
    assert!(String::from_utf8_lossy(&raw.stderr).contains("is not an ancestor"));

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let patched = std::fs::read_to_string(fx.downstream.join("vendor/patched.txt")).unwrap();
    assert!(
        patched.contains("our local patch"),
        "local patch must survive the pull: {patched}"
    );

    let gitrepo = std::fs::read_to_string(fx.downstream.join("vendor/.gitrepo")).unwrap();
    assert!(gitrepo.contains("branch = v2"));
}

#[skuld::test]
fn allowlisted_conflict_auto_resolves_to_upstream() {
    let fx = Fixture::build(ConflictKind::Allowlisted);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(
        go_mod.contains("newdep"),
        "upstream's go.mod content should win: {go_mod}"
    );
    assert!(
        !go_mod.contains("patchdep"),
        "our spurious downstream-only require should not survive: {go_mod}"
    );

    let go_sum = std::fs::read_to_string(fx.downstream.join("vendor/go.sum")).unwrap();
    assert!(
        go_sum.contains("v2.0.0"),
        "upstream's go.sum content should win: {go_sum}"
    );

    // `git subrepo commit` (the finishing command on the conflict-resolve
    // path, unlike a clean pull which finishes on its own) does NOT
    // update .gitrepo's `branch` field — it stays at v1 even though
    // `commit` and the tree content are v2. Confirms the explicit fixup
    // in handle_conflict.
    let gitrepo = std::fs::read_to_string(fx.downstream.join("vendor/.gitrepo")).unwrap();
    assert!(
        gitrepo.contains("branch = v2"),
        "the branch pin must be updated even on the conflict-resolve path: {gitrepo}"
    );
}

#[skuld::test]
fn allowlisted_go_mod_conflict_declines_when_a_downstream_replace_would_be_lost() {
    // Blindly `checkout --theirs go.mod` takes the WHOLE file from
    // upstream, discarding any of our own load-bearing lines regardless
    // of where the actual conflicting hunk was — e.g. v2ray-core's real
    // go.mod carries a downstream-only `replace .../utls => ../utls` that
    // upstream never has. This must NOT be silently dropped.
    //
    // go.sum also conflicts in this fixture (both sides edit it) and must
    // be declined too, not silently auto-resolved to upstream: it's a
    // checksum lockfile whose only valid content matches its paired
    // go.mod, which stays conflicted here.
    let fx = Fixture::build(ConflictKind::AllowlistedWithReplace);

    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { mut unresolved, .. } => {
            unresolved.sort();
            assert_eq!(
                unresolved,
                vec!["go.mod".to_string(), "go.sum".to_string()],
                "go.mod must be treated as unresolved when a downstream replace would be lost, \
                 and go.sum must be declined along with it rather than silently resolved to an \
                 inconsistent upstream version"
            );
        }
        Outcome::Clean => panic!("expected go.mod to be left for a human, not silently resolved"),
    }
}

#[skuld::test]
fn allowlisted_go_mod_conflict_declines_when_a_block_form_replace_would_be_lost() {
    // go_mod_replace_directives exists specifically because a naive
    // line-prefix filter misses go.mod's block replace syntax — the OTHER
    // preservation test above only exercises the single-line form, so it
    // wouldn't catch a regression back to that naive approach. This one
    // would.
    let fx = Fixture::build(ConflictKind::AllowlistedWithBlockReplace);

    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { mut unresolved, .. } => {
            unresolved.sort();
            assert_eq!(
                unresolved,
                vec!["go.mod".to_string(), "go.sum".to_string()],
                "go.mod must be treated as unresolved when a block-form downstream replace would \
                 be lost, and go.sum (which also conflicts in this fixture) must be declined \
                 along with it"
            );
        }
        Outcome::Clean => panic!("expected go.mod to be left for a human, not silently resolved"),
    }
}

#[skuld::test]
fn allowlisted_go_mod_conflict_declines_when_upstream_retargets_a_shared_replace_directive() {
    // Both sides carry a `replace ourdownstream/loadbearing => ...`
    // directive for the same left-hand module path, but pointed at
    // different targets — a path-only comparison would see "theirs
    // already has this module replaced" and wrongly consider nothing
    // lost. The comparison must be over the whole directive (old+new
    // path), so this must still decline.
    let fx = Fixture::build(ConflictKind::AllowlistedWithRetargetedReplace);

    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { mut unresolved, .. } => {
            unresolved.sort();
            assert_eq!(
                unresolved,
                vec!["go.mod".to_string(), "go.sum".to_string()],
                "go.mod must be treated as unresolved when upstream retargets our replace \
                 directive to a different destination"
            );
        }
        Outcome::Clean => panic!("expected go.mod to be left for a human, not silently resolved"),
    }
}

#[skuld::test]
fn allowlisted_go_mod_conflict_auto_resolves_when_upstream_already_carries_the_same_replace() {
    // The happy path for a go.mod that carries a `replace` line at all:
    // upstream's go.mod has the exact same directive we do, so nothing
    // would actually be lost by taking theirs. Must still auto-resolve.
    let fx = Fixture::build(ConflictKind::AllowlistedWithMatchingReplace);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(
        go_mod.contains("newdep") && go_mod.contains("loadbearing"),
        "upstream's go.mod (which already carries our replace directive) should win: {go_mod}"
    );
}

#[skuld::test]
fn allowlisted_delete_conflict_removes_the_file_instead_of_erroring() {
    // A delete/modify conflict (upstream deleted, downstream modified) has
    // no "theirs" blob for `git checkout --theirs` to check out — plain
    // `checkout --theirs` fails here. Resolving to theirs means removing
    // the file, since upstream's version of "the file" is "gone".
    let fx = Fixture::build(ConflictKind::AllowlistedDelete);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));
    assert!(
        !fx.downstream.join("vendor/go.sum").exists(),
        "go.sum should be removed, matching upstream's deletion"
    );
}

#[skuld::test]
fn go_sum_conflict_declines_when_go_mod_merged_cleanly_but_diverged_from_upstream() {
    // go.mod only changes downstream (adds patchdep) and merges cleanly
    // via git's own 3-way merge — never flagged as a conflict at all,
    // since only our side touched it — while go.sum conflicts on its own.
    // Taking upstream's go.sum here would pair it with a go.mod that
    // isn't upstream's, producing an inconsistent checksum/module pair
    // with no signal to a human that anything is wrong.
    let fx = Fixture::build(ConflictKind::GoSumConflictsAloneWithMismatchedGoMod);

    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { unresolved, .. } => {
            assert_eq!(
                unresolved,
                vec!["go.sum".to_string()],
                "go.sum must be declined when go.mod (never itself conflicted) diverged from upstream"
            );
        }
        Outcome::Clean => {
            panic!("expected go.sum to be left for a human, not silently resolved against a mismatched go.mod")
        }
    }

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(
        go_mod.contains("patchdep"),
        "go.mod should have merged cleanly, keeping our local addition: {go_mod}"
    );
}

#[skuld::test]
fn allowlisted_go_mod_conflict_declines_when_upstream_deletes_go_mod_and_a_replace_would_be_lost() {
    // The delete/modify direction (upstream deleted go.mod, downstream
    // modified it) has no "theirs" blob at all — deleting our go.mod
    // outright loses the replace directive just as surely as
    // `checkout --theirs` would, so it must decline exactly like the
    // modify/modify case above, not silently fall through to `git rm`.
    //
    // go.sum also conflicts in this fixture (both sides edit it) and must
    // decline too: go.mod stays unmerged (declined), so
    // blob_matches_upstream's hard "an unmerged path is never a match"
    // check must be what declines go.sum here — a stale pre-fix version
    // that let an unmerged go.mod's absent stage-0 read coincidentally
    // equal upstream's absent go.mod (upstream deleted it too) would
    // wrongly treat this as "matches" and silently resolve go.sum.
    let fx = Fixture::build(ConflictKind::AllowlistedDeleteWithReplace);

    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { mut unresolved, .. } => {
            unresolved.sort();
            assert_eq!(
                unresolved,
                vec!["go.mod".to_string(), "go.sum".to_string()],
                "go.mod must be treated as unresolved when deleting it would lose a downstream \
                 replace, and go.sum must decline alongside it since go.mod's fate isn't decided"
            );
        }
        Outcome::Clean => panic!("expected go.mod to be left for a human, not silently deleted"),
    }
    assert!(
        fx.downstream.join("vendor/go.mod").exists(),
        "go.mod must not be deleted while the conflict is unresolved"
    );
}

#[skuld::test]
fn go_mod_conflict_resolves_to_upstream_when_downstream_deleted_it() {
    // The reverse delete/modify direction (downstream deleted go.mod,
    // upstream modified it) has no "ours" blob — the replace-directive
    // preservation check must not crash trying to read one that doesn't
    // exist. There's nothing of ours to lose, so resolving to theirs
    // (resurrecting the file from upstream) is correct.
    let fx = Fixture::build(ConflictKind::DownstreamDeletesGoMod);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(
        go_mod.contains("newdep"),
        "upstream's go.mod should be resurrected: {go_mod}"
    );
}

#[skuld::test]
fn allowlisted_workflow_conflict_auto_resolves_to_upstream() {
    // is_auto_resolvable's `.github/workflows/` branch has no go.mod-style
    // content-preservation check — unlike go.mod it's resolved
    // unconditionally to upstream. This exercises that path through a real
    // conflict end-to-end (checkout --theirs, add, subrepo commit), not
    // just the bare is_auto_resolvable predicate.
    let fx = Fixture::build(ConflictKind::AllowlistedWorkflow);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let workflow = std::fs::read_to_string(fx.downstream.join("vendor/.github/workflows/ci.yml")).unwrap();
    assert!(
        workflow.contains("upstream-changed"),
        "upstream's workflow content should win: {workflow}"
    );
}

#[skuld::test]
fn glob_metacharacter_filename_conflict_resolves_without_touching_the_sibling() {
    // `resolve_to_theirs` prefixes every pathspec with `:(literal)` so a
    // conflicted filename containing glob metacharacters (`[1]`) can't
    // also match an unrelated sibling under git's default glob-pathspec
    // matching. This is a delete/modify conflict (upstream deleted the
    // file), exercising the `git rm` pathspec specifically — the branch
    // where a naive (non-literal) pathspec would delete BOTH files.
    let fx = Fixture::build(ConflictKind::AllowlistedGlobMetacharacterFilename);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    assert!(
        !fx.downstream.join("vendor/.github/workflows/x[1].yml").exists(),
        "x[1].yml should be removed, matching upstream's deletion"
    );
    let sibling = std::fs::read_to_string(fx.downstream.join("vendor/.github/workflows/x1.yml")).unwrap();
    assert_eq!(
        sibling, "sibling, do not touch\n",
        "the unrelated sibling x1.yml must survive untouched: {sibling}"
    );
}

#[skuld::test]
fn non_ascii_workflow_filename_conflict_auto_resolves_to_upstream() {
    // `unmerged_paths` uses `-z` (NUL-delimited output) specifically so a
    // conflicted non-ASCII filename isn't returned C-quoted (which would
    // break `is_auto_resolvable`'s `.github/workflows/` prefix match).
    let fx = Fixture::build(ConflictKind::AllowlistedWorkflowNonAscii);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let workflow = std::fs::read_to_string(fx.downstream.join("vendor/.github/workflows/café.yml")).unwrap();
    assert_eq!(
        workflow, "upstream-changed\n",
        "upstream's non-ASCII-named workflow content should win: {workflow}"
    );
}

#[skuld::test]
fn go_sum_conflict_auto_resolves_when_go_mod_never_conflicted_and_already_matches_upstream() {
    // The positive mirror of go_sum_conflict_declines_when_go_mod_merged_
    // cleanly_but_diverged_from_upstream: go.mod is untouched on both
    // sides (never even appears in the conflicted set) and trivially
    // matches upstream, so go.sum's own conflict must still auto-resolve
    // — the coupling check must not be a blanket decline whenever go.mod
    // wasn't itself resolved via the allowlist.
    let fx = Fixture::build(ConflictKind::GoSumConflictsAloneWithMatchingGoMod);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let go_sum = std::fs::read_to_string(fx.downstream.join("vendor/go.sum")).unwrap();
    assert!(
        go_sum.contains("v2.0.0"),
        "upstream's go.sum content should win: {go_sum}"
    );
}

#[skuld::test]
fn go_mod_matching_upstream_via_a_clean_merge_does_not_falsely_flag_an_untouched_go_sum() {
    // The go.mod/go.sum consistency safety net is gated on THIS module
    // having explicitly auto-resolved go.mod (`auto_resolved`), not on
    // "go.mod happens to already match upstream" — otherwise a go.mod
    // that only upstream ever touched (merges cleanly via git's own
    // 3-way merge, landing upstream's exact content, but never appears
    // in `conflicted` and never goes through `resolve_to_theirs`) would
    // falsely flag an untouched, pre-existing go.sum divergence on every
    // pull that also happens to have an unrelated real conflict elsewhere.
    let fx = Fixture::build(ConflictKind::UpstreamOnlyGoModChangeWithConflictingWorkflow);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(
        go_mod.contains("newdep"),
        "go.mod should merge cleanly to upstream's content: {go_mod}"
    );
    let workflow = std::fs::read_to_string(fx.downstream.join("vendor/.github/workflows/ci.yml")).unwrap();
    assert!(
        workflow.contains("upstream-changed"),
        "the real workflow conflict should auto-resolve to upstream: {workflow}"
    );
    // The one observable that distinguishes "the safety net correctly
    // stayed silent" from "it wrongly fired": go.sum here is untouched by
    // this pull (upstream never changes it in this fixture) and must
    // still read as downstream's own patched content, not upstream's.
    let go_sum = std::fs::read_to_string(fx.downstream.join("vendor/go.sum")).unwrap();
    assert_eq!(
        go_sum, "fixture v1.0.0-patched h1:def=\n",
        "go.sum must be untouched — the safety net must not have fired: {go_sum}"
    );
}

#[skuld::test]
fn go_mod_conflict_auto_resolves_and_silently_realigns_a_now_stale_go_sum() {
    // The standalone case for GoModConflictsAloneLeavingGoSumStale — see
    // that variant's doc and handle_conflict's "Final safety net" comment
    // for why go.sum is realigned rather than left unresolved.
    let fx = Fixture::build(ConflictKind::GoModConflictsAloneLeavingGoSumStale);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(
        go_mod.contains("newdep"),
        "go.mod should auto-resolve to upstream: {go_mod}"
    );
    // This fixture's upstream only bumps go.mod (v2 leaves go.sum
    // unchanged from v1), so upstream's own go.sum is v1's content —
    // "fixture v1.0.0 h1:abc=" — not our downstream patch.
    let go_sum = std::fs::read_to_string(fx.downstream.join("vendor/go.sum")).unwrap();
    assert_eq!(
        go_sum, "fixture v1.0.0 h1:abc=\n",
        "the now-stale go.sum should be silently realigned to upstream's (unchanged) content: {go_sum}"
    );
}

#[skuld::test]
fn go_mod_conflict_auto_resolves_and_removes_a_go_sum_upstream_never_shipped() {
    // Mirrors go_mod_conflict_auto_resolves_and_silently_realigns_a_now_
    // stale_go_sum, but upstream never has go.sum at all (absent at v1
    // and v2) — the go.mod/go.sum consistency safety net's realignment
    // must fall back to removing go.sum (mirroring resolve_to_theirs's
    // own !theirs_present branch) rather than trying to `git checkout`
    // upstream content that doesn't exist in the fetch ref's tree.
    let fx = Fixture::build(ConflictKind::GoModConflictsAloneWithGoSumNeverUpstream);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(
        go_mod.contains("newdep"),
        "go.mod should auto-resolve to upstream: {go_mod}"
    );
    assert!(
        !fx.downstream.join("vendor/go.sum").exists(),
        "go.sum should be removed, matching upstream never having shipped one"
    );
}

#[skuld::test]
fn go_mod_conflict_auto_resolves_and_resurrects_a_go_sum_downstream_deleted() {
    // The mirror image of the "stale content" case: go.sum never
    // conflicts (only downstream touched it, by deleting it), so git's
    // clean 3-way merge just keeps the deletion — a filesystem-existence
    // gate on the safety net would miss this entirely and silently commit
    // a go.mod with no go.sum at all. Must resurrect go.sum from
    // upstream's (unchanged) content.
    let fx = Fixture::build(ConflictKind::DownstreamDeletesGoSumWhileUpstreamKeepsIt);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(
        go_mod.contains("newdep"),
        "go.mod should auto-resolve to upstream: {go_mod}"
    );
    let go_sum = std::fs::read_to_string(fx.downstream.join("vendor/go.sum")).unwrap();
    assert_eq!(
        go_sum, "fixture v1.0.0 h1:abc=\n",
        "go.sum should be resurrected from upstream's (unchanged) content: {go_sum}"
    );
}

#[skuld::test]
fn go_mod_conflict_auto_resolves_when_go_sum_is_absent_on_both_sides() {
    // The both-absent combination the go.mod/go.sum consistency safety
    // net's content comparison (ours_go_sum != upstream_go_sum) must
    // no-op on: neither side ever has go.sum, so both reads are `None`,
    // comparing equal — no `git rm` on a path never staged, nothing
    // spuriously reported.
    let fx = Fixture::build(ConflictKind::GoModConflictsAloneWithGoSumAbsentEverywhere);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(
        go_mod.contains("newdep"),
        "go.mod should auto-resolve to upstream: {go_mod}"
    );
    assert!(
        !fx.downstream.join("vendor/go.sum").exists(),
        "go.sum should remain absent — it was never present on either side"
    );
}

#[skuld::test]
fn mixed_conflict_auto_resolves_the_allowlisted_part_only() {
    // Same go.mod/go.sum realignment as GoModConflictsAloneLeavingGoSumStale,
    // alongside a real, unresolvable conflict on patched.txt.
    let fx = Fixture::build(ConflictKind::Mixed);

    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted {
            unresolved,
            mut auto_resolved,
            ..
        } => {
            assert_eq!(
                unresolved,
                vec!["patched.txt".to_string()],
                "go.mod should have been auto-resolved, leaving only the real conflict"
            );
            auto_resolved.sort();
            assert_eq!(
                auto_resolved,
                vec!["go.mod".to_string(), "go.sum".to_string()],
                "go.mod's auto-resolution and go.sum's silent realignment must both be \
                 disclosed in Outcome::Conflicted's auto_resolved field"
            );
        }
        Outcome::Clean => panic!("expected a real conflict on patched.txt to survive"),
    }
}

#[skuld::test]
fn real_conflict_stops_uncommitted_like_git_pull() {
    let fx = Fixture::build(ConflictKind::Real);
    let before_head = git_output(&fx.downstream, &["rev-parse", "HEAD"]);

    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { unresolved, .. } => {
            assert_eq!(unresolved, vec!["patched.txt".to_string()]);
        }
        Outcome::Clean => panic!("expected a conflict on patched.txt"),
    }

    let after_head = git_output(&fx.downstream, &["rev-parse", "HEAD"]);
    assert_eq!(
        before_head, after_head,
        "a real conflict must not commit anything on the downstream repo"
    );
}

#[skuld::test]
fn real_conflict_stops_uncommitted_from_a_linked_worktree() {
    // The other worktree tests below only cover outcomes that end Clean.
    // This is the only test that inspects Outcome::Conflicted's
    // `worktree` field and asserts nothing was committed — needs to run
    // from a linked worktree too.
    let fx = Fixture::build(ConflictKind::Real);
    let worktree_path = fx.dir.path().join("downstream-worktree");
    git(&fx.downstream, &["worktree", "add", worktree_path.to_str().unwrap()]);
    let before_head = git_output(&worktree_path, &["rev-parse", "HEAD"]);

    let outcome =
        pull_subrepo::run(&worktree_path, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted {
            worktree, unresolved, ..
        } => {
            assert_eq!(unresolved, vec!["patched.txt".to_string()]);
            assert!(
                worktree.is_dir(),
                "the reported conflict worktree should exist: {}",
                worktree.display()
            );
        }
        Outcome::Clean => panic!("expected a conflict on patched.txt"),
    }

    let after_head = git_output(&worktree_path, &["rev-parse", "HEAD"]);
    assert_eq!(
        before_head, after_head,
        "a real conflict must not commit anything on the worktree's HEAD"
    );
}

#[skuld::test]
fn two_real_conflicts_are_both_reported() {
    let fx = Fixture::build(ConflictKind::TwoReal);
    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { mut unresolved, .. } => {
            unresolved.sort();
            assert_eq!(
                unresolved,
                vec!["also_patched.txt".to_string(), "patched.txt".to_string()]
            );
        }
        Outcome::Clean => panic!("expected both files to conflict"),
    }
}

#[skuld::test]
fn refuses_to_run_when_a_conflict_resolution_is_already_in_progress() {
    let fx = Fixture::build(ConflictKind::Real);

    let first = pull_subrepo::run(&fx.downstream, "vendor", "v2")
        .expect("first conflicted run should report Conflicted, not Err");
    assert!(matches!(first, Outcome::Conflicted { .. }));

    // Simulate the human being mid-resolution: the worktree pull_subrepo::run
    // left behind still has unmerged patched.txt in it. Running again
    // without cleaning up first must refuse, not silently `git subrepo
    // clean` it out from under them — `git subrepo clean` skips
    // git-subrepo's own working-copy-clean guard, so it would otherwise
    // delete their in-progress resolution with no confirmation.
    let result = pull_subrepo::run(&fx.downstream, "vendor", "v2");
    assert!(
        result.is_err(),
        "must refuse rather than silently discard an in-progress resolution"
    );

    // The conflict markers must still be there — proving nothing got wiped.
    let worktree = fx.dir.path().join("downstream/.git/tmp/subrepo/vendor");
    let patched = std::fs::read_to_string(worktree.join("patched.txt")).unwrap();
    assert!(
        patched.contains("<<<<<<<"),
        "the in-progress resolution's conflict markers must survive: {patched}"
    );
}

#[skuld::test]
fn an_unexpected_pull_failure_surfaces_as_an_error_not_a_conflict() {
    // A nonexistent tag fails at git-subrepo's fetch step, with neither
    // the stale-parent stderr text nor the merge-conflict stdout text —
    // handle_conflict's catch-all bail branch, otherwise untested by every
    // other ConflictKind (which only ever produce one of those two).
    let fx = Fixture::build(ConflictKind::None);
    let result = pull_subrepo::run(&fx.downstream, "vendor", "this-tag-does-not-exist");
    assert!(
        result.is_err(),
        "a nonexistent tag should surface as an Err, not Outcome::Conflicted"
    );
}

#[skuld::test]
fn dirty_tree_is_rejected_before_touching_anything() {
    let fx = Fixture::build(ConflictKind::None);
    std::fs::write(fx.downstream.join("README.md"), "dirty\n").unwrap();

    let result = pull_subrepo::run(&fx.downstream, "vendor", "v2");
    assert!(result.is_err(), "a dirty tree must be rejected up front");

    let readme = std::fs::read_to_string(fx.downstream.join("README.md")).unwrap();
    assert_eq!(readme, "dirty\n", "the dirty file must be untouched");
}

#[skuld::test]
fn works_identically_from_a_linked_worktree() {
    let fx = Fixture::build(ConflictKind::None);
    let worktree_path = fx.dir.path().join("downstream-worktree");
    git(&fx.downstream, &["worktree", "add", worktree_path.to_str().unwrap()]);

    let outcome =
        pull_subrepo::run(&worktree_path, "vendor", "v2").expect("pull should succeed from a linked worktree");
    assert!(matches!(outcome, Outcome::Clean));
}

#[skuld::test]
fn leftover_subrepo_branch_from_a_manual_pull_does_not_block_a_later_pull() {
    // git-subrepo leaves the `subrepo/<subdir>` branch behind after EVERY
    // successful pull, including ones run outside this tool entirely (e.g.
    // the documented manual VENDORING.md flow).
    // `ensure_no_in_progress_conflict_resolution` must not treat that
    // benign residue as an in-progress conflict.
    let fx = Fixture::build(ConflictKind::None);
    git(&fx.downstream, &["subrepo", "pull", "vendor", "-b", "v2"]);
    // Sanity: confirm the fixture reproduces the leftover-branch state this
    // test exists to guard against (panics via `git`'s own assert if not).
    git(
        &fx.downstream,
        &["show-ref", "--verify", "--quiet", "refs/heads/subrepo/vendor"],
    );

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2")
        .expect("a leftover branch from a completed pull must not block a later pull");
    assert!(matches!(outcome, Outcome::Clean));
}

#[skuld::test]
fn ref_unsafe_subdir_is_rejected_before_touching_anything() {
    let fx = Fixture::build(ConflictKind::None);
    let before_head = git_output(&fx.downstream, &["rev-parse", "HEAD"]);

    let err = match pull_subrepo::run(&fx.downstream, "some vendor", "v2") {
        Err(e) => e,
        Ok(_) => panic!("a subdir needing percent-encoding must be rejected up front"),
    };
    assert!(
        format!("{err:#}").contains("check-ref-format"),
        "error should name the actual cause: {err:#}"
    );

    let after_head = git_output(&fx.downstream, &["rev-parse", "HEAD"]);
    assert_eq!(before_head, after_head, "nothing should be committed on rejection");
}

#[skuld::test]
fn trailing_slash_subdir_still_pulls_cleanly() {
    // git-subrepo's own `check-and-normalize-subdir` strips a trailing `/`
    // before doing anything else (e.g. what shell tab-completion appends to
    // a directory argument) — this module must normalize the same way
    // before building worktree/branch paths from `subdir`.
    let fx = Fixture::build(ConflictKind::None);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor/", "v2").expect("a trailing slash must not be rejected");
    assert!(matches!(outcome, Outcome::Clean));
}

#[skuld::test]
fn up_to_date_pull_still_realigns_the_branch_pin() {
    // git-subrepo's "already up to date" no-op path (the requested tag
    // resolves to the commit already recorded) leaves `.gitrepo` completely
    // untouched — Outcome::Clean must still mean the tag pin is current.
    let fx = Fixture::build(ConflictKind::None);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("first pull to v2 should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let upstream = fx.dir.path().join("upstream");
    git(&upstream, &["tag", "v3", "v2"]);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v3").expect("re-tag pull to v3 should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let gitrepo = std::fs::read_to_string(fx.downstream.join("vendor/.gitrepo")).unwrap();
    assert!(
        gitrepo.contains("branch = v3"),
        "the tag pin must be realigned even when git-subrepo itself no-ops: {gitrepo}"
    );
}

#[skuld::test]
fn untracked_file_inside_subdir_colliding_with_upstream_is_rejected_before_touching_anything() {
    // git-subrepo's fold-in step does `git rm -r <subdir>` and only then
    // `git read-tree --prefix=<subdir> -u <upstream>` — an untracked file
    // under `<subdir>` colliding with a path the new upstream tree
    // introduces makes `read-tree` abort AFTER the `rm` already deleted and
    // staged the whole subtree. `ensure_clean_tree` must catch this before
    // any of that runs, not just report git-subrepo's own opaque failure.
    let fx = Fixture::build(ConflictKind::None);
    let upstream = fx.dir.path().join("upstream");
    std::fs::write(upstream.join("newfile.txt"), "new upstream content\n").unwrap();
    git(&upstream, &["add", "-A"]);
    git(&upstream, &["commit", "-m", "v2b: add newfile.txt"]);
    git(&upstream, &["tag", "-f", "v2"]);

    std::fs::write(fx.downstream.join("vendor/newfile.txt"), "untracked local content\n").unwrap();

    let before_head = git_output(&fx.downstream, &["rev-parse", "HEAD"]);
    let result = pull_subrepo::run(&fx.downstream, "vendor", "v2");
    assert!(
        result.is_err(),
        "an untracked file colliding with upstream must be rejected up front"
    );

    let after_head = git_output(&fx.downstream, &["rev-parse", "HEAD"]);
    assert_eq!(before_head, after_head, "nothing should be committed on rejection");
    assert!(
        fx.downstream.join("vendor/patched.txt").exists(),
        "the vendored subtree must remain intact, not half-deleted"
    );
}

#[skuld::test]
fn leading_dot_slash_and_double_slash_subdir_normalize_and_pull_cleanly() {
    // normalize_subdir strips a leading `./`, a trailing `/` (covered by
    // trailing_slash_subdir_still_pulls_cleanly above), AND collapses
    // repeated `/` — this test covers the other two forms.
    let fx = Fixture::build(ConflictKind::None);
    let outcome = pull_subrepo::run(&fx.downstream, "./vendor", "v2").expect("a leading ./ must not be rejected");
    assert!(matches!(outcome, Outcome::Clean));
}

#[skuld::test]
fn stale_parent_fixup_commit_is_disclosed_when_the_retry_still_conflicts() {
    // The retry after fix_stale_parent lands its .gitrepo realignment
    // commit; a real (non-fatal) conflict on the retried pull must still
    // disclose that commit via Outcome::Conflicted's `fixup_commit` field,
    // not silently drop it.
    let fx = Fixture::build(ConflictKind::Real);
    fx.corrupt_parent();

    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");

    // A real conflict never commits anything further to the outer repo, so
    // HEAD at this point is exactly the fixup commit fix_stale_parent made.
    let fixup_commit = git_output(&fx.downstream, &["rev-parse", "HEAD"]).trim().to_string();

    match outcome {
        Outcome::Conflicted {
            unresolved,
            fixup_commit: disclosed,
            ..
        } => {
            assert_eq!(unresolved, vec!["patched.txt".to_string()]);
            assert_eq!(
                disclosed.as_deref(),
                Some(fixup_commit.as_str()),
                "the fixup commit must be disclosed in Outcome::Conflicted"
            );
        }
        Outcome::Clean => panic!("expected a real conflict on patched.txt to survive"),
    }
}

#[skuld::test]
fn stale_parent_fixup_add_commit_failure_is_disclosed() {
    // fix_stale_parent writes .gitrepo to disk and `git add`s it before
    // `git commit` — if the commit itself is blocked, the error must say
    // the file was already modified/staged, not just report the raw git
    // commit failure.
    let fx = Fixture::build(ConflictKind::None);
    fx.corrupt_parent();
    install_rejecting_pre_commit_hook(&fx.downstream);

    let err = match pull_subrepo::run(&fx.downstream, "vendor", "v2") {
        Err(e) => e,
        Ok(_) => panic!("expected the blocked fixup commit to surface as an error"),
    };
    let message = format!("{err:#}");
    assert!(
        message.contains("already modified and staged to realign `parent`"),
        "fix_stale_parent's add/commit disclosure is missing: {message}"
    );
}

#[skuld::test]
fn tag_pin_realignment_commit_failure_after_a_plain_pull_discloses_both_layers() {
    // ensure_tag_pin_matches, called from run()'s plain (non-stale-parent)
    // success path, writes .gitrepo and `git add`s it before `git commit`.
    // A blocked commit here must surface BOTH ensure_tag_pin_matches's own
    // add/commit disclosure AND the outer plain-success-path disclosure
    // (that git subrepo pull already committed real content before this
    // failure) — anyhow's error chain should carry both layers.
    let fx = Fixture::build(ConflictKind::None);
    let upstream = fx.dir.path().join("upstream");
    // v3 == v2's exact commit: forces git-subrepo's "already up to date"
    // no-op on the second pull, so only ensure_tag_pin_matches's own
    // realignment commit is at stake, not a real git-subrepo merge commit.
    git(&upstream, &["tag", "v3", "v2"]);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("first pull to v2 should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    install_rejecting_pre_commit_hook(&fx.downstream);

    let err = match pull_subrepo::run(&fx.downstream, "vendor", "v3") {
        Err(e) => e,
        Ok(_) => panic!("expected the blocked tag-pin realignment commit to surface as an error"),
    };
    let message = format!("{err:#}");
    assert!(
        message.contains("already succeeded"),
        "the outer plain-success-path disclosure is missing: {message}"
    );
    assert!(
        message.contains("already modified and staged to realign `branch`"),
        "ensure_tag_pin_matches's own add/commit disclosure is missing: {message}"
    );
}

#[skuld::test]
fn a_branch_with_unfolded_work_is_rejected_even_though_the_worktree_is_gone() {
    // Distinguishes benign post-success branch residue (which must NOT
    // block a later pull, see leftover_subrepo_branch_from_a_manual_pull_*)
    // from a human's resolution commit that was never folded in via
    // `git subrepo commit <subdir>` — simulated here by resolving a real
    // conflict inside the temp worktree, committing there, then manually
    // removing the worktree without ever running the fold-in step.
    let fx = Fixture::build(ConflictKind::Real);
    let raw = Command::new("git")
        .args(["subrepo", "pull", "vendor", "-b", "v2"])
        .current_dir(&fx.downstream)
        .output()
        .unwrap();
    assert!(!raw.status.success(), "fixture should reproduce a real conflict");

    let worktree = fx.dir.path().join("downstream/.git/tmp/subrepo/vendor");
    std::fs::write(worktree.join("patched.txt"), "resolved content\n").unwrap();
    git(&worktree, &["add", "-A"]);
    git(&worktree, &["commit", "-m", "resolve conflict"]);
    std::fs::remove_dir_all(&worktree).unwrap();

    let result = pull_subrepo::run(&fx.downstream, "vendor", "v2");
    assert!(
        result.is_err(),
        "a branch carrying an un-folded-in resolution commit must be refused even once its \
         worktree is gone"
    );
}

#[skuld::test]
fn allowlisted_conflict_resolves_from_a_linked_worktree() {
    // Exercises the git_common_dir / temp-worktree-location code inside
    // handle_conflict — the part of pull_subrepo that's actually
    // worktree-position sensitive.
    let fx = Fixture::build(ConflictKind::Allowlisted);
    let worktree_path = fx.dir.path().join("downstream-worktree");
    git(&fx.downstream, &["worktree", "add", worktree_path.to_str().unwrap()]);

    let outcome = pull_subrepo::run(&worktree_path, "vendor", "v2")
        .expect("conflict resolution should succeed from a linked worktree");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(worktree_path.join("vendor/go.mod")).unwrap();
    assert!(go_mod.contains("newdep"));
}

#[skuld::test]
fn force_commit_conflicted_commits_the_conflicted_tree_and_fixes_the_branch_field() {
    let fx = Fixture::build(ConflictKind::Real);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").unwrap();
    assert!(matches!(outcome, Outcome::Conflicted { .. }));

    pull_subrepo::force_commit_conflicted(&fx.downstream, "vendor", "v2")
        .expect("force-commit should succeed even with conflict markers present");

    let gitrepo = std::fs::read_to_string(fx.downstream.join("vendor/.gitrepo")).unwrap();
    assert!(
        gitrepo.contains("branch = v2"),
        "branch field must be fixed even on the forced-conflicted-commit path: {gitrepo}"
    );

    let patched = std::fs::read_to_string(fx.downstream.join("vendor/patched.txt")).unwrap();
    assert!(
        patched.contains("<<<<<<<"),
        "conflict markers should be literally committed, per the CI-only policy: {patched}"
    );
}

#[skuld::test]
fn force_commit_conflicted_preserves_already_resolved_allowlisted_files() {
    // The real CI path always follows a pull-subrepo call that returned
    // exit code 2, which can leave a worktree mixing already-resolved
    // allowlisted files (go.mod, auto-resolved by handle_conflict before
    // it ever reports Conflicted) with still-conflicted real ones — not
    // just a single conflicted file like the test above.
    let fx = Fixture::build(ConflictKind::Mixed);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").unwrap();
    match outcome {
        Outcome::Conflicted { unresolved, .. } => assert_eq!(unresolved, vec!["patched.txt".to_string()]),
        Outcome::Clean => panic!("expected patched.txt to remain conflicted"),
    }

    pull_subrepo::force_commit_conflicted(&fx.downstream, "vendor", "v2")
        .expect("force-commit should succeed on a mixed conflict");

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(
        go_mod.contains("newdep") && !go_mod.contains("<<<<<<<"),
        "go.mod should already be cleanly resolved to upstream, not committed with markers: {go_mod}"
    );

    // go.sum here is only edited downstream (never by upstream), so it
    // merges cleanly and stale — the go.mod/go.sum consistency safety net
    // (see ConflictKind::Mixed) realigns it too.
    let go_sum = std::fs::read_to_string(fx.downstream.join("vendor/go.sum")).unwrap();
    assert_eq!(
        go_sum, "fixture v1.0.0 h1:abc=\n",
        "go.sum should already be realigned to upstream, not committed stale: {go_sum}"
    );

    let patched = std::fs::read_to_string(fx.downstream.join("vendor/patched.txt")).unwrap();
    assert!(
        patched.contains("<<<<<<<"),
        "patched.txt's real conflict markers should be committed literally: {patched}"
    );
}

#[skuld::test]
fn force_commit_conflicted_refuses_when_the_worktree_has_no_unmerged_paths() {
    // A hard guard (not a debug_assert), immediately before an
    // irreversible commit in unattended CI: force_commit_conflicted must
    // refuse a worktree that exists but has already been resolved by hand
    // (e.g. a human resolved and committed in the worktree themselves,
    // per pull-subrepo's own printed instructions, without folding it in)
    // rather than force-committing what isn't actually a conflicted pull.
    let fx = Fixture::build(ConflictKind::Real);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").unwrap();
    assert!(matches!(outcome, Outcome::Conflicted { .. }));

    let worktree = fx.dir.path().join("downstream/.git/tmp/subrepo/vendor");
    std::fs::write(worktree.join("patched.txt"), "resolved by hand\n").unwrap();
    git(&worktree, &["add", "-A"]);
    git(&worktree, &["commit", "-m", "resolved by hand"]);

    let err = pull_subrepo::force_commit_conflicted(&fx.downstream, "vendor", "v2")
        .expect_err("must refuse to force-commit a worktree with no unmerged paths");
    assert!(
        format!("{err:#}").contains("refusing to force-commit"),
        "error should explain the refusal: {err:#}"
    );
}

#[skuld::test]
fn force_commit_conflicted_errors_when_no_conflict_worktree_exists() {
    // A clean pull leaves no conflict worktree at all (best_effort_clean
    // removes it) — force_commit_conflicted must error rather than
    // operate on nothing.
    let fx = Fixture::build(ConflictKind::None);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").unwrap();
    assert!(matches!(outcome, Outcome::Clean));

    let err = pull_subrepo::force_commit_conflicted(&fx.downstream, "vendor", "v2")
        .expect_err("must error when there's no conflict worktree to force-commit");
    assert!(
        format!("{err:#}").contains("no conflicted subrepo temp worktree found"),
        "error should explain there's nothing to force-commit: {err:#}"
    );
}

#[skuld::test]
fn force_commit_conflicted_refuses_when_an_untracked_file_exists_in_the_outer_subdir() {
    // Mirrors untracked_file_inside_subdir_colliding_with_upstream_is_
    // rejected_before_touching_anything, but for force_commit_conflicted:
    // git-subrepo's own fold-in (`git rm -r` then `git read-tree
    // --prefix`, inside finish_conflict_fold_in) doesn't check for
    // untracked files itself, so one under <subdir> aborts read-tree
    // AFTER rm already deleted and staged the entire subtree — confirmed
    // live. force_commit_conflicted must refuse up front (the same
    // ensure_clean_tree guard run() already applies) rather than
    // destructively half-wiping <subdir>.
    let fx = Fixture::build(ConflictKind::Real);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").unwrap();
    assert!(matches!(outcome, Outcome::Conflicted { .. }));

    std::fs::write(fx.downstream.join("vendor/untracked.txt"), "oops\n").unwrap();

    let err = pull_subrepo::force_commit_conflicted(&fx.downstream, "vendor", "v2")
        .expect_err("must refuse when an untracked file exists under <subdir>");
    assert!(
        format!("{err:#}").contains("untracked files exist"),
        "error should explain the refusal: {err:#}"
    );
    assert!(
        fx.downstream.join("vendor/patched.txt").exists(),
        "the vendored subtree must remain intact, not half-deleted"
    );
}

#[skuld::test]
fn real_conflict_under_rebase_method_is_refused_before_touching_ours_theirs() {
    // assert_join_method_is_merge guards every ours/theirs assumption in
    // this module (checkout --theirs, the go.mod replace-directive check,
    // blob_matches_upstream's stage-0 read) — under `method = rebase`,
    // git-subrepo swaps which side is stage 2 vs stage 3, which would
    // silently invert all of them. Must refuse rather than proceed.
    let fx = Fixture::build(ConflictKind::Real);
    fx.set_join_method_rebase();

    let err = match pull_subrepo::run(&fx.downstream, "vendor", "v2") {
        Err(e) => e,
        Ok(_) => panic!("a non-merge join method must be refused, not silently resolved with inverted semantics"),
    };
    assert!(
        format!("{err:#}").contains("method = rebase"),
        "error should name the actual method mismatch: {err:#}"
    );
}

#[skuld::test]
fn is_auto_resolvable_covers_the_documented_allowlist() {
    assert!(pull_subrepo::is_auto_resolvable("go.mod"));
    assert!(pull_subrepo::is_auto_resolvable("go.sum"));
    assert!(pull_subrepo::is_auto_resolvable(".github/workflows/ci.yml"));
    assert!(!pull_subrepo::is_auto_resolvable("patched.txt"));
}
