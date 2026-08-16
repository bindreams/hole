//! Shared test fixture infrastructure for `pull_subrepo`'s test suite,
//! used by both `pull_subrepo_tests.rs` (clean-pull/stale-parent) and
//! `pull_subrepo/conflict_tests.rs` (conflict-handling).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

/// Guards the `SKIP` env var against a cross-test race: `skuld` runs every
/// `#[skuld::test]` in this crate's process concurrently, and
/// `pull_subrepo::skip_check_vendoring_integrity_matches_prek_toml_hook_id`
/// briefly clears process-global `SKIP` to observe its default value. If
/// that window overlaps a `check_vendoring_integrity_tests.rs`
/// `always_run_hazard_end_to_end_*` test — the only tests that install a
/// *real*, unconditionally-failing `check-vendoring-integrity` pre-commit
/// hook and depend on every internal commit actually carrying
/// `SKIP=check-vendoring-integrity` — that commit could lose the SKIP value
/// mid-run and fail for a reason unrelated to whatever code change
/// triggered it. Every test in that set acquires this lock for its entire
/// body; every other test that merely calls `pull_subrepo::run`/
/// `finish_vendor_bump::run` without installing a real failing hook has no
/// pre-commit hook to trip either way and doesn't need to acquire it.
pub(crate) static SKIP_ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Which upstream file(s) v2 changes, matched against what our local
/// downstream patch also touches.
pub(crate) enum ConflictKind {
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

pub(crate) struct Fixture {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) downstream: PathBuf,
}

impl Fixture {
    pub(crate) fn build(conflict: ConflictKind) -> Self {
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
    pub(crate) fn corrupt_parent(&self) {
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
    pub(crate) fn set_join_method_rebase(&self) {
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

pub(crate) fn git_init(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    git(path, &["init", "--initial-branch=main", "--quiet"]);
    // Fixtures never intend platform-dependent line-ending mutation —
    // a checkout inside these tests (e.g. resolving an allowlisted
    // conflict to upstream's content) must not silently smudge LF to
    // CRLF on a Windows runner with a global `core.autocrlf=true`
    // (GitHub's windows-latest default) and desync from what the test
    // literally wrote/asserts.
    git(path, &["config", "core.autocrlf", "false"]);
    git(path, &["config", "user.email", "fixture@example.com"]);
    git(path, &["config", "user.name", "fixture"]);
}

pub(crate) fn git(cwd: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| panic!("failed to run git {args:?} in {}: {e}", cwd.display()));
    assert!(status.success(), "git {args:?} failed in {}", cwd.display());
}

pub(crate) fn git_output(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git").args(args).current_dir(cwd).output().unwrap();
    assert!(output.status.success(), "git {args:?} failed in {}", cwd.display());
    String::from_utf8(output.stdout).unwrap()
}

/// Installs a `pre-commit` hook that unconditionally rejects the commit —
/// a deterministic, cross-platform way to force a `git commit` to fail
/// after its preceding `git add` already succeeded, for tests exercising
/// the disclosure wrapped around exactly that gap.
pub(crate) fn install_rejecting_pre_commit_hook(repo: &Path) {
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
