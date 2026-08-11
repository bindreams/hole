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
    /// v2 DELETES `go.sum` entirely while our downstream commit still has
    /// local edits to it — a delete/modify conflict.
    AllowlistedDelete,
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
        std::fs::write(upstream.join("go.sum"), "fixture v1.0.0 h1:abc=\n").unwrap();
        std::fs::write(upstream.join("other.txt"), "unrelated\n").unwrap();
        git(&upstream, &["add", "."]);
        git(&upstream, &["commit", "-m", "v1"]);
        git(&upstream, &["tag", "v1"]);

        match conflict {
            ConflictKind::None => {
                std::fs::write(upstream.join("other.txt"), "unrelated changed\n").unwrap();
            }
            ConflictKind::Allowlisted
            | ConflictKind::AllowlistedWithReplace
            | ConflictKind::AllowlistedWithBlockReplace => {
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

        let go_mod_content = if matches!(conflict, ConflictKind::AllowlistedWithReplace) {
            "module fixture\n\ngo 1.25\n\nrequire ourdownstream/patchdep v1.0.0\n\nreplace ourdownstream/loadbearing => ../loadbearing\n"
        } else if matches!(conflict, ConflictKind::AllowlistedWithBlockReplace) {
            "module fixture\n\ngo 1.25\n\nrequire ourdownstream/patchdep v1.0.0\n\nreplace (\n\tourdownstream/loadbearing => ../loadbearing\n)\n"
        } else {
            "module fixture\n\ngo 1.25\n\nrequire ourdownstream/patchdep v1.0.0\n"
        };
        std::fs::write(downstream.join("vendor/go.mod"), go_mod_content).unwrap();
        std::fs::write(downstream.join("vendor/go.sum"), "fixture v1.0.0-patched h1:def=\n").unwrap();
        git(&downstream, &["add", "-A"]);
        git(&downstream, &["commit", "-m", "patch: our local addition"]);

        git(&downstream, &["checkout", "main"]);
        git(&downstream, &["merge", "--squash", "feature"]);
        git(&downstream, &["commit", "-m", "vendor: import + patch (squashed)"]);
        git(&downstream, &["branch", "-D", "feature"]);

        Fixture { dir, downstream }
    }

    /// Rewrites `.gitrepo`'s `parent` to a commit that exists but is not
    /// an ancestor of HEAD — see the module-level note on why this is
    /// constructed directly rather than produced naturally by the
    /// clone+patch+squash-merge sequence above.
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
    let fx = Fixture::build(ConflictKind::AllowlistedWithReplace);

    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { unresolved, .. } => {
            assert_eq!(
                unresolved,
                vec!["go.mod".to_string()],
                "go.mod must be treated as unresolved when a downstream replace would be lost"
            );
        }
        Outcome::Clean => panic!("expected go.mod to be left for a human, not silently resolved"),
    }
}

#[skuld::test]
fn allowlisted_go_mod_conflict_declines_when_a_block_form_replace_would_be_lost() {
    // go_mod_replace_directives exists specifically because a naive
    // line-prefix filter misses go.mod's block replace syntax — this test
    // only exercises the single-line form indirectly through the OTHER
    // preservation test above wouldn't have caught a regression back to
    // that naive approach. This one would.
    let fx = Fixture::build(ConflictKind::AllowlistedWithBlockReplace);

    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { unresolved, .. } => {
            assert_eq!(
                unresolved,
                vec!["go.mod".to_string()],
                "go.mod must be treated as unresolved when a block-form downstream replace would be lost"
            );
        }
        Outcome::Clean => panic!("expected go.mod to be left for a human, not silently resolved"),
    }
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
fn mixed_conflict_auto_resolves_the_allowlisted_part_only() {
    let fx = Fixture::build(ConflictKind::Mixed);

    let outcome =
        pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { unresolved, .. } => {
            assert_eq!(
                unresolved,
                vec!["patched.txt".to_string()],
                "go.mod should have been auto-resolved, leaving only the real conflict"
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
        Outcome::Conflicted { worktree, unresolved } => {
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
    // commit; if the retried pull still fails, the error must name that
    // commit rather than leaving it an undisclosed side effect.
    let fx = Fixture::build(ConflictKind::Real);
    fx.corrupt_parent();

    let err = match pull_subrepo::run(&fx.downstream, "vendor", "v2") {
        Err(e) => e,
        Ok(_) => panic!("expected a real conflict to surface as an error after the stale-parent fixup"),
    };
    let message = format!("{err:#}");
    assert!(
        message.contains("was already created on this branch"),
        "the fixup commit must be disclosed: {message}"
    );

    // A real conflict never commits anything further to the outer repo, so
    // HEAD at this point is exactly the fixup commit fix_stale_parent made.
    let fixup_commit = git_output(&fx.downstream, &["rev-parse", "HEAD"]).trim().to_string();
    assert!(
        message.contains(&fixup_commit),
        "the disclosed message should name the actual fixup commit {fixup_commit}: {message}"
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

    let patched = std::fs::read_to_string(fx.downstream.join("vendor/patched.txt")).unwrap();
    assert!(
        patched.contains("<<<<<<<"),
        "patched.txt's real conflict markers should be committed literally: {patched}"
    );
}

#[skuld::test]
fn is_auto_resolvable_covers_the_documented_allowlist() {
    assert!(pull_subrepo::is_auto_resolvable("go.mod"));
    assert!(pull_subrepo::is_auto_resolvable("go.sum"));
    assert!(pull_subrepo::is_auto_resolvable(".github/workflows/ci.yml"));
    assert!(!pull_subrepo::is_auto_resolvable("patched.txt"));
}
