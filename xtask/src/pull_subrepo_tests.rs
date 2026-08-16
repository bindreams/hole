use std::process::Command;

use super::pull_subrepo::test_support::{git, git_output, install_rejecting_pre_commit_hook, ConflictKind, Fixture};
use super::pull_subrepo::{self, Outcome};

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
fn leading_dot_slash_subdir_normalizes_and_pulls_cleanly() {
    // normalize_subdir also strips a trailing `/` (covered by
    // trailing_slash_subdir_still_pulls_cleanly above) and collapses
    // repeated `/` — the fixture's subrepo is a single path component
    // ("vendor"), with no natural multi-component path to exercise that
    // collapse against, so this test covers only the leading `./` form.
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

/// `skip_check_vendoring_integrity` hardcodes the literal `"check-vendoring-integrity"` as
/// the `SKIP` value it sets, and `prek.toml`'s hook entry hardcodes the same string as its
/// `id`. Nothing else ties these together — a rename of one without the other means every
/// xtask-internal commit silently starts getting rejected by the local pre-commit hook
/// again, with no test failure pointing at the cause. Mirrors
/// `identity_checks_match_the_real_build_yaml_ex_ray_tests_target`'s pattern of checking a
/// hardcoded expectation against the real files, rather than a full TOML parse.
#[skuld::test]
fn skip_check_vendoring_integrity_matches_prek_toml_hook_id() {
    const HOOK_ID: &str = "check-vendoring-integrity";

    let root = crate::repo_root().expect("repo root");
    let prek_toml = std::fs::read_to_string(root.join("prek.toml")).expect("read prek.toml");
    assert!(
        prek_toml.contains(&format!("id = \"{HOOK_ID}\"")),
        "prek.toml no longer has a hook with id = \"{HOOK_ID}\" — update it in lockstep with \
         pull_subrepo::skip_check_vendoring_integrity"
    );

    // SKIP is process-global env state; save/restore around the read so this test doesn't
    // observe, or leave behind, a developer's own unrelated SKIP export. The lock guards
    // against a concurrently-running `always_run_hazard_end_to_end_*` test observing SKIP
    // mid-clear — see `test_support::SKIP_ENV_TEST_LOCK`'s own doc.
    let _skip_env_guard = pull_subrepo::test_support::SKIP_ENV_TEST_LOCK.lock().unwrap();
    let saved = std::env::var_os("SKIP");
    unsafe { std::env::remove_var("SKIP") };
    let actual = pull_subrepo::skip_check_vendoring_integrity();
    match saved {
        Some(v) => unsafe { std::env::set_var("SKIP", v) },
        None => unsafe { std::env::remove_var("SKIP") },
    }

    assert_eq!(
        actual, HOOK_ID,
        "skip_check_vendoring_integrity()'s hardcoded SKIP literal has drifted from \
         prek.toml's check-vendoring-integrity hook id"
    );
}
