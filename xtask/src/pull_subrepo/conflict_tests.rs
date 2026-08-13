//! Tests for `pull_subrepo::conflict` — allowlist auto-resolution, the
//! real-conflict stop, and the CI-only `force_commit_conflicted`. Shares
//! `pull_subrepo_tests.rs`'s `Fixture`/`ConflictKind` machinery via
//! `super::test_support` (see that module for the fixture-building
//! rationale).

use std::path::Path;

use crate::pull_subrepo::test_support::{
    git, git_init, git_output, install_rejecting_pre_commit_hook, ConflictKind, Fixture,
};
use crate::pull_subrepo::{self, Outcome};

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
    assert!(super::conflict::is_auto_resolvable("go.mod"));
    assert!(super::conflict::is_auto_resolvable("go.sum"));
    assert!(super::conflict::is_auto_resolvable(".github/workflows/ci.yml"));
    assert!(!super::conflict::is_auto_resolvable("patched.txt"));
}

#[skuld::test]
fn unmerged_path_with_a_leading_space_is_reported_verbatim_not_trimmed() {
    // `git diff -z`'s NUL-delimited output preserves a leading space in a
    // conflicted path exactly — routing it through `run_git`'s `.trim()`
    // (instead of the untrimmed `run_git_raw`) would silently strip a
    // leading space off the first entry, since `\0` isn't Unicode
    // whitespace but a leading ASCII space is (confirmed live on git
    // 2.53.0).
    let dir = tempfile::tempdir().unwrap();
    let upstream = dir.path().join("upstream");
    let downstream = dir.path().join("downstream");

    git_init(&upstream);
    std::fs::write(upstream.join(" lead.txt"), "upstream line one\n").unwrap();
    git(&upstream, &["add", "-A"]);
    git(&upstream, &["commit", "-m", "v1"]);
    git(&upstream, &["tag", "v1"]);

    std::fs::write(upstream.join(" lead.txt"), "upstream line one CHANGED\n").unwrap();
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
        downstream.join("vendor/ lead.txt"),
        "upstream line one\nour local patch\n",
    )
    .unwrap();
    git(&downstream, &["add", "-A"]);
    git(&downstream, &["commit", "-m", "patch: our local addition"]);
    git(&downstream, &["checkout", "main"]);
    git(&downstream, &["merge", "--squash", "feature"]);
    git(&downstream, &["commit", "-m", "vendor: import + patch (squashed)"]);
    git(&downstream, &["branch", "-D", "feature"]);

    let outcome =
        pull_subrepo::run(&downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { unresolved, .. } => {
            assert_eq!(
                unresolved,
                vec![" lead.txt".to_string()],
                "the leading space in the conflicted path must survive verbatim, not be trimmed off"
            );
        }
        Outcome::Clean => panic!("expected a conflict on ` lead.txt`"),
    }
}

#[skuld::test]
fn allowlisted_conflict_commit_failure_is_disclosed() {
    // handle_conflict's own finishing `git commit --no-edit` (in the
    // allowlist-resolved temp worktree) is wrapped with a disclosure since
    // the allowlisted paths are already resolved and staged by the time it
    // runs — a blocked commit here must say so, not just report the raw
    // git failure.
    let fx = Fixture::build(ConflictKind::Allowlisted);
    install_rejecting_pre_commit_hook(&fx.downstream);

    let err = match pull_subrepo::run(&fx.downstream, "vendor", "v2") {
        Err(e) => e,
        Ok(_) => panic!("expected the blocked worktree commit to surface as an error"),
    };
    let message = format!("{err:#}");
    assert!(
        message.contains("already resolved and staged"),
        "handle_conflict's own commit disclosure is missing: {message}"
    );
}

#[skuld::test]
fn force_commit_conflicted_commit_failure_is_disclosed() {
    // force_commit_conflicted's own `git add -A` + commit is wrapped with a
    // disclosure since the conflicted tree is already staged by the time
    // it runs — a blocked commit here must say so.
    let fx = Fixture::build(ConflictKind::Real);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").unwrap();
    assert!(matches!(outcome, Outcome::Conflicted { .. }));

    install_rejecting_pre_commit_hook(&fx.downstream);

    let err = pull_subrepo::force_commit_conflicted(&fx.downstream, "vendor", "v2")
        .expect_err("expected the blocked commit to surface as an error");
    let message = format!("{err:#}");
    assert!(
        message.contains("already staged the entire"),
        "force_commit_conflicted's own commit disclosure is missing: {message}"
    );
}

/// Like `install_rejecting_pre_commit_hook`, but only rejects a commit
/// whose cwd's basename isn't `allowed_cwd_basename` — git hooks are
/// shared across every worktree of a repo (confirmed live: installing an
/// unconditional reject on the outer repo also blocks a commit run inside
/// git-subrepo's own temp conflict worktree), so a plain unconditional
/// reject can only ever block whichever commit in a chain happens first.
/// This lets that first commit through so a *later* one in the same chain
/// can be exercised in isolation.
fn install_pre_commit_hook_rejecting_outside(repo: &Path, allowed_cwd_basename: &str) {
    let hooks_dir = repo.join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    let hook_path = hooks_dir.join("pre-commit");
    std::fs::write(
        &hook_path,
        format!(
            "#!/bin/sh\ncase \"$(basename \"$(pwd)\")\" in\n  {allowed_cwd_basename}) exit 0 ;;\n  *) exit 1 ;;\nesac\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[skuld::test]
fn finish_conflict_fold_in_subrepo_commit_failure_is_disclosed() {
    // finish_conflict_fold_in's `git subrepo commit` (the fold-in step, run
    // at repo_root) is wrapped with a disclosure since a commit already
    // exists in the resolved temp worktree by the time it runs — confirmed
    // against the installed git-subrepo 0.4.9 source that this step really
    // does invoke porcelain `git commit` (not the hook-bypassing
    // `commit-tree`) whenever the repo already has commits, so it's
    // genuinely hook-blockable.
    //
    // Isolating this from handle_conflict's OWN preceding worktree commit
    // (also hook-blockable, and always the first commit in this same
    // chain) needs a hook that lets exactly that one commit through —
    // otherwise a plain unconditional reject blocks the worktree commit
    // first and this step is never reached at all.
    let fx = Fixture::build(ConflictKind::Allowlisted);
    install_pre_commit_hook_rejecting_outside(&fx.downstream, "vendor");

    let err = match pull_subrepo::run(&fx.downstream, "vendor", "v2") {
        Err(e) => e,
        Ok(_) => panic!("expected the blocked fold-in commit to surface as an error"),
    };
    let message = format!("{err:#}");
    assert!(
        message.contains("a commit was already made in the subrepo temp worktree"),
        "finish_conflict_fold_in's own `git subrepo commit` disclosure is missing: {message}"
    );
}

#[skuld::test]
fn handle_conflict_bails_when_the_worktree_has_no_unmerged_paths() {
    // handle_conflict's catch-all bail has two distinct triggers: no
    // worktree at all (tested via a nonexistent tag, see
    // an_unexpected_pull_failure_surfaces_as_an_error_not_a_conflict), and
    // a worktree that exists but has no unmerged paths at all — a
    // distinct, structurally load-bearing branch since this module's own
    // docs stress that string-matching git-subrepo's stdout is unreliable,
    // making this diff-based check important to guard with a regression
    // test.
    //
    // Reproduced via a CLEAN merge (no real conflict at all): its
    // git-subrepo-internal fold-in commit (at repo_root, still inside the
    // same `git subrepo pull` invocation, confirmed hook-blockable per the
    // note on `finish_conflict_fold_in_subrepo_commit_failure_is_
    // disclosed` above) is blocked by a rejecting hook. The merge itself
    // already succeeded with zero conflicts before that commit runs, and
    // git-subrepo only removes the temp worktree AFTER that commit
    // succeeds — so the worktree it leaves behind has no unmerged paths at
    // all, while `git subrepo pull` as a whole still exits non-zero.
    let fx = Fixture::build(ConflictKind::None);
    install_rejecting_pre_commit_hook(&fx.downstream);

    let err = match pull_subrepo::run(&fx.downstream, "vendor", "v2") {
        Err(e) => e,
        Ok(_) => panic!("expected the blocked internal fold-in commit to surface as an error"),
    };
    let message = format!("{err:#}");
    assert!(
        message.contains("but has no unmerged paths"),
        "the worktree-exists-but-no-unmerged-paths bail branch's message is missing: {message}"
    );
}
