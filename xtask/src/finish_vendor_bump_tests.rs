use std::path::Path;
use std::process::Command;

use super::finish_vendor_bump::test_support::FixtureBuilder;
use super::finish_vendor_bump::{self, IdentityCheckOutcome};

fn git(cwd: &Path, args: &[&str]) {
    let status = Command::new("git").args(args).current_dir(cwd).status().unwrap();
    assert!(status.success(), "git {args:?} failed in {}", cwd.display());
}

fn init_repo_with_vendoring_md(dep_heading: &str, old_version: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let vendoring_dir = dir.path().join("crates/ex-ray/third_party");
    std::fs::create_dir_all(&vendoring_dir).unwrap();
    std::fs::write(
        vendoring_dir.join("VENDORING.md"),
        format!("# Vendoring\n\n## `{dep_heading}/` — pinned **{old_version}** ([upstream](https://example.com))\n\nSome patch notes.\n"),
    )
    .unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-m", "initial"]);
    dir
}

#[skuld::test]
fn updates_the_vendoring_note_and_commits() {
    let dir = init_repo_with_vendoring_md("widget", "v1.0.0");

    finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0").unwrap();

    let note = std::fs::read_to_string(dir.path().join("crates/ex-ray/third_party/VENDORING.md")).unwrap();
    assert!(
        note.contains("pinned **v2.0.0**"),
        "note should show the new version: {note}"
    );
    assert!(!note.contains("v1.0.0"));

    let log = Command::new("git")
        .args(["log", "-1", "--format=%s"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&log.stdout).contains("widget"));
}

#[skuld::test]
fn a_second_call_with_no_changes_does_not_fail_on_an_empty_commit() {
    let dir = init_repo_with_vendoring_md("widget", "v1.0.0");
    finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0").unwrap();

    let result = finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0");
    assert!(result.is_ok(), "a no-op second call must not fail: {result:?}");
}

#[skuld::test]
fn a_second_call_does_not_sweep_up_unrelated_staged_files() {
    let dir = init_repo_with_vendoring_md("widget", "v1.0.0");
    finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0").unwrap();

    std::fs::write(dir.path().join("unrelated.txt"), "someone's in-progress work\n").unwrap();
    git(dir.path(), &["add", "unrelated.txt"]);

    finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0").unwrap();

    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let status_str = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_str.contains("unrelated.txt"),
        "unrelated staged file must survive untouched, not swept into the docs commit: {status_str}"
    );
}

#[skuld::test]
fn failing_identity_check_is_reported_not_swallowed() {
    let dir = tempfile::tempdir().unwrap();
    let ex_ray = dir.path().join("crates/ex-ray");
    std::fs::create_dir_all(&ex_ray).unwrap();
    std::fs::write(ex_ray.join("go.mod"), "module example.com/ex-ray\n\ngo 1.25\n").unwrap();
    // Deliberate syntax error — the very first check (crates/ex-ray's own
    // go test ./...) must fail on this.
    std::fs::write(ex_ray.join("main.go"), "package main\n\nfunc broken( {\n").unwrap();

    let outcome = finish_vendor_bump::run_identity_checks(dir.path()).unwrap();
    match outcome {
        IdentityCheckOutcome::Failed { detail } => {
            assert!(detail.contains("test"), "detail should name the failing step: {detail}");
        }
        IdentityCheckOutcome::Passed => panic!("expected the syntax error to fail"),
    }
}

/// Exercises the FULL `run()` sequence end-to-end — including
/// `run_go_mod_tidy_and_commit`, the outer `go.mod` require-line rewrite,
/// and `run_identity_checks` reaching `IdentityCheckOutcome::Passed`. Two
/// real, self-contained Go modules (no external imports, so `go mod tidy`
/// touches nothing over the network) linked by a `replace` directive,
/// mirroring the real `crates/ex-ray` / vendored-dep pair. `run_identity_checks`
/// runs its v2ray-core-scoped test unconditionally (not gated on `subdir`),
/// so the fixture's `v2ray_core_stub()` gives it a minimal, always-passing
/// target to run against.
#[skuld::test]
fn run_updates_go_mod_and_commits_the_full_sequence() {
    let fx = FixtureBuilder::default().v2ray_core_stub().build();

    // v1.1.0, not v2.0.0: Go's semantic import versioning hard-rejects a
    // require line whose version is v2+ unless the module path itself
    // carries a matching `/v2` suffix (confirmed against the real `go`
    // toolchain — `go.mod` fails to parse at all, independent of the
    // `replace` directive). `example.com/widget` has no such suffix, so
    // this test bumps within the same major version.
    let outcome = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0").unwrap();
    assert!(
        matches!(outcome, IdentityCheckOutcome::Passed),
        "expected the minimal fixture to pass identity checks"
    );

    let go_mod = std::fs::read_to_string(fx.ex_ray_dir().join("go.mod")).unwrap();
    assert!(
        go_mod.contains("example.com/widget v1.1.0") && !go_mod.contains("vv1.1.0"),
        "require line should be bumped to exactly v1.1.0, not double-prefixed: {go_mod}"
    );

    let note = std::fs::read_to_string(fx.vendoring_dir().join("VENDORING.md")).unwrap();
    assert!(note.contains("pinned **v1.1.0**"));

    // Re-run with the same target: proves the go.mod/go.sum commit path's
    // own commit_if_staged guard (distinct call site from the
    // VENDORING.md note's) also survives a no-op re-run.
    let second = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0");
    assert!(
        second.is_ok(),
        "a second, no-op run must not fail on an empty go.mod/go.sum commit: {second:?}"
    );
}

/// The `FinishVendorBump` doc comment (`xtask/src/lib.rs`) claims `run()`
/// "commit[s] each step's own changes — regardless of
/// whether the identity check passed." The only prior test reaching
/// `IdentityCheckOutcome::Failed` calls `run_identity_checks` directly,
/// skipping the VENDORING.md/go.mod steps entirely — this exercises the
/// claim through the actual `run()` entry point `cargo xtask
/// finish-vendor-bump` calls.
#[skuld::test]
fn run_commits_earlier_steps_even_when_the_identity_check_fails() {
    // Deliberate test failure in crates/ex-ray's own suite — the FIRST
    // check run_identity_checks performs, so VENDORING.md and go.mod are
    // already updated and committed by the time this fails. No
    // `v2ray_core_stub()`: this failure short-circuits before the second,
    // v2ray-core-scoped check ever runs.
    let fx = FixtureBuilder::default()
        .ex_ray_main_test_go(
            "package main\n\nimport \"testing\"\n\nfunc TestBroken(t *testing.T) { t.Fatal(\"deliberate failure\") }\n",
        )
        .build();

    // v1.1.0, not v2.0.0 — see the comment in
    // run_updates_go_mod_and_commits_the_full_sequence.
    let outcome = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0").unwrap();
    assert!(
        matches!(outcome, IdentityCheckOutcome::Failed { .. }),
        "expected the deliberate test failure to surface"
    );

    let log = Command::new("git")
        .args(["log", "--format=%s"])
        .current_dir(fx.root())
        .output()
        .unwrap();
    let messages = String::from_utf8_lossy(&log.stdout);
    assert!(
        messages.contains("widget"),
        "the VENDORING.md/go.mod commits must already be on HEAD despite the identity-check failure: {messages}"
    );

    let go_mod = std::fs::read_to_string(fx.ex_ray_dir().join("go.mod")).unwrap();
    assert!(
        go_mod.contains("v1.1.0"),
        "go.mod should still be bumped even though the identity check failed: {go_mod}"
    );
}

/// `run_identity_checks` runs its scoped test unconditionally against
/// `crates/ex-ray/third_party/v2ray-core` specifically — matching
/// build.yaml's `ex-ray-tests` target, which names that path regardless
/// of which dep a bump touches (see that function's doc comment). All
/// four scoped directories are created here (not just `tls`): `go test`
/// against a mix of existing and nonexistent package patterns fails on
/// the missing ones regardless of whether the present package's own
/// tests pass — creating only one directory would make this test's
/// assertion pass for the wrong reason (a "no such directory" artifact,
/// not the deliberate failure actually being detected).
#[skuld::test]
fn identity_check_runs_the_scoped_v2ray_core_test() {
    let dir = tempfile::tempdir().unwrap();
    let v2ray_core = dir.path().join("crates/ex-ray/third_party/v2ray-core");
    let ex_ray = dir.path().join("crates/ex-ray");
    std::fs::create_dir_all(&v2ray_core).unwrap();
    std::fs::create_dir_all(&ex_ray).unwrap();
    std::fs::write(ex_ray.join("go.mod"), "module example.com/ex-ray\n\ngo 1.25\n").unwrap();
    std::fs::write(ex_ray.join("main.go"), "package main\n\nfunc main() {}\n").unwrap();

    std::fs::write(v2ray_core.join("go.mod"), "module example.com/v2ray-core\n\ngo 1.25\n").unwrap();
    for pkg in ["tls", "quic", "hysteria2", "transportcommon"] {
        let pkg_dir = v2ray_core.join("transport/internet").join(pkg);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join(format!("{pkg}.go")), format!("package {pkg}\n")).unwrap();
    }
    std::fs::write(
        v2ray_core.join("transport/internet/tls/tls_test.go"),
        "package tls\n\nimport \"testing\"\n\nfunc TestBroken(t *testing.T) { t.Fatal(\"deliberate failure\") }\n",
    )
    .unwrap();

    let outcome = finish_vendor_bump::run_identity_checks(dir.path()).unwrap();
    match outcome {
        IdentityCheckOutcome::Failed { detail } => {
            assert!(
                detail.contains("deliberate failure"),
                "the scoped v2ray-core test's own failure should surface, not a missing-directory artifact: {detail}"
            );
        }
        IdentityCheckOutcome::Passed => {
            panic!("expected the deliberately failing scoped test to be exercised and fail")
        }
    }
}

#[skuld::test]
fn identity_check_passes_when_all_scoped_v2ray_core_tests_pass() {
    let dir = tempfile::tempdir().unwrap();
    let v2ray_core = dir.path().join("crates/ex-ray/third_party/v2ray-core");
    let ex_ray = dir.path().join("crates/ex-ray");
    std::fs::create_dir_all(&v2ray_core).unwrap();
    std::fs::create_dir_all(&ex_ray).unwrap();
    std::fs::write(ex_ray.join("go.mod"), "module example.com/ex-ray\n\ngo 1.25\n").unwrap();
    std::fs::write(ex_ray.join("main.go"), "package main\n\nfunc main() {}\n").unwrap();

    std::fs::write(v2ray_core.join("go.mod"), "module example.com/v2ray-core\n\ngo 1.25\n").unwrap();
    for pkg in ["tls", "quic", "hysteria2", "transportcommon"] {
        let pkg_dir = v2ray_core.join("transport/internet").join(pkg);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join(format!("{pkg}.go")), format!("package {pkg}\n")).unwrap();
    }

    let outcome = finish_vendor_bump::run_identity_checks(dir.path()).unwrap();
    assert!(matches!(outcome, IdentityCheckOutcome::Passed));
}

#[skuld::test]
fn update_vendoring_note_fails_when_the_heading_is_missing() {
    let dir = init_repo_with_vendoring_md("widget", "v1.0.0");

    let result = finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "nonexistent-dep", "v2.0.0");

    let err = result.expect_err("a dep_name with no matching heading must fail, not silently no-op");
    assert!(
        format!("{err:#}").contains("nonexistent-dep"),
        "error should name the dep it couldn't find a heading for: {err:#}"
    );
}

#[skuld::test]
fn update_vendoring_note_fails_when_the_heading_is_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let vendoring_dir = dir.path().join("crates/ex-ray/third_party");
    std::fs::create_dir_all(&vendoring_dir).unwrap();
    // Heading present but missing the closing `**` around the version.
    std::fs::write(
        vendoring_dir.join("VENDORING.md"),
        "# Vendoring\n\n## `widget/` — pinned **v1.0.0 ([upstream](https://example.com))\n",
    )
    .unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-m", "initial"]);

    let result = finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0");

    let err = result.expect_err("a heading missing its closing `**` must fail, not silently corrupt the file");
    assert!(
        format!("{err:#}").contains("malformed"),
        "error should say the heading is malformed: {err:#}"
    );
}

/// A malformed heading's closing-`**` search must not run past the
/// heading's own line: the real VENDORING.md documents multiple deps,
/// each with its own bold-marked version further down the file — an
/// unbounded search would skip a malformed heading's missing `**` and
/// latch onto one of those instead, silently splicing out everything in
/// between and committing the corrupted result.
#[skuld::test]
fn update_vendoring_note_fails_when_the_heading_is_malformed_even_with_a_later_bold_marker() {
    let dir = tempfile::tempdir().unwrap();
    let vendoring_dir = dir.path().join("crates/ex-ray/third_party");
    std::fs::create_dir_all(&vendoring_dir).unwrap();
    std::fs::write(
        vendoring_dir.join("VENDORING.md"),
        "# Vendoring\n\n## `widget/` — pinned **v1.0.0 ([upstream](https://example.com))\n\nSome notes.\n\n## `other/` — pinned **v2.0.0** ([upstream](https://example.com))\n",
    )
    .unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-m", "initial"]);

    let before = std::fs::read_to_string(vendoring_dir.join("VENDORING.md")).unwrap();

    let result = finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v9.9.9");

    let err = result.expect_err("a malformed heading must fail even when a later line has its own `**`");
    assert!(
        format!("{err:#}").contains("malformed"),
        "error should say the heading is malformed: {err:#}"
    );
    let after = std::fs::read_to_string(vendoring_dir.join("VENDORING.md")).unwrap();
    assert_eq!(
        after, before,
        "VENDORING.md must be left untouched, not partially corrupted"
    );
}

/// The block-form `require ( ... )` shape — what the real
/// `crates/ex-ray/go.mod` actually uses, since it has several
/// requirements — with an unrelated require line in the same block,
/// proving the bump touches only the target entry.
#[skuld::test]
fn run_bumps_the_target_line_in_a_block_form_require_and_preserves_the_rest() {
    // `other` is a second, real, locally-replaced module so `go mod tidy`
    // has a reason to keep it — an unresolvable/unimported "unrelated"
    // entry would just be pruned as unused, defeating the point of this
    // test.
    let fx = FixtureBuilder::default()
        .extra_dep("other", "module example.com/other\n\ngo 1.25\n", "package other\n")
        .ex_ray_go_mod(
            "module example.com/ex-ray\n\ngo 1.25\n\nrequire (\n\texample.com/other v1.9.0\n\t\
             example.com/widget v1.0.0\n)\n\nreplace example.com/other => ./third_party/other\n\n\
             replace example.com/widget => ./third_party/widget\n",
        )
        .ex_ray_main_go(
            "package main\n\nimport (\n\t_ \"example.com/other\"\n\t_ \"example.com/widget\"\n)\n\nfunc main() {}\n",
        )
        .v2ray_core_stub()
        .build();

    let outcome = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0").unwrap();
    assert!(matches!(outcome, IdentityCheckOutcome::Passed));

    let go_mod = std::fs::read_to_string(fx.ex_ray_dir().join("go.mod")).unwrap();
    assert!(
        go_mod.contains("example.com/widget v1.1.0"),
        "target line should be bumped: {go_mod}"
    );
    assert!(
        go_mod.contains("example.com/other v1.9.0"),
        "the unrelated require line must survive untouched: {go_mod}"
    );
}

/// `go mod edit -require` upserts: a `subdir` that doesn't correspond to
/// any module already required by `crates/ex-ray/go.mod` (e.g. a typo)
/// must not silently gain a brand-new require line for the wrong tag.
#[skuld::test]
fn run_refuses_when_the_module_has_no_existing_require_line() {
    // No require line for example.com/widget at all.
    let fx = FixtureBuilder::default()
        .ex_ray_go_mod("module example.com/ex-ray\n\ngo 1.25\n")
        .ex_ray_main_go("package main\n\nfunc main() {}\n")
        .build();

    let result = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0");
    let err = result.expect_err("a module with no existing require line must refuse, not silently add one");
    assert!(
        format!("{err:#}").contains("no require line"),
        "error should explain there's nothing to bump: {err:#}"
    );

    let go_mod = std::fs::read_to_string(fx.ex_ray_dir().join("go.mod")).unwrap();
    assert!(
        !go_mod.contains("example.com/widget"),
        "go.mod must not gain a new require line: {go_mod}"
    );
}

/// `run_identity_checks`'s two `go test` invocations must match
/// `build.yaml`'s `ex-ray-tests` target's `run:` steps exactly (this
/// module's own reason for existing that way). Parses the REAL repo's
/// build.yaml, not a fixture, so a future edit to that target fails this
/// test loudly instead of drifting silently — the same drift-guard
/// pattern `ci_nextest_parity_tests.rs`/`ci_timeouts_tests.rs` already
/// establish in this codebase.
#[skuld::test]
fn identity_checks_match_the_real_build_yaml_ex_ray_tests_target() {
    let root = crate::repo_root().expect("repo root");
    let manifest =
        crate::manifest::Manifest::parse(&std::fs::read_to_string(root.join("build.yaml")).expect("read build.yaml"))
            .expect("parse build.yaml");
    let target = manifest
        .get("ex-ray-tests")
        .expect("build.yaml has an ex-ray-tests target");

    let commands: Vec<&str> = target
        .run
        .iter()
        .map(|step| match step {
            crate::manifest::Step::Bash { command, .. } => command.as_str(),
            crate::manifest::Step::Process { .. } => {
                panic!("ex-ray-tests run steps are expected to be bash, not process")
            }
        })
        .collect();

    assert_eq!(
        commands,
        vec![
            "cd crates/ex-ray && go test ./...",
            "cd crates/ex-ray/third_party/v2ray-core && go test ./transport/internet/tls/... \
             ./transport/internet/quic/... ./transport/internet/hysteria2/... \
             ./transport/internet/transportcommon/...",
        ],
        "build.yaml's ex-ray-tests target has drifted from what run_identity_checks hardcodes — \
         update finish_vendor_bump.rs to match"
    );
}

#[skuld::test]
fn run_refuses_when_gitrepo_has_no_branch_line() {
    // Present but malformed: no `branch = ` line at all. No require line in
    // ex-ray's go.mod either — this refusal must fire before that would
    // otherwise matter.
    let fx = FixtureBuilder::default()
        .dep_gitrepo(
            "[subrepo]\n\tremote = https://example.com/widget\n\tcommit = 0000000000000000000000000000000000000000\n",
        )
        .ex_ray_go_mod("module example.com/ex-ray\n\ngo 1.25\n")
        .ex_ray_main_go("package main\n\nfunc main() {}\n")
        .build();

    let result = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0");
    let err = result.expect_err("a .gitrepo with no branch line must refuse the run");
    assert!(
        format!("{err:#}").contains("no `branch = ` line"),
        "error should name the missing field: {err:#}"
    );
}

#[skuld::test]
fn run_fails_with_a_clear_message_when_the_vendored_go_mod_has_no_module_line() {
    // No `module` line at all in the vendored dep's own go.mod.
    let fx = FixtureBuilder::default()
        .dep_go_mod("go 1.25\n")
        .ex_ray_go_mod("module example.com/ex-ray\n\ngo 1.25\n")
        .ex_ray_main_go("package main\n\nfunc main() {}\n")
        .build();

    let result = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0");
    let err = result.expect_err("a vendored go.mod with no module line must fail clearly");
    assert!(
        format!("{err:#}").contains("no `module` line"),
        "error should name the missing field: {err:#}"
    );
}

/// `dep_name` and `subdir` are two independent arguments only because
/// `vendor-bump.yaml` (and a human running this by hand) always computes
/// both from the same `<name>` — a copy-paste mismatch between them (e.g.
/// `finish-vendor-bump crates/ex-ray/third_party/utls v2ray-core v1.9.0`)
/// must be refused before anything is written, not silently accepted as
/// "bump utls's go.mod entry, but document it under v2ray-core's
/// VENDORING.md heading."
#[skuld::test]
fn run_refuses_when_dep_name_does_not_match_subdirs_final_component() {
    let dir = tempfile::tempdir().unwrap();
    let vendored = dir.path().join("crates/ex-ray/third_party/widget");
    let vendoring_dir = dir.path().join("crates/ex-ray/third_party");
    std::fs::create_dir_all(&vendored).unwrap();
    std::fs::create_dir_all(dir.path().join("crates/ex-ray")).unwrap();

    std::fs::write(
        vendoring_dir.join("VENDORING.md"),
        "# Vendoring\n\n## `widget/` — pinned **v1.0.0** ([upstream](https://example.com))\n\n## `other/` — pinned **v1.0.0** ([upstream](https://example.com))\n",
    )
    .unwrap();

    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-m", "initial"]);

    // subdir's final component is "widget", but dep_name names "other".
    let result = finish_vendor_bump::run(dir.path(), "crates/ex-ray/third_party/widget", "other", "v1.1.0");
    let err = result.expect_err("a dep_name/subdir mismatch must refuse the run");
    assert!(
        format!("{err:#}").contains("widget") && format!("{err:#}").contains("other"),
        "error should name both the given dep_name and subdir's actual final component: {err:#}"
    );

    let note = std::fs::read_to_string(vendoring_dir.join("VENDORING.md")).unwrap();
    assert!(
        note.contains("`other/` — pinned **v1.0.0**"),
        "VENDORING.md must not be touched before the cross-check: {note}"
    );
}

/// A human who resolves a `pull-subrepo` conflict by hand and skips the
/// documented `.gitrepo` `branch` fixup (see `pull-subrepo`'s own conflict
/// message) must not get a silently wrong VENDORING.md/go.mod commit —
/// nothing in the identity check inspects a version string.
#[skuld::test]
fn run_refuses_when_gitrepo_branch_does_not_match_new_tag() {
    // .gitrepo still records the OLD tag — the exact state a human leaves
    // behind by skipping the documented manual fixup after resolving a
    // conflict by hand.
    let fx = FixtureBuilder::default()
        .dep_gitrepo(
            "[subrepo]\n\tremote = https://example.com/widget\n\tbranch = v1.0.0\n\t\
             commit = 0000000000000000000000000000000000000000\n\t\
             parent = 0000000000000000000000000000000000000000\n\tmethod = merge\n\tcmdver = 0.4.9\n",
        )
        .build();

    let result = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0");
    let err = result.expect_err("a mismatched .gitrepo branch must refuse the run");
    assert!(
        format!("{err:#}").contains("v1.0.0") && format!("{err:#}").contains("v1.1.0"),
        "error should name both the recorded and the requested tag: {err:#}"
    );

    let note = std::fs::read_to_string(fx.vendoring_dir().join("VENDORING.md")).unwrap();
    assert!(
        note.contains("pinned **v1.0.0**"),
        "VENDORING.md must not be touched before the .gitrepo cross-check: {note}"
    );
}

/// `go mod tidy` can raise a require above what was just written — e.g. a
/// replaced sibling module's own go.mod requiring the same dependency at a
/// higher version (mirrors the real utls/v2ray-core shape: ex-ray's go.mod
/// requires utls indirectly, while v2ray-core's own go.mod requires it
/// directly). Confirmed empirically against the real toolchain: rewriting
/// a direct require down while a replaced dependency's go.mod still
/// demands higher makes `go mod tidy` silently pick the higher one. This
/// must surface as an error, not a silently-wrong commit.
#[skuld::test]
fn run_bails_when_go_mod_tidy_raises_the_version_above_what_was_requested() {
    // `mid` requires widget at v1.5.0 directly — higher than the v1.2.0
    // bump attempted below. No `v2ray_core_stub()`: this bail happens
    // inside `run_go_mod_tidy_and_commit`, before `run_identity_checks`
    // ever runs.
    let fx = FixtureBuilder::default()
        .extra_dep(
            "mid",
            "module example.com/mid\n\ngo 1.25\n\nrequire example.com/widget v1.5.0\n\n\
             replace example.com/widget => ../widget\n",
            "package mid\n\nimport _ \"example.com/widget\"\n",
        )
        .ex_ray_go_mod(
            "module example.com/ex-ray\n\ngo 1.25\n\nrequire (\n\texample.com/mid v1.0.0\n\t\
             example.com/widget v1.0.0\n)\n\nreplace example.com/widget => ./third_party/widget\n\n\
             replace example.com/mid => ./third_party/mid\n",
        )
        .ex_ray_main_go(
            "package main\n\nimport (\n\t_ \"example.com/mid\"\n\t_ \"example.com/widget\"\n)\n\nfunc main() {}\n",
        )
        .build();

    let result = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.2.0");
    let err = result.expect_err("go mod tidy raising the version above v1.2.0 must surface as an error");
    let message = format!("{err:#}");
    assert!(
        message.contains("v1.2.0") && message.contains("v1.5.0"),
        "error should name both the requested and the graph-forced version: {message}"
    );
    assert!(
        message.contains("reset --hard"),
        "this bail happens inside run_go_mod_tidy_and_commit, so it must carry the same landed- \
         VENDORING.md-commit disclosure as the go-mod-tidy-command-failure case: {message}"
    );

    let go_mod = std::fs::read_to_string(fx.ex_ray_dir().join("go.mod")).unwrap();
    assert!(
        go_mod.contains("v1.5.0"),
        "go.mod is left showing what `go mod tidy` actually produced, for inspection: {go_mod}"
    );
}

/// A require line whose module isn't actually imported by any Go source
/// gets pruned entirely by `go mod tidy` (confirmed empirically) — the
/// resulting "no longer required" state must surface as an error, not a
/// silently-empty commit, and must carry the same landed-commit
/// disclosure as every other failure inside `run_go_mod_tidy_and_commit`.
#[skuld::test]
fn run_bails_when_go_mod_tidy_prunes_the_require_line_as_unused() {
    // Deliberately does NOT import widget — `go mod tidy` prunes the
    // require line entirely as unused.
    let fx = FixtureBuilder::default()
        .ex_ray_main_go("package main\n\nfunc main() {}\n")
        .v2ray_core_stub()
        .build();

    let result = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0");
    let err = result.expect_err("a pruned require line must surface as an error, not an empty commit");
    let message = format!("{err:#}");
    assert!(
        message.contains("no longer required"),
        "error should explain the require line vanished: {message}"
    );
    assert!(
        message.contains("reset --hard"),
        "the already-landed VENDORING.md commit must still be disclosed: {message}"
    );

    // The `replace` directive itself survives (Go doesn't remove a
    // human-authored replace just because nothing requires it anymore) —
    // only the `require` line vanishes, so check for that specifically
    // rather than any mention of the module path.
    let go_mod = std::fs::read_to_string(fx.ex_ray_dir().join("go.mod")).unwrap();
    assert!(
        !go_mod.contains("require"),
        "go.mod's require line should be pruned, left for inspection: {go_mod}"
    );
}

/// A `go.sum` tracked in git but missing from disk (its checksums no
/// longer needed) must have that deletion staged and committed, not
/// silently left dangling. A naive on-disk-`.exists()`-only check would
/// skip it entirely (confirmed empirically: `git add` on such a path
/// succeeds and stages the deletion; only a path absent from BOTH disk and
/// the index is a hard `git add` error).
#[skuld::test]
fn a_tracked_go_sum_deleted_from_disk_has_its_deletion_committed() {
    // A go.sum tracked from an earlier vendoring state — its content
    // doesn't matter here, nothing in this path parses it.
    let fx = FixtureBuilder::default()
        .go_sum("stale checksum line\n")
        .v2ray_core_stub()
        .build();

    // Deleted from disk without telling git — matches a `go.sum` whose
    // checksums this bump no longer needs, however it came to vanish.
    std::fs::remove_file(fx.ex_ray_dir().join("go.sum")).unwrap();

    finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0").unwrap();

    let tracked = Command::new("git")
        .args(["ls-files", "--", "crates/ex-ray/go.sum"])
        .current_dir(fx.root())
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&tracked.stdout).trim().is_empty(),
        "the go.sum deletion must be committed, not left dangling untracked"
    );
    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(fx.root())
        .output()
        .unwrap();
    let status_str = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_str.trim().is_empty(),
        "nothing should be left uncommitted: {status_str}"
    );
}

/// When `go mod tidy` itself fails, the VENDORING.md version-note commit
/// (an earlier, independent step) has already landed on the branch — that
/// must be disclosed, not left a silent side effect (matches
/// `pull_subrepo`'s own disclosure convention after an irreversible
/// commit). go.mod's rewritten require line must also be restored to its
/// original content rather than left half-applied and uncommitted.
#[skuld::test]
fn run_discloses_the_landed_vendoring_commit_when_go_mod_tidy_itself_fails() {
    // The `replace` target doesn't exist — `go mod tidy` fails
    // deterministically and offline, regardless of the require-line
    // rewrite succeeding.
    let fx = FixtureBuilder::default()
        .ex_ray_go_mod(
            "module example.com/ex-ray\n\ngo 1.25\n\nrequire example.com/widget v1.0.0\n\n\
             replace example.com/widget => ./third_party/does-not-exist\n",
        )
        .build();

    let result = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0");
    let err = result.expect_err("a nonexistent replace target must fail go mod tidy");
    let message = format!("{err:#}");
    assert!(
        message.contains("go mod tidy"),
        "the underlying go mod tidy failure must still be visible: {message}"
    );
    assert!(
        message.contains("reset --hard"),
        "the already-landed VENDORING.md commit must be disclosed, not left a silent side effect: {message}"
    );

    let log = Command::new("git")
        .args(["log", "-1", "--format=%s"])
        .current_dir(fx.root())
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&log.stdout).contains("widget"),
        "the VENDORING.md commit must actually be on HEAD, matching what the disclosure claims"
    );

    let go_mod = std::fs::read_to_string(fx.ex_ray_dir().join("go.mod")).unwrap();
    assert!(
        go_mod.contains("v1.0.0") && !go_mod.contains("v1.1.0"),
        "go.mod should be restored to its pre-rewrite state after go mod tidy fails: {go_mod}"
    );
}

/// If `go mod tidy` fails AND the subsequent restore write also fails
/// (e.g. a read-only `go.sum`), that restore failure must be folded into
/// the returned error, not silently dropped. A read-only `go.sum` (not
/// go.mod, which `go mod edit`/`go mod tidy` themselves need to write —
/// making it read-only would fail earlier, before this specific branch)
/// exercises exactly the restore step without disturbing the rest of the
/// sequence.
#[skuld::test]
fn run_folds_a_restore_failure_into_the_returned_error() {
    // The `replace` target doesn't exist — `go mod tidy` fails
    // deterministically and offline (see the sibling disclosure test).
    let fx = FixtureBuilder::default()
        .ex_ray_go_mod(
            "module example.com/ex-ray\n\ngo 1.25\n\nrequire example.com/widget v1.0.0\n\n\
             replace example.com/widget => ./third_party/does-not-exist\n",
        )
        .go_sum("stale checksum line\n")
        .build();
    let go_sum = fx.ex_ray_dir().join("go.sum");

    // Made read-only only now, after the fixture's own commit (which just
    // reads the file — read-only doesn't block that). The original
    // permissions are kept so cleanup below restores the exact prior mode
    // rather than blanket-clearing to world-writable (`set_readonly(false)`
    // on Unix sets 0o666, which clippy's `permissions_set_readonly_false`
    // lint flags for exactly this reason).
    let original_perms = std::fs::metadata(&go_sum).unwrap().permissions();
    let mut readonly_perms = original_perms.clone();
    readonly_perms.set_readonly(true);
    std::fs::set_permissions(&go_sum, readonly_perms).unwrap();

    let result = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0");

    // Restore writability before any assertion can early-return via
    // `assert!` panicking, so `TempDir`'s teardown can still delete it.
    std::fs::set_permissions(&go_sum, original_perms).unwrap();

    let err = result.expect_err("a nonexistent replace target must fail go mod tidy");
    let message = format!("{err:#}");
    assert!(
        message.contains("also failed to restore the original state"),
        "the restore failure must be folded into the returned error, not silently dropped: {message}"
    );
    assert!(
        message.contains("go.sum"),
        "the error should name the file that failed to restore: {message}"
    );
}

// The unresolved-conflict sentinel ====================================================================================

fn git_hash_object(cwd: &Path, rel_path: &str) -> String {
    let output = Command::new("git")
        .args(["hash-object", rel_path])
        .current_dir(cwd)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git hash-object {rel_path} failed in {}",
        cwd.display()
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

#[skuld::test]
fn run_clears_the_sentinel_when_every_listed_path_was_genuinely_touched() {
    let fx = FixtureBuilder::default().v2ray_core_stub().build();
    let widget_dir = fx.vendoring_dir().join("widget");

    std::fs::write(widget_dir.join("patched.go"), "package widget\n\n// original\n").unwrap();
    git(fx.root(), &["add", "-A"]);
    git(fx.root(), &["commit", "-m", "conflicted commit (simulated)"]);
    let recorded_hash = git_hash_object(&widget_dir, "patched.go");
    std::fs::write(
        widget_dir.join(".vendor-conflict"),
        format!("patched.go\t{recorded_hash}\n"),
    )
    .unwrap();
    git(fx.root(), &["add", "-A"]);
    git(fx.root(), &["commit", "-m", "add sentinel (simulated force-commit)"]);

    // The human resolves the conflict for real.
    std::fs::write(widget_dir.join("patched.go"), "package widget\n\n// resolved by hand\n").unwrap();
    git(fx.root(), &["add", "-A"]);
    git(fx.root(), &["commit", "-m", "patch: resolve conflict by hand"]);

    let outcome = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0").unwrap();
    assert!(matches!(outcome, IdentityCheckOutcome::Passed), "{outcome:?}");

    assert!(
        !widget_dir.join(".vendor-conflict").exists(),
        "the sentinel should be removed from disk"
    );
    let tracked = Command::new("git")
        .args(["ls-files", "crates/ex-ray/third_party/widget/.vendor-conflict"])
        .current_dir(fx.root())
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&tracked.stdout).trim().is_empty(),
        "the sentinel's removal should be committed, not merely deleted on disk"
    );
}

#[skuld::test]
fn run_refuses_to_clear_the_sentinel_when_a_listed_path_is_unchanged() {
    let fx = FixtureBuilder::default().v2ray_core_stub().build();
    let widget_dir = fx.vendoring_dir().join("widget");

    std::fs::write(
        widget_dir.join("patched.go"),
        "package widget\n\n// original, silently kept\n",
    )
    .unwrap();
    git(fx.root(), &["add", "-A"]);
    git(fx.root(), &["commit", "-m", "conflicted commit (simulated)"]);
    let recorded_hash = git_hash_object(&widget_dir, "patched.go");
    std::fs::write(
        widget_dir.join(".vendor-conflict"),
        format!("patched.go\t{recorded_hash}\n"),
    )
    .unwrap();
    git(fx.root(), &["add", "-A"]);
    git(fx.root(), &["commit", "-m", "add sentinel (simulated force-commit)"]);

    // No further edit to patched.go — the human never actually touched it.
    let err = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0")
        .expect_err("must refuse to clear the sentinel when a listed path is unchanged");
    let message = format!("{err:#}");
    assert!(
        message.contains("patched.go"),
        "the specific unchanged path must be named: {message}"
    );

    assert!(
        widget_dir.join(".vendor-conflict").exists(),
        "the sentinel must not be removed"
    );
    // Confirms no sentinel-clearing commit was made — the earlier steps
    // (VENDORING.md note, go.mod bump) DID land, per this module's own
    // "commit each step's own changes" contract, so HEAD moved from the
    // sentinel-add commit, but no *further* commit removed the sentinel.
    let log = Command::new("git")
        .args(["log", "--format=%s"])
        .current_dir(fx.root())
        .output()
        .unwrap();
    let subjects = String::from_utf8_lossy(&log.stdout);
    assert!(
        !subjects.contains("clear vendor-conflict sentinel"),
        "no sentinel-clearing commit should exist: {subjects}"
    );
}

#[skuld::test]
fn run_treats_recorded_deleted_vs_still_absent_path_as_unchanged_still_flagged() {
    // A delete/modify conflict resolved (or force-committed) with "theirs"
    // recorded as `<deleted>` — if the human never touches the path (it's
    // still absent), that must still count as unchanged, not a free pass.
    let fx = FixtureBuilder::default().v2ray_core_stub().build();
    let widget_dir = fx.vendoring_dir().join("widget");

    std::fs::write(widget_dir.join(".vendor-conflict"), "gone.go\t<deleted>\n").unwrap();
    git(fx.root(), &["add", "-A"]);
    git(
        fx.root(),
        &["commit", "-m", "add sentinel recording a deleted path (simulated)"],
    );

    let err = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0")
        .expect_err("recorded <deleted> vs. still-absent must count as unchanged");
    assert!(format!("{err:#}").contains("gone.go"), "{err:#}");
    assert!(
        widget_dir.join(".vendor-conflict").exists(),
        "the sentinel must not be removed"
    );
}

#[skuld::test]
fn run_treats_recorded_real_hash_vs_now_absent_path_as_changed_cleared() {
    // The reverse delete-direction: the human's genuine resolution was to
    // delete a path that had real content recorded — that's a valid
    // resolution (e.g. "theirs" wins a delete/modify conflict) and must
    // count as changed, clearing the sentinel.
    let fx = FixtureBuilder::default().v2ray_core_stub().build();
    let widget_dir = fx.vendoring_dir().join("widget");

    std::fs::write(widget_dir.join("patched.go"), "package widget\n\n// will be deleted\n").unwrap();
    git(fx.root(), &["add", "-A"]);
    git(fx.root(), &["commit", "-m", "conflicted commit (simulated)"]);
    let recorded_hash = git_hash_object(&widget_dir, "patched.go");
    std::fs::write(
        widget_dir.join(".vendor-conflict"),
        format!("patched.go\t{recorded_hash}\n"),
    )
    .unwrap();
    git(fx.root(), &["add", "-A"]);
    git(fx.root(), &["commit", "-m", "add sentinel (simulated force-commit)"]);

    // The human's real resolution: delete the path outright.
    git(fx.root(), &["rm", "crates/ex-ray/third_party/widget/patched.go"]);
    git(fx.root(), &["commit", "-m", "patch: resolve by deleting patched.go"]);

    let outcome = finish_vendor_bump::run(fx.root(), "crates/ex-ray/third_party/widget", "widget", "v1.1.0").unwrap();
    assert!(matches!(outcome, IdentityCheckOutcome::Passed), "{outcome:?}");
    assert!(
        !widget_dir.join(".vendor-conflict").exists(),
        "the sentinel should be cleared"
    );
}
