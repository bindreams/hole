//! Unit tests for the per-leg step evaluator plus the structural conformance
//! tests that hold the unified `ci` job to its documented shape: which steps
//! each platform runs, and the order constraints that keep the lanes from
//! corrupting one another.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use crate::ci_platform_coverage::{
    continue_on_error_declarations, legs, non_upload_steps_after, reaches_sidecar_rewrite, steps_after, steps_on,
    steps_on_after_failure, steps_over_wall, Leg,
};
use crate::manifest::Manifest;

fn leg<'a>(all: &'a [Leg], name: &str) -> &'a Leg {
    all.iter()
        .find(|l| l.name() == name)
        .unwrap_or_else(|| panic!("no leg {name}"))
}

const FIXTURE: &str = r"
jobs:
  ci:
    strategy:
      matrix:
        include:
          - { os: windows, arch: amd64, runner: w, hole: true, cache-saver: true }
          - { os: darwin,  arch: arm64, runner: m, hole: true }
          - { os: linux,   arch: amd64, runner: l }
    steps:
      - id: checkout
        uses: actions/checkout@v7
      - id: archive
        if: ${{ !cancelled() }}
        run: echo
      - id: test-archive
        if: ${{ !cancelled() && steps.archive.outcome == 'success' }}
        run: echo
      - id: hole-build
        if: ${{ !cancelled() && matrix.hole == true }}
        run: echo
      - id: hole-test
        if: ${{ !cancelled() && steps.hole-build.outcome == 'success' }}
        run: echo
      - id: clippy-other
        if: ${{ !cancelled() && matrix.hole != true }}
        run: echo
      - id: tun-windows
        if: ${{ !cancelled() && matrix.os == 'windows' && matrix.arch == 'amd64' }}
        run: echo
      - id: mac-or-failure
        if: ${{ matrix.hole == true && (matrix.os == 'darwin' || failure() || cancelled()) }}
        uses: actions/upload-artifact@v7
      - id: only-on-failure
        if: ${{ failure() }}
        run: echo
      - id: cleanup
        if: ${{ always() && matrix.hole == true }}
        run: echo
";

#[skuld::test]
fn legs_are_the_matrix_include_entries() {
    let all = legs(FIXTURE, "ci").expect("legs");
    let names: Vec<String> = all.iter().map(Leg::name).collect();
    assert_eq!(names, vec!["windows/amd64", "darwin/arm64", "linux/amd64"]);
}

#[skuld::test]
fn a_step_without_if_runs_on_every_leg() {
    let all = legs(FIXTURE, "ci").unwrap();
    for l in &all {
        assert!(steps_on(l, FIXTURE, "ci").unwrap().contains("checkout"), "{}", l.name());
    }
}

#[skuld::test]
fn a_matrix_flag_gates_a_step_to_the_flagged_legs() {
    let all = legs(FIXTURE, "ci").unwrap();
    assert!(steps_on(leg(&all, "windows/amd64"), FIXTURE, "ci")
        .unwrap()
        .contains("hole-build"));
    assert!(!steps_on(leg(&all, "linux/amd64"), FIXTURE, "ci")
        .unwrap()
        .contains("hole-build"));
}

/// An unset flag compares unequal to `true`, so `!= true` selects the legs
/// that never set it.
#[skuld::test]
fn inequality_against_an_unset_flag_selects_the_unflagged_legs() {
    let all = legs(FIXTURE, "ci").unwrap();
    assert!(steps_on(leg(&all, "linux/amd64"), FIXTURE, "ci")
        .unwrap()
        .contains("clippy-other"));
    assert!(!steps_on(leg(&all, "darwin/arm64"), FIXTURE, "ci")
        .unwrap()
        .contains("clippy-other"));
}

/// A step that consumes another's outcome is on only where that step is.
#[skuld::test]
fn an_outcome_gate_follows_the_gated_step_on_the_same_leg() {
    let all = legs(FIXTURE, "ci").unwrap();
    assert!(steps_on(leg(&all, "windows/amd64"), FIXTURE, "ci")
        .unwrap()
        .contains("hole-test"));
    assert!(!steps_on(leg(&all, "linux/amd64"), FIXTURE, "ci")
        .unwrap()
        .contains("hole-test"));
    assert!(steps_on(leg(&all, "linux/amd64"), FIXTURE, "ci")
        .unwrap()
        .contains("test-archive"));
}

#[skuld::test]
fn os_and_arch_comparisons_conjoin() {
    let all = legs(FIXTURE, "ci").unwrap();
    assert!(steps_on(leg(&all, "windows/amd64"), FIXTURE, "ci")
        .unwrap()
        .contains("tun-windows"));
    assert!(!steps_on(leg(&all, "darwin/arm64"), FIXTURE, "ci")
        .unwrap()
        .contains("tun-windows"));
}

/// The evaluator models a healthy run: no step failed, nothing was cancelled.
#[skuld::test]
fn status_functions_are_evaluated_for_a_healthy_run() {
    let all = legs(FIXTURE, "ci").unwrap();
    let mac = steps_on(leg(&all, "darwin/arm64"), FIXTURE, "ci").unwrap();
    assert!(mac.contains("mac-or-failure"), "darwin uploads unconditionally");
    assert!(mac.contains("cleanup"), "always() is on");
    assert!(!mac.contains("only-on-failure"), "failure() is off in a healthy run");
    let win = steps_on(leg(&all, "windows/amd64"), FIXTURE, "ci").unwrap();
    assert!(!win.contains("mac-or-failure"), "non-darwin uploads only on failure");
}

#[skuld::test]
fn an_unsupported_expression_is_an_error_not_a_guess() {
    let ci = "
jobs:
  ci:
    strategy:
      matrix:
        include:
          - { os: linux, arch: amd64 }
    steps:
      - id: a
        if: contains(github.ref, 'main')
        run: echo
";
    let all = legs(ci, "ci").unwrap();
    let err = steps_on(&all[0], ci, "ci").unwrap_err();
    assert!(format!("{err:#}").contains("contains"), "unexpected error: {err:#}");
}

/// A one-step job whose probe step carries `condition`, on a two-leg matrix.
fn probe_job(condition: &str) -> String {
    format!(
        "
jobs:
  ci:
    strategy:
      matrix:
        include:
          - {{ os: windows, arch: amd64, name: Windows, flag: true, off: false }}
          - {{ os: linux, arch: amd64, name: Linux }}
    steps:
      - id: first
        run: echo
      - id: probe
        if: ${{{{ {condition} }}}}
        run: echo
      - id: later
        run: echo
"
    )
}

/// Does the probe step run on the first leg, or why not evaluable.
fn probe_runs(condition: &str) -> anyhow::Result<bool> {
    let ci = probe_job(condition);
    let all = legs(&ci, "ci")?;
    Ok(steps_on(&all[0], &ci, "ci")?.contains("probe"))
}

fn probe_error(condition: &str) -> String {
    format!("{:#}", probe_runs(condition).expect_err(condition))
}

/// A `matrix.<key>` that no include entry defines is a typo, not a flag a leg
/// happens to lack: it must not quietly evaluate to a truth value.
#[skuld::test]
fn a_matrix_key_no_leg_defines_is_an_error() {
    let err = probe_error("matrix.hloe == true");
    assert!(err.contains("hloe"), "unexpected error: {err}");
    let err = probe_error("matrix.hloe != true");
    assert!(err.contains("hloe"), "unexpected error: {err}");
    // Defined on one leg only: the other leg lacks it, which is normal.
    assert!(probe_runs("matrix.flag == true").unwrap());
    let ci = probe_job("matrix.flag == true");
    let all = legs(&ci, "ci").unwrap();
    assert!(!steps_on(&all[1], &ci, "ci").unwrap().contains("probe"));
}

#[skuld::test]
fn a_non_scalar_matrix_value_is_an_error() {
    let ci = "
jobs:
  ci:
    strategy:
      matrix:
        include:
          - { os: linux, arch: amd64, tags: [a, b] }
    steps:
      - id: probe
        if: matrix.tags == 'a'
        run: echo
";
    let all = legs(ci, "ci").unwrap();
    let err = format!("{:#}", steps_on(&all[0], ci, "ci").unwrap_err());
    assert!(err.contains("tags"), "unexpected error: {err}");
}

/// A leg without `os` or `arch` string values would be named "/" and sort with
/// every other such leg, so the matrix is rejected where it is read.
#[skuld::test]
fn a_leg_without_os_and_arch_strings_is_an_error() {
    for entry in ["{ arch: amd64 }", "{ os: linux }", "{ os: linux, arch: [amd64] }"] {
        let ci = format!(
            "
jobs:
  ci:
    strategy:
      matrix:
        include:
          - {entry}
    steps:
      - id: a
        run: echo
"
        );
        let err = format!("{:#}", legs(&ci, "ci").unwrap_err());
        assert!(
            err.contains("os") || err.contains("arch"),
            "{entry}: unexpected error: {err}"
        );
    }
}

// ===== expression evaluator ==========================================================================================

#[skuld::test]
fn a_forward_step_reference_is_an_error() {
    let err = probe_error("steps.later.outcome == 'success'");
    assert!(err.contains("later"), "unexpected error: {err}");
}

#[skuld::test]
fn each_malformed_expression_is_an_error_naming_the_problem() {
    for (condition, expected) in [
        ("matrix.flag matrix.flag", "trailing input"),
        ("matrix.name == 'Win", "unterminated string"),
        ("(matrix.flag", "missing `)`"),
        ("always(1)", "takes arguments"),
        ("steps.first.conclusion == 'success'", "only `steps.<id>.outcome`"),
        ("matrix.flag &&", "unexpected end"),
        ("matrix.flag & matrix.flag", "unsupported character"),
        ("github.ref == 'x'", "unsupported context reference"),
        ("hashFiles('x')", "takes arguments"),
        ("contains()", "contains"),
    ] {
        let err = probe_error(condition);
        assert!(err.contains(expected), "{condition}: expected {expected:?} in {err}");
    }
}

/// `&&` binds tighter than `||`: `true || false && false` is true. Left to
/// right it would be false.
#[skuld::test]
fn and_binds_tighter_than_or_without_parentheses() {
    assert!(probe_runs("matrix.flag == true || matrix.off == true && matrix.off == true").unwrap());
    assert!(!probe_runs("matrix.off == true && matrix.off == true || matrix.off == true").unwrap());
    assert!(probe_runs("matrix.off == true && matrix.off == true || matrix.flag == true").unwrap());
}

/// `!` binds tighter than `==`: `!'x' == 'false'` is `false == 'false'`, which
/// compares 0 with NaN and is false. Read as `!('x' == 'false')` it would be true.
#[skuld::test]
fn not_binds_tighter_than_equality() {
    assert!(!probe_runs("!'x' == 'false'").unwrap());
    assert!(probe_runs("!'x' == '0'").unwrap());
}

/// String equality ignores case, as GitHub's does.
#[skuld::test]
fn string_equality_ignores_case() {
    assert!(probe_runs("matrix.name == 'WINDOWS'").unwrap());
    assert!(probe_runs("'Windows' == 'windows'").unwrap());
    assert!(!probe_runs("matrix.name != 'windows'").unwrap());
}

#[skuld::test]
fn every_step_must_carry_an_id() {
    let ci = "
jobs:
  ci:
    strategy:
      matrix:
        include:
          - { os: linux, arch: amd64 }
    steps:
      - run: echo
";
    let all = legs(ci, "ci").unwrap();
    assert!(steps_on(&all[0], ci, "ci").is_err());
}

#[skuld::test]
fn steps_after_lists_the_later_steps_in_order() {
    assert_eq!(
        steps_after(FIXTURE, "ci", "hole-test").unwrap(),
        vec![
            "clippy-other",
            "tun-windows",
            "mac-or-failure",
            "only-on-failure",
            "cleanup"
        ]
    );
    assert!(steps_after(FIXTURE, "ci", "nope").is_err());
}

#[skuld::test]
fn continue_on_error_is_reported_unless_literally_false() {
    let ci = "
jobs:
  ci:
    steps:
      - id: a
        continue-on-error: true
        run: echo
      - id: b
        continue-on-error: false
        run: echo
      - id: c
        continue-on-error: ${{ matrix.experimental }}
        run: echo
      - id: d
        run: echo
";
    assert_eq!(continue_on_error_declarations(ci, "ci").unwrap(), vec!["a", "c"]);
}

/// A job-level `continue-on-error` lets every step fail while the job stays
/// green, so it counts like a step-level one, literal or fed by the matrix.
#[skuld::test]
fn a_job_level_continue_on_error_is_reported_unless_literally_false() {
    for (value, reported) in [
        ("true", true),
        ("${{ matrix.experimental }}", true),
        ("${{ matrix.os == 'linux' }}", true),
        ("false", false),
    ] {
        let ci = format!(
            "
jobs:
  ci:
    continue-on-error: {value}
    steps:
      - id: a
        run: echo
"
        );
        let got = continue_on_error_declarations(&ci, "ci").unwrap();
        assert_eq!(!got.is_empty(), reported, "job-level continue-on-error: {value}");
    }
    let none = "
jobs:
  ci:
    steps:
      - id: a
        run: echo
";
    assert!(continue_on_error_declarations(none, "ci").unwrap().is_empty());
}

// ===== failure scenarios =============================================================================================

const FAILURE_FIXTURE: &str = r"
jobs:
  ci:
    strategy:
      matrix:
        include:
          - { os: linux, arch: amd64, runner: l }
    steps:
      - id: a
        run: echo
      - id: b
        run: echo
      - id: after-implicit
        run: echo
      - id: after-not-cancelled
        if: ${{ !cancelled() }}
        run: echo
      - id: cleanup
        if: ${{ always() }}
        run: echo
      - id: on-failure
        if: ${{ failure() }}
        run: echo
      - id: gated-on-b
        if: ${{ !cancelled() && steps.b.outcome == 'success' }}
        run: echo
      - id: gated-on-not-skipped
        if: ${{ !cancelled() && steps.b.outcome != 'skipped' }}
        run: echo
      - id: explicit-success
        if: ${{ success() }}
        run: echo
";

fn ran_after_failure_of(id: &str) -> BTreeSet<String> {
    let all = legs(FAILURE_FIXTURE, "ci").unwrap();
    steps_on_after_failure(&all[0], FAILURE_FIXTURE, "ci", id).unwrap()
}

/// GitHub gives a step with no status function an implicit `success()`, so it
/// is skipped once an earlier step has failed; `!cancelled()` and `always()` are
/// status functions and run on.
#[skuld::test]
fn after_a_failure_only_steps_with_a_status_function_other_than_success_run() {
    let ran = ran_after_failure_of("b");
    assert!(ran.contains("a") && ran.contains("b"), "steps up to the failure ran");
    assert!(
        !ran.contains("after-implicit"),
        "implicit success() is false after a failure"
    );
    assert!(!ran.contains("explicit-success"));
    assert!(ran.contains("after-not-cancelled"));
    assert!(ran.contains("cleanup"));
    assert!(ran.contains("on-failure"), "failure() is true after a failure");
}

/// The failed step's own outcome is `failure`, which is what separates a gate
/// written `== 'success'` from one weakened to `!= 'skipped'`.
#[skuld::test]
fn the_failed_step_has_the_outcome_failure() {
    let ran = ran_after_failure_of("b");
    assert!(!ran.contains("gated-on-b"), "== 'success' no longer holds");
    assert!(
        ran.contains("gated-on-not-skipped"),
        "!= 'skipped' still holds for a failed step"
    );
}

#[skuld::test]
fn a_healthy_run_is_the_scenario_with_no_failure() {
    let all = legs(FAILURE_FIXTURE, "ci").unwrap();
    let ran = steps_on(&all[0], FAILURE_FIXTURE, "ci").unwrap();
    assert!(ran.contains("after-implicit") && ran.contains("explicit-success") && ran.contains("gated-on-b"));
    assert!(!ran.contains("on-failure"));
}

#[skuld::test]
fn a_failure_of_a_step_that_does_not_run_is_an_error() {
    let all = legs(FIXTURE, "ci").unwrap();
    // `hole-build` is gated on `matrix.hole`, which linux/amd64 does not set.
    let err = steps_on_after_failure(leg(&all, "linux/amd64"), FIXTURE, "ci", "hole-build").unwrap_err();
    assert!(format!("{err:#}").contains("hole-build"), "{err:#}");
}

// ===== what may run after a lane =====================================================================================

#[skuld::test]
fn only_artifact_uploads_may_follow_a_lane_without_being_reported() {
    let ci = "
jobs:
  ci:
    steps:
      - id: lane
        run: echo
      - id: upload
        uses: actions/upload-artifact@v7
      - id: script
        run: echo
      - id: toolchain-action
        uses: ./.github/actions/setup-build
      - id: other-action
        uses: actions/setup-node@v7
      - id: skipped-here
        run: echo
";
    let ran: BTreeSet<String> = ["lane", "upload", "script", "toolchain-action", "other-action"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        non_upload_steps_after(ci, "ci", "lane", &ran).unwrap(),
        vec!["script", "toolchain-action", "other-action"]
    );
}

// ===== budgets against the wall ======================================================================================

const WALL_FIXTURE: &str = r"
jobs:
  ci:
    timeout-minutes: ${{ matrix.timeout }}
    strategy:
      matrix:
        include:
          - { os: linux, arch: amd64, runner: l, timeout: 30 }
          - { os: linux, arch: arm64, runner: l, timeout: 60, big: true }
    steps:
      - id: small
        timeout-minutes: 10
        run: echo
      - id: big
        if: ${{ matrix.big == true }}
        timeout-minutes: 45
        run: echo
      - id: exact
        timeout-minutes: 30
        run: echo
";

#[skuld::test]
fn a_step_budget_above_the_wall_of_a_leg_it_runs_on_is_reported() {
    // Switch the 45-minute step on for the 30-minute leg.
    let ci = WALL_FIXTURE.replace(
        "{ os: linux, arch: amd64, runner: l, timeout: 30 }",
        "{ os: linux, arch: amd64, runner: l, timeout: 30, big: true }",
    );
    let all = legs(&ci, "ci").unwrap();
    assert_eq!(
        steps_over_wall(&all[0], &ci, "ci").unwrap(),
        vec![("big".to_string(), 45)]
    );
}

/// A step that does not run on a leg is not held to that leg's wall, and a
/// budget equal to the wall is allowed (it can still fire first).
#[skuld::test]
fn a_step_off_the_leg_or_equal_to_the_wall_is_not_reported() {
    let all = legs(WALL_FIXTURE, "ci").unwrap();
    assert!(steps_over_wall(&all[0], WALL_FIXTURE, "ci").unwrap().is_empty());
    assert!(steps_over_wall(&all[1], WALL_FIXTURE, "ci").unwrap().is_empty());
}

#[skuld::test]
fn a_leg_without_a_literal_wall_is_an_error() {
    let ci = "
jobs:
  ci:
    strategy:
      matrix:
        include:
          - { os: linux, arch: amd64, runner: l }
    steps:
      - id: a
        timeout-minutes: 5
        run: echo
";
    let all = legs(ci, "ci").unwrap();
    assert!(steps_over_wall(&all[0], ci, "ci").is_err());
}

fn sidecar_manifest() -> Manifest {
    Manifest::parse(
        r#"
targets:
  ex-ray:
    platforms: [linux/amd64]
    build: cargo xtask ex-ray
  galoshes:
    depends: ex-ray
    platforms: [linux/amd64]
    build: cargo xtask galoshes
  tests:
    depends: galoshes
    platforms: [linux/amd64]
    build: cargo nextest run --no-run
  plain:
    platforms: [linux/amd64]
    build: cargo build
  wrapper:
    platforms: [linux/amd64]
    build: cargo xtask build tests
"#,
    )
    .expect("fixture manifest parses")
}

#[skuld::test]
fn a_cascade_through_galoshes_or_ex_ray_rewrites_the_sidecars() {
    let m = sidecar_manifest();
    for cmd in [
        "cargo xtask build tests",
        "cargo xtask run tests",
        "cargo xtask build wrapper",
        "cargo xtask galoshes",
        "cargo xtask ex-ray",
        "cargo xtask deps",
    ] {
        assert!(reaches_sidecar_rewrite(cmd, &m).unwrap(), "{cmd}");
    }
}

#[skuld::test]
fn commands_that_never_reach_the_sidecars_do_not_rewrite_them() {
    let m = sidecar_manifest();
    for cmd in [
        "cargo xtask build plain",
        "cargo xtask verify-skuld-label-coverage",
        "cargo nextest run -E 'package(a)'",
        "df -h .",
    ] {
        assert!(!reaches_sidecar_rewrite(cmd, &m).unwrap(), "{cmd}");
    }
}

// ===== conformance ===================================================================================================

fn read_repo(rel: &str) -> String {
    let root = crate::repo_root().expect("repo root");
    fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

const ALL_LEGS: [&str; 6] = [
    "windows/amd64",
    "windows/arm64",
    "darwin/amd64",
    "darwin/arm64",
    "linux/amd64",
    "linux/arm64",
];
const HOLE_LEGS: [&str; 3] = ["windows/amd64", "darwin/amd64", "darwin/arm64"];
const DARWIN: [&str; 2] = ["darwin/amd64", "darwin/arm64"];
const NON_HOLE_LEGS: [&str; 3] = ["windows/arm64", "linux/amd64", "linux/arm64"];

/// Step id → the legs it runs on in a healthy run. Written from the old-job →
/// new-step mapping table in the PR description, independently of ci.yaml, so a
/// matrix flag lost in an edit fails here instead of silently dropping a lane.
///
/// Failure-only steps (installer log dump and bridge-log upload, DMG
/// diagnostics) are off in a healthy run by construction and are listed in
/// `FAILURE_ONLY`.
fn golden() -> BTreeMap<&'static str, Vec<&'static str>> {
    let mut g: BTreeMap<&'static str, Vec<&'static str>> = BTreeMap::new();
    for id in [
        "checkout",
        "setup-python",
        "setup-uv",
        "setup-build",
        "cargo-binstall",
        "install-nextest",
        "install-prek",
        "provision",
        "lint-platform-dependent",
        "archive",
        "test-garter",
        "test-galoshes",
        "test-tooling",
        "test-plugin-e2e",
    ] {
        g.insert(id, ALL_LEGS.to_vec());
    }
    g.insert("install-bash", DARWIN.to_vec());
    // Platform-independent lint, frontend, ECH tests and the renovate check run once.
    for id in [
        "lint",
        "lint-release-scripts",
        "frontend-build",
        "frontend-check",
        "test-ex-ray-ech",
        "setup-node-lts",
        "renovate-config",
    ] {
        g.insert(id, vec!["linux/amd64"]);
    }
    g.insert("test-ex-ray-unit", vec!["windows/amd64", "darwin/arm64"]);
    g.insert("clippy-hole", HOLE_LEGS.to_vec());
    g.insert("doc-hole", HOLE_LEGS.to_vec());
    g.insert("clippy-ex-galoshes", NON_HOLE_LEGS.to_vec());
    g.insert("doc-ex-galoshes", NON_HOLE_LEGS.to_vec());
    for id in ["dmg-start", "dmg"] {
        g.insert(id, DARWIN.to_vec());
    }
    for id in [
        "installer-pytest",
        "installer-build-msi",
        "installer-smoke",
        "installer-tauri-driver",
        "installer-msedgedriver",
        "installer-gsudo",
        "installer-install",
        "installer-verify-install",
        "installer-kill-launch",
        "installer-verify-gsudo",
        "installer-e2e",
        "installer-kill",
        "installer-uninstall",
        "installer-verify-uninstall",
        "installer-upload-msi-logs",
        "hole-test-tun",
        "hole-verify-executed",
    ] {
        g.insert(id, vec!["windows/amd64"]);
    }
    for id in [
        "hole-build",
        "hole-verify-partition",
        "hole-verify-labels",
        "hole-verify-run-env",
        "hole-test-non-tun",
        "hole-build-state",
        "hole-verify-no-compile",
    ] {
        g.insert(id, HOLE_LEGS.to_vec());
    }
    g.insert("hole-test-tun-macos", DARWIN.to_vec());
    // Darwin uploads bridge logs unconditionally; elsewhere only on failure.
    g.insert("hole-upload-bridge-logs", DARWIN.to_vec());
    g
}

const FAILURE_ONLY: [&str; 4] = [
    "installer-dump-log",
    "installer-upload-bridge-logs",
    "dmg-diagnostics",
    "dmg-upload-diagnostics",
];

/// Every platform runs exactly the steps the mapping says, and no leg gained or
/// lost a lane. The matrix flags are the only thing selecting lanes, so one
/// deleted flag would otherwise be invisible: the job stays green.
#[skuld::test]
fn the_six_legs_run_exactly_the_documented_step_ids() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    let all = legs(&ci_yaml, "ci").expect("legs");
    assert_eq!(
        all.iter().map(Leg::name).collect::<BTreeSet<_>>(),
        ALL_LEGS.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>(),
        "the matrix must list exactly the six platforms"
    );

    let golden = golden();
    for l in &all {
        let want: BTreeSet<String> = golden
            .iter()
            .filter(|(_, on)| on.contains(&l.name().as_str()))
            .map(|(id, _)| id.to_string())
            .collect();
        let got = steps_on(l, &ci_yaml, "ci").expect("evaluate steps");
        assert_eq!(
            got.difference(&want).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "{}: steps that run but the mapping does not list",
            l.name()
        );
        assert_eq!(
            want.difference(&got).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "{}: lanes the mapping lists that no longer run",
            l.name()
        );
    }
}

/// The golden table and the job agree on the set of step ids, so a step added to
/// ci.yaml without a mapping row (or a typo in the table) cannot pass by being
/// absent from every leg.
#[skuld::test]
fn every_ci_step_is_either_in_the_mapping_or_failure_only() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    let all_ids: BTreeSet<String> = steps_after(&ci_yaml, "ci", "checkout")
        .expect("order")
        .into_iter()
        .chain(["checkout".to_string()])
        .collect();
    let known: BTreeSet<String> = golden()
        .keys()
        .map(|s| s.to_string())
        .chain(FAILURE_ONLY.iter().map(|s| s.to_string()))
        .collect();
    assert_eq!(
        all_ids.symmetric_difference(&known).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "ci.yaml step ids and the mapping table disagree"
    );
}

/// The step that compares the build state after the last lane. It runs a Python
/// script that reads `target/`; it writes nothing and runs no toolchain, so it
/// may follow lanes that must be last.
const READ_ONLY_CHECK: &str = "hole-verify-no-compile";

/// The exemption above is by id, so the step must stay what it is exempted as:
/// one comparison script, no cargo and no `sudo`.
#[skuld::test]
fn the_read_only_check_only_compares_the_build_state() {
    let run = step_runs(&read_repo(".github/workflows/ci.yaml"))
        .remove(READ_ONLY_CHECK)
        .expect("the read-only check step has a run:");
    assert!(run.contains("target-state.sh compare"), "{run}");
    for word in run.split(|c: char| !c.is_alphanumeric()) {
        assert!(
            !["cargo", "sudo", "rustc", "go", "npm", "npx"].contains(&word),
            "{word} in {run}"
        );
    }
}

/// #200: the Windows TUN lane corrupts NDIS loopback, so every loopback user
/// (compiles through sccache, tests, the installer E2E) runs before it. What may
/// follow on the Windows leg is the #999 proof step, a set diff over two files,
/// the build-state comparison (`hole-verify-no-compile`, which only reads
/// `target/`), and artifact uploads (`uses:` steps, no `run:`). A script step is not allowed
/// by default: the installer E2E drives WebDriver over loopback and invokes no
/// toolchain, so a toolchain-word check would not catch it.
#[skuld::test]
fn nothing_but_the_proof_step_and_uploads_follows_the_windows_tun_lane() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    let on_windows = steps_on_leg(&ci_yaml, "windows/amd64");
    let offenders: Vec<String> = non_upload_steps_after(&ci_yaml, "ci", "hole-test-tun", &on_windows)
        .expect("order")
        .into_iter()
        .filter(|id| id != "hole-verify-executed" && id != READ_ONLY_CHECK)
        .collect();
    assert!(
        offenders.is_empty(),
        "steps other than an artifact upload after the Windows TUN lane (#200): {offenders:?}"
    );
}

/// The macOS TUN lane runs as root and leaves root-owned files in `target/` that
/// no later unprivileged step could overwrite, so nothing but an artifact upload
/// follows it on a macOS leg — no script step, and no `uses:` step that runs a
/// toolchain (`./.github/actions/setup-build`, `setup-node`, ...). The one
/// exception is `hole-verify-no-compile`, which only reads `target/` and has to
/// follow the last lane to see what it did.
#[skuld::test]
fn the_macos_root_lane_is_the_last_script_step_on_macos() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    for name in ["darwin/amd64", "darwin/arm64"] {
        let ran = steps_on_leg(&ci_yaml, name);
        let offenders: Vec<String> = non_upload_steps_after(&ci_yaml, "ci", "hole-test-tun-macos", &ran)
            .expect("order")
            .into_iter()
            .filter(|id| id != READ_ONLY_CHECK)
            .collect();
        assert!(
            offenders.is_empty(),
            "{name}: steps other than an artifact upload after the macOS root lane: {offenders:?}"
        );
    }
}

/// `ex-ray` and `galoshes` binaries under `.cache/` are inputs of the `hole` and
/// `galoshes` build scripts (`rerun-if-changed`). A step that rewrites them
/// after `hole-build` makes the test lanes recompile `hole` — uncached and, on
/// macOS, as root. So every step that re-runs the sidecar cascade precedes it.
#[skuld::test]
fn nothing_between_hole_build_and_the_last_hole_lane_rewrites_the_sidecars() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    let manifest = Manifest::parse(&read_repo("build.yaml")).expect("parse build.yaml");
    let runs = step_runs(&ci_yaml);

    let after_build = steps_after(&ci_yaml, "ci", "hole-build").expect("order");
    let last_lane = after_build
        .iter()
        .rposition(|id| id.starts_with("hole-test-"))
        .expect("a hole test lane follows hole-build");
    let mut offenders = Vec::new();
    for id in &after_build[..=last_lane] {
        let Some(run) = runs.get(id.as_str()) else { continue };
        for cmd in crate::ci_coverage::split_commands(&crate::ci_coverage::join_line_continuations(run)) {
            if reaches_sidecar_rewrite(&cmd, &manifest).expect("resolve command") {
                offenders.push(format!("{id}: {cmd}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these steps rebuild ex-ray/galoshes after hole-build, so the hole lanes recompile: {offenders:?}"
    );

    // Guard the guard: the steps that must precede hole-build really do reach
    // the sidecars, so the detector is not vacuously passing.
    for id in ["installer-build-msi", "dmg"] {
        let run = runs.get(id).unwrap_or_else(|| panic!("no run for {id}"));
        let reaches = crate::ci_coverage::split_commands(&crate::ci_coverage::join_line_continuations(run))
            .iter()
            .any(|cmd| reaches_sidecar_rewrite(cmd, &manifest).unwrap());
        assert!(reaches, "{id} no longer resolves to a sidecar-rewriting cascade");
        assert!(!after_build.contains(&id.to_string()), "{id} must precede hole-build");
    }
}

/// "A test that can't fail CI is not protecting anyone from anything": no step
/// of the unified job may be allowed to fail without failing the job.
#[skuld::test]
fn no_step_of_the_ci_job_continues_on_error() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    assert_eq!(
        continue_on_error_declarations(&ci_yaml, "ci").unwrap(),
        Vec::<String>::new()
    );
}

fn steps_on_leg(ci_yaml: &str, name: &str) -> BTreeSet<String> {
    let all = legs(ci_yaml, "ci").expect("legs");
    steps_on(leg(&all, name), ci_yaml, "ci").expect("evaluate steps")
}

fn step_runs(ci_yaml: &str) -> BTreeMap<String, String> {
    crate::ci_platform_coverage::step_runs(ci_yaml, "ci").expect("step runs")
}

/// A step's own `timeout-minutes` can only fire if the job wall is not reached
/// first: when the wall fires instead, the lanes after it do not run. So no step that runs on a leg has a budget
/// above that leg's wall.
#[skuld::test]
fn no_step_budget_exceeds_the_wall_of_a_leg_it_runs_on() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    for l in legs(&ci_yaml, "ci").expect("legs") {
        assert_eq!(
            steps_over_wall(&l, &ci_yaml, "ci").expect("budgets"),
            Vec::<(String, u64)>::new(),
            "{}: steps whose own budget exceeds the job wall, so the wall fires first",
            l.name()
        );
    }
}

/// The longest `timeout-minutes` any pre-merge job allowed for the lanes that
/// run on the leg (owner, 2026-09-10: job walls are raised, never lowered). Read off
/// `origin/main` at b834d335 and independent of ci.yaml.
const WALL_FLOOR: [(&str, u64); 6] = [
    ("windows/amd64", 80),
    ("windows/arm64", 45),
    ("darwin/amd64", 150),
    ("darwin/arm64", 80),
    ("linux/amd64", 45),
    ("linux/arm64", 45),
];

#[skuld::test]
fn no_leg_wall_is_below_the_walls_of_the_jobs_it_absorbed() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    let all = legs(&ci_yaml, "ci").expect("legs");
    for (name, floor) in WALL_FLOOR {
        let wall = leg(&all, name)
            .wall()
            .unwrap_or_else(|| panic!("{name} has no literal timeout"));
        assert!(
            wall >= floor,
            "{name}: wall {wall} is below the {floor} minutes a previous job allowed"
        );
    }
}

// ===== failure paths =================================================================================================

fn ran_after_failure(leg_name: &str, failing: &str) -> BTreeSet<String> {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    let all = legs(&ci_yaml, "ci").expect("legs");
    steps_on_after_failure(leg(&all, leg_name), &ci_yaml, "ci", failing).expect("evaluate steps")
}

/// A failed installer E2E must still tear down: kill the app, uninstall, verify
/// the uninstall, and upload the logs. The TUN lane still runs, because one
/// failing lane hides nothing.
#[skuld::test]
fn a_failed_installer_e2e_still_cleans_up_and_leaves_the_other_lanes_running() {
    let ran = ran_after_failure("windows/amd64", "installer-e2e");
    for id in [
        "installer-kill",
        "installer-dump-log",
        "installer-uninstall",
        "installer-verify-uninstall",
        "installer-upload-msi-logs",
        "installer-upload-bridge-logs",
        "hole-test-tun",
    ] {
        assert!(ran.contains(id), "{id} must run after installer-e2e fails");
    }
}

/// The TUN lane shares the VM with the installer block. If the MSI's SYSTEM
/// service may still be installed (the uninstall verification failed), the lane
/// would run next to a live production bridge on the same WFP, route and adapter
/// state, so its verdicts would be confounded. A failure that leaves nothing
/// installed (the MSI never built, or the E2E failed and the uninstall verified
/// clean) does not stop it.
#[skuld::test]
fn the_tun_lane_does_not_run_beside_an_installation_that_may_remain() {
    assert!(
        !ran_after_failure("windows/amd64", "installer-verify-uninstall").contains("hole-test-tun"),
        "hole-test-tun ran although the uninstall verification failed"
    );
    for failing in ["installer-e2e", "installer-install", "installer-build-msi"] {
        assert!(
            ran_after_failure("windows/amd64", failing).contains("hole-test-tun"),
            "hole-test-tun must still run when only {failing} failed"
        );
    }
}

/// The #999 proof step reads both lanes' reports, which is only meaningful once
/// both passed: a failed lane leaves partial reports and is its own signal.
#[skuld::test]
fn the_proof_step_runs_only_when_both_lanes_passed() {
    for failing in ["hole-test-non-tun", "hole-test-tun"] {
        let ran = ran_after_failure("windows/amd64", failing);
        assert!(
            !ran.contains("hole-verify-executed"),
            "hole-verify-executed ran although {failing} failed"
        );
    }
    assert!(steps_on_leg(&read_repo(".github/workflows/ci.yaml"), "windows/amd64").contains("hole-verify-executed"));
}

#[skuld::test]
fn a_failed_non_tun_lane_does_not_hide_the_tun_lane() {
    assert!(ran_after_failure("windows/amd64", "hole-test-non-tun").contains("hole-test-tun"));
    for name in ["darwin/amd64", "darwin/arm64"] {
        assert!(
            ran_after_failure(name, "hole-test-non-tun").contains("hole-test-tun-macos"),
            "{name}"
        );
    }
}

#[skuld::test]
fn a_failed_dmg_still_captures_diagnostics_and_runs_the_hole_lanes() {
    for name in ["darwin/amd64", "darwin/arm64"] {
        let ran = ran_after_failure(name, "dmg");
        for id in [
            "dmg-diagnostics",
            "dmg-upload-diagnostics",
            "hole-build",
            "hole-test-non-tun",
        ] {
            assert!(ran.contains(id), "{name}: {id} must run after dmg fails");
        }
    }
}

/// Steps that are meant to run when something failed earlier: log dumps and
/// artifact uploads.
const RUNS_AFTER_A_FAILURE: [&str; 4] = [
    "installer-dump-log",
    "installer-upload-msi-logs",
    "installer-upload-bridge-logs",
    "hole-upload-bridge-logs",
];

/// Every later step requires `provision`, so a broken VM fails once instead of
/// once per lane: after it fails, only the evidence-collecting steps run.
#[skuld::test]
fn a_failed_provision_stops_every_lane() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    let after = steps_after(&ci_yaml, "ci", "provision").expect("order");
    for l in legs(&ci_yaml, "ci").expect("legs") {
        let ran = steps_on_after_failure(&l, &ci_yaml, "ci", "provision").expect("evaluate steps");
        let offenders: Vec<&String> = after
            .iter()
            .filter(|id| ran.contains(id.as_str()) && !RUNS_AFTER_A_FAILURE.contains(&id.as_str()))
            .collect();
        assert!(
            offenders.is_empty(),
            "{}: steps that run although provisioning failed: {offenders:?}",
            l.name()
        );
    }
}
