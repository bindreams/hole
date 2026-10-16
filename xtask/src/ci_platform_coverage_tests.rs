//! Unit tests for the per-leg step evaluator plus the structural conformance
//! tests that hold the unified `ci` job to its documented shape: which steps
//! each platform runs, and the order constraints that keep the lanes from
//! corrupting one another.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use crate::ci_platform_coverage::{
    legs, reaches_sidecar_rewrite, steps_after, steps_on, steps_with_continue_on_error, Leg,
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
    assert_eq!(steps_with_continue_on_error(ci, "ci").unwrap(), vec!["a", "c"]);
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
        "lint-host",
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
    g.insert("clippy-ex-galoshes", NON_HOLE_LEGS.to_vec());
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
        "hole-test-non-tun",
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

/// #200: the Windows TUN lane corrupts NDIS loopback, so every loopback user
/// (compiles through sccache, tests, the installer E2E) runs before it. What may
/// follow on the Windows leg is the #999 proof step, a set diff over two files,
/// and artifact uploads (`uses:` steps, no `run:`). A script step is not allowed
/// by default: the installer E2E drives WebDriver over loopback and invokes no
/// toolchain, so a toolchain-word check would not catch it.
#[skuld::test]
fn nothing_but_the_proof_step_and_uploads_follows_the_windows_tun_lane() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    let runs = step_runs(&ci_yaml);
    let on_windows = steps_on_leg(&ci_yaml, "windows/amd64");
    let offenders: Vec<String> = steps_after(&ci_yaml, "ci", "hole-test-tun")
        .expect("order")
        .into_iter()
        .filter(|id| on_windows.contains(id) && id != "hole-verify-executed")
        .filter(|id| runs.contains_key(id.as_str()))
        .collect();
    assert!(
        offenders.is_empty(),
        "script steps after the Windows TUN lane (#200): {offenders:?}"
    );
}

/// The macOS TUN lane runs as root and leaves root-owned files in `target/` that
/// no later unprivileged step could overwrite, so no script step follows it on a
/// macOS leg.
#[skuld::test]
fn the_macos_root_lane_is_the_last_script_step_on_macos() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    let runs = step_runs(&ci_yaml);
    let on_darwin: BTreeSet<String> = ["darwin/amd64", "darwin/arm64"]
        .iter()
        .flat_map(|name| steps_on_leg(&ci_yaml, name))
        .collect();
    let offenders: Vec<String> = steps_after(&ci_yaml, "ci", "hole-test-tun-macos")
        .expect("order")
        .into_iter()
        .filter(|id| on_darwin.contains(id))
        .filter(|id| runs.contains_key(id.as_str()))
        .collect();
    assert!(
        offenders.is_empty(),
        "script steps after the macOS root lane: {offenders:?}"
    );
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
        steps_with_continue_on_error(&ci_yaml, "ci").unwrap(),
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
