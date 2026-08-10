//! Unit tests for the installer-assembly detectors plus the
//! `ci_installer_assembly_jobs_share_a_timeout_budget` structural conformance
//! test.

use std::collections::BTreeSet;
use std::fs;

use crate::ci_timeouts::{assembles_installer, installer_assembly_job_timeouts, xtask_target};
use crate::manifest::Manifest;

// ===== assembles_installer ===========================================================================================

#[skuld::test]
fn msi_and_dmg_assembly_commands_are_detected() {
    assert!(assembles_installer("uv run --directory msi-installer build"));
    assert!(assembles_installer("uv run --directory dmg-installer build"));
}

#[skuld::test]
fn quoted_assembly_commands_are_detected() {
    assert!(assembles_installer(r#"uv run --directory "msi-installer" build"#));
    assert!(assembles_installer("uv run --directory 'dmg-installer' build"));
}

#[skuld::test]
fn consuming_the_package_is_not_assembling_it() {
    assert!(!assembles_installer("uv run --directory dmg-installer pytest -v"));
}

#[skuld::test]
fn unrelated_uv_projects_are_ignored() {
    assert!(!assembles_installer("uv run --directory tools build"));
}

#[skuld::test]
fn plain_commands_are_ignored() {
    assert!(!assembles_installer("cargo build --release -p hole"));
    assert!(!assembles_installer(""));
}

// ===== xtask_target ==================================================================================================

#[skuld::test]
fn both_run_and_build_spellings_resolve() {
    assert_eq!(
        xtask_target("cargo xtask run hole-dmg-tests").unwrap(),
        Some("hole-dmg-tests")
    );
    assert_eq!(xtask_target("cargo xtask build hole-msi").unwrap(), Some("hole-msi"));
}

#[skuld::test]
fn quoted_targets_resolve() {
    assert_eq!(
        xtask_target(r#"cargo xtask build "hole-msi""#).unwrap(),
        Some("hole-msi")
    );
}

#[skuld::test]
fn non_xtask_commands_resolve_to_nothing() {
    assert_eq!(xtask_target("cargo build --release").unwrap(), None);
    assert_eq!(xtask_target("cargo xtask deps").unwrap(), None);
}

/// A workflow-expression target can't be resolved against build.yaml, so it must
/// fail loudly rather than drop the job out of the class.
#[skuld::test]
fn templated_targets_are_an_error() {
    let err = xtask_target(r#"cargo xtask build "hole-${{ matrix.ext }}""#).unwrap_err();
    assert!(
        err.to_string().contains("templated xtask target"),
        "unexpected error: {err}"
    );
}

// ===== installer_assembly_job_timeouts ===============================================================================

fn fixture_manifest() -> Manifest {
    Manifest::parse(
        r#"
targets:
  pkg:
    platforms: [linux/amd64]
    build:
      - cargo build --release -p thing
      - cargo xtask render-background
      - uv run --directory pkg-installer build
  pkg-tests:
    depends: pkg
    platforms: [linux/amd64]
    run: uv run --directory pkg-installer pytest -v
  render-background:
    platforms: [linux/amd64]
    build: cargo run -p renderer
  nested:
    platforms: [linux/amd64]
    build: cargo xtask build pkg
  unrelated:
    platforms: [linux/amd64]
    build: cargo build --release
"#,
    )
    .expect("fixture manifest parses")
}

#[skuld::test]
fn assembly_is_found_through_a_transitive_depends_edge() {
    let ci = r#"
jobs:
  a:
    timeout-minutes: 45
    steps:
      - run: cargo xtask run pkg-tests
  b:
    timeout-minutes: 10
    steps:
      - run: cargo xtask run unrelated
"#;
    let got = installer_assembly_job_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got.keys().collect::<Vec<_>>(), vec!["a"]);
    assert_eq!(got["a"], Some(45));
}

/// The assembling command is the third of three build steps — `hole-dmg`'s real
/// shape, where the `uv run … build` handoff is neither first nor alone.
#[skuld::test]
fn assembly_is_found_mid_way_through_a_multi_step_build_list() {
    let ci = r#"
jobs:
  a:
    timeout-minutes: 45
    steps:
      - run: cargo xtask build pkg
"#;
    let got = installer_assembly_job_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got["a"], Some(45));
}

/// A target that composes the installer build as a nested `cargo xtask` step
/// rather than a `depends` edge is still in the class.
#[skuld::test]
fn assembly_is_found_through_a_nested_xtask_step() {
    let ci = r#"
jobs:
  a:
    timeout-minutes: 45
    steps:
      - run: cargo xtask build nested
"#;
    let got = installer_assembly_job_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got["a"], Some(45));
}

/// GitHub allows an expression for `timeout-minutes` (a per-leg matrix budget,
/// as `test-hole` uses). A job outside the class must not break the parse.
#[skuld::test]
fn an_expression_timeout_outside_the_class_is_ignored() {
    let ci = r#"
jobs:
  a:
    timeout-minutes: 45
    steps:
      - run: cargo xtask build pkg
  b:
    timeout-minutes: ${{ matrix.timeout }}
    steps:
      - run: cargo xtask run unrelated
"#;
    let got = installer_assembly_job_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got.keys().collect::<Vec<_>>(), vec!["a"]);
}

/// Inside the class an expression cannot be compared against a sibling, so it
/// must fail loudly rather than silently drop out of the equality check.
#[skuld::test]
fn an_expression_timeout_inside_the_class_is_an_error() {
    let ci = r#"
jobs:
  a:
    timeout-minutes: ${{ matrix.timeout }}
    steps:
      - run: cargo xtask build pkg
"#;
    let err = installer_assembly_job_timeouts(ci, &fixture_manifest()).unwrap_err();
    assert!(format!("{err:#}").contains("expression"), "unexpected error: {err:#}");
}

/// A YAML-quoted number is a literal, not an expression — classification is on
/// the `${{` syntax, not on which serde shape the scalar happened to take.
#[skuld::test]
fn a_quoted_numeric_timeout_is_a_literal() {
    let ci = r#"
jobs:
  a:
    timeout-minutes: "60"
    steps:
      - run: cargo xtask build pkg
"#;
    let got = installer_assembly_job_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got["a"], Some(60));
}

/// An odd scalar on an unrelated job must not abort the whole ci.yaml parse —
/// the failure mode the expression handling exists to prevent.
#[skuld::test]
fn an_odd_timeout_scalar_outside_the_class_does_not_break_parsing() {
    let ci = r#"
jobs:
  a:
    timeout-minutes: 45
    steps:
      - run: cargo xtask build pkg
  b:
    timeout-minutes: 0.5
    steps:
      - run: cargo xtask run unrelated
"#;
    let got = installer_assembly_job_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got.keys().collect::<Vec<_>>(), vec!["a"]);
}

#[skuld::test]
fn a_non_integral_timeout_inside_the_class_is_an_error() {
    let ci = r#"
jobs:
  a:
    timeout-minutes: 0.5
    steps:
      - run: cargo xtask build pkg
"#;
    let err = installer_assembly_job_timeouts(ci, &fixture_manifest()).unwrap_err();
    assert!(format!("{err:#}").contains("whole number"), "unexpected error: {err:#}");
}

#[skuld::test]
fn a_job_without_a_declared_timeout_is_reported_as_none() {
    let ci = r#"
jobs:
  a:
    steps:
      - run: cargo xtask build pkg
"#;
    let got = installer_assembly_job_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got["a"], None);
}

#[skuld::test]
fn steps_without_run_blocks_do_not_panic() {
    let ci = r#"
jobs:
  a:
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@v7
      - run: cargo xtask build pkg
"#;
    let got = installer_assembly_job_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got["a"], Some(45));
}

/// The `visited` guard must stop a `depends` cycle rather than recurse forever.
/// `Manifest::parse` accepts the cycle, so the walk is what has to terminate.
#[skuld::test]
fn a_depends_cycle_terminates() {
    let cyclic = Manifest::parse(
        r#"
targets:
  a:
    depends: b
    platforms: [linux/amd64]
    build: cargo build -p a
  b:
    depends: a
    platforms: [linux/amd64]
    build: cargo build -p b
"#,
    )
    .expect("cyclic fixture parses");

    let ci = r#"
jobs:
  j:
    timeout-minutes: 10
    steps:
      - run: cargo xtask build a
"#;
    let got = installer_assembly_job_timeouts(ci, &cyclic).expect("analyze");
    assert!(got.is_empty(), "no target in the cycle assembles an installer");
}

/// A self-referential `cargo xtask` step must terminate too — the nested-step
/// recursion shares the same `visited` set as the `depends` walk.
#[skuld::test]
fn a_self_referential_xtask_step_terminates() {
    let looping = Manifest::parse(
        r#"
targets:
  a:
    platforms: [linux/amd64]
    build: cargo xtask build a
"#,
    )
    .expect("self-referential fixture parses");

    let ci = r#"
jobs:
  j:
    timeout-minutes: 10
    steps:
      - run: cargo xtask build a
"#;
    let got = installer_assembly_job_timeouts(ci, &looping).expect("analyze");
    assert!(got.is_empty());
}

// ===== conformance ===================================================================================================

/// Every `ci.yaml` job that assembles a release installer carries the same
/// `timeout-minutes`.
///
/// Assembling an installer is the heaviest work CI does, so these jobs run
/// closest to their wall — and the slowest runner in the matrix sets the real
/// requirement. A member budgeted below its siblings does not fail cleanly; it
/// gets SIGKILLed mid-compile and reads as a flake.
#[skuld::test]
fn ci_installer_assembly_jobs_share_a_timeout_budget() {
    let root = crate::repo_root().expect("repo root");
    let manifest = Manifest::parse(&fs::read_to_string(root.join("build.yaml")).expect("read build.yaml"))
        .expect("parse build.yaml");
    let ci_yaml = fs::read_to_string(root.join(".github/workflows/ci.yaml")).expect("read ci.yaml");

    let timeouts = installer_assembly_job_timeouts(&ci_yaml, &manifest).expect("analyze ci.yaml");

    // Guard the guard by MEMBERSHIP, not count: a job silently dropping out of
    // detection while another drops in would keep any count-based check green.
    for id in ["test-installer", "test-dmg-signing"] {
        assert!(
            timeouts.contains_key(id),
            "{id:?} no longer resolves as an installer-assembly job (found {:?}) — \
             the detector in ci_timeouts.rs has drifted from ci.yaml/build.yaml",
            timeouts.keys().collect::<Vec<_>>()
        );
    }

    let undeclared: Vec<&String> = timeouts.iter().filter(|(_, t)| t.is_none()).map(|(id, _)| id).collect();
    assert!(
        undeclared.is_empty(),
        "installer-assembly jobs must declare timeout-minutes, these do not: {undeclared:?}"
    );

    let distinct: BTreeSet<u64> = timeouts.values().flatten().copied().collect();
    assert_eq!(
        distinct.len(),
        1,
        "installer-assembly jobs disagree on timeout-minutes: {timeouts:?} — \
         they do the same class of work, so they get the same budget; change all of them together"
    );
}
