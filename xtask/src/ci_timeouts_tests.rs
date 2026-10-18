//! Unit tests for the installer-assembly detectors, the per-step timeout
//! audits, and the `ci_installer_assembly_steps_share_a_timeout_budget`,
//! `ci_steps_declare_a_literal_timeout` and
//! `ci_step_budgets_sit_on_the_five_minute_grid` structural conformance tests.

use std::collections::BTreeSet;
use std::fs;

use crate::ci_timeouts::{
    assembles_installer, installer_assembly_step_timeouts, steps_off_the_budget_grid, steps_without_literal_timeout,
    xtask_target,
};
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

// ===== installer_assembly_step_timeouts ==============================================================================

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

fn key(job: &str, step: &str) -> (String, String) {
    (job.to_string(), step.to_string())
}

#[skuld::test]
fn assembly_is_found_through_a_transitive_depends_edge() {
    let ci = r#"
jobs:
  a:
    steps:
      - name: assemble
        timeout-minutes: 45
        run: cargo xtask run pkg-tests
      - name: other
        timeout-minutes: 10
        run: cargo xtask run unrelated
"#;
    let got = installer_assembly_step_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got.keys().collect::<Vec<_>>(), vec![&key("a", "assemble")]);
    assert_eq!(got[&key("a", "assemble")], Some(45));
}

/// The assembling command is the third of three build steps — `hole-dmg`'s real
/// shape, where the `uv run … build` handoff is neither first nor alone.
#[skuld::test]
fn assembly_is_found_mid_way_through_a_multi_step_build_list() {
    let ci = r#"
jobs:
  a:
    steps:
      - name: assemble
        timeout-minutes: 45
        run: cargo xtask build pkg
"#;
    let got = installer_assembly_step_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got[&key("a", "assemble")], Some(45));
}

/// A target that composes the installer build as a nested `cargo xtask` step
/// rather than a `depends` edge is still in the class.
#[skuld::test]
fn assembly_is_found_through_a_nested_xtask_step() {
    let ci = r#"
jobs:
  a:
    steps:
      - name: assemble
        timeout-minutes: 45
        run: cargo xtask build nested
"#;
    let got = installer_assembly_step_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got[&key("a", "assemble")], Some(45));
}

/// In a unified job the job-level `timeout-minutes` is a per-leg matrix
/// expression; it is not the installer step's budget and must neither be read
/// nor break the parse.
#[skuld::test]
fn a_step_that_reaches_an_installer_is_in_the_class_and_its_job_timeout_is_ignored() {
    let ci = r#"
jobs:
  ci:
    timeout-minutes: ${{ matrix.timeout }}
    steps:
      - id: dmg
        timeout-minutes: 80
        run: cargo xtask build pkg
"#;
    let got = installer_assembly_step_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got[&key("ci", "dmg")], Some(80));
}

#[skuld::test]
fn two_installer_steps_with_different_budgets_are_reported() {
    let ci = r#"
jobs:
  ci:
    steps:
      - id: msi
        timeout-minutes: 80
        run: cargo xtask build pkg
      - id: dmg
        timeout-minutes: 60
        run: cargo xtask run pkg-tests
"#;
    let got = installer_assembly_step_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got[&key("ci", "msi")], Some(80));
    assert_eq!(got[&key("ci", "dmg")], Some(60));
}

#[skuld::test]
fn a_non_installer_step_is_outside_the_class() {
    let ci = r#"
jobs:
  ci:
    steps:
      - id: plain
        timeout-minutes: ${{ matrix.timeout }}
        run: cargo xtask run unrelated
"#;
    let got = installer_assembly_step_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert!(got.is_empty());
}

/// Inside the class an expression cannot be compared against a sibling, so it
/// must fail loudly rather than silently drop out of the equality check.
#[skuld::test]
fn an_expression_timeout_inside_the_class_is_an_error() {
    let ci = r#"
jobs:
  a:
    steps:
      - id: assemble
        timeout-minutes: ${{ matrix.timeout }}
        run: cargo xtask build pkg
"#;
    let err = installer_assembly_step_timeouts(ci, &fixture_manifest()).unwrap_err();
    assert!(format!("{err:#}").contains("expression"), "unexpected error: {err:#}");
}

/// A YAML-quoted number is a literal, not an expression — classification is on
/// the `${{` syntax, not on which serde shape the scalar happened to take.
#[skuld::test]
fn a_quoted_numeric_timeout_is_a_literal() {
    let ci = r#"
jobs:
  a:
    steps:
      - id: assemble
        timeout-minutes: "60"
        run: cargo xtask build pkg
"#;
    let got = installer_assembly_step_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got[&key("a", "assemble")], Some(60));
}

/// An odd scalar on a step outside the class must not abort the whole ci.yaml
/// parse — the failure mode the expression handling exists to prevent.
#[skuld::test]
fn an_odd_timeout_scalar_outside_the_class_does_not_break_parsing() {
    let ci = r#"
jobs:
  a:
    steps:
      - id: assemble
        timeout-minutes: 45
        run: cargo xtask build pkg
      - id: other
        timeout-minutes: 0.5
        run: cargo xtask run unrelated
"#;
    let got = installer_assembly_step_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got.keys().collect::<Vec<_>>(), vec![&key("a", "assemble")]);
}

#[skuld::test]
fn a_non_integral_timeout_inside_the_class_is_an_error() {
    let ci = r#"
jobs:
  a:
    steps:
      - id: assemble
        timeout-minutes: 0.5
        run: cargo xtask build pkg
"#;
    let err = installer_assembly_step_timeouts(ci, &fixture_manifest()).unwrap_err();
    assert!(format!("{err:#}").contains("whole number"), "unexpected error: {err:#}");
}

#[skuld::test]
fn an_installer_step_without_a_timeout_is_reported_as_none() {
    let ci = r#"
jobs:
  a:
    steps:
      - id: assemble
        run: cargo xtask build pkg
"#;
    let got = installer_assembly_step_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got[&key("a", "assemble")], None);
}

#[skuld::test]
fn steps_without_run_blocks_do_not_panic() {
    let ci = r#"
jobs:
  a:
    steps:
      - uses: actions/checkout@v7
      - id: assemble
        timeout-minutes: 45
        run: cargo xtask build pkg
"#;
    let got = installer_assembly_step_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got[&key("a", "assemble")], Some(45));
}

/// A step is identified by `id`, else `name`, else its position.
#[skuld::test]
fn steps_are_keyed_by_id_then_name_then_position() {
    let ci = r#"
jobs:
  a:
    steps:
      - id: by-id
        name: ignored
        timeout-minutes: 1
        run: cargo xtask build pkg
      - name: by-name
        timeout-minutes: 2
        run: cargo xtask build pkg
      - timeout-minutes: 3
        run: cargo xtask build pkg
"#;
    let got = installer_assembly_step_timeouts(ci, &fixture_manifest()).expect("analyze");
    assert_eq!(got[&key("a", "by-id")], Some(1));
    assert_eq!(got[&key("a", "by-name")], Some(2));
    assert_eq!(got[&key("a", "steps[2]")], Some(3));
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
    steps:
      - id: s
        timeout-minutes: 10
        run: cargo xtask build a
"#;
    let got = installer_assembly_step_timeouts(ci, &cyclic).expect("analyze");
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
    steps:
      - id: s
        timeout-minutes: 10
        run: cargo xtask build a
"#;
    let got = installer_assembly_step_timeouts(ci, &looping).expect("analyze");
    assert!(got.is_empty());
}

// ===== steps_without_literal_timeout =================================================================================

/// A step with no bound runs to the job wall, and a wall that fires destroys
/// the step's log (#989), so every step — `uses:` ones included — declares one.
#[skuld::test]
fn steps_without_a_literal_timeout_are_named() {
    let ci = r#"
jobs:
  ci:
    steps:
      - uses: actions/checkout@v7
      - id: bounded
        timeout-minutes: 5
        run: echo
      - id: quoted
        timeout-minutes: "7"
        run: echo
      - id: templated
        timeout-minutes: ${{ matrix.timeout }}
        run: echo
      - id: fractional
        timeout-minutes: 0.5
        run: echo
  other:
    steps:
      - id: elsewhere
        run: echo
"#;
    let missing = steps_without_literal_timeout(ci, "ci").expect("analyze");
    assert_eq!(missing, vec!["steps[0]", "templated", "fractional"]);
}

#[skuld::test]
fn an_unknown_job_is_an_error_for_the_timeout_audit() {
    let err = steps_without_literal_timeout("jobs:\n  a:\n    steps: []\n", "ci").unwrap_err();
    assert!(format!("{err:#}").contains("\"ci\""), "unexpected error: {err:#}");
}

// ===== steps_off_the_budget_grid =====================================================================================

/// The header rule rounds a step budget up to 5m and gives a step under 4m 5m,
/// so a literal below 5 or not a multiple of 5 contradicts it. Expressions and
/// absent bounds are `steps_without_literal_timeout`'s business, not this one's.
#[skuld::test]
fn budgets_below_five_or_off_the_five_minute_grid_are_named() {
    let ci = r#"
jobs:
  ci:
    steps:
      - uses: actions/checkout@v7
      - id: five
        timeout-minutes: 5
        run: echo
      - id: three
        timeout-minutes: 3
        run: echo
      - id: twelve
        timeout-minutes: 12
        run: echo
      - id: zero
        timeout-minutes: 0
        run: echo
      - id: quoted-seven
        timeout-minutes: "7"
        run: echo
      - id: eighty
        timeout-minutes: 80
        run: echo
      - id: templated
        timeout-minutes: ${{ matrix.timeout }}
        run: echo
  other:
    steps:
      - id: elsewhere
        timeout-minutes: 3
        run: echo
"#;
    let off = steps_off_the_budget_grid(ci, "ci").expect("analyze");
    assert_eq!(
        off,
        vec![
            ("three".to_string(), 3),
            ("twelve".to_string(), 12),
            ("zero".to_string(), 0),
            ("quoted-seven".to_string(), 7),
        ]
    );
}

#[skuld::test]
fn an_unknown_job_is_an_error_for_the_budget_grid_audit() {
    let err = steps_off_the_budget_grid("jobs:\n  a:\n    steps: []\n", "ci").unwrap_err();
    assert!(format!("{err:#}").contains("\"ci\""), "unexpected error: {err:#}");
}

// ===== conformance ===================================================================================================

/// Every `ci.yaml` step that assembles a release installer carries the same
/// `timeout-minutes`.
///
/// Assembling an installer is the heaviest work CI does, so these steps run
/// closest to their budget — and the slowest runner in the matrix sets the real
/// requirement. A member budgeted below its siblings does not fail cleanly; it
/// gets killed mid-compile and reads as a flake. The two steps share a job but
/// not a runner; equality costs nothing, so the old class rule stays.
#[skuld::test]
fn ci_installer_assembly_steps_share_a_timeout_budget() {
    let root = crate::repo_root().expect("repo root");
    let manifest = Manifest::parse(&fs::read_to_string(root.join("build.yaml")).expect("read build.yaml"))
        .expect("parse build.yaml");
    let ci_yaml = fs::read_to_string(root.join(".github/workflows/ci.yaml")).expect("read ci.yaml");

    let timeouts = installer_assembly_step_timeouts(&ci_yaml, &manifest).expect("analyze ci.yaml");

    // Guard the guard by MEMBERSHIP, not count: a step silently dropping out of
    // detection while another drops in would keep any count-based check green.
    for id in ["installer-build-msi", "dmg"] {
        let k = ("ci".to_string(), id.to_string());
        assert!(
            timeouts.contains_key(&k),
            "{id:?} no longer resolves as an installer-assembly step (found {:?}) — \
             the detector in ci_timeouts.rs has drifted from ci.yaml/build.yaml",
            timeouts.keys().collect::<Vec<_>>()
        );
    }

    let undeclared: Vec<&(String, String)> = timeouts.iter().filter(|(_, t)| t.is_none()).map(|(k, _)| k).collect();
    assert!(
        undeclared.is_empty(),
        "installer-assembly steps must declare timeout-minutes, these do not: {undeclared:?}"
    );

    let distinct: BTreeSet<u64> = timeouts.values().flatten().copied().collect();
    assert_eq!(
        distinct.len(),
        1,
        "installer-assembly steps disagree on timeout-minutes: {timeouts:?} — \
         they do the same class of work, so they get the same budget; change all of them together"
    );
}

/// Every step of the unified `ci` job declares a literal `timeout-minutes`.
#[skuld::test]
fn ci_steps_declare_a_literal_timeout() {
    let root = crate::repo_root().expect("repo root");
    let ci_yaml = fs::read_to_string(root.join(".github/workflows/ci.yaml")).expect("read ci.yaml");

    let missing = steps_without_literal_timeout(&ci_yaml, "ci").expect("analyze ci.yaml");
    assert!(
        missing.is_empty(),
        "these steps of the `ci` job declare no literal timeout-minutes, so a hang runs to the job wall \
         and the wall destroys the step's log: {missing:?}"
    );
}

/// Every literal step budget of the `ci` job follows the header rule in
/// `ci.yaml`: a multiple of 5, never below 5.
#[skuld::test]
fn ci_step_budgets_sit_on_the_five_minute_grid() {
    let root = crate::repo_root().expect("repo root");
    let ci_yaml = fs::read_to_string(root.join(".github/workflows/ci.yaml")).expect("read ci.yaml");

    let off = steps_off_the_budget_grid(&ci_yaml, "ci").expect("analyze ci.yaml");
    assert!(
        off.is_empty(),
        "these steps of the `ci` job have a timeout-minutes that is below 5 or not a multiple of 5, \
         against the step-budget rule in ci.yaml's header: {off:?}"
    );
}
