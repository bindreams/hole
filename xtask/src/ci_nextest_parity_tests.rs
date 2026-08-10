//! Unit tests for the compile-then-run chain resolver plus the
//! `ci_test_hole_steps_match_the_hole_tests_target` structural conformance test.

use std::fs;

use crate::ci_nextest_parity::{target_nextest_run, test_job};
use crate::manifest::Manifest;

// ===== test_job ======================================================================================================

/// A `run:` block written as a folded scalar and one written with backslash
/// continuations must reduce to the same text.
#[skuld::test]
fn folded_and_continued_commands_normalize_to_one_line() {
    let ci = "
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - name: folded
        run: >
          cargo nextest run --no-default-features
          -E 'package(a)
              + package(b)'
      - name: continued
        run: |
          cargo nextest run --no-default-features \\
            -E 'package(a) + package(b)'
";
    let job = test_job(ci, "j").expect("analyze");
    let cmds: Vec<&str> = job.runs.iter().map(|(_, c)| c.as_str()).collect();
    assert_eq!(
        cmds,
        vec![
            "cargo nextest run --no-default-features -E 'package(a) + package(b)'",
            "cargo nextest run --no-default-features -E 'package(a) + package(b)'"
        ]
    );
}

/// The macOS TUN step states its environment inline under `sudo env …` where its
/// siblings use step-level `env:`. That prefix is not part of the nextest
/// command and must not make the step look different from them.
#[skuld::test]
fn a_sudo_env_prefix_is_stripped() {
    let ci = r#"
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - name: root
        run: sudo env "PATH=$PATH" "HOME=$HOME" SKULD_LABELS=tun cargo nextest run -E 'package(a)'
"#;
    let job = test_job(ci, "j").expect("analyze");
    assert_eq!(
        job.runs,
        vec![("root".into(), "cargo nextest run -E 'package(a)'".into())]
    );
}

/// Only a *leading* prefix is stripped: an `=` inside the command's own flags is
/// part of the command.
#[skuld::test]
fn flags_carrying_an_equals_sign_survive_normalization() {
    let ci = "
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - name: s
        run: cargo nextest run --config-file=x.toml -E 'package(a)'
";
    let job = test_job(ci, "j").expect("analyze");
    assert_eq!(job.runs[0].1, "cargo nextest run --config-file=x.toml -E 'package(a)'");
}

/// `--no-run` compiles rather than runs, so it is a different operation from the
/// `run:` command being compared against — build.yaml states it separately.
#[skuld::test]
fn compile_only_steps_are_not_runs() {
    let ci = "
jobs:
  j:
    steps:
      - uses: actions/checkout@v7
      - run: cargo xtask build tests
      - name: build
        run: cargo nextest run --no-run -E 'package(a)'
";
    assert!(test_job(ci, "j").expect("analyze").runs.is_empty());
}

/// Several nextest runs in one `run:` block each get their own entry rather than
/// collapsing onto the step's label.
#[skuld::test]
fn every_run_in_a_multi_command_step_is_reported() {
    let ci = "
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - name: both
        run: |
          cargo nextest run -E 'package(a)'
          cargo nextest run -E 'package(b)'
";
    let job = test_job(ci, "j").expect("analyze");
    assert_eq!(job.runs.len(), 2);
    assert_eq!(job.runs[0].1, "cargo nextest run -E 'package(a)'");
    assert_eq!(job.runs[1].1, "cargo nextest run -E 'package(b)'");
}

/// An unnamed step still has to be identifiable in a failure message.
#[skuld::test]
fn unnamed_steps_fall_back_to_id_then_position() {
    let ci = "
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - id: has-id
        run: cargo nextest run -E 'package(a)'
      - run: cargo nextest run -E 'package(b)'
";
    let job = test_job(ci, "j").expect("analyze");
    assert_eq!(job.runs[0].0, "has-id");
    assert_eq!(job.runs[1].0, "steps[2]");
}

// ----- the compiled target -------------------------------------------------------------------------------------------

#[skuld::test]
fn the_compiled_target_is_read_off_the_build_step() {
    let ci = "
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - run: cargo nextest run -E 'package(a)'
";
    assert_eq!(test_job(ci, "j").expect("analyze").target, "tests");
}

/// Nothing ties the runs to a build.yaml target, so there is no defensible thing
/// to compare them against — the invariant must not quietly become vacuous.
#[skuld::test]
fn a_job_that_builds_nothing_is_an_error() {
    let ci = "
jobs:
  j:
    steps:
      - run: cargo nextest run -E 'package(a)'
";
    let err = test_job(ci, "j").unwrap_err();
    assert!(
        format!("{err:#}").contains("no `cargo xtask"),
        "unexpected error: {err:#}"
    );
}

#[skuld::test]
fn a_job_that_builds_two_targets_is_an_error() {
    let ci = "
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - run: cargo xtask build other
      - run: cargo nextest run -E 'package(a)'
";
    let err = test_job(ci, "j").unwrap_err();
    assert!(format!("{err:#}").contains("ambiguous"), "unexpected error: {err:#}");
}

#[skuld::test]
fn a_missing_job_is_an_error() {
    let err = test_job("jobs:\n  j:\n    steps: []\n", "gone").unwrap_err();
    assert!(
        format!("{err:#}").contains("no job \"gone\""),
        "unexpected error: {err:#}"
    );
}

// ----- environment ---------------------------------------------------------------------------------------------------

/// `RUSTFLAGS` reaches cargo's fingerprint, so a step carrying it no longer
/// re-executes what the build step compiled — whether it is exported as
/// step-level `env:` or inline, and whether it lands on the compile step or a
/// run step.
#[skuld::test]
fn a_fingerprint_relevant_variable_is_an_error_wherever_it_appears() {
    let step_level = "
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - name: s
        env:
          RUSTFLAGS: -C target-cpu=native
        run: cargo nextest run -E 'package(a)'
";
    let on_the_build_step = "
jobs:
  j:
    steps:
      - name: b
        env:
          CARGO_TARGET_DIR: /tmp/t
        run: cargo xtask build tests
      - run: cargo nextest run -E 'package(a)'
";
    let inline = "
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - name: s
        run: sudo env RUSTC_WRAPPER=sccache cargo nextest run -E 'package(a)'
";
    for (ci, needle) in [
        (step_level, "\"RUSTFLAGS\""),
        (on_the_build_step, "\"CARGO_TARGET_DIR\""),
        (inline, "\"RUSTC_WRAPPER\""),
    ] {
        let err = test_job(ci, "j").unwrap_err();
        assert!(format!("{err:#}").contains(needle), "unexpected error: {err:#}");
    }
}

/// The variables the two files legitimately state differently stay allowed.
#[skuld::test]
fn fingerprint_neutral_variables_are_allowed() {
    let ci = r#"
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - name: s
        env:
          SKULD_LABELS: "!tun"
        run: cargo nextest run -E 'package(a)'
"#;
    assert_eq!(test_job(ci, "j").expect("analyze").runs.len(), 1);
}

// ===== target_nextest_run ============================================================================================

fn fixture_manifest() -> Manifest {
    Manifest::parse(
        r#"
targets:
  tests:
    platforms: [linux/amd64]
    build: cargo nextest run --no-run --no-default-features -E 'package(a)'
    run: >
      cargo nextest run --no-default-features
      -E 'package(a)'
  twice:
    platforms: [linux/amd64]
    run:
      - cargo nextest run -E 'package(a)'
      - cargo nextest run -E 'package(b)'
  none:
    platforms: [linux/amd64]
    run: cargo xtask build tests
  flagged:
    platforms: [linux/amd64]
    run:
      - bash:
          command: cargo nextest run -E 'package(a)'
          environment: { RUSTFLAGS: -C target-cpu=native }
"#,
    )
    .expect("fixture manifest parses")
}

/// The `build:` twin differs only by `--no-run`; taking it instead would compare
/// the CI steps against a compile command.
#[skuld::test]
fn the_run_command_is_taken_not_its_no_run_twin() {
    assert_eq!(
        target_nextest_run(&fixture_manifest(), "tests").expect("resolve"),
        "cargo nextest run --no-default-features -E 'package(a)'"
    );
}

#[skuld::test]
fn an_ambiguous_or_absent_run_command_is_an_error() {
    for (target, needle) in [("twice", "2 nextest"), ("none", "0 nextest")] {
        let err = target_nextest_run(&fixture_manifest(), target).unwrap_err();
        assert!(format!("{err:#}").contains(needle), "unexpected error: {err:#}");
    }
}

/// build.yaml's `environment:` is dropped by `step_command`, so it has to be
/// checked separately or a fingerprint-relevant variable there is invisible.
#[skuld::test]
fn a_fingerprint_relevant_step_environment_is_an_error() {
    let err = target_nextest_run(&fixture_manifest(), "flagged").unwrap_err();
    assert!(
        format!("{err:#}").contains("\"RUSTFLAGS\""),
        "unexpected error: {err:#}"
    );
}

#[skuld::test]
fn a_missing_target_is_an_error() {
    let err = target_nextest_run(&fixture_manifest(), "gone").unwrap_err();
    assert!(
        format!("{err:#}").contains("no target \"gone\""),
        "unexpected error: {err:#}"
    );
}

// ===== conformance ===================================================================================================

/// Steps of `ci.yaml`'s `test-hole` job that we require to be nextest runs.
const TEST_HOLE_RUN_STEPS: [&str; 3] = [
    "Test (non-TUN)",
    "Test (TUN, runs last for #200)",
    "Test (TUN, macOS — root for pfctl)",
];

/// Every nextest run in `ci.yaml`'s `test-hole` job invokes exactly the command
/// build.yaml's `hole-tests` target runs — see [`crate::ci_nextest_parity`] for why.
///
/// `hole-tests` is read off the job's build step rather than assumed, and pinned
/// here as well: `hole` and `hole-tests` do not share a resolvable feature set
/// (#723), so a retarget is a decision to take deliberately, not to absorb.
#[skuld::test]
fn ci_test_hole_steps_match_the_hole_tests_target() {
    let root = crate::repo_root().expect("repo root");
    let manifest = Manifest::parse(&fs::read_to_string(root.join("build.yaml")).expect("read build.yaml"))
        .expect("parse build.yaml");
    let ci_yaml = fs::read_to_string(root.join(".github/workflows/ci.yaml")).expect("read ci.yaml");

    let job = test_job(&ci_yaml, "test-hole").expect("analyze ci.yaml");
    assert_eq!(
        job.target, "hole-tests",
        "ci.yaml test-hole now compiles a different build.yaml target"
    );
    let expected = target_nextest_run(&manifest, &job.target).expect("resolve the compiled target");

    // Guard the guard by MEMBERSHIP: a step renamed out of detection would leave
    // any count-based check green while its command drifted unwatched.
    let labels: Vec<&str> = job.runs.iter().map(|(label, _)| label.as_str()).collect();
    for step in TEST_HOLE_RUN_STEPS {
        assert!(
            labels.contains(&step),
            "ci.yaml test-hole step {step:?} no longer resolves as a nextest run (found {labels:?})"
        );
    }

    for (label, cmd) in &job.runs {
        assert_eq!(
            cmd, &expected,
            "ci.yaml test-hole step {label:?} must run exactly what build.yaml's {:?} target runs \
             (see module docs for why)",
            job.target
        );
    }
}
