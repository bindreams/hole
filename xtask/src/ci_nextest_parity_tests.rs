//! Unit tests for the compile-then-run chain resolver plus the
//! `ci_test_hole_steps_match_the_hole_tests_target` structural conformance test.

use std::fs;

use crate::ci_nextest_parity::{post_build_cargo_launches, target_nextest_run, test_job, NO_COMPILE_GATE};
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
    let job = test_job(ci, "j", None).expect("analyze");
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
      - id: hole-build
        run: cargo xtask build tests
      - name: root
        run: sudo env "PATH=$PATH" "HOME=$HOME" SKULD_LABELS=tun cargo nextest run -E 'package(a)'
"#;
    let job = test_job(ci, "j", None).expect("analyze");
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
    let job = test_job(ci, "j", None).expect("analyze");
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
    assert!(test_job(ci, "j", None).expect("analyze").runs.is_empty());
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
    let job = test_job(ci, "j", None).expect("analyze");
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
    let job = test_job(ci, "j", None).expect("analyze");
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
    assert_eq!(test_job(ci, "j", None).expect("analyze").target, "tests");
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
    let err = test_job(ci, "j", None).unwrap_err();
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
    let err = test_job(ci, "j", None).unwrap_err();
    assert!(format!("{err:#}").contains("ambiguous"), "unexpected error: {err:#}");
}

#[skuld::test]
fn a_missing_job_is_an_error() {
    let err = test_job("jobs:\n  j:\n    steps: []\n", "gone", None).unwrap_err();
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
        let err = test_job(ci, "j", None).unwrap_err();
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
    assert_eq!(test_job(ci, "j", None).expect("analyze").runs.len(), 1);
}

/// `NEXTEST_PROFILE` picks a per-lane nextest profile (bindreams/hole#999's
/// non-tun/tun split) without perturbing the compared command text, whether
/// stated as step-level `env:` or inline under `sudo env …`.
#[skuld::test]
fn nextest_profile_is_fingerprint_neutral() {
    let step_level = r#"
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - name: s
        env:
          NEXTEST_PROFILE: non-tun
        run: cargo nextest run -E 'package(a)'
"#;
    assert_eq!(test_job(step_level, "j", None).expect("analyze").runs.len(), 1);

    let inline = r#"
jobs:
  j:
    steps:
      - id: hole-build
        run: cargo xtask build tests
      - name: root
        run: sudo env "PATH=$PATH" "HOME=$HOME" NEXTEST_PROFILE=tun cargo nextest run -E 'package(a)'
"#;
    assert_eq!(
        test_job(inline, "j", None).expect("analyze").runs,
        vec![("root".into(), "cargo nextest run -E 'package(a)'".into())]
    );
}

// ===== launch prefix: the no-compile gate and forwarded variables ====================================================

/// The no-compile gate wraps the command, so it is a launcher like `sudo`: the
/// compared text is what comes after it.
#[skuld::test]
fn the_no_compile_gate_is_stripped_and_reported() {
    let ci = format!(
        "
jobs:
  j:
    steps:
      - run: cargo xtask build tests
      - name: plain
        run: cargo nextest run -E 'package(a)'
      - name: gated
        run: {NO_COMPILE_GATE} cargo nextest run -E 'package(a)'
"
    );
    let job = test_job(&ci, "j", None).expect("analyze");
    assert_eq!(job.runs[0].1, job.runs[1].1);
    assert!(!job.launches[0].1.gated);
    assert!(job.launches[1].1.gated);
}

/// Under `sudo` the child's environment is whatever `env` is told, so the
/// ambient value of a variable is forwarded by naming it. The child then sees
/// what the compile step saw, which is the property this module guards.
#[skuld::test]
fn a_forwarded_variable_is_a_launcher_not_a_change() {
    let ci = r#"
jobs:
  j:
    steps:
      - id: hole-build
        run: cargo xtask build tests
      - name: root
        run: sudo env "PATH=$PATH" "HOME=$HOME" "CARGO_INCREMENTAL=$CARGO_INCREMENTAL" cargo nextest run -E 'package(a)'
"#;
    let job = test_job(ci, "j", None).expect("analyze");
    assert_eq!(job.runs[0].1, "cargo nextest run -E 'package(a)'");
    let launch = &job.launches[0].1;
    assert!(launch.privileged);
    assert!(launch.forwarded.contains("CARGO_INCREMENTAL"));
    assert!(
        !launch.forwarded.contains("PATH"),
        "PATH is neutral, not a forward of interest"
    );
}

/// A literal value is a change (it can differ from what the compile step saw),
/// and so is a value taken from another variable.
#[skuld::test]
fn a_set_or_renamed_variable_is_not_a_forward() {
    for assignment in [
        "CARGO_INCREMENTAL=0",
        "CARGO_INCREMENTAL=$OTHER",
        "RUSTFLAGS=${CARGO_INCREMENTAL}",
    ] {
        let ci = format!(
            r#"
jobs:
  j:
    steps:
      - id: hole-build
        run: cargo xtask build tests
      - name: root
        run: sudo env "{assignment}" cargo nextest run -E 'package(a)'
"#
        );
        let err = test_job(&ci, "j", None).unwrap_err();
        assert!(
            format!("{err:#}").contains("fingerprint-neutral"),
            "{assignment}: {err:#}"
        );
    }
}

/// `${NAME}` is the same forward as `$NAME`.
#[skuld::test]
fn a_braced_forward_is_recognized() {
    let ci = r#"
jobs:
  j:
    steps:
      - id: hole-build
        run: cargo xtask build tests
      - name: root
        run: sudo env "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}" cargo nextest run -E 'package(a)'
"#;
    let job = test_job(ci, "j", None).expect("analyze");
    assert!(job.launches[0].1.forwarded.contains("CARGO_INCREMENTAL"));
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

// ===== step_prefix ===================================================================================================

#[skuld::test]
fn test_job_ignores_xtask_steps_outside_the_prefix() {
    let ci = r"
jobs:
  ci:
    steps:
      - id: test-plugin-e2e
        run: cargo xtask run plugin-e2e-tests
      - id: hole-build
        run: cargo xtask build hole-tests
      - id: hole-test
        run: cargo nextest run -E 'package(a)'
";
    let job = test_job(ci, "ci", Some("hole-")).expect("analyze");
    assert_eq!(job.target, "hole-tests");
    assert_eq!(job.runs.len(), 1);

    // Unscoped, the plugin step is a second compile target, as before.
    let err = test_job(ci, "ci", None).unwrap_err();
    assert!(format!("{err:#}").contains("builds both"), "unexpected error: {err:#}");
}

#[skuld::test]
fn two_build_steps_inside_the_prefix_are_still_ambiguous() {
    let ci = r"
jobs:
  ci:
    steps:
      - id: hole-build
        run: cargo xtask build hole-tests
      - id: hole-other
        run: cargo xtask run other
";
    let err = test_job(ci, "ci", Some("hole-")).unwrap_err();
    assert!(format!("{err:#}").contains("builds both"), "unexpected error: {err:#}");
}

#[skuld::test]
fn an_unknown_prefix_is_an_error_not_an_empty_pass() {
    let ci = "jobs:\n  ci:\n    steps:\n      - id: a\n        run: cargo xtask build t\n";
    let err = test_job(ci, "ci", Some("hole-")).unwrap_err();
    assert!(format!("{err:#}").contains("hole-"), "unexpected error: {err:#}");
}

// ===== post_build_cargo_launches =====================================================================================

/// Every cargo command after the build step is a place cargo can compile, not
/// just the nextest runs: `nextest list` builds test binaries too.
#[skuld::test]
fn a_cargo_xtask_step_after_the_build_is_reported_with_its_gate_state() {
    let ci = "
jobs:
  j:
    steps:
      - name: before
        run: cargo xtask run lint
      - id: hole-build
        run: cargo xtask build tests
      - name: gated
        run: .github/scripts/fail-on-compile.sh cargo xtask verify-a
      - name: bare
        run: cargo xtask verify-b
      - name: no cargo
        run: echo done
";
    let launches = post_build_cargo_launches(ci, "j", "hole-").expect("analyze");
    let got: Vec<(&str, bool)> = launches.iter().map(|(l, launch)| (l.as_str(), launch.gated)).collect();
    assert_eq!(got, vec![("gated", true), ("bare", false)]);
}

/// A step that mentions cargo only after `sudo env …` is still a cargo step.
#[skuld::test]
fn a_privileged_cargo_step_after_the_build_is_reported() {
    let ci = r#"
jobs:
  j:
    steps:
      - id: hole-build
        run: cargo xtask build tests
      - name: root
        run: sudo env "PATH=$PATH" cargo xtask verify-b
"#;
    let launches = post_build_cargo_launches(ci, "j", "hole-").expect("analyze");
    assert_eq!(launches.len(), 1);
    assert!(launches[0].1.privileged && !launches[0].1.gated);
}

/// Each cargo command of a multi-command step counts on its own.
#[skuld::test]
fn every_cargo_command_in_a_step_after_the_build_is_reported() {
    let ci = "
jobs:
  j:
    steps:
      - id: hole-build
        run: cargo xtask build tests
      - name: two
        run: |
          .github/scripts/fail-on-compile.sh cargo xtask a
          cargo xtask b
";
    let launches = post_build_cargo_launches(ci, "j", "hole-").expect("analyze");
    let gated: Vec<bool> = launches.iter().map(|(_, l)| l.gated).collect();
    assert_eq!(gated, vec![true, false]);
}

#[skuld::test]
fn a_job_with_no_build_step_is_an_error_for_the_post_build_scan() {
    let ci = "jobs:\n  j:\n    steps:\n      - run: cargo xtask verify\n";
    let err = post_build_cargo_launches(ci, "j", "hole-").unwrap_err();
    assert!(format!("{err:#}").contains("hole-"), "unexpected error: {err:#}");
}

// ===== conformance ===================================================================================================

/// `hole-` steps of `ci.yaml`'s `ci` job that we require to be nextest runs.
const TEST_HOLE_RUN_STEPS: [&str; 3] = [
    "Test (non-TUN)",
    "Test (TUN, last test lane for #200)",
    "Test (TUN, macOS — root for pfctl)",
];

/// Every nextest run in `ci.yaml`'s `hole-` steps invokes exactly the command
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

    let job = test_job(&ci_yaml, "ci", Some("hole-")).expect("analyze ci.yaml");
    assert_eq!(
        job.target, "hole-tests",
        "ci.yaml's hole- steps now compile a different build.yaml target"
    );
    let expected = target_nextest_run(&manifest, &job.target).expect("resolve the compiled target");

    // Guard the guard by MEMBERSHIP: a step renamed out of detection would leave
    // any count-based check green while its command drifted unwatched.
    let labels: Vec<&str> = job.runs.iter().map(|(label, _)| label.as_str()).collect();
    for step in TEST_HOLE_RUN_STEPS {
        assert!(
            labels.contains(&step),
            "ci.yaml hole- step {step:?} no longer resolves as a nextest run (found {labels:?})"
        );
    }

    for (label, cmd) in &job.runs {
        assert_eq!(
            cmd, &expected,
            "ci.yaml hole- step {label:?} must run exactly what build.yaml's {:?} target runs \
             (see module docs for why)",
            job.target
        );
    }
}

/// A step that compiles after `hole-build` is not re-executing what it built: on
/// Windows a lane recompiled `hole`, `galoshes` and `garter-bin`, on macOS the
/// root step recompiled twenty workspace crates as root. And a compile in a
/// verify step masks drift: the lanes after it find fresh artifacts and pass.
/// Every cargo command after the build therefore runs under the gate, which
/// fails the step if cargo prints a `Compiling` line, so the property is checked
/// on every run rather than remembered.
#[skuld::test]
fn every_cargo_step_after_hole_build_runs_under_the_no_compile_gate() {
    // Guard the guard by MEMBERSHIP: a step renamed out of detection would leave
    // the scan green while its gate state went unwatched.
    const MUST_BE_SCANNED: [&str; 6] = [
        "Verify SKULD_LABELS TUN/non-TUN partition",
        "Verify global_net_state label matches the nextest.toml filter",
        "Test (non-TUN)",
        "Test (TUN, last test lane for #200)",
        "Verify every global_net_state test executed (windows leg, #999)",
        "Test (TUN, macOS — root for pfctl)",
    ];
    let root = crate::repo_root().expect("repo root");
    let ci_yaml = fs::read_to_string(root.join(".github/workflows/ci.yaml")).expect("read ci.yaml");
    let launches = post_build_cargo_launches(&ci_yaml, "ci", "hole-").expect("analyze ci.yaml");

    let scanned: Vec<&str> = launches.iter().map(|(label, _)| label.as_str()).collect();
    for step in MUST_BE_SCANNED {
        assert!(
            scanned.contains(&step),
            "ci.yaml step {step:?} is no longer scanned as a cargo step after the build (found {scanned:?})"
        );
    }

    let ungated: Vec<&str> = launches
        .iter()
        .filter(|(_, launch)| !launch.gated)
        .map(|(label, _)| label.as_str())
        .collect();
    assert_eq!(
        ungated,
        Vec::<&str>::new(),
        "these steps run cargo after hole-build and can compile without failing; start them with {NO_COMPILE_GATE}"
    );
    assert!(
        root.join(NO_COMPILE_GATE).is_file(),
        "{NO_COMPILE_GATE} is referenced by ci.yaml but missing"
    );
}

/// `sudo env` replaces the environment wholesale. `CARGO_INCREMENTAL` (set to 0
/// by the toolchain action) is part of every workspace unit's profile, so a root
/// step that drops it hashes each workspace crate differently and recompiles all
/// of them (measured: 20 crates, as root). Variables dropped for the same reason
/// belong in this list, each with its measurement.
#[skuld::test]
fn a_privileged_lane_forwards_the_variables_that_feed_cargos_fingerprint() {
    const MUST_FORWARD: [&str; 1] = ["CARGO_INCREMENTAL"];
    let root = crate::repo_root().expect("repo root");
    let ci_yaml = fs::read_to_string(root.join(".github/workflows/ci.yaml")).expect("read ci.yaml");
    let job = test_job(&ci_yaml, "ci", Some("hole-")).expect("analyze ci.yaml");

    let privileged: Vec<_> = job.launches.iter().filter(|(_, l)| l.privileged).collect();
    assert!(!privileged.is_empty(), "no privileged lane found: the guard is vacuous");
    for (label, launch) in privileged {
        for var in MUST_FORWARD {
            assert!(
                launch.forwarded.contains(var),
                "privileged lane {label:?} does not forward {var}: add \"{var}=${var}\" after `sudo env`"
            );
        }
    }
}
