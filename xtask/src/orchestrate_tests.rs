use clap::Parser;

use crate::manifest::*;
use crate::orchestrate::*;
use crate::Cli;

fn manifest(yaml: &str) -> Manifest {
    Manifest::parse(yaml).unwrap()
}

#[skuld::test]
fn plan_topologically_orders_deps_first() {
    let m = manifest(
        r"
targets:
  c:
    depends: b
    platforms: windows/amd64
  b:
    depends: a
    platforms: windows/amd64
  a:
    platforms: windows/amd64
",
    );
    let plan = Plan::new(&m).unwrap();
    let order = plan.order_for(&["c"], Platform::new(Os::Windows, Arch::Amd64)).unwrap();
    assert_eq!(order, vec!["a", "b", "c"]);
}

#[skuld::test]
fn plan_dedups_shared_transitive_deps() {
    // diamond: d -> b, d -> c, b -> a, c -> a; a should appear once.
    let m = manifest(
        r"
targets:
  a:
    platforms: windows/amd64
  b:
    depends: a
    platforms: windows/amd64
  c:
    depends: a
    platforms: windows/amd64
  d:
    depends: [b, c]
    platforms: windows/amd64
",
    );
    let plan = Plan::new(&m).unwrap();
    let order = plan.order_for(&["d"], Platform::new(Os::Windows, Arch::Amd64)).unwrap();
    let count_a = order.iter().filter(|&&n| n == "a").count();
    assert_eq!(count_a, 1, "expected `a` once, got order {order:?}");
    // a precedes b and c; b/c precede d.
    let pos = |name| order.iter().position(|&n| n == name).unwrap();
    assert!(pos("a") < pos("b"));
    assert!(pos("a") < pos("c"));
    assert!(pos("b") < pos("d"));
    assert!(pos("c") < pos("d"));
}

#[skuld::test]
fn deps_not_applicable_to_host_are_silently_skipped() {
    // Mirrors hole-on-darwin transitively reaching wintun (windows-only).
    let m = manifest(
        r"
targets:
  wintun:
    platforms: windows/amd64
  galoshes:
    platforms: [windows/amd64, darwin/amd64]
  hole:
    depends: [galoshes, wintun]
    platforms: [windows/amd64, darwin/amd64]
",
    );
    let plan = Plan::new(&m).unwrap();

    // Building hole on windows includes wintun.
    let win = plan
        .order_for(&["hole"], Platform::new(Os::Windows, Arch::Amd64))
        .unwrap();
    assert!(win.contains(&"wintun"));
    assert!(win.contains(&"galoshes"));
    assert!(win.contains(&"hole"));

    // Building hole on darwin silently skips wintun.
    let darwin = plan
        .order_for(&["hole"], Platform::new(Os::Darwin, Arch::Amd64))
        .unwrap();
    assert!(!darwin.contains(&"wintun"));
    assert!(darwin.contains(&"galoshes"));
    assert!(darwin.contains(&"hole"));
}

#[skuld::test]
fn root_target_must_apply_to_host_platform() {
    let m = manifest(
        r"
targets:
  hole-msi:
    platforms: windows/amd64
",
    );
    let plan = Plan::new(&m).unwrap();
    let err = plan
        .order_for(&["hole-msi"], Platform::new(Os::Darwin, Arch::Arm64))
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("hole-msi") && msg.contains("darwin/arm64"),
        "expected applicability error, got: {msg}"
    );
}

#[skuld::test]
fn unknown_root_target_errors() {
    let m = manifest(
        r"
targets:
  foo:
    platforms: windows/amd64
",
    );
    let plan = Plan::new(&m).unwrap();
    let err = plan
        .order_for(&["bogus"], Platform::new(Os::Windows, Arch::Amd64))
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("bogus"),
        "expected message naming unknown target, got: {msg}"
    );
}

#[skuld::test]
fn cycle_detection_self_loop() {
    let m = manifest(
        r"
targets:
  foo:
    depends: foo
    platforms: windows/amd64
",
    );
    let err = Plan::new(&m).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("cycle") && msg.contains("foo"),
        "expected cycle error naming foo, got: {msg}"
    );
}

#[skuld::test]
fn cycle_detection_two_node_cycle() {
    let m = manifest(
        r"
targets:
  a:
    depends: b
    platforms: windows/amd64
  b:
    depends: a
    platforms: windows/amd64
",
    );
    let err = Plan::new(&m).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("cycle") && (msg.contains("a") || msg.contains("b")),
        "expected cycle error, got: {msg}"
    );
}

#[skuld::test]
fn cycle_detection_three_node_cycle() {
    let m = manifest(
        r"
targets:
  a:
    depends: b
    platforms: windows/amd64
  b:
    depends: c
    platforms: windows/amd64
  c:
    depends: a
    platforms: windows/amd64
",
    );
    let err = Plan::new(&m).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("cycle"), "expected cycle error, got: {msg}");
}

#[skuld::test]
fn target_names_returns_declaration_order() {
    let m = manifest(
        r"
targets:
  zulu:
    platforms: windows/amd64
  alpha:
    platforms: windows/amd64
  mike:
    platforms: windows/amd64
",
    );
    let plan = Plan::new(&m).unwrap();
    assert_eq!(plan.target_names(), vec!["zulu", "alpha", "mike"]);
}

#[skuld::test]
fn order_for_multiple_roots_unions_their_subgraphs() {
    let m = manifest(
        r"
targets:
  a:
    platforms: windows/amd64
  b:
    platforms: windows/amd64
  x:
    depends: a
    platforms: windows/amd64
  y:
    depends: b
    platforms: windows/amd64
",
    );
    let plan = Plan::new(&m).unwrap();
    let order = plan
        .order_for(&["x", "y"], Platform::new(Os::Windows, Arch::Amd64))
        .unwrap();
    assert!(order.contains(&"a"));
    assert!(order.contains(&"b"));
    assert!(order.contains(&"x"));
    assert!(order.contains(&"y"));
    let pos = |name| order.iter().position(|&n| n == name).unwrap();
    assert!(pos("a") < pos("x"));
    assert!(pos("b") < pos("y"));
}

#[skuld::test]
fn render_list_shows_host_applicability_and_runnable() {
    let m = manifest(
        r"
targets:
  hole-msi:
    platforms: windows/amd64
  hole-dmg:
    platforms: [darwin/amd64, darwin/arm64]
  prek:
    platforms: windows/amd64
    run: prek run
",
    );
    let host = Platform::new(Os::Windows, Arch::Amd64);
    let out = render_list(&m, Some(host));
    // Header + one line per target.
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4);
    assert!(
        lines[0].contains("TARGET") && lines[0].contains("HOST") && lines[0].contains("RUN?"),
        "header missing column: {}",
        lines[0]
    );
    // Build-only target on host: yes / (empty run mark).
    assert!(lines[1].contains("hole-msi") && lines[1].contains(" yes "));
    assert!(
        !lines[1].trim_end().ends_with('*'),
        "hole-msi has no run: but is marked runnable: {}",
        lines[1]
    );
    // Build-only target off host: no / (empty run mark).
    assert!(lines[2].contains("hole-dmg") && lines[2].contains(" no "));
    // Runnable target: trailing `*` marker. trim_end to ignore any column padding.
    assert!(lines[3].contains("prek"));
    assert!(
        lines[3].trim_end().ends_with('*'),
        "prek declares run: but is not marked runnable: {}",
        lines[3]
    );
}

// `run_step` tests assume bash is available — Git Bash on Windows runners,
// system bash on macOS / Linux. These are unconditional: per CLAUDE.md, tests
// must not silently skip on missing dependencies.

#[skuld::test]
fn run_step_bash_succeeds_on_zero_exit() {
    let dir = tempfile::tempdir().unwrap();
    let step = Step::Bash {
        command: "true".to_string(),
        environment: Default::default(),
    };
    run_step(&step, dir.path()).unwrap();
}

#[skuld::test]
fn run_step_bash_fails_on_nonzero_exit() {
    let dir = tempfile::tempdir().unwrap();
    let step = Step::Bash {
        command: "exit 7".to_string(),
        environment: Default::default(),
    };
    let err = run_step(&step, dir.path()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("exit"), "expected exit-status error, got: {msg}");
}

#[skuld::test]
fn run_step_bash_environment_overrides_inherited() {
    // The step's `environment:` map should take effect (and also drive the
    // SKULD_LABELS-style usage in build.yaml).
    let dir = tempfile::tempdir().unwrap();
    let mut env = std::collections::HashMap::new();
    env.insert("HOLE_TEST_VAR".to_string(), "set-from-step".to_string());
    let step = Step::Bash {
        command: r#"[ "$HOLE_TEST_VAR" = "set-from-step" ]"#.to_string(),
        environment: env,
    };
    run_step(&step, dir.path()).unwrap();
}

#[skuld::test]
fn run_step_process_fails_on_nonzero_exit() {
    let dir = tempfile::tempdir().unwrap();
    // Use a command that's available on every CI platform via `cargo` (always
    // on PATH inside `cargo xtask` invocations), and force a non-zero exit by
    // requesting an unknown subcommand.
    let step = Step::Process {
        args: vec!["cargo".to_string(), "this-subcommand-does-not-exist".to_string()],
        environment: Default::default(),
    };
    let err = run_step(&step, dir.path()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("exit"), "expected exit-status error, got: {msg}");
}

#[skuld::test]
fn run_step_process_empty_args_errors() {
    let dir = tempfile::tempdir().unwrap();
    let step = Step::Process {
        args: vec![],
        environment: Default::default(),
    };
    let err = run_step(&step, dir.path()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("empty"), "expected empty-args error, got: {msg}");
}

// ===== execute_run ===================================================================================================
//
// `cargo xtask run <name>` semantics: build cascade for the target first, then
// the target's own `run:` steps. Runs do not depend on other runs.

fn host_platform() -> Platform {
    // Tests in this module use bash steps that only need a working shell, so
    // the actual host doesn't matter for behavior — we just need a `Platform`
    // that matches the synthetic manifests' `platforms:` lists. Resolve from
    // the real host so we don't accidentally encode the test host into the
    // manifest's platform set.
    Platform::host().expect("test host must be in the known platform set")
}

fn host_yaml() -> String {
    // String form of the host platform — `<os>/<arch>` — for use inside the
    // raw-YAML test fixtures.
    host_platform().to_string()
}

#[skuld::test]
fn execute_run_executes_build_cascade_then_run() {
    // Synthesize a target whose build step writes a sentinel file and whose
    // run step reads it back. If the build cascade is skipped, the run step
    // exits non-zero and the test fails.
    let dir = tempfile::tempdir().unwrap();
    let sentinel = dir.path().join("sentinel.txt");
    let sentinel_str = sentinel.to_string_lossy().replace('\\', "/");

    let yaml = format!(
        r#"
targets:
  foo:
    platforms: {host}
    build:
      - bash: 'echo built > "{sentinel}"'
    run:
      - bash: 'test "$(cat "{sentinel}")" = built'
"#,
        host = host_yaml(),
        sentinel = sentinel_str,
    );
    let m = Manifest::parse(&yaml).unwrap();
    let plan = Plan::new(&m).unwrap();
    execute_run(&plan, "foo", host_platform(), dir.path()).unwrap();
    // Sentinel must be on disk after run_run returns.
    assert!(sentinel.exists(), "expected build to have created sentinel");
}

#[skuld::test]
fn execute_run_does_not_cascade_other_runs() {
    // Pins the framework rule: "runs do not depend on other runs". A child
    // target depends on a parent for *build*; running the child must NOT
    // invoke the parent's `run:` steps.
    //
    // Setup: parent's run: writes a "parent-ran" file; child's run: writes a
    // "child-ran" file. After running child, only "child-ran" must exist.
    let dir = tempfile::tempdir().unwrap();
    let parent_marker = dir.path().join("parent-ran");
    let child_marker = dir.path().join("child-ran");
    let parent_str = parent_marker.to_string_lossy().replace('\\', "/");
    let child_str = child_marker.to_string_lossy().replace('\\', "/");

    let yaml = format!(
        r#"
targets:
  parent:
    platforms: {host}
    build:
      - bash: 'true'
    run:
      - bash: 'touch "{parent}"'
  child:
    depends: parent
    platforms: {host}
    build:
      - bash: 'true'
    run:
      - bash: 'touch "{child}"'
"#,
        host = host_yaml(),
        parent = parent_str,
        child = child_str,
    );
    let m = Manifest::parse(&yaml).unwrap();
    let plan = Plan::new(&m).unwrap();
    execute_run(&plan, "child", host_platform(), dir.path()).unwrap();

    assert!(child_marker.exists(), "child's run: must have executed");
    assert!(
        !parent_marker.exists(),
        "parent's run: must NOT have executed — runs do not cascade"
    );
}

#[skuld::test]
fn execute_run_errors_on_empty_run() {
    // A target with no `run:` steps cannot be run. Pin the exact message so
    // shell scripts piping into stderr stay stable.
    let m = manifest(&format!(
        r"
targets:
  build-only:
    platforms: {host}
    build: 'true'
",
        host = host_yaml(),
    ));
    let plan = Plan::new(&m).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let err = execute_run(&plan, "build-only", host_platform(), dir.path()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains(r#"target "build-only" has no run steps defined"#),
        "expected exact empty-run message, got: {msg}"
    );
}

#[skuld::test]
fn execute_run_errors_on_unknown_target() {
    let m = manifest(&format!(
        r"
targets:
  foo:
    platforms: {host}
",
        host = host_yaml(),
    ));
    let plan = Plan::new(&m).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let err = execute_run(&plan, "nonexistent", host_platform(), dir.path()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains(r#"unknown target: "nonexistent""#),
        "expected exact unknown-target message, got: {msg}"
    );
}

#[skuld::test]
fn execute_run_errors_on_platform_mismatch() {
    // Pick a non-host platform deterministically: if host is windows, use
    // darwin; otherwise use windows. The target declares only the non-host
    // platform, so order_for should reject it.
    let host = host_platform();
    let other = if host.os == Os::Windows {
        Platform::new(Os::Darwin, Arch::Arm64)
    } else {
        Platform::new(Os::Windows, Arch::Amd64)
    };

    let yaml = format!(
        r#"
targets:
  off-host:
    platforms: {other}
    run: 'true'
"#,
    );
    let m = Manifest::parse(&yaml).unwrap();
    let plan = Plan::new(&m).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let err = execute_run(&plan, "off-host", host, dir.path()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("does not apply to host platform") && msg.contains("off-host"),
        "expected platform-mismatch message, got: {msg}"
    );
}

#[skuld::test]
fn execute_run_aborts_on_build_failure() {
    // Build step returns non-zero. Run step would create a marker file; that
    // marker must NOT exist after the call (the build failure must abort
    // before any run step executes).
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran-anyway");
    let marker_str = marker.to_string_lossy().replace('\\', "/");

    let yaml = format!(
        r#"
targets:
  foo:
    platforms: {host}
    build:
      - bash: 'exit 7'
    run:
      - bash: 'touch "{marker}"'
"#,
        host = host_yaml(),
        marker = marker_str,
    );
    let m = Manifest::parse(&yaml).unwrap();
    let plan = Plan::new(&m).unwrap();
    let err = execute_run(&plan, "foo", host_platform(), dir.path()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("building target") && msg.contains("foo"),
        "expected build-context error, got: {msg}"
    );
    assert!(
        !marker.exists(),
        "run step executed despite build failure (marker file present)"
    );
}

#[skuld::test]
fn cycle_detection_diverging_cycle_lists_full_scc() {
    // `c -> b -> a -> b` (a points back to b, not c). c has an inbound edge
    // from outside the cycle (and the toposort error names some node in the
    // SCC). The error message must report all SCC members, not wander off
    // into the non-cycle tail.
    let m = Manifest::parse(
        r"
targets:
  a:
    depends: b
    platforms: windows/amd64
  b:
    depends: a
    platforms: windows/amd64
  c:
    depends: b
    platforms: windows/amd64
",
    )
    .unwrap();
    let err = Plan::new(&m).unwrap_err();
    let msg = format!("{err:#}");
    // The SCC is {a, b}; c is on a path leading to it but not part of the cycle.
    assert!(
        msg.contains("a") && msg.contains("b") && !msg.contains("\"c\""),
        "expected cycle to list a and b but not c, got: {msg}"
    );
}

// ===== CLI shape =====================================================================================================
//
// The framework explicitly forbids `cargo xtask run --all`; "run everything"
// is not a meaningful operation. Pin this at the clap-parse level so a
// future edit that adds `#[arg(long)] all: bool` to `Command::Run` is
// rejected by the test suite, not silently merged.

#[skuld::test]
fn cli_run_rejects_all_flag() {
    let err = match Cli::try_parse_from(["xtask", "run", "--all"]) {
        Ok(_) => panic!("expected --all to be rejected on the run subcommand"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("--all") || msg.contains("unexpected"),
        "expected --all to be rejected on the run subcommand, got: {msg}"
    );
}

#[skuld::test]
fn cli_run_requires_target_positional() {
    // No positional → clap MissingRequiredArgument. This pins that we use a
    // required positional rather than `Option<String>`-with-runtime-check.
    let err = match Cli::try_parse_from(["xtask", "run"]) {
        Ok(_) => panic!("expected `xtask run` (no positional) to be rejected"),
        Err(e) => e,
    };
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::MissingRequiredArgument,
        "expected MissingRequiredArgument, got: {:?}",
        err.kind()
    );
}
