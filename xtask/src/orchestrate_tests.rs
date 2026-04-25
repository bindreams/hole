use crate::manifest::*;
use crate::orchestrate::*;

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
fn verb_partition_splits_on_tests_suffix() {
    let m = manifest(
        r"
targets:
  hole:
    platforms: windows/amd64
  hole-tests:
    platforms: windows/amd64
  galoshes:
    platforms: windows/amd64
  galoshes-tests:
    platforms: windows/amd64
",
    );
    let plan = Plan::new(&m).unwrap();

    let build_targets = plan.targets_for_verb(Verb::Build);
    assert_eq!(build_targets, vec!["hole", "galoshes"]);
    let test_targets = plan.targets_for_verb(Verb::Test);
    assert_eq!(test_targets, vec!["hole-tests", "galoshes-tests"]);
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
fn render_list_shows_host_applicability() {
    let m = manifest(
        r"
targets:
  hole-msi:
    platforms: windows/amd64
  hole-dmg:
    platforms: [darwin/amd64, darwin/arm64]
",
    );
    let host = Platform::new(Os::Windows, Arch::Amd64);
    let out = render_list(&m, Some(host));
    // Header + one line per target.
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("TARGET") && lines[0].contains("HOST"));
    assert!(lines[1].contains("hole-msi") && lines[1].ends_with("yes"));
    assert!(lines[2].contains("hole-dmg") && lines[2].ends_with("no"));
}

#[skuld::test]
fn run_step_bash_succeeds_on_zero_exit() {
    // Trivial bash command. Skipped on platforms without bash on PATH.
    if which_bash_exists() {
        let dir = tempfile::tempdir().unwrap();
        let step = Step::Bash {
            command: "true".to_string(),
            environment: Default::default(),
        };
        run_step(&step, dir.path()).unwrap();
    }
}

#[skuld::test]
fn run_step_bash_fails_on_nonzero_exit() {
    if which_bash_exists() {
        let dir = tempfile::tempdir().unwrap();
        let step = Step::Bash {
            command: "exit 7".to_string(),
            environment: Default::default(),
        };
        let err = run_step(&step, dir.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("exit"), "expected exit-status error, got: {msg}");
    }
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

fn which_bash_exists() -> bool {
    std::process::Command::new("bash")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
