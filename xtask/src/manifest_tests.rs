use std::collections::HashMap;

use crate::manifest::*;

fn parse(yaml: &str) -> anyhow::Result<Manifest> {
    Manifest::parse(yaml)
}

#[skuld::test]
fn parses_minimal_manifest() {
    let m = parse(
        r"
targets:
  foo:
    platforms: windows/amd64
    build: echo hi
",
    )
    .unwrap();

    let foo = m.get("foo").unwrap();
    assert_eq!(foo.name, "foo");
    assert_eq!(foo.depends, Vec::<String>::new());
    assert_eq!(foo.platforms, vec![Platform::new(Os::Windows, Arch::Amd64)]);
    assert_eq!(
        foo.build,
        vec![Step::Bash {
            command: "echo hi".to_string(),
            environment: HashMap::new(),
        }]
    );
}

#[skuld::test]
fn depends_short_syntax_equals_list_syntax() {
    let single = parse(
        r"
targets:
  base:
    platforms: windows/amd64
  foo:
    depends: base
    platforms: windows/amd64
",
    )
    .unwrap();
    let listy = parse(
        r"
targets:
  base:
    platforms: windows/amd64
  foo:
    depends: [base]
    platforms: windows/amd64
",
    )
    .unwrap();

    assert_eq!(single.get("foo").unwrap().depends, vec!["base".to_string()]);
    assert_eq!(single.get("foo").unwrap().depends, listy.get("foo").unwrap().depends);
}

#[skuld::test]
fn build_short_syntax_equals_list_syntax() {
    let bare = parse(
        r#"
targets:
  foo:
    platforms: windows/amd64
    build: "echo hi"
"#,
    )
    .unwrap();
    let listed = parse(
        r#"
targets:
  foo:
    platforms: windows/amd64
    build:
      - bash: "echo hi"
"#,
    )
    .unwrap();

    assert_eq!(bare.get("foo").unwrap().build, listed.get("foo").unwrap().build);
}

#[skuld::test]
fn run_short_syntax_equals_list_syntax() {
    // `run:` reuses `BuildRaw`, so the same shorthand layers apply: bare string
    // ↔ `[bash: <string>]`. Pin to catch any divergence if the raw types ever
    // split.
    let bare = parse(
        r#"
targets:
  foo:
    platforms: windows/amd64
    run: "echo hi"
"#,
    )
    .unwrap();
    let listed = parse(
        r#"
targets:
  foo:
    platforms: windows/amd64
    run:
      - bash: "echo hi"
"#,
    )
    .unwrap();

    assert_eq!(bare.get("foo").unwrap().run, listed.get("foo").unwrap().run);
    assert_eq!(
        bare.get("foo").unwrap().run,
        vec![Step::Bash {
            command: "echo hi".to_string(),
            environment: HashMap::new(),
        }]
    );
}

#[skuld::test]
fn step_polymorphism_canonicalizes_uniformly() {
    let m = parse(
        r#"
targets:
  foo:
    platforms: windows/amd64
    build:
      - "echo a"
      - bash: "echo b"
      - bash:
          command: "echo c"
          environment: { K: V }
      - process: ["cargo", "build"]
      - process:
          args: ["go", "build"]
          environment: { GOOS: linux }
"#,
    )
    .unwrap();

    let steps = &m.get("foo").unwrap().build;
    assert_eq!(steps.len(), 5);

    // Three bash flavors → two with empty env, one with K=V.
    assert_eq!(
        steps[0],
        Step::Bash {
            command: "echo a".to_string(),
            environment: HashMap::new(),
        }
    );
    assert_eq!(
        steps[1],
        Step::Bash {
            command: "echo b".to_string(),
            environment: HashMap::new(),
        }
    );
    let mut env_kv = HashMap::new();
    env_kv.insert("K".to_string(), "V".to_string());
    assert_eq!(
        steps[2],
        Step::Bash {
            command: "echo c".to_string(),
            environment: env_kv,
        }
    );

    // Two process flavors → empty env vs explicit env.
    assert_eq!(
        steps[3],
        Step::Process {
            args: vec!["cargo".to_string(), "build".to_string()],
            environment: HashMap::new(),
        }
    );
    let mut env_goos = HashMap::new();
    env_goos.insert("GOOS".to_string(), "linux".to_string());
    assert_eq!(
        steps[4],
        Step::Process {
            args: vec!["go".to_string(), "build".to_string()],
            environment: env_goos,
        }
    );
}

#[skuld::test]
fn platforms_three_shapes_produce_same_set() {
    let scalar = parse(
        r"
targets:
  foo:
    platforms: windows/amd64
",
    )
    .unwrap();
    let list = parse(
        r"
targets:
  foo:
    platforms: [windows/amd64]
",
    )
    .unwrap();
    let matrix = parse(
        r"
targets:
  foo:
    platforms:
      matrix:
        os: [windows]
        arch: [amd64]
",
    )
    .unwrap();

    let expected = vec![Platform::new(Os::Windows, Arch::Amd64)];
    assert_eq!(scalar.get("foo").unwrap().platforms, expected);
    assert_eq!(list.get("foo").unwrap().platforms, expected);
    assert_eq!(matrix.get("foo").unwrap().platforms, expected);
}

#[skuld::test]
fn platform_matrix_is_cartesian_product() {
    let m = parse(
        r"
targets:
  foo:
    platforms:
      matrix:
        os: [windows, linux, darwin]
        arch: [amd64, arm64]
",
    )
    .unwrap();

    let plats = &m.get("foo").unwrap().platforms;
    assert_eq!(plats.len(), 6);
    for os in [Os::Windows, Os::Linux, Os::Darwin] {
        for arch in [Arch::Amd64, Arch::Arm64] {
            assert!(
                plats.contains(&Platform::new(os, arch)),
                "missing {os}/{arch} in matrix expansion"
            );
        }
    }
}

#[skuld::test]
fn platform_typo_rejected_at_parse_time() {
    let err = parse(
        r"
targets:
  foo:
    platforms: [windwos/amd64]
",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("windwos") || msg.contains("unknown os"),
        "expected typo rejection message, got: {msg}"
    );
}

#[skuld::test]
fn arch_typo_rejected_at_parse_time() {
    let err = parse(
        r"
targets:
  foo:
    platforms: [windows/x86_64]
",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("x86_64") || msg.contains("unknown arch"),
        "expected typo rejection message, got: {msg}"
    );
}

#[skuld::test]
fn missing_dep_is_an_error() {
    let err = parse(
        r"
targets:
  foo:
    depends: nonexistent
    platforms: windows/amd64
",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("foo") && msg.contains("nonexistent"),
        "expected message naming both target and missing dep, got: {msg}"
    );
}

#[skuld::test]
fn duplicate_platform_within_target_rejected() {
    let err = parse(
        r"
targets:
  foo:
    platforms: [windows/amd64, windows/amd64]
",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("more than once") && msg.contains("windows/amd64"),
        "expected dup-platform message, got: {msg}"
    );
}

#[skuld::test]
fn missing_platform_shape_is_rejected() {
    // platforms: is required.
    let err = parse(
        r"
targets:
  foo:
    build: echo hi
",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("platforms") || msg.contains("missing field"),
        "expected message about missing platforms field, got: {msg}"
    );
}

#[skuld::test]
fn target_with_no_build_steps_is_legal() {
    // Some targets (e.g. a hypothetical pure aggregator) might have no build
    // steps and just exist as a dep collector. The parser accepts this.
    let m = parse(
        r"
targets:
  foo:
    platforms: windows/amd64
",
    )
    .unwrap();
    assert_eq!(m.get("foo").unwrap().build, Vec::<Step>::new());
}

#[skuld::test]
fn target_with_no_run_steps_is_legal() {
    // The `run:` field is optional. Targets without it deserialize with an
    // empty `Vec<Step>`. `cargo xtask run X` will reject these at invocation
    // time (orchestrate_tests::run_run_errors_on_empty_run pins that), but
    // the manifest itself accepts them.
    let m = parse(
        r"
targets:
  foo:
    platforms: windows/amd64
    build: echo hi
",
    )
    .unwrap();
    assert_eq!(m.get("foo").unwrap().run, Vec::<Step>::new());
    assert!(!m.get("foo").unwrap().has_run());
}

#[skuld::test]
fn run_step_polymorphism_canonicalizes_uniformly() {
    // Mirrors `step_polymorphism_canonicalizes_uniformly` for `build:`.
    // `run:` reuses the same `Step`/`StepRaw` types, but pin the equivalence
    // explicitly: a future split (separate `RunStep`) would silently lose
    // shape parity.
    let m = parse(
        r#"
targets:
  foo:
    platforms: windows/amd64
    run:
      - "echo a"
      - bash: "echo b"
      - bash:
          command: "echo c"
          environment: { K: V }
      - process: ["cargo", "build"]
      - process:
          args: ["go", "build"]
          environment: { GOOS: linux }
"#,
    )
    .unwrap();

    let steps = &m.get("foo").unwrap().run;
    assert_eq!(steps.len(), 5);
    assert_eq!(
        steps[0],
        Step::Bash {
            command: "echo a".to_string(),
            environment: HashMap::new(),
        }
    );
    let mut env_kv = HashMap::new();
    env_kv.insert("K".to_string(), "V".to_string());
    assert_eq!(
        steps[2],
        Step::Bash {
            command: "echo c".to_string(),
            environment: env_kv,
        }
    );
    let mut env_goos = HashMap::new();
    env_goos.insert("GOOS".to_string(), "linux".to_string());
    assert_eq!(
        steps[4],
        Step::Process {
            args: vec!["go".to_string(), "build".to_string()],
            environment: env_goos,
        }
    );
}

#[skuld::test]
fn iter_preserves_declaration_order() {
    let m = parse(
        r"
targets:
  zulu:
    platforms: windows/amd64
  alpha:
    platforms: windows/amd64
  mike:
    platforms: windows/amd64
",
    )
    .unwrap();
    let names: Vec<&str> = m.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, vec!["zulu", "alpha", "mike"]);
}

#[skuld::test]
fn applies_to_filters_correctly() {
    let m = parse(
        r"
targets:
  win-only:
    platforms: windows/amd64
  multi:
    platforms: [windows/amd64, darwin/arm64]
",
    )
    .unwrap();

    let win = Platform::new(Os::Windows, Arch::Amd64);
    let darwin = Platform::new(Os::Darwin, Arch::Arm64);
    let linux = Platform::new(Os::Linux, Arch::Amd64);

    assert!(m.get("win-only").unwrap().applies_to(win));
    assert!(!m.get("win-only").unwrap().applies_to(darwin));
    assert!(!m.get("win-only").unwrap().applies_to(linux));

    assert!(m.get("multi").unwrap().applies_to(win));
    assert!(m.get("multi").unwrap().applies_to(darwin));
    assert!(!m.get("multi").unwrap().applies_to(linux));
}

#[skuld::test]
fn has_run_distinguishes_runnable_targets() {
    // `has_run()` replaces the old name-suffix-based `is_test()`. A target is
    // runnable iff it declares `run:` steps — independent of name. This is
    // the semantic shift that lets non-test targets (clippy, prek,
    // frontend-check, hole's dev mode) live in the manifest as first-class
    // runnables.
    let m = parse(
        r"
targets:
  build-only:
    platforms: windows/amd64
    build: echo build
  runnable:
    platforms: windows/amd64
    run: echo run
  both:
    platforms: windows/amd64
    build: echo build
    run: echo run
  empty:
    platforms: windows/amd64
",
    )
    .unwrap();
    assert!(!m.get("build-only").unwrap().has_run());
    assert!(m.get("runnable").unwrap().has_run());
    assert!(m.get("both").unwrap().has_run());
    assert!(!m.get("empty").unwrap().has_run());
}

#[skuld::test]
fn empty_matrix_os_axis_rejected() {
    let err = parse(
        r"
targets:
  foo:
    platforms:
      matrix:
        os: []
        arch: [amd64]
",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("os") && msg.contains("at least one"),
        "expected empty-matrix-os error, got: {msg}"
    );
}

#[skuld::test]
fn empty_matrix_arch_axis_rejected() {
    let err = parse(
        r"
targets:
  foo:
    platforms:
      matrix:
        os: [windows]
        arch: []
",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("arch") && msg.contains("at least one"),
        "expected empty-matrix-arch error, got: {msg}"
    );
}

#[skuld::test]
fn unknown_field_in_platform_matrix_rejected() {
    let err = parse(
        r"
targets:
  foo:
    platforms:
      matrix:
        os: [windows]
        arch: [amd64]
        typo: [x]
",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("typo") || msg.contains("unknown field"),
        "expected unknown-field rejection, got: {msg}"
    );
}

#[skuld::test]
fn production_build_yaml_parses() {
    // Regression guard: any change to build.yaml that breaks parsing or
    // structural validation (missing dep, typo'd platform, dup platform)
    // should fail this test, not silently break CI.
    let yaml = include_str!("../../build.yaml");
    let m = Manifest::parse(yaml).expect("production build.yaml must parse cleanly");
    // Sanity: a few targets we always expect to exist.
    for name in [
        "v2ray-plugin",
        "galoshes",
        "hole",
        "hole-msi",
        "hole-dmg",
        "hole-tests",
        "frontend-build",
        // Lint and check targets — proof that the manifest expresses non-test
        // runnables. Removing any of these would silently strip a CI gate.
        "clippy-hole",
        "clippy-ex-galoshes",
        "prek",
        "frontend-check",
    ] {
        assert!(
            m.get(name).is_some(),
            "production build.yaml is missing expected target {name:?}"
        );
    }

    // hole's `run:` is the canonical dev-mode entry point. The five `*-tests`
    // targets all carry a canonical local nextest invocation. Removing any of
    // these would re-fragment runner knowledge across CI / scripts / docs.
    assert!(m.get("hole").unwrap().has_run(), "hole must declare run: (dev mode)");
    for tests in [
        "hole-tests",
        "galoshes-tests",
        "garter-tests",
        "garter-bin-tests",
        "mock-plugin-tests",
    ] {
        assert!(
            m.get(tests).unwrap().has_run(),
            "{tests:?} must declare run: (canonical nextest invocation)"
        );
    }
}

#[skuld::test]
fn clippy_hole_target_shape() {
    let yaml = include_str!("../../build.yaml");
    let m = Manifest::parse(yaml).expect("production build.yaml must parse cleanly");
    let t = m.get("clippy-hole").expect("clippy-hole target missing");
    // Hole platforms only — non-Hole platforms gate workspace clippy on
    // `cfg(target_os)`-restricted crates that don't compile there.
    assert_eq!(
        t.platforms,
        vec![
            Platform::new(Os::Windows, Arch::Amd64),
            Platform::new(Os::Darwin, Arch::Amd64),
            Platform::new(Os::Darwin, Arch::Arm64),
        ]
    );
    assert!(t.build.is_empty(), "clippy targets have no separate build phase");
    assert_eq!(
        t.run,
        vec![Step::Bash {
            command: "cargo clippy --workspace --all-targets -- -D warnings".to_string(),
            environment: HashMap::new(),
        }]
    );
    assert_eq!(t.depends, Vec::<String>::new());
}

#[skuld::test]
fn prek_target_shape() {
    let yaml = include_str!("../../build.yaml");
    let m = Manifest::parse(yaml).expect("production build.yaml must parse cleanly");
    let t = m.get("prek").expect("prek target missing");
    // Full matrix: prek is platform-independent and devs on any host should
    // be able to run it locally.
    assert_eq!(t.platforms.len(), 6);
    assert!(t.build.is_empty());
    // SKIP=cargo-clippy is load-bearing — clippy lives in the per-platform
    // clippy-* targets, and prek would otherwise duplicate that work on
    // whatever single platform CI runs prek on.
    let mut env = HashMap::new();
    env.insert("SKIP".to_string(), "cargo-clippy".to_string());
    assert_eq!(
        t.run,
        vec![Step::Bash {
            command: "prek run --all-files --show-diff-on-failure".to_string(),
            environment: env,
        }]
    );
}

#[skuld::test]
fn frontend_check_target_shape() {
    let yaml = include_str!("../../build.yaml");
    let m = Manifest::parse(yaml).expect("production build.yaml must parse cleanly");
    let t = m.get("frontend-check").expect("frontend-check target missing");
    // Full matrix: tsc is platform-independent.
    assert_eq!(t.platforms.len(), 6);
    assert!(t.build.is_empty());
    assert_eq!(
        t.run,
        vec![
            Step::Bash {
                command: "npm ci --no-audit --no-fund".to_string(),
                environment: HashMap::new(),
            },
            Step::Bash {
                command: "npm run check".to_string(),
                environment: HashMap::new(),
            },
        ]
    );
    // No `depends: frontend-build`. tsc reads source files directly; the
    // Vite bundle is an artifact, not an input to the type-check.
    assert_eq!(t.depends, Vec::<String>::new());
}

#[skuld::test]
fn frontend_build_target_shape() {
    // The Renovate npm safety gate (see Frontend check CI job) depends on
    // `frontend-build` producing ui/dist/ on linux/amd64 with strict-lockfile
    // semantics. Pin the shape so a future edit can't silently weaken the gate.
    let yaml = include_str!("../../build.yaml");
    let m = Manifest::parse(yaml).expect("production build.yaml must parse cleanly");
    let t = m.get("frontend-build").expect("frontend-build target missing");

    assert_eq!(t.platforms, vec![Platform::new(Os::Linux, Arch::Amd64)]);
    assert_eq!(
        t.build,
        vec![
            Step::Bash {
                command: "npm ci --no-audit --no-fund".to_string(),
                environment: HashMap::new(),
            },
            Step::Bash {
                command: "npm run build".to_string(),
                environment: HashMap::new(),
            },
        ],
    );
    // Adding a `depends:` would silently start compiling Rust on every PR
    // (the gate is supposed to be JS-only). Adding a `run:` step would make
    // `cargo xtask run frontend-build` succeed with whatever side effect the
    // step has — `frontend-build` is an artifact target, not a runnable, so
    // pin both as load-bearing.
    assert_eq!(t.depends, Vec::<String>::new());
    assert!(!t.has_run());
}

#[skuld::test]
fn tests_targets_run_matches_build_minus_no_run() {
    // Each `*-tests` target's `run:` is the canonical local nextest invocation
    // — the same command line as its `build:` minus `--no-run`. CI doesn't
    // exercise these `run:` blocks (test-hole / test-garter / test-galoshes
    // use SKULD_LABELS / archive-based paths instead), so a typo in any of
    // them would only surface when a developer runs `cargo xtask run X-tests`.
    // Pin the symmetry here so a manifest edit that drifts run from build is
    // caught at unit-test time.
    let yaml = include_str!("../../build.yaml");
    let m = Manifest::parse(yaml).expect("production build.yaml must parse cleanly");

    for name in ["hole-tests", "galoshes-tests", "garter-tests", "garter-bin-tests", "mock-plugin-tests"] {
        let t = m.get(name).unwrap_or_else(|| panic!("{name:?} target missing"));
        assert_eq!(
            t.build.len(),
            1,
            "{name:?} build is expected to be a single nextest invocation"
        );
        assert_eq!(t.run.len(), 1, "{name:?} run is expected to be a single nextest invocation");
        let (Step::Bash { command: build_cmd, .. }, Step::Bash { command: run_cmd, .. }) = (&t.build[0], &t.run[0])
        else {
            panic!("{name:?}: build/run must be Bash steps");
        };
        // Trim and normalize whitespace before comparing — YAML's `>` folded
        // scalar collapses newlines into spaces, but the resulting strings can
        // still differ by trailing whitespace from line continuations.
        let build_normalized: String = build_cmd.split_whitespace().collect::<Vec<_>>().join(" ");
        let run_normalized: String = run_cmd.split_whitespace().collect::<Vec<_>>().join(" ");
        let expected_run = build_normalized.replace(" --no-run", "");
        assert_eq!(
            run_normalized, expected_run,
            "{name:?}: run command must equal build command with `--no-run` removed.\n  \
             build (normalized): {build_normalized:?}\n  \
             expected run: {expected_run:?}\n  \
             actual run (normalized): {run_normalized:?}"
        );
        // Sanity: build must contain --no-run, run must not.
        assert!(build_cmd.contains("--no-run"), "{name:?} build must contain --no-run");
        assert!(!run_cmd.contains("--no-run"), "{name:?} run must not contain --no-run");
    }
}
