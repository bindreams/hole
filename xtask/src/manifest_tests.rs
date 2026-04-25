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
fn is_test_uses_name_suffix() {
    let m = parse(
        r"
targets:
  foo:
    platforms: windows/amd64
  foo-tests:
    platforms: windows/amd64
  foo-test:
    platforms: windows/amd64
  pretests:
    platforms: windows/amd64
",
    )
    .unwrap();
    // Only the exact `-tests` suffix qualifies as a test target. `-test`
    // (singular) and the bare suffix `tests` (no dash) are NOT test targets;
    // adding either by accident shouldn't silently flip CI behavior.
    assert!(!m.get("foo").unwrap().is_test());
    assert!(m.get("foo-tests").unwrap().is_test());
    assert!(!m.get("foo-test").unwrap().is_test());
    assert!(!m.get("pretests").unwrap().is_test());
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
    for name in ["v2ray-plugin", "galoshes", "hole", "hole-msi", "hole-dmg", "hole-tests"] {
        assert!(
            m.get(name).is_some(),
            "production build.yaml is missing expected target {name:?}"
        );
    }
}
