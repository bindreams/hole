//! Unit tests for the `ci_toolchain_pins` scanners (against inline YAML, which
//! prove REACH — that the scanner actually walks a given YAML shape) plus the
//! `toolchain_pin_*` structural conformance tests (against the real repo,
//! which prove the repo currently satisfies what the scanners check).

use std::fs;

use crate::ci_toolchain_pins::{
    ci_config_files, env_scopes_of, files_installing_a_rust_toolchain, floating_go_sites,
    hand_rolled_rust_toolchain_sites, pin_step_scripts, steps_of, toolchain_env_sites,
};

/// Write `yaml` to a fresh temp file and return its path. The scanners take
/// `files: &[PathBuf]`, so an inline-YAML unit test needs a real file on disk.
fn temp_yaml(yaml: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("workflow.yaml");
    fs::write(&path, yaml).expect("write temp yaml");
    (dir, path)
}

// ===== unit: reach ===================================================================================================

#[skuld::test]
fn toolchain_pin_setup_go_step_with_a_go_version_key_is_reported() {
    let (_dir, path) = temp_yaml(
        r#"
jobs:
  build:
    steps:
      - uses: actions/setup-go@v7
        with:
          go-version: stable
"#,
    );
    let sites = floating_go_sites(std::slice::from_ref(&path)).expect("scan");
    assert_eq!(sites, vec![format!("{}:0", path.display())]);
}

#[skuld::test]
fn toolchain_pin_setup_go_step_in_a_flow_mapping_is_still_reported() {
    let (_dir, path) = temp_yaml(
        "jobs:\n  build:\n    steps:\n      - uses: actions/setup-go@v7\n        with: { go-version: stable }\n",
    );
    let sites = floating_go_sites(std::slice::from_ref(&path)).expect("scan");
    assert_eq!(sites, vec![format!("{}:0", path.display())]);
}

#[skuld::test]
fn toolchain_pin_setup_go_step_pointing_outside_ex_ray_is_reported() {
    let (_dir, path) = temp_yaml(
        r#"
jobs:
  build:
    steps:
      - uses: actions/setup-go@v7
        with:
          go-version-file: crates/ex-ray/third_party/v2ray-core/go.mod
"#,
    );
    let sites = floating_go_sites(std::slice::from_ref(&path)).expect("scan");
    assert_eq!(sites, vec![format!("{}:0", path.display())]);
}

#[skuld::test]
fn toolchain_pin_manual_rustup_install_in_a_run_step_is_reported() {
    let (_dir, path) = temp_yaml(
        r#"
jobs:
  build:
    steps:
      - run: rustup toolchain install stable
"#,
    );
    let sites = hand_rolled_rust_toolchain_sites(std::slice::from_ref(&path)).expect("scan");
    assert_eq!(sites, vec![format!("{}:0", path.display())]);
}

#[skuld::test]
fn toolchain_pin_a_third_party_rust_toolchain_action_is_reported() {
    let (_dir, path) = temp_yaml(
        r#"
jobs:
  build:
    steps:
      - uses: actions-rust-lang/setup-rust-toolchain@v1
"#,
    );
    let sites = hand_rolled_rust_toolchain_sites(std::slice::from_ref(&path)).expect("scan");
    assert_eq!(sites, vec![format!("{}:0", path.display())]);
}

#[skuld::test]
fn toolchain_pin_a_composite_action_shape_is_scanned() {
    // Without a dedicated `runs.steps[]` walk, a scanner that only reads
    // `jobs.*.steps[]` passes every real-repo test while never parsing a
    // composite action at all — `setup-build`, `setup-rust`, etc. are all
    // this shape.
    let (_dir, path) = temp_yaml(
        r#"
runs:
  steps:
    - uses: dtolnay/rust-toolchain@stable
"#,
    );
    let sites = hand_rolled_rust_toolchain_sites(std::slice::from_ref(&path)).expect("scan");
    assert_eq!(sites, vec![format!("{}:0", path.display())]);
}

#[skuld::test]
fn toolchain_pin_a_step_level_toolchain_env_override_is_reported() {
    let (_dir, path) = temp_yaml(
        r#"
jobs:
  build:
    steps:
      - run: echo hi
        env:
          GOTOOLCHAIN: latest
      - run: echo hi
        env:
          RUSTUP_TOOLCHAIN: nightly
"#,
    );
    let sites = toolchain_env_sites(std::slice::from_ref(&path)).expect("scan");
    assert_eq!(
        sites,
        vec![format!("{}:0", path.display()), format!("{}:1", path.display())]
    );
}

#[skuld::test]
fn toolchain_pin_a_job_level_toolchain_env_override_is_reported() {
    let (_dir, path) = temp_yaml(
        r#"
jobs:
  build:
    env:
      RUSTUP_TOOLCHAIN: nightly
    steps:
      - run: echo hi
"#,
    );
    let sites = toolchain_env_sites(std::slice::from_ref(&path)).expect("scan");
    assert_eq!(sites, vec![format!("{}:job build", path.display())]);
}

#[skuld::test]
fn toolchain_pin_a_workflow_level_toolchain_env_override_is_reported() {
    let (_dir, path) = temp_yaml(
        r#"
env:
  GOTOOLCHAIN: latest
jobs:
  build:
    steps:
      - run: echo hi
"#,
    );
    let sites = toolchain_env_sites(std::slice::from_ref(&path)).expect("scan");
    assert_eq!(sites, vec![format!("{}:workflow", path.display())]);
}

#[skuld::test]
fn toolchain_pin_a_conforming_setup_go_step_is_not_reported() {
    let (_dir, path) = temp_yaml(
        r#"
jobs:
  build:
    steps:
      - uses: actions/setup-go@v7
        with:
          go-version-file: crates/ex-ray/go.mod
"#,
    );
    let sites = floating_go_sites(&[path]).expect("scan");
    assert!(sites.is_empty(), "conforming setup-go step reported: {sites:?}");
}

// `env_scopes_of`/`steps_of` are exercised indirectly by every test above; this
// covers a document with all three env scopes present at once, which the
// site-detector tests never assemble in one file.
#[skuld::test]
fn steps_and_env_scopes_are_read_from_both_workflow_and_action_shapes() {
    let workflow = r#"
env:
  FOO: bar
jobs:
  build:
    env:
      BAZ: qux
    steps:
      - run: echo hi
        env:
          QUUX: corge
"#;
    let steps = steps_of(workflow).expect("parse steps");
    assert_eq!(steps.len(), 1);
    let scopes = env_scopes_of(workflow).expect("parse env scopes");
    assert_eq!(scopes.len(), 3, "workflow + job + step scopes: {scopes:?}");

    let action = "runs:\n  steps:\n    - run: echo hi\n    - uses: actions/checkout@v7\n";
    let steps = steps_of(action).expect("parse composite action steps");
    assert_eq!(steps.len(), 2);
}

// ===== conformance: the real repo ====================================================================================

#[skuld::test]
fn toolchain_pin_rust_installer_lives_only_in_setup_rust() {
    let root = crate::repo_root().expect("repo root");
    let files = ci_config_files(&root).expect("collect ci config files");
    let installers = files_installing_a_rust_toolchain(&files).expect("scan for rust toolchain installers");
    assert_eq!(
        installers,
        vec![root.join(".github/actions/setup-rust/action.yaml")],
        "a Rust toolchain must be installed only by ./.github/actions/setup-rust"
    );
}

#[skuld::test]
fn toolchain_pin_setup_rust_passes_the_channel_it_read() {
    let root = crate::repo_root().expect("repo root");
    let path = root.join(".github/actions/setup-rust/action.yaml");
    let yaml = fs::read_to_string(&path).expect("read setup-rust action.yaml");
    let steps = steps_of(&yaml).expect("parse setup-rust steps");
    let installer = steps
        .iter()
        .find(|s| {
            s.uses
                .as_deref()
                .is_some_and(|u| u.starts_with("dtolnay/rust-toolchain"))
        })
        .expect("setup-rust must contain a dtolnay/rust-toolchain step");
    let toolchain = installer
        .with
        .get("toolchain")
        .and_then(|v| v.as_str())
        .expect("dtolnay/rust-toolchain step must set with.toolchain to a string");
    assert!(
        toolchain.trim_start().starts_with("${{"),
        "with.toolchain must be an expression reading the pin file, not a literal like \
         {toolchain:?}"
    );
}

#[skuld::test]
fn toolchain_pin_setup_rust_reads_the_pin_file() {
    let root = crate::repo_root().expect("repo root");
    let yaml =
        fs::read_to_string(root.join(".github/actions/setup-rust/action.yaml")).expect("read setup-rust action.yaml");
    let scripts = pin_step_scripts(&yaml).expect("pin step scripts");
    assert!(
        scripts.iter().any(|s| s.contains("rust-toolchain.toml")),
        "no run: step in setup-rust reads rust-toolchain.toml; a `with.toolchain` expression \
         alone doesn't prove the installed compiler tracks the pin file. scripts={scripts:?}"
    );
}

#[skuld::test]
fn toolchain_pin_every_setup_go_step_reads_ex_ray_go_mod() {
    let root = crate::repo_root().expect("repo root");
    let files = ci_config_files(&root).expect("collect ci config files");
    let sites = floating_go_sites(&files).expect("scan for floating go versions");
    assert!(sites.is_empty(), "floating Go version at: {sites:?}");
}

#[skuld::test]
fn toolchain_pin_no_step_installs_a_toolchain_by_hand() {
    let root = crate::repo_root().expect("repo root");
    let files = ci_config_files(&root).expect("collect ci config files");
    let sites = hand_rolled_rust_toolchain_sites(&files).expect("scan for hand-rolled installs");
    assert!(sites.is_empty(), "hand-rolled Rust toolchain install at: {sites:?}");
}

#[skuld::test]
fn toolchain_pin_no_env_overrides_a_toolchain() {
    let root = crate::repo_root().expect("repo root");
    let files = ci_config_files(&root).expect("collect ci config files");
    let sites = toolchain_env_sites(&files).expect("scan for toolchain env overrides");
    assert!(sites.is_empty(), "GOTOOLCHAIN/RUSTUP_TOOLCHAIN override at: {sites:?}");
}

#[skuld::test]
fn toolchain_pin_rust_channel_is_fully_qualified() {
    let root = crate::repo_root().expect("repo root");
    let text = fs::read_to_string(root.join("rust-toolchain.toml")).expect("read rust-toolchain.toml");
    let channel = text
        .lines()
        .find_map(|line| {
            let rest = line.trim().strip_prefix("channel")?.trim_start();
            let rest = rest.strip_prefix('=')?.trim();
            let inner = rest.strip_prefix('"')?;
            inner.strip_suffix('"')
        })
        .expect("rust-toolchain.toml declares a `channel`");
    // A named channel (e.g. "stable") is a valid Renovate *range*, and the
    // default range strategy never moves a range — so an unqualified channel
    // would be an unmanaged float wearing a pin's clothes.
    let is_fully_qualified = channel.split('.').count() == 3
        && channel
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    assert!(
        is_fully_qualified,
        "rust-toolchain.toml's channel {channel:?} is not a fully-qualified X.Y.Z version"
    );
}
