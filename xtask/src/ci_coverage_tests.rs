//! Unit tests for the token extractors plus the `every_workspace_crate_runs_in_ci`
//! structural conformance test (the anti-orphan gate, #526).

use std::collections::BTreeSet;
use std::fs;

use crate::ci_coverage::{ci_run_packages, package_tokens};
use crate::manifest::Manifest;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

// ===== package_tokens ================================================================================================

#[skuld::test]
fn package_tokens_from_filter_expression() {
    assert_eq!(
        package_tokens("cargo nextest run -E 'package(a) + package(b)'"),
        set(&["a", "b"])
    );
}

#[skuld::test]
fn package_tokens_from_dash_p() {
    assert_eq!(
        package_tokens("cargo nextest archive -p garter -p garter-bin"),
        set(&["garter", "garter-bin"])
    );
}

#[skuld::test]
fn package_tokens_mixed_forms() {
    assert_eq!(
        package_tokens("cargo nextest run -p util -E 'package(hole) + package(dump)'"),
        set(&["util", "hole", "dump"])
    );
}

#[skuld::test]
fn package_tokens_ignores_feature_paths() {
    // The real test-hole invocation: `--features tombstone/crash-dumps,…` must
    // NOT contribute a bogus token, but `package(tombstone)` must still yield
    // `tombstone`. A slash-bearing feature path is not a valid package name.
    let cmd = "cargo nextest run --no-default-features \
        --features tombstone/crash-dumps,tombstone/crash-child \
        -E 'package(hole) + package(hole-bridge) + package(tombstone)'";
    assert_eq!(package_tokens(cmd), set(&["hole", "hole-bridge", "tombstone"]));
}

#[skuld::test]
fn package_tokens_empty_when_none() {
    assert_eq!(package_tokens("cargo build --release"), BTreeSet::new());
}

// ===== ci_run_packages ===============================================================================================

fn fixture_manifest() -> Manifest {
    // `foo-tests` build names a DIFFERENT package (`foo-build-only`) than its
    // run, so resolving it via `cargo xtask run` must yield only `foo` — the
    // `--no-run` build must not leak `foo-build-only`. `lint-only` mimics a
    // clippy target: a `-p`-bearing command that is not a test run.
    Manifest::parse(
        r"
targets:
  foo-tests:
    platforms: windows/amd64
    build: cargo nextest run --no-run -p foo-build-only
    run: cargo nextest run -p foo
  bar-tests:
    platforms: windows/amd64
    run: cargo nextest run -E 'package(bar) + package(bar-extra)'
  lint-only:
    platforms: windows/amd64
    run: cargo clippy -p linted-pkg --all-targets -- -D warnings
",
    )
    .expect("fixture manifest parses")
}

#[skuld::test]
fn ci_run_packages_direct_nextest_run() {
    let ci = r"
jobs:
  test:
    steps:
      - name: Run tests
        run: cargo nextest run -E 'package(a) + package(b)'
";
    assert_eq!(ci_run_packages(ci, &fixture_manifest()).unwrap(), set(&["a", "b"]));
}

#[skuld::test]
fn ci_run_packages_ignores_archive_and_no_run() {
    // `cargo nextest archive` builds but does not RUN; `--no-run` likewise.
    let ci = r"
jobs:
  build:
    steps:
      - run: cargo nextest archive -p a -p b --archive-file x.tar.zst
      - run: cargo nextest run --no-run -p c
";
    assert_eq!(ci_run_packages(ci, &fixture_manifest()).unwrap(), BTreeSet::new());
}

#[skuld::test]
fn ci_run_packages_matches_cargo_nextest_spelling() {
    // The archive-lane test jobs invoke `cargo-nextest nextest run` (binary
    // name, then subcommand), not `cargo nextest run`. Both must be recognized
    // as test runs — missing this is how test-garter/test-galoshes were
    // silently uncredited.
    let ci = r"
jobs:
  test:
    steps:
      - run: |
          mkdir -p target/debug
          cargo-nextest nextest run --archive-file x.tar.zst -E 'package(a)'
";
    assert_eq!(ci_run_packages(ci, &fixture_manifest()).unwrap(), set(&["a"]));
}

#[skuld::test]
fn ci_run_packages_resolves_xtask_run_target() {
    // `cargo xtask run foo-tests` must contribute `foo` from the target's RUN
    // command only. Its `--no-run` build names `foo-build-only`, which must NOT
    // leak in — building is not running.
    let ci = r"
jobs:
  e2e:
    steps:
      - run: cargo xtask run foo-tests
";
    assert_eq!(ci_run_packages(ci, &fixture_manifest()).unwrap(), set(&["foo"]));
}

#[skuld::test]
fn ci_run_packages_does_not_credit_clippy_p_flags() {
    // `cargo xtask run lint-only` resolves to a `cargo clippy -p linted-pkg`
    // command. Clippy compiles, it does not run tests — `linted-pkg` must not
    // be credited. Counting it would let a merely-linted crate masquerade as
    // test-covered (the #513 self-fulfilling-filter trap).
    let ci = r"
jobs:
  lint:
    steps:
      - run: cargo xtask run lint-only
";
    assert_eq!(ci_run_packages(ci, &fixture_manifest()).unwrap(), BTreeSet::new());
}

#[skuld::test]
fn ci_run_packages_splits_multi_statement_run_block() {
    // A `run:` block is a shell script: the leading `mkdir` must not swallow the
    // nextest command that follows it on the next line / after `&&`.
    let ci = r"
jobs:
  test:
    steps:
      - run: |
          mkdir -p target/debug
          cargo nextest run -p a && echo done
";
    assert_eq!(ci_run_packages(ci, &fixture_manifest()).unwrap(), set(&["a"]));
}

#[skuld::test]
fn ci_run_packages_unions_across_jobs_and_steps() {
    let ci = r"
jobs:
  one:
    steps:
      - run: cargo nextest run -p direct
  two:
    steps:
      - run: cargo xtask run bar-tests
";
    assert_eq!(
        ci_run_packages(ci, &fixture_manifest()).unwrap(),
        set(&["direct", "bar", "bar-extra"])
    );
}

// ===== Structural conformance: every workspace crate runs in CI ======================================================

/// Workspace crates that legitimately run on no CI test job, each with a reason.
///
/// HYGIENE (enforced below): every entry must be a real workspace member AND
/// must NOT already be covered. If a crate gains CI coverage, delete its entry —
/// a stale allowlist would mask a future regression (the #513 "no
/// self-fulfilling filter" rule).
const UNTESTED_IN_CI: &[(&str, &str)] = &[];

#[skuld::test]
fn every_workspace_crate_runs_in_ci() {
    let root = crate::repo_root().expect("repo root");

    let metadata = cargo_metadata::MetadataCommand::new()
        .manifest_path(root.join("Cargo.toml"))
        .no_deps()
        .exec()
        .expect("cargo metadata");
    let members: BTreeSet<String> = metadata
        .workspace_packages()
        .iter()
        .map(|p| p.name.to_string())
        .collect();

    let manifest = Manifest::parse(&fs::read_to_string(root.join("build.yaml")).expect("read build.yaml"))
        .expect("parse build.yaml");
    let ci_yaml = fs::read_to_string(root.join(".github/workflows/ci.yaml")).expect("read ci.yaml");
    let covered = ci_run_packages(&ci_yaml, &manifest).expect("compute CI coverage");

    let allowlisted: BTreeSet<String> = UNTESTED_IN_CI.iter().map(|(name, _)| name.to_string()).collect();

    // Every member must be covered by a CI test job or explicitly allowlisted.
    let uncovered: Vec<&String> = members
        .iter()
        .filter(|m| !covered.contains(*m) && !allowlisted.contains(*m))
        .collect();
    assert!(
        uncovered.is_empty(),
        "these workspace crates run on no CI test job and are not allowlisted: {uncovered:?}\n\
         add a CI test job or an UNTESTED_IN_CI entry (with a reason)"
    );

    // Allowlist hygiene: no phantom entries (must be a real member) ...
    for (name, _) in UNTESTED_IN_CI {
        assert!(
            members.contains(*name),
            "UNTESTED_IN_CI lists {name:?}, which is not a workspace member — remove the stale entry"
        );
    }
    // ... and no stale entries (a now-covered crate must lose its exemption).
    for (name, _) in UNTESTED_IN_CI {
        assert!(
            !covered.contains(*name),
            "UNTESTED_IN_CI lists {name:?}, but CI now runs it — remove the stale allowlist entry"
        );
    }
}
