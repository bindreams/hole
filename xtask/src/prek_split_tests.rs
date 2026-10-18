//! Unit tests for the lint split plus the conformance tests that hold the real
//! `.github/lint.toml`, `prek.toml` and `ci.yaml` to it.

use std::collections::BTreeSet;
use std::fs;

use crate::prek_split::{hook_ids, LintSplit, CLIPPY_HOOK};

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

const PREK: &str = r#"
[[repos]]
repo = "local"

[[repos.hooks]]
id = "cargo-clippy"

[[repos.hooks]]
id = "go-lint"

[[repos.hooks]]
id = "ty"

[[repos]]
repo = "https://example.invalid/hooks"
rev = "v1"
hooks = [
  { id = "inline-a" },
  { id = "inline-b", args = ["--x"] },
]

[[repos]]
repo = "https://example.invalid/fmt"
rev = "v1"

[[repos.hooks]]
id = "twice"

[[repos.hooks]]
id = "twice"
name = "second config of the same hook"
"#;

// ===== hook_ids ======================================================================================================

#[skuld::test]
fn hook_ids_cover_table_form_and_inline_form_and_dedupe() {
    assert_eq!(
        hook_ids(PREK).unwrap(),
        set(&["cargo-clippy", "go-lint", "ty", "inline-a", "inline-b", "twice"])
    );
}

// ===== LintSplit =====================================================================================================

fn split(lint_toml: &str) -> anyhow::Result<LintSplit> {
    LintSplit::parse(lint_toml, PREK)
}

#[skuld::test]
fn the_listed_hooks_are_the_platform_dependent_ones() {
    let s = split(r#"platform-dependent = ["go-lint", "inline-a"]"#).unwrap();
    assert_eq!(s.platform_dependent(), ["go-lint", "inline-a"]);
}

/// A listed id that no hook has would silently run nothing on every leg, so it
/// is an error that names the id.
#[skuld::test]
fn a_listed_id_that_is_not_a_hook_is_an_error() {
    let err = split(r#"platform-dependent = ["go-lint", "go-lnt"]"#).unwrap_err();
    assert!(format!("{err:#}").contains("go-lnt"), "{err:#}");
}

/// A typo in the key would make the list empty and every hook run once; a
/// missing or extra key is an error, not an empty list.
#[skuld::test]
fn a_missing_or_unknown_key_is_an_error() {
    assert!(split("").is_err());
    assert!(split(r#"platform-dependant = ["go-lint"]"#).is_err());
    assert!(split("platform-dependent = [\"go-lint\"]\nother = 1").is_err());
    assert!(split(r#"platform-dependent = "go-lint""#).is_err());
}

#[skuld::test]
fn an_empty_list_is_allowed_and_means_every_hook_runs_once() {
    let s = split("platform-dependent = []").unwrap();
    assert!(s.platform_dependent().is_empty());
    assert_eq!(s.platform_dependent_args(), None, "nothing to run on every leg");
    assert_eq!(
        s.portable_args(),
        ["run", "--all-files", "--show-diff-on-failure", "--skip", "cargo-clippy"]
    );
}

/// The portable run skips what runs elsewhere: the listed hooks (every leg) and
/// `cargo-clippy` (the per-leg `clippy-*` steps). The per-leg run names exactly
/// the listed hooks. Both come from the one list.
#[skuld::test]
fn both_runs_are_derived_from_the_one_list() {
    let s = split(r#"platform-dependent = ["go-lint", "inline-a"]"#).unwrap();
    assert_eq!(
        s.portable_args(),
        [
            "run",
            "--all-files",
            "--show-diff-on-failure",
            "--skip",
            "cargo-clippy",
            "--skip",
            "go-lint",
            "--skip",
            "inline-a"
        ]
    );
    assert_eq!(
        s.platform_dependent_args().unwrap(),
        ["run", "go-lint", "inline-a", "--all-files", "--show-diff-on-failure"]
    );
}

/// The portable run skips `cargo-clippy` by id. If prek.toml renames or drops it,
/// that skip would be stale: clippy would run a second time in the portable step
/// or prek would ignore the unknown id, depending on prek.
#[skuld::test]
fn a_prek_toml_without_the_clippy_hook_is_an_error() {
    let prek = r#"
[[repos]]
repo = "local"

[[repos.hooks]]
id = "go-lint"
"#;
    let err = LintSplit::parse(r#"platform-dependent = ["go-lint"]"#, prek).unwrap_err();
    assert!(format!("{err:#}").contains(CLIPPY_HOOK), "{err:#}");
}

/// A hook cannot be both the clippy steps' and the per-leg run's: it would run
/// twice per leg while the portable run skips it once.
#[skuld::test]
fn listing_the_clippy_hook_as_platform_dependent_is_an_error() {
    let err = split(r#"platform-dependent = ["cargo-clippy"]"#).unwrap_err();
    assert!(format!("{err:#}").contains(CLIPPY_HOOK), "{err:#}");
}

#[skuld::test]
fn a_duplicate_id_is_listed_once() {
    let s = split(r#"platform-dependent = ["go-lint", "go-lint"]"#).unwrap();
    assert_eq!(s.platform_dependent(), ["go-lint"]);
}

// ===== conformance ===================================================================================================

fn read_repo(rel: &str) -> String {
    let root = crate::repo_root().expect("repo root");
    fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// `.github/lint.toml` lists only hooks `prek.toml` has. Every other hook is
/// portable by default, so a new hook needs no entry anywhere.
#[skuld::test]
fn the_repo_lint_toml_lists_only_real_hooks() {
    let s = LintSplit::parse(&read_repo(".github/lint.toml"), &read_repo("prek.toml")).expect("lint.toml");
    assert!(
        !s.platform_dependent().is_empty(),
        "go-lint is platform-dependent (see the evidence in lint.toml); an empty list drops its per-leg run"
    );
}

/// Every hook of the real `prek.toml` runs on exactly one of three paths: the
/// portable run (every hook it does not skip), the per-leg platform-dependent
/// run, or the per-leg `clippy-*` steps. The test reads the hooks off the real
/// file and the skips off the real argv, so a rename in either place breaks it.
#[skuld::test]
fn every_real_hook_runs_on_exactly_one_path() {
    let hooks = hook_ids(&read_repo("prek.toml")).expect("hook ids");
    let s = LintSplit::parse(&read_repo(".github/lint.toml"), &read_repo("prek.toml")).expect("lint.toml");

    let portable = s.portable_args();
    let skipped: BTreeSet<String> = portable
        .windows(2)
        .filter(|w| w[0] == "--skip")
        .map(|w| w[1].clone())
        .collect();
    let portable_runs: BTreeSet<String> = hooks.difference(&skipped).cloned().collect();
    let platform_dependent: BTreeSet<String> = s.platform_dependent().iter().cloned().collect();
    let clippy: BTreeSet<String> = set(&[CLIPPY_HOOK]);

    assert!(
        skipped.is_subset(&hooks),
        "the portable run skips ids prek.toml lacks: {:?}",
        skipped.difference(&hooks).collect::<Vec<_>>()
    );
    for (a, b, names) in [
        (&portable_runs, &platform_dependent, "portable and platform-dependent"),
        (&portable_runs, &clippy, "portable and clippy"),
        (&platform_dependent, &clippy, "platform-dependent and clippy"),
    ] {
        assert!(
            a.is_disjoint(b),
            "{names} both run {:?}",
            a.intersection(b).collect::<Vec<_>>()
        );
    }
    let covered: BTreeSet<String> = portable_runs
        .iter()
        .chain(&platform_dependent)
        .chain(&clippy)
        .cloned()
        .collect();
    assert_eq!(covered, hooks, "a hook runs on no path");
}

/// CI runs the two derived commands and nothing hand-listed: the portable one
/// on the `portable-lint` leg, the platform-dependent one on every leg.
#[skuld::test]
fn ci_runs_the_derived_prek_commands() {
    let ci_yaml = read_repo(".github/workflows/ci.yaml");
    let runs = crate::ci_platform_coverage::step_runs(&ci_yaml, "ci").expect("step runs");
    assert_eq!(runs["lint"].trim(), "cargo xtask prek portable");
    assert_eq!(
        runs["lint-platform-dependent"].trim(),
        "cargo xtask prek platform-dependent"
    );
}
