//! Unit tests for guard 2's structural building blocks (bindreams/hole#894):
//! [`group_config`], [`job_list_template`], [`narrow_filter`], and
//! [`set_mismatch`]. `verify` itself is not unit-tested directly — every
//! piece of logic it orchestrates is covered here.

use std::collections::{BTreeMap, BTreeSet};

use crate::global_net_state_conformance::{group_config, job_list_template, narrow_filter, set_mismatch};
use crate::manifest::Manifest;

fn names(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn empty_manifest() -> Manifest {
    Manifest::parse("targets: {}").expect("empty manifest parses")
}

// ===== group_config ==================================================================================================

/// Two unrelated test-groups/overrides plus the target one — `group_config`
/// must find exactly the named group's `filter` and `max_threads`, ignoring
/// the others.
const FIXTURE_NEXTEST_TOML: &str = r#"
[test-groups.other_group]
max-threads = 4

[[profile.default.overrides]]
filter = 'test(/foo/)'
test-group = 'other_group'

[test-groups.global_net_state]
max-threads = 1

[[profile.default.overrides]]
filter = 'test(/bar/)'
test-group = 'global_net_state'

[[profile.default.overrides]]
filter = 'test(/baz/)'
test-group = 'yet_another'
"#;

#[skuld::test]
fn group_config_finds_filter_and_max_threads() {
    let cfg = group_config(FIXTURE_NEXTEST_TOML, "global_net_state").expect("find group config");
    assert_eq!(cfg.filter, "test(/bar/)");
    assert_eq!(cfg.max_threads, 1);
}

#[skuld::test]
fn group_config_errors_when_group_is_absent() {
    let err = group_config(FIXTURE_NEXTEST_TOML, "nonexistent_group").expect_err("should error");
    assert!(err.to_string().contains("nonexistent_group"), "{err}");
}

#[skuld::test]
fn group_config_errors_on_duplicate_override_entries() {
    let toml = r#"
[test-groups.global_net_state]
max-threads = 1

[[profile.default.overrides]]
filter = 'test(/bar/)'
test-group = 'global_net_state'

[[profile.default.overrides]]
filter = 'test(/qux/)'
test-group = 'global_net_state'
"#;
    let err = group_config(toml, "global_net_state").expect_err("should error");
    assert!(err.to_string().contains("global_net_state"), "{err}");
}

#[skuld::test]
fn group_config_errors_when_max_threads_is_missing() {
    let toml = r#"
[test-groups.global_net_state]

[[profile.default.overrides]]
filter = 'test(/bar/)'
test-group = 'global_net_state'
"#;
    let err = group_config(toml, "global_net_state").expect_err("should error");
    assert!(
        err.to_string().contains("max-threads") || err.to_string().contains("max_threads"),
        "{err}"
    );
}

// ===== job_list_template =============================================================================================

#[skuld::test]
fn job_list_template_errors_on_zero_commands() {
    let ci = r"
jobs:
  test-hole:
    steps:
      - run: echo hello
";
    let err = job_list_template(ci, &empty_manifest(), "test-hole").expect_err("should error");
    assert!(err.to_string().contains("test-hole"), "{err}");
}

#[skuld::test]
fn job_list_template_errors_when_commands_diverge_in_e_value() {
    let ci = r"
jobs:
  test-hole:
    steps:
      - run: cargo nextest run -p a -E 'package(a)'
      - run: cargo nextest run -p a -E 'package(b)'
";
    let err = job_list_template(ci, &empty_manifest(), "test-hole").expect_err("should error on -E divergence");
    assert!(
        err.to_string().contains("test-hole") || err.to_string().to_lowercase().contains("diverge"),
        "{err}"
    );
}

#[skuld::test]
fn job_list_template_returns_the_shared_argv_when_commands_agree() {
    let ci = r"
jobs:
  test-hole:
    steps:
      - run: cargo nextest run -p a -E 'package(a)'
      - run: cargo nextest run -p a -E 'package(a)'
";
    let template = job_list_template(ci, &empty_manifest(), "test-hole").expect("agree");
    assert_eq!(
        template,
        argv(&[
            "cargo",
            "nextest",
            "list",
            "--message-format",
            "json",
            "-p",
            "a",
            "-E",
            "package(a)"
        ])
    );
}

// ===== narrow_filter =================================================================================================

#[skuld::test]
fn narrow_filter_wraps_the_existing_e_flag_value() {
    let list_command = argv(&[
        "cargo",
        "nextest",
        "list",
        "--message-format",
        "json",
        "-E",
        "package(hole)",
    ]);
    let narrowed = narrow_filter(&list_command, "test(/foo/)").expect("narrow");
    assert_eq!(
        narrowed,
        argv(&[
            "cargo",
            "nextest",
            "list",
            "--message-format",
            "json",
            "-E",
            "(package(hole)) & (test(/foo/))"
        ])
    );
}

#[skuld::test]
fn narrow_filter_errors_without_an_e_flag() {
    let list_command = argv(&["cargo", "nextest", "list", "--message-format", "json", "-p", "a"]);
    let err = narrow_filter(&list_command, "test(/foo/)").expect_err("should error");
    assert!(err.to_string().contains("-E"), "{err}");
}

// ===== set_mismatch ==================================================================================================

fn binmap(entries: &[(&str, &[&str])]) -> BTreeMap<String, BTreeSet<String>> {
    entries.iter().map(|(k, v)| (k.to_string(), names(v))).collect()
}

#[skuld::test]
fn set_mismatch_reports_nothing_when_sets_are_equal_including_both_empty() {
    let name_matched = binmap(&[("hole-bridge", &["a", "b"]), ("tun-engine", &[])]);
    let label_matched = binmap(&[("hole-bridge", &["a", "b"]), ("tun-engine", &[])]);
    assert!(set_mismatch(&name_matched, &label_matched).is_empty());
}

#[skuld::test]
fn set_mismatch_reports_name_only_extras() {
    let name_matched = binmap(&[("hole-bridge", &["a", "b"])]);
    let label_matched = binmap(&[("hole-bridge", &["a"])]);
    let mismatches = set_mismatch(&name_matched, &label_matched);
    assert_eq!(mismatches.len(), 1);
    assert_eq!(mismatches["hole-bridge"], (names(&["b"]), names(&[])));
}

#[skuld::test]
fn set_mismatch_reports_label_only_extras() {
    let name_matched = binmap(&[("hole-bridge", &["a"])]);
    let label_matched = binmap(&[("hole-bridge", &["a", "c"])]);
    let mismatches = set_mismatch(&name_matched, &label_matched);
    assert_eq!(mismatches.len(), 1);
    assert_eq!(mismatches["hole-bridge"], (names(&[]), names(&["c"])));
}

#[skuld::test]
fn set_mismatch_reports_both_directions_simultaneously_per_binary() {
    let name_matched = binmap(&[("hole-bridge", &["a", "b"])]);
    let label_matched = binmap(&[("hole-bridge", &["a", "c"])]);
    let mismatches = set_mismatch(&name_matched, &label_matched);
    assert_eq!(mismatches.len(), 1);
    assert_eq!(mismatches["hole-bridge"], (names(&["b"]), names(&["c"])));
}

#[skuld::test]
fn set_mismatch_treats_a_binary_absent_from_one_map_as_empty_on_that_side() {
    let name_matched = binmap(&[("hole-bridge", &["a"])]);
    let label_matched: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mismatches = set_mismatch(&name_matched, &label_matched);
    assert_eq!(mismatches.len(), 1);
    assert_eq!(mismatches["hole-bridge"], (names(&["a"]), names(&[])));
}
