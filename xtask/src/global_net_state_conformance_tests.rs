//! Unit tests for guard 2's structural building blocks (bindreams/hole#894):
//! [`group_config`], [`job_list_template`], [`narrow_filter`], and
//! [`set_mismatch`] — and guard 3's (bindreams/hole#999):
//! [`junit_executed_tests`], [`merge_executed`], and [`set_missing`].
//! `verify`/`verify_executed` themselves are not unit-tested directly — every
//! piece of logic they orchestrate is covered here.

use std::collections::{BTreeMap, BTreeSet};

use crate::global_net_state_conformance::{
    group_config, job_list_template, junit_executed_tests, merge_executed, narrow_filter, set_mismatch, set_missing,
};
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

// ===== junit_executed_tests (bindreams/hole#999) =====================================================================

#[skuld::test]
fn junit_executed_tests_collects_passed_and_failed_but_not_skipped() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="hole-bridge">
    <testcase classname="hole-bridge" name="passed_test" time="0.1"/>
    <testcase classname="hole-bridge" name="failed_test" time="0.1">
      <failure message="assertion failed">details</failure>
    </testcase>
    <testcase classname="hole-bridge" name="skipped_test" time="0.0">
      <skipped/>
    </testcase>
  </testsuite>
</testsuites>
"#;
    let executed = junit_executed_tests(xml).expect("parse");
    assert_eq!(executed["hole-bridge"], names(&["passed_test", "failed_test"]));
}

#[skuld::test]
fn junit_executed_tests_groups_by_classname_across_multiple_testsuites() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="hole-bridge">
    <testcase classname="hole-bridge" name="a"/>
  </testsuite>
  <testsuite name="tun-engine">
    <testcase classname="tun-engine" name="b"/>
  </testsuite>
</testsuites>
"#;
    let executed = junit_executed_tests(xml).expect("parse");
    assert_eq!(executed.len(), 2);
    assert_eq!(executed["hole-bridge"], names(&["a"]));
    assert_eq!(executed["tun-engine"], names(&["b"]));
}

#[skuld::test]
fn junit_executed_tests_errors_on_malformed_xml() {
    let err = junit_executed_tests("not xml at all <<<").expect_err("should error");
    assert!(
        err.to_string().to_lowercase().contains("xml") || err.to_string().contains("parsing"),
        "{err}"
    );
}

#[skuld::test]
fn junit_executed_tests_errors_when_testcase_has_no_classname() {
    let xml = r#"<testsuites><testsuite><testcase name="a"/></testsuite></testsuites>"#;
    let err = junit_executed_tests(xml).expect_err("should error");
    assert!(err.to_string().contains("classname"), "{err}");
}

#[skuld::test]
fn junit_executed_tests_errors_when_testcase_has_no_name() {
    let xml = r#"<testsuites><testsuite><testcase classname="hole-bridge"/></testsuite></testsuites>"#;
    let err = junit_executed_tests(xml).expect_err("should error");
    assert!(err.to_string().contains("name"), "{err}");
}

#[skuld::test]
fn junit_executed_tests_returns_empty_map_for_a_report_with_no_testcases() {
    let xml = r#"<testsuites><testsuite name="empty"></testsuite></testsuites>"#;
    let executed = junit_executed_tests(xml).expect("parse");
    assert!(executed.is_empty());
}

// ===== merge_executed (bindreams/hole#999) ===========================================================================

#[skuld::test]
fn merge_executed_unions_names_within_a_shared_binary_id() {
    // The real motivating case: a mocked test runs only in the non-TUN
    // step's report, a privileged one only in the TUN step's — both must
    // survive the merge even though neither report alone has both.
    let non_tun = binmap(&[("tun-engine", &["mocked_release_all_test"])]);
    let tun = binmap(&[("tun-engine", &["privileged_gateway_test"])]);
    let merged = merge_executed([non_tun, tun]);
    assert_eq!(
        merged["tun-engine"],
        names(&["mocked_release_all_test", "privileged_gateway_test"])
    );
}

#[skuld::test]
fn merge_executed_unions_across_different_binary_ids() {
    let a = binmap(&[("hole-bridge", &["x"])]);
    let b = binmap(&[("tun-engine::gateway_privileged", &["y"])]);
    let merged = merge_executed([a, b]);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged["hole-bridge"], names(&["x"]));
    assert_eq!(merged["tun-engine::gateway_privileged"], names(&["y"]));
}

#[skuld::test]
fn merge_executed_of_a_single_map_is_that_map() {
    let only = binmap(&[("hole-bridge", &["a", "b"])]);
    let merged = merge_executed([only.clone()]);
    assert_eq!(merged, only);
}

#[skuld::test]
fn merge_executed_of_zero_maps_is_empty() {
    let merged = merge_executed(Vec::<BTreeMap<String, BTreeSet<String>>>::new());
    assert!(merged.is_empty());
}

#[skuld::test]
fn merge_executed_deduplicates_a_name_present_in_more_than_one_map() {
    // A test that happens to run in both partitions (e.g. TUN and non-TUN,
    // were that ever true for one test) must not produce a duplicate — sets
    // already guarantee this, but pin it as the documented behavior.
    let a = binmap(&[("hole-bridge", &["a"])]);
    let b = binmap(&[("hole-bridge", &["a"])]);
    let merged = merge_executed([a, b]);
    assert_eq!(merged["hole-bridge"], names(&["a"]));
}

// ===== set_missing (bindreams/hole#999) ==============================================================================

#[skuld::test]
fn set_missing_is_empty_when_every_expected_test_was_executed() {
    let expected = binmap(&[("hole-bridge", &["a", "b"])]);
    let executed = binmap(&[("hole-bridge", &["a", "b", "c"])]);
    assert!(set_missing(&expected, &executed).is_empty());
}

#[skuld::test]
fn set_missing_reports_expected_tests_absent_from_execution() {
    let expected = binmap(&[("hole-bridge", &["a", "b"])]);
    let executed = binmap(&[("hole-bridge", &["a"])]);
    let missing = set_missing(&expected, &executed);
    assert_eq!(missing.len(), 1);
    assert_eq!(missing["hole-bridge"], names(&["b"]));
}

#[skuld::test]
fn set_missing_treats_a_binary_absent_from_executed_as_entirely_missing() {
    let expected = binmap(&[("hole-bridge", &["a"])]);
    let executed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let missing = set_missing(&expected, &executed);
    assert_eq!(missing.len(), 1);
    assert_eq!(missing["hole-bridge"], names(&["a"]));
}

#[skuld::test]
fn set_missing_ignores_tests_executed_but_not_expected() {
    // `executed` may legitimately be a superset (e.g. other labels ran in the
    // same job) — only the expected → executed direction matters here.
    let expected = binmap(&[("hole-bridge", &["a"])]);
    let executed = binmap(&[("hole-bridge", &["a", "z"])]);
    assert!(set_missing(&expected, &executed).is_empty());
}
