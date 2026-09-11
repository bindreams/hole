//! Unit tests for guard 2's structural building blocks (bindreams/hole#894):
//! [`group_config`], [`job_list_template`], [`narrow_filter`],
//! [`set_mismatch`], [`conformant_membership`], and [`verify_with`] itself —
//! and guard 3's (bindreams/hole#999): [`junit_executed_tests`],
//! [`merge_executed`], the recorded-expectation handoff, [`set_missing`], and
//! [`verify_executed`] itself. Neither guard shells out to a real `cargo
//! nextest list`/subprocess from a unit test — guard 3 only reads files, and
//! guard 2's `verify` takes its one subprocess call as a parameter
//! ([`verify_with`]), so a fake `list` closure stands in for it against a
//! fixtured `.github/workflows/ci.yaml` / `.config/nextest.toml` /
//! `build.yaml` on disk (plain-text reads, not a synthetic compilable
//! workspace). [`verify`] itself is just `verify_with(..., run_nextest_list)`
//! and is not separately tested.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::global_net_state_conformance::{
    conformant_membership, group_config, job_list_template, junit_executed_tests, merge_executed, narrow_filter,
    read_expectation, set_mismatch, set_missing, verify_executed, verify_with, write_expectation, Expectation,
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

// ===== merge_executed (bindreams/hole#999) ===========================================================================

/// The property the whole per-lane-report design rests on: the group spans
/// BOTH `SKULD_LABELS` lanes, so neither lane's report alone accounts for it
/// and only their union does. Asserted against each lane individually as
/// well, so a regression that silently reads one report cannot pass this.
#[skuld::test]
fn merge_executed_accounts_for_a_group_that_neither_lane_covers_alone() {
    let expected = binmap(&[("tun-engine", &["privileged_one", "unprivileged_two"])]);
    let tun_lane = binmap(&[("tun-engine", &["privileged_one"])]);
    let non_tun_lane = binmap(&[("tun-engine", &["unprivileged_two"])]);

    assert_eq!(
        set_missing(&expected, &tun_lane)["tun-engine"],
        names(&["unprivileged_two"])
    );
    assert_eq!(
        set_missing(&expected, &non_tun_lane)["tun-engine"],
        names(&["privileged_one"])
    );
    assert!(set_missing(&expected, &merge_executed(&[non_tun_lane, tun_lane])).is_empty());
}

#[skuld::test]
fn merge_executed_merges_binaries_present_in_only_one_report() {
    let a = binmap(&[("hole-bridge", &["a"])]);
    let b = binmap(&[("tun-engine", &["b"])]);
    let united = merge_executed(&[a, b]);
    assert_eq!(united.len(), 2);
    assert_eq!(united["hole-bridge"], names(&["a"]));
    assert_eq!(united["tun-engine"], names(&["b"]));
}

#[skuld::test]
fn merge_executed_of_a_single_report_is_that_report() {
    let only = binmap(&[("hole-bridge", &["a", "b"])]);
    assert_eq!(merge_executed(std::slice::from_ref(&only)), only);
}

#[skuld::test]
fn merge_executed_of_nothing_is_empty() {
    assert!(merge_executed(&[]).is_empty());
}

/// A test present in more than one lane's report — sets already guarantee
/// this, but pin it as the documented behavior.
#[skuld::test]
fn merge_executed_deduplicates_a_name_present_in_more_than_one_report() {
    let a = binmap(&[("hole-bridge", &["a"])]);
    let b = binmap(&[("hole-bridge", &["a"])]);
    assert_eq!(merge_executed(&[a, b])["hole-bridge"], names(&["a"]));
}

// ===== recorded expectation (bindreams/hole#999) =====================================================================

#[skuld::test]
fn expectation_round_trips_through_the_recorded_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A subdirectory that does not exist yet: the recording step writes under
    // `target/`, which a `cargo xtask` run has created, but the guard must not
    // depend on that.
    let path = dir.path().join("nested/expected.json");
    let recorded = Expectation {
        job: "test-hole".to_string(),
        tests: binmap(&[("tun-engine", &["a", "b"]), ("hole-bridge", &["c"])]),
    };

    write_expectation(&path, &recorded).expect("record");
    assert_eq!(read_expectation(&path).expect("read back"), recorded);
}

/// The recording and the reading live in two different ci.yaml steps, so
/// "someone dropped the recording step" is a real failure mode — it must name
/// the flag that produces the file rather than surfacing a bare ENOENT.
#[skuld::test]
fn read_expectation_names_the_recording_flag_when_the_file_is_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let err = read_expectation(&dir.path().join("absent.json")).expect_err("should error");
    let msg = err.to_string();
    assert!(msg.contains("--record"), "{msg}");
}

// ===== verify_executed (bindreams/hole#999, guard 3 end-to-end) ======================================================

/// A minimal JUnit report naming exactly the given `(classname, [name, ...])`
/// testcases — enough for [`junit_executed_tests`] to parse, nothing else.
fn junit_xml(entries: &[(&str, &[&str])]) -> String {
    let mut testcases = String::new();
    for (classname, names) in entries {
        for name in *names {
            testcases.push_str(&format!(
                "    <testcase classname=\"{classname}\" name=\"{name}\" time=\"0.1\"/>\n"
            ));
        }
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n  <testsuite name=\"suite\">\n{testcases}  \
         </testsuite>\n</testsuites>\n"
    )
}

/// Guard 3's whole point: a group member guard 2 recorded but that never
/// shows up (non-skipped) in any lane's JUnit report must fail loudly, by
/// name — a green job that silently ran fewer than expected must not pass.
#[skuld::test]
fn verify_executed_fails_when_a_group_member_never_appears_in_any_junit_report() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_expectation(
        &dir.path().join("expected.json"),
        &Expectation {
            job: "test-hole".to_string(),
            tests: binmap(&[("tun-engine", &["privileged_one", "unprivileged_two"])]),
        },
    )
    .expect("record");
    // Only one of the two expected tests appears in the (single) lane report.
    std::fs::write(
        dir.path().join("junit.xml"),
        junit_xml(&[("tun-engine", &["privileged_one"])]),
    )
    .expect("write junit");

    let err = verify_executed(dir.path(), Path::new("expected.json"), &[PathBuf::from("junit.xml")])
        .expect_err("a missing group member must fail guard 3");
    assert!(err.to_string().contains("unprivileged_two"), "{err}");
}

/// The green counterpart: every recorded group member appears somewhere
/// across the lane reports (here split across two, mirroring the non-tun/tun
/// lane split guard 3 exists to reunite — see this module's doc).
#[skuld::test]
fn verify_executed_passes_when_every_group_member_appears_in_the_junit_reports() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_expectation(
        &dir.path().join("expected.json"),
        &Expectation {
            job: "test-hole".to_string(),
            tests: binmap(&[("tun-engine", &["privileged_one", "unprivileged_two"])]),
        },
    )
    .expect("record");
    std::fs::write(
        dir.path().join("non-tun-junit.xml"),
        junit_xml(&[("tun-engine", &["unprivileged_two"])]),
    )
    .expect("write junit");
    std::fs::write(
        dir.path().join("tun-junit.xml"),
        junit_xml(&[("tun-engine", &["privileged_one"])]),
    )
    .expect("write junit");

    verify_executed(
        dir.path(),
        Path::new("expected.json"),
        &[PathBuf::from("non-tun-junit.xml"), PathBuf::from("tun-junit.xml")],
    )
    .expect("every expected test appears across the two lane reports");
}

/// Zero `--junit` reports would confirm nothing — the same emptiness defense
/// guard 2 applies to its own listings (bindreams/hole#865 audit finding 4).
#[skuld::test]
fn verify_executed_errs_when_no_junit_paths_are_given() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_expectation(
        &dir.path().join("expected.json"),
        &Expectation {
            job: "test-hole".to_string(),
            tests: binmap(&[("tun-engine", &["a"])]),
        },
    )
    .expect("record");

    let err = verify_executed(dir.path(), Path::new("expected.json"), &[]).expect_err("no reports to read");
    assert!(err.to_string().contains("--junit"), "{}", err);
}

/// A vacuously-empty recorded expectation must not pass trivially — the exact
/// risk M5 (bindreams/hole#999) named for `verify`'s `--record` branch, from
/// guard 3's side: even if it somehow got written, guard 3 must still refuse
/// to treat "nothing was expected" as "everything ran".
#[skuld::test]
fn verify_executed_errs_when_the_recorded_expectation_is_vacuously_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_expectation(
        &dir.path().join("expected.json"),
        &Expectation {
            job: "test-hole".to_string(),
            tests: binmap(&[("tun-engine", &[])]),
        },
    )
    .expect("record");
    std::fs::write(
        dir.path().join("junit.xml"),
        junit_xml(&[("tun-engine", &["unrelated"])]),
    )
    .expect("write junit");

    let err = verify_executed(dir.path(), Path::new("expected.json"), &[PathBuf::from("junit.xml")])
        .expect_err("an empty recorded expectation has nothing to confirm");
    assert!(err.to_string().contains("EMPTY"), "{}", err);
}

// ===== conformant_membership (bindreams/hole#894 / #999) =============================================================

/// The property M5 (bindreams/hole#999) named directly: reaching `Ok` here
/// must never carry a vacuously-empty membership, because `verify` writes
/// this exact return value out via `--record` for guard 3 to diff against —
/// an empty write would make that diff trivially pass no matter what actually
/// ran.
#[skuld::test]
fn conformant_membership_returns_the_agreed_membership_when_it_is_non_empty() {
    let matched = binmap(&[("hole-bridge", &["a", "b"])]);
    let out = conformant_membership(matched.clone(), matched, "test-hole", "test(/bar/)").expect("agree, non-empty");
    assert_eq!(out, binmap(&[("hole-bridge", &["a", "b"])]));
}

/// Guards exactly the #999 risk M5 calls out: when the two sides disagree,
/// `conformant_membership` must error rather than return either side — here
/// the label side is empty, so returning `Ok` would let `verify` record an
/// empty expectation that trivially passes guard 3's diff.
#[skuld::test]
fn conformant_membership_errs_rather_than_recording_when_only_one_side_matched_anything() {
    let name_matched = binmap(&[("hole-bridge", &["a"])]);
    let label_matched: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let err = conformant_membership(name_matched, label_matched, "test-hole", "test(/bar/)")
        .expect_err("a one-sided match is a real divergence, not something to record");
    let msg = err.to_string();
    assert!(msg.contains("hole-bridge") && msg.contains('a'), "{msg}");
}

/// The other half of the same defense (bindreams/hole#865 audit finding 4,
/// carried into #999 by the same reasoning): a vacuous empty/empty pass must
/// not be recordable either.
#[skuld::test]
fn conformant_membership_errs_when_neither_side_matched_anything() {
    let empty: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let err = conformant_membership(empty.clone(), empty, "test-hole", "test(/bar/)")
        .expect_err("an empty/empty pass has nothing to verify or record");
    let msg = err.to_string();
    assert!(msg.contains("test-hole") && msg.contains("ANY"), "{msg}");
}

// ===== verify_with (bindreams/hole#894 / #999, guard 2's orchestration with an injected `list`) ======================

/// A minimal `ci.yaml` + `.config/nextest.toml` + `build.yaml` on disk —
/// `verify_with`'s only real file I/O, all plain text, none of it a
/// `cargo nextest list` subprocess — plus a fake `list` closure lets
/// `verify_with` itself be pinned without compiling a synthetic workspace.
fn write_repo_fixture(dir: &Path) {
    std::fs::create_dir_all(dir.join(".github/workflows")).expect("mkdir ci.yaml dir");
    std::fs::write(
        dir.join(".github/workflows/ci.yaml"),
        "
jobs:
  test-hole:
    steps:
      - run: cargo nextest run -p a -E 'package(a)'
      - run: cargo nextest run -p a -E 'package(a)'
",
    )
    .expect("write ci.yaml");
    std::fs::create_dir_all(dir.join(".config")).expect("mkdir .config");
    std::fs::write(dir.join(".config/nextest.toml"), FIXTURE_NEXTEST_TOML).expect("write nextest.toml");
    std::fs::write(dir.join("build.yaml"), "targets: {}").expect("write build.yaml");
}

/// The exact risk M5 (bindreams/hole#999) named for `verify`'s `--record`
/// branch: it must write the *label*-matched set, not the name-matched one.
/// `bin_b` here is label-only (an empty-set entry the name side never lists,
/// which is not itself a conformance mismatch — see `set_mismatch`), so its
/// presence in the recorded file is proof of which side was actually
/// written.
#[skuld::test]
fn verify_with_records_the_label_matched_set_not_the_name_matched_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_repo_fixture(dir.path());

    let list = |_: &Path, _: &[String], labels: Option<&str>| -> anyhow::Result<BTreeMap<String, BTreeSet<String>>> {
        Ok(match labels {
            None => binmap(&[("pkg::bin_a", &["t1", "t2"])]),
            Some(_) => {
                let mut m = binmap(&[("pkg::bin_a", &["t1", "t2"])]);
                m.insert("pkg::bin_b".to_string(), BTreeSet::new());
                m
            }
        })
    };

    let record_path = dir.path().join("expected.json");
    verify_with(dir.path(), "test-hole", Some(Path::new("expected.json")), list).expect("conformant");

    let recorded = read_expectation(&record_path).expect("read back");
    assert!(
        recorded.tests.contains_key("pkg::bin_b"),
        "expected the label-matched extra binary to be recorded, got {:?}",
        recorded.tests
    );
}

/// The `record: None` half of the same guarantee: nothing is ever written
/// when the caller didn't ask for a recording.
#[skuld::test]
fn verify_with_writes_nothing_when_record_is_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_repo_fixture(dir.path());

    let list = |_: &Path, _: &[String], _: Option<&str>| -> anyhow::Result<BTreeMap<String, BTreeSet<String>>> {
        Ok(binmap(&[("pkg::bin_a", &["t1"])]))
    };

    verify_with(dir.path(), "test-hole", None, list).expect("conformant");

    assert!(!dir.path().join("expected.json").exists());
}

/// The other half M5 (bindreams/hole#999) asked for directly: a failed
/// conformance check must not write a file either — the guard's whole point
/// is that a rejected membership is never the one guard 3 reads back.
#[skuld::test]
fn verify_with_writes_nothing_when_the_conformance_check_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_repo_fixture(dir.path());

    let list = |_: &Path, _: &[String], labels: Option<&str>| -> anyhow::Result<BTreeMap<String, BTreeSet<String>>> {
        Ok(match labels {
            None => binmap(&[("pkg::bin_a", &["t1"])]),
            Some(_) => binmap(&[("pkg::bin_a", &["t2"])]),
        })
    };

    let record_path = dir.path().join("expected.json");
    verify_with(dir.path(), "test-hole", Some(Path::new("expected.json")), list).expect_err("mismatch should fail");

    assert!(!record_path.exists());
}
