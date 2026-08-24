//! Unit tests for the skuld-label conservation guard (bindreams/hole#891):
//! [`extract_lane_candidates`], [`pick_complementary_pair`],
//! [`matching_test_names`], and [`stranded_tests`].

use std::collections::{BTreeMap, BTreeSet};

use crate::skuld_label_coverage::{
    extract_lane_candidates, matching_test_names, pick_complementary_pair, stranded_tests, LaneCandidate,
};

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn names(items: &[&str]) -> BTreeSet<String> {
    set(items)
}

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn candidate(label_value: &str, packages: &[&str], list_command: &[&str]) -> LaneCandidate {
    LaneCandidate {
        label_value: label_value.to_string(),
        packages: set(packages),
        list_command: argv(list_command),
    }
}

// ===== extract_lane_candidates =======================================================================================

/// The realistic shape: an `env:`-block step (non-TUN), an inline
/// `sudo env ... SKULD_LABELS=` step (macOS TUN), and a plain-`env:` Windows
/// TUN step. All three must be found, with the launcher prefix stripped from
/// `list_command` and `run` swapped for `list --message-format json`.
#[skuld::test]
fn finds_env_block_and_inline_skuld_labels() {
    let ci = r#"
jobs:
  test-hole:
    steps:
      - run: cargo xtask build hole-tests
      - name: Test (non-TUN)
        env:
          SKULD_LABELS: "!tun"
        run: cargo nextest run --no-default-features -E 'package(hole) + package(dump)'
      - name: Test (TUN, windows)
        if: matrix.os == 'windows'
        env:
          SKULD_LABELS: "tun"
        run: cargo nextest run --no-default-features -E 'package(hole) + package(dump)'
      - name: Test (TUN, macOS)
        if: matrix.os == 'darwin'
        run: >
          sudo env "PATH=$PATH" "HOME=$HOME" SKULD_LABELS=tun
          cargo nextest run --no-default-features -E 'package(hole) + package(dump)'
"#;
    let candidates = extract_lane_candidates(ci, "test-hole").expect("extract");
    assert_eq!(candidates.len(), 3);

    let expected_list_command = argv(&[
        "cargo",
        "nextest",
        "list",
        "--message-format",
        "json",
        "--no-default-features",
        "-E",
        "package(hole) + package(dump)",
    ]);

    let non_tun = &candidates[0];
    assert_eq!(non_tun.label_value, "!tun");
    assert_eq!(non_tun.packages, set(&["hole", "dump"]));
    assert_eq!(non_tun.list_command, expected_list_command);

    let windows_tun = &candidates[1];
    assert_eq!(windows_tun.label_value, "tun");

    let macos_tun = &candidates[2];
    assert_eq!(macos_tun.label_value, "tun");
    // The `sudo env ...` launcher prefix must not survive into the list command.
    assert_eq!(macos_tun.list_command, expected_list_command);
}

#[skuld::test]
fn ignores_non_nextest_and_no_run_steps() {
    let ci = r#"
jobs:
  test-hole:
    steps:
      - run: cargo xtask build hole-tests
      - name: compile only
        run: cargo nextest run --no-run -E 'package(hole)'
      - name: clippy
        run: cargo clippy -p hole
"#;
    let candidates = extract_lane_candidates(ci, "test-hole").expect("extract");
    assert!(candidates.is_empty());
}

#[skuld::test]
fn missing_skuld_labels_is_an_error() {
    let ci = r#"
jobs:
  test-hole:
    steps:
      - name: unlabeled
        run: cargo nextest run -E 'package(hole)'
"#;
    let err = extract_lane_candidates(ci, "test-hole").expect_err("should error");
    assert!(err.to_string().contains("no SKULD_LABELS"), "{err}");
}

#[skuld::test]
fn unknown_job_is_an_error() {
    let ci = "jobs:\n  other:\n    steps: []\n";
    assert!(extract_lane_candidates(ci, "test-hole").is_err());
}

// ===== pick_complementary_pair =======================================================================================

#[skuld::test]
fn pairs_exact_negations_over_the_same_packages() {
    let off = candidate("!tun", &["a", "b"], &["list off"]);
    let on = candidate("tun", &["a", "b"], &["list on"]);
    let candidates = vec![off.clone(), on.clone()];

    let (found_off, found_on) = pick_complementary_pair(&candidates).expect("pair");
    assert_eq!(*found_off, off);
    assert_eq!(*found_on, on);
}

/// Windows and macOS TUN steps both declare `SKULD_LABELS: "tun"` over the
/// same packages — the duplicate must not register as a second pair.
#[skuld::test]
fn duplicate_on_candidates_collapse_before_pairing() {
    let off = candidate("!tun", &["a"], &["list off"]);
    let on_windows = candidate("tun", &["a"], &["list on"]);
    let on_macos = candidate("tun", &["a"], &["list on"]); // identical in every field
    let candidates = vec![off.clone(), on_windows.clone(), on_macos];

    let (found_off, found_on) = pick_complementary_pair(&candidates).expect("pair");
    assert_eq!(*found_off, off);
    assert_eq!(*found_on, on_windows);
}

#[skuld::test]
fn values_that_are_not_exact_negations_are_an_error() {
    let a = candidate("tun", &["a"], &["list a"]);
    let b = candidate("other", &["a"], &["list b"]);
    let err = pick_complementary_pair(&[a, b]).expect_err("should error");
    assert!(err.to_string().contains("not exact negations"), "{err}");
}

/// A negation over a DIFFERENT package set must not pair — that would compare
/// two unrelated lanes' conservation, not one lane's.
#[skuld::test]
fn negation_over_different_packages_does_not_pair() {
    let off = candidate("!tun", &["a"], &["list off"]);
    let on = candidate("tun", &["b"], &["list on"]);
    let err = pick_complementary_pair(&[off, on]).expect_err("should error");
    assert!(err.to_string().contains("different package sets"), "{err}");
}

/// The scenario this guard exists to catch at the extraction layer: the
/// Windows and macOS TUN steps both declare `SKULD_LABELS` over the same
/// packages, but only one of them drifted (typo'd `"tun"` to `"tnu"`). A
/// search for *some* matching `"!X"`/`"X"` pair would find the still-correct
/// macOS candidate and silently ignore the Windows one — this must instead
/// reject the whole group: a third, unpaired value is itself the bug.
#[skuld::test]
fn a_third_unpaired_value_for_the_same_package_set_is_an_error() {
    let off = candidate("!tun", &["a"], &["list off"]);
    let on_macos = candidate("tun", &["a"], &["list on macos"]);
    let on_windows_typo = candidate("tnu", &["a"], &["list on windows"]);
    let err = pick_complementary_pair(&[off, on_macos, on_windows_typo]).expect_err("should error");
    assert!(err.to_string().contains("distinct SKULD_LABELS values"), "{err}");
}

#[skuld::test]
fn ambiguous_pairs_are_an_error() {
    let off1 = candidate("!tun", &["a"], &["list"]);
    let on1 = candidate("tun", &["a"], &["list"]);
    let off2 = candidate("!windows_console", &["b"], &["list"]);
    let on2 = candidate("windows_console", &["b"], &["list"]);
    let err = pick_complementary_pair(&[off1, on1, off2, on2]).expect_err("should error");
    assert!(err.to_string().contains("expected exactly one"), "{err}");
}

// ===== matching_test_names ===========================================================================================

/// Trimmed from a real `cargo nextest list --message-format json -p
/// dev-console` capture: `testcases` only ever holds entries skuld actually
/// selected, all with `filter-match.status == "matches"` — skuld drops
/// everything else before nextest's discovery phase ever sees it.
#[skuld::test]
fn parses_matching_testcases_per_binary() {
    let json = r#"
{
  "rust-suites": {
    "dev-console": {
      "package-name": "dev-console",
      "testcases": {
        "a_test": { "kind": "test", "ignored": false, "filter-match": { "status": "matches" } },
        "b_test": { "kind": "test", "ignored": false, "filter-match": { "status": "matches" } }
      }
    },
    "dev-console::bin/dev-console": {
      "package-name": "dev-console",
      "testcases": {}
    }
  }
}
"#;
    let parsed = matching_test_names(json).expect("parse");
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed["dev-console"], names(&["a_test", "b_test"]));
    assert_eq!(parsed["dev-console::bin/dev-console"], BTreeSet::new());
}

/// Defensive: a non-"matches" status (nextest's own `-E`/name filtering can
/// produce one, even though skuld's own label filtering never does — see the
/// module doc) must not count as selected.
#[skuld::test]
fn non_matching_status_is_excluded() {
    let json = r#"
{
  "rust-suites": {
    "pkg": {
      "package-name": "pkg",
      "testcases": {
        "kept": { "kind": "test", "ignored": false, "filter-match": { "status": "matches" } },
        "dropped": { "kind": "test", "ignored": false, "filter-match": { "status": "excluded" } }
      }
    }
  }
}
"#;
    let parsed = matching_test_names(json).expect("parse");
    assert_eq!(parsed["pkg"], names(&["kept"]));
}

// ===== stranded_tests ================================================================================================

fn binmap(entries: &[(&str, &[&str])]) -> BTreeMap<String, BTreeSet<String>> {
    entries.iter().map(|(k, v)| (k.to_string(), names(v))).collect()
}

/// The common, EXPECTED shape for most `test-hole` packages: zero `tun`
/// tests, all of them landing in the non-TUN side. Requirement #2 — must NOT
/// be flagged.
#[skuld::test]
fn fully_conserved_by_the_off_side_alone_is_not_stranded() {
    let baseline = binmap(&[("dump", &["a", "b", "c"])]);
    let off = binmap(&[("dump", &["a", "b", "c"])]);
    let on: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    assert!(stranded_tests(&baseline, &off, &on).is_empty());
}

/// The other legitimate shape: a package with SOME tun tests, correctly
/// partitioned across both sides.
#[skuld::test]
fn conserved_across_both_sides_is_not_stranded() {
    let baseline = binmap(&[("tun-engine", &["windows_lockdown_ok", "unit_builder_ok"])]);
    let off = binmap(&[("tun-engine", &["unit_builder_ok"])]);
    let on = binmap(&[("tun-engine", &["windows_lockdown_ok"])]);

    assert!(stranded_tests(&baseline, &off, &on).is_empty());
}

/// The bug: a test compiled in but selected by neither side (simulating a
/// typo'd `SKULD_LABELS` value on the "on" side).
#[skuld::test]
fn a_test_selected_by_neither_side_is_stranded() {
    let baseline = binmap(&[("tun-engine", &["windows_lockdown_ok", "unit_builder_ok"])]);
    let off = binmap(&[("tun-engine", &["unit_builder_ok"])]);
    let on: BTreeMap<String, BTreeSet<String>> = BTreeMap::new(); // "tun" typo'd -> matches nothing

    let stranded = stranded_tests(&baseline, &off, &on);
    assert_eq!(stranded.len(), 1);
    assert_eq!(stranded["tun-engine"], names(&["windows_lockdown_ok"]));
}

/// A binary present in the baseline but entirely absent from one of the two
/// list outputs (defensive edge case) is treated as contributing zero from
/// that side, not as a parse error.
#[skuld::test]
fn binary_absent_from_a_side_is_treated_as_empty() {
    let baseline = binmap(&[("hole", &["only_test"])]);
    let off: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let on: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    let stranded = stranded_tests(&baseline, &off, &on);
    assert_eq!(stranded["hole"], names(&["only_test"]));
}

/// A binary with zero tests at all (baseline empty) contributes no entry —
/// not even an empty one.
#[skuld::test]
fn empty_baseline_binary_is_not_reported() {
    let baseline = binmap(&[("empty-crate", &[])]);
    let off: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let on: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    assert!(stranded_tests(&baseline, &off, &on).is_empty());
}
