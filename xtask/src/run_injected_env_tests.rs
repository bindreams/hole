#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::collections::BTreeSet;
use std::ffi::OsString;

use crate::child_env::is_run_injected;
use crate::run_injected_env::{parse_parent_names, unexplained_additions_with, KEPT_TOOLCHAIN};
use crate::test_child::{MODE_ENV, OUT_ENV};

fn names(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

fn set(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[skuld::test]
fn a_name_the_parent_already_had_is_not_an_addition() {
    assert!(unexplained_additions_with(&names(&["PATH", "HOME"]), &set(&["HOME", "PATH"]), false).is_empty());
}

#[skuld::test]
fn run_injected_names_are_explained_even_those_cargo_adds_later() {
    let launch = names(&[
        "PATH",
        "CARGO_MANIFEST_DIR",
        "CARGO_PKG_NAME",
        "CARGO_PKG_ADDED_IN_THE_FUTURE",
    ]);
    assert!(unexplained_additions_with(&launch, &set(&["PATH"]), false).is_empty());
}

#[skuld::test]
fn every_kept_toolchain_name_is_explained() {
    let launch: Vec<OsString> = KEPT_TOOLCHAIN.iter().map(|(n, _)| OsString::from(n)).collect();
    assert!(unexplained_additions_with(&launch, &set(&["PATH"]), false).is_empty());
}

/// A new variable of cargo's, in neither list, is the failure the check exists
/// for. The result is sorted and has no repeats.
#[skuld::test]
fn a_name_in_no_list_is_reported_sorted_and_once() {
    let launch = names(&[
        "PATH",
        "CARGO_NEW_THING",
        "AARDVARK",
        "CARGO_NEW_THING",
        "CARGO_PKG_NAME",
    ]);
    assert_eq!(
        unexplained_additions_with(&launch, &set(&["PATH"]), false),
        ["AARDVARK", "CARGO_NEW_THING"]
    );
}

/// A kept name that the strip also removes would be a contradiction the check
/// could never see: the name is in one list or the other.
#[skuld::test]
fn no_kept_name_is_one_the_strip_removes_and_each_has_a_reason() {
    for &(name, why) in KEPT_TOOLCHAIN {
        assert!(!is_run_injected(name), "{name} is both kept and stripped");
        assert!(!why.trim().is_empty(), "{name} has no reason");
    }
}

/// Windows environment names are case-insensitive, and a shell may spell
/// `Path` as `PATH`: that is not an addition there, and is on a case-sensitive host.
#[skuld::test]
fn names_differing_only_in_case_match_where_the_platform_folds_case() {
    let launch = names(&["PATH"]);
    let parent = set(&["Path"]);
    assert!(unexplained_additions_with(&launch, &parent, true).is_empty());
    assert_eq!(unexplained_additions_with(&launch, &parent, false), ["PATH"]);
}

#[skuld::test]
fn a_baseline_is_one_name_per_line_blank_lines_and_crlf_ignored() {
    assert_eq!(parse_parent_names("PATH\r\n\nHOME\n").unwrap(), set(&["HOME", "PATH"]));
}

/// A baseline recorded inside `cargo run` already holds the injected names and
/// would hide every one of them; one recorded from nothing would explain nothing.
#[skuld::test]
fn a_baseline_that_cannot_be_a_parent_environment_is_refused() {
    let injected = parse_parent_names("PATH\nCARGO_PKG_NAME\n").unwrap_err().to_string();
    assert!(injected.contains("CARGO_PKG_NAME"), "{injected}");
    assert!(parse_parent_names("\n\r\n").is_err());
}

/// Run `verify-run-injected-env`'s check in a child that strips first (as
/// `main` does). The child inherits this process's environment minus any
/// run-injected names (the stand-in for the shell that started `cargo run`),
/// plus `added`. The baseline holds the inherited names, `extra_baseline` and the
/// two the harness sets. Returns (success, stderr).
fn verify_in_child(added: &[(&str, &str)], extra_baseline: &[&str]) -> (bool, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let baseline_file = dir.path().join("parent-env.txt");
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("current_exe"));
    let mut baseline: BTreeSet<String> = [MODE_ENV, OUT_ENV]
        .into_iter()
        .chain(extra_baseline.iter().copied())
        .map(str::to_string)
        .collect();
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy().into_owned();
        if is_run_injected(&name) {
            cmd.env_remove(&name);
        } else {
            baseline.insert(name);
        }
    }
    std::fs::write(&baseline_file, baseline.into_iter().collect::<Vec<_>>().join("\n")).expect("write baseline");
    cmd.env(MODE_ENV, "strip-then-verify-run-injected-env")
        .env(OUT_ENV, &baseline_file);
    for (k, v) in added {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn the child");
    (out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The strip has already removed the injected variables when the subcommand
/// runs; a launch of injected, kept and inherited names still passes.
#[skuld::test]
fn a_launch_of_injected_kept_and_inherited_names_passes() {
    let (ok, stderr) = verify_in_child(
        &[
            ("CARGO_MANIFEST_DIR", "/x"),
            ("CARGO_PKG_NAME", "x"),
            ("CARGO_HOME", "/cargo"),
            ("RUSTUP_TOOLCHAIN", "stable"),
        ],
        &[],
    );
    assert!(ok, "{stderr}");
}

#[skuld::test]
fn a_variable_cargo_added_that_nothing_explains_fails_naming_it() {
    let (ok, stderr) = verify_in_child(&[("CARGO_PKG_NAME", "x"), ("CARGO_BRAND_NEW", "1")], &[]);
    assert!(!ok, "must fail");
    assert!(stderr.contains("CARGO_BRAND_NEW"), "{stderr}");
    assert!(!stderr.contains("CARGO_PKG_NAME"), "{stderr}");
}

#[skuld::test]
fn the_same_variable_in_the_parents_baseline_is_not_an_addition() {
    let (ok, stderr) = verify_in_child(&[("CARGO_BRAND_NEW", "1")], &["CARGO_BRAND_NEW"]);
    assert!(ok, "{stderr}");
}
