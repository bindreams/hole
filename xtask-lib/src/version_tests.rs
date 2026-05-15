use crate::version::*;
use semver::Version;
use std::path::Path;

fn v(major: u64, minor: u64, patch: u64) -> Version {
    Version::new(major, minor, patch)
}

// Workspace fixture helpers ===========================================================================================

fn write(path: impl AsRef<Path>, content: &str) {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn cargo_with_group(name: &str, version: &str, group: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "{version}"

[package.metadata.hole-release]
group = "{group}"
"#
    )
}

fn cargo_with_group_publish_false(name: &str, version: &str, group: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "{version}"
publish = false

[package.metadata.hole-release]
group = "{group}"
"#
    )
}

fn cargo_publish_false_no_group(name: &str, version: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "{version}"
publish = false
"#
    )
}

fn cargo_publishable_no_group(name: &str, version: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "{version}"
"#
    )
}

// Group ===============================================================================================================

#[skuld::test]
fn group_parse_known() {
    assert_eq!(Group::parse("hole").unwrap(), Group::Hole);
    assert_eq!(Group::parse("garter").unwrap(), Group::Garter);
    assert_eq!(Group::parse("galoshes").unwrap(), Group::Galoshes);
    assert_eq!(Group::parse("v2ray-plugin").unwrap(), Group::V2rayPlugin);
}

#[skuld::test]
fn group_parse_unknown_rejected() {
    let err = Group::parse("nonsense").unwrap_err();
    assert!(err.to_string().contains("unknown release group"));
}

#[skuld::test]
fn group_tag_glob() {
    assert_eq!(Group::Hole.tag_glob(), "releases/hole/v[0-9]*.[0-9]*.[0-9]*");
    assert_eq!(Group::Garter.tag_glob(), "releases/garter/v[0-9]*.[0-9]*.[0-9]*");
}

#[skuld::test]
fn group_tag_prefix() {
    assert_eq!(Group::Hole.tag_prefix(), "releases/hole/v");
    assert_eq!(Group::V2rayPlugin.tag_prefix(), "releases/v2ray-plugin/v");
}

#[skuld::test]
fn group_all_lists_four() {
    assert_eq!(Group::all().len(), 4);
}

// read_workspace_versions =============================================================================================

#[skuld::test]
fn workspace_versions_happy_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a", "b", "g"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "1.2.3", "hole"),
    );
    write(
        root.join("b").join("Cargo.toml"),
        &cargo_with_group("b", "1.2.3", "hole"),
    );
    write(
        root.join("g").join("Cargo.toml"),
        &cargo_with_group("g", "0.5.0", "garter"),
    );

    let ws = read_workspace_versions(root).unwrap();
    assert_eq!(ws.by_group.get(&Group::Hole), Some(&v(1, 2, 3)));
    assert_eq!(ws.by_group.get(&Group::Garter), Some(&v(0, 5, 0)));
}

#[skuld::test]
fn workspace_versions_within_group_inconsistency_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a", "b"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "1.2.3", "hole"),
    );
    write(
        root.join("b").join("Cargo.toml"),
        &cargo_with_group("b", "1.2.4", "hole"),
    );

    let err = read_workspace_versions(root).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("group 'hole'"), "msg was: {msg}");
    assert!(msg.contains("inconsistent"));
}

#[skuld::test]
fn workspace_versions_cross_group_drift_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["h", "g"]
"#,
    );
    write(
        root.join("h").join("Cargo.toml"),
        &cargo_with_group("h", "1.0.0", "hole"),
    );
    write(
        root.join("g").join("Cargo.toml"),
        &cargo_with_group("g", "0.3.5", "garter"),
    );

    let ws = read_workspace_versions(root).unwrap();
    assert_eq!(ws.by_group.get(&Group::Hole), Some(&v(1, 0, 0)));
    assert_eq!(ws.by_group.get(&Group::Garter), Some(&v(0, 3, 5)));
}

#[skuld::test]
fn workspace_versions_drift_prevention_publishable_without_group_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a", "rogue"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "1.2.3", "hole"),
    );
    write(
        root.join("rogue").join("Cargo.toml"),
        &cargo_publishable_no_group("rogue", "1.2.3"),
    );

    let err = read_workspace_versions(root).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("publishable"), "msg was: {msg}");
    assert!(msg.contains("hole-release"), "msg was: {msg}");
}

#[skuld::test]
fn workspace_versions_publish_false_without_group_allowed() {
    // Internal tooling: publish=false AND no group. Treated as ungrouped, skipped.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a", "tool"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "1.2.3", "hole"),
    );
    write(
        root.join("tool").join("Cargo.toml"),
        &cargo_publish_false_no_group("tool", "0.0.0"),
    );

    let ws = read_workspace_versions(root).unwrap();
    assert_eq!(ws.by_group.get(&Group::Hole), Some(&v(1, 2, 3)));
    // tool's 0.0.0 version is not counted toward anything.
}

#[skuld::test]
fn workspace_versions_publish_false_with_group_counted() {
    // Internal lib crate: publish=false but PART of a group (its version
    // is locked with the group). Confirms orthogonality of publish=false
    // and group membership.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a", "b"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "1.2.3", "hole"),
    );
    write(
        root.join("b").join("Cargo.toml"),
        &cargo_with_group_publish_false("b", "1.2.4", "hole"), // different version
    );

    // Inconsistency must still fire (1.2.3 vs 1.2.4) — publish=false does not exempt.
    let err = read_workspace_versions(root).unwrap_err();
    assert!(format!("{err:#}").contains("inconsistent"));
}

#[skuld::test]
fn workspace_versions_v2ray_plugin_from_external_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "1.2.3", "hole"),
    );
    write(
        root.join("external").join("v2ray-plugin").join("version.toml"),
        "version = \"5.3.0\"\n",
    );

    let ws = read_workspace_versions(root).unwrap();
    assert_eq!(ws.by_group.get(&Group::V2rayPlugin), Some(&v(5, 3, 0)));
}

#[skuld::test]
fn workspace_versions_v2ray_plugin_rejects_pre_release() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "1.2.3", "hole"),
    );
    write(
        root.join("external").join("v2ray-plugin").join("version.toml"),
        "version = \"5.3.0-rc1\"\n",
    );

    let err = read_workspace_versions(root).unwrap_err();
    assert!(format!("{err:#}").contains("strict MAJOR.MINOR.PATCH"));
}

#[skuld::test]
fn workspace_versions_unknown_group_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "1.2.3", "nonsense"),
    );

    let err = read_workspace_versions(root).unwrap_err();
    assert!(format!("{err:#}").contains("unknown release group"));
}

#[skuld::test]
fn workspace_versions_rejects_pre_release() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "1.2.3-beta", "hole"),
    );

    let err = read_workspace_versions(root).unwrap_err();
    assert!(format!("{err:#}").contains("strict MAJOR.MINOR.PATCH"));
}

#[skuld::test]
fn workspace_versions_rejects_glob_members() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["crates/*"]
"#,
    );
    let err = read_workspace_versions(root).unwrap_err();
    assert!(format!("{err:#}").contains("glob"));
}

// cargo_toml_version_for_group ========================================================================================

#[skuld::test]
fn version_for_group_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "1.2.3", "hole"),
    );

    assert_eq!(cargo_toml_version_for_group(root, Group::Hole).unwrap(), v(1, 2, 3));
}

#[skuld::test]
fn version_for_group_missing_group_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "1.2.3", "hole"),
    );

    let err = cargo_toml_version_for_group(root, Group::Garter).unwrap_err();
    assert!(format!("{err:#}").contains("garter"));
}

// is_valid_next =======================================================================================================

#[skuld::test]
fn equal_versions() {
    assert!(is_valid_next(&v(0, 1, 0), &v(0, 1, 0)));
}

#[skuld::test]
fn equal_nonzero() {
    assert!(is_valid_next(&v(2, 3, 4), &v(2, 3, 4)));
}

#[skuld::test]
fn patch_bump() {
    assert!(is_valid_next(&v(0, 1, 0), &v(0, 1, 1)));
}

#[skuld::test]
fn minor_bump() {
    assert!(is_valid_next(&v(0, 1, 0), &v(0, 2, 0)));
}

#[skuld::test]
fn major_bump() {
    assert!(is_valid_next(&v(0, 1, 0), &v(1, 0, 0)));
}

#[skuld::test]
fn patch_bump_from_nonzero() {
    assert!(is_valid_next(&v(1, 2, 3), &v(1, 2, 4)));
}

#[skuld::test]
fn minor_bump_from_nonzero() {
    assert!(is_valid_next(&v(1, 2, 3), &v(1, 3, 0)));
}

#[skuld::test]
fn major_bump_from_nonzero() {
    assert!(is_valid_next(&v(1, 2, 3), &v(2, 0, 0)));
}

#[skuld::test]
fn double_patch_bump_rejected() {
    assert!(!is_valid_next(&v(0, 1, 0), &v(0, 1, 2)));
}

#[skuld::test]
fn minor_bump_without_patch_reset_rejected() {
    assert!(!is_valid_next(&v(0, 1, 3), &v(0, 2, 3)));
}

#[skuld::test]
fn major_bump_without_minor_reset_rejected() {
    assert!(!is_valid_next(&v(1, 2, 0), &v(2, 2, 0)));
}

#[skuld::test]
fn major_bump_without_patch_reset_rejected() {
    assert!(!is_valid_next(&v(1, 0, 3), &v(2, 0, 3)));
}

#[skuld::test]
fn downgrade_rejected() {
    assert!(!is_valid_next(&v(1, 0, 0), &v(0, 9, 0)));
}

#[skuld::test]
fn skip_minor_rejected() {
    assert!(!is_valid_next(&v(1, 0, 0), &v(1, 2, 0)));
}

#[skuld::test]
fn multi_component_bump_rejected() {
    assert!(!is_valid_next(&v(1, 0, 0), &v(1, 1, 1)));
}

// validate_against_tag ================================================================================================
//
// These tests exercise the bootstrap path (no tag yet) since we cannot
// easily create real tags inside a tempdir without spawning git init.
// The error path (--exact without a tag) is structural and worth pinning.

#[skuld::test]
fn validate_against_tag_bootstrap_no_tag_accepts_anything() {
    // Empty repo with no tags at all → nearest_tag_version returns Ok(None).
    // Non-exact validate_against_tag must then accept the Cargo.toml version.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "0.1.0", "hole"),
    );

    init_git_repo(root);

    let resolved = validate_against_tag(root, Group::Hole, false).unwrap();
    assert_eq!(resolved, v(0, 1, 0));
}

#[skuld::test]
fn validate_against_tag_bootstrap_no_tag_with_exact_errors() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a"]
"#,
    );
    write(
        root.join("a").join("Cargo.toml"),
        &cargo_with_group("a", "0.1.0", "hole"),
    );

    init_git_repo(root);

    let err = validate_against_tag(root, Group::Hole, true).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("no `releases/hole/v...` tag yet"), "msg was: {msg}");
}

fn init_git_repo(root: &Path) {
    use std::process::Command;
    fn git(root: &Path, args: &[&str]) {
        let s = Command::new("git").args(args).current_dir(root).status().unwrap();
        assert!(s.success(), "git {} failed in {}", args.join(" "), root.display());
    }
    git(root, &["init", "--quiet"]);
    git(root, &["config", "user.email", "test@example.invalid"]);
    git(root, &["config", "user.name", "Test"]);
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "init"]);
}

// display_version =====================================================================================================
//
// We don't unit-test display_version's full happy path directly because
// it shells out to `git` and depends on the on-disk state of an actual
// repo. The fallback to "0.0.0-unknown" on failure means it can be called
// from build.rs without risk of panic, which is the contract that matters.
// Bootstrap behavior is exercised via validate_against_tag above.
