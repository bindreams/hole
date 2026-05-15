use crate::test_support::{create_tag, empty_commit, init_git_repo};
use crate::v2ray_plugin_version::*;
use crate::version::{ancestor_tags, Group};
use semver::Version;
use std::path::Path;

// Helpers =============================================================================================================

fn write(path: impl AsRef<Path>, content: &str) {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn write_version_toml(root: &Path, version: &str) {
    write(
        root.join("external").join("v2ray-plugin").join("version.toml"),
        &format!("version = \"{version}\"\n"),
    );
}

// parse_version_string: shape =========================================================================================

#[skuld::test]
fn shape_accepts_strict_semver() {
    let v = parse_version_string("1.3.2").unwrap();
    assert_eq!(v, Version::new(1, 3, 2));
    assert!(v.pre.is_empty());
}

#[skuld::test]
fn shape_accepts_hole_n_pre_release() {
    let v = parse_version_string("1.3.3-hole.1").unwrap();
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 3);
    assert_eq!(v.patch, 3);
    assert_eq!(v.pre.as_str(), "hole.1");
}

#[skuld::test]
fn shape_accepts_zero_version() {
    parse_version_string("0.0.1").unwrap();
}

#[skuld::test]
fn shape_accepts_large_hole_iteration() {
    let v = parse_version_string("99.99.99-hole.999").unwrap();
    assert_eq!(v.pre.as_str(), "hole.999");
}

#[skuld::test]
fn shape_rejects_alpha_pre_release() {
    let err = parse_version_string("1.3.2-alpha").unwrap_err();
    assert!(format!("{err:#}").contains("hole.N"));
}

#[skuld::test]
fn shape_rejects_rc_pre_release() {
    let err = parse_version_string("1.3.2-rc.1").unwrap_err();
    assert!(format!("{err:#}").contains("hole.N"));
}

#[skuld::test]
fn shape_rejects_bare_hole_no_number() {
    let err = parse_version_string("1.3.2-hole").unwrap_err();
    assert!(format!("{err:#}").contains("hole.N"));
}

#[skuld::test]
fn shape_rejects_hole_zero() {
    let err = parse_version_string("1.3.2-hole.0").unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains(">= 1"), "msg was: {msg}");
}

#[skuld::test]
fn shape_rejects_hole_non_numeric_suffix() {
    let err = parse_version_string("1.3.2-hole.abc").unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("positive integer"), "msg was: {msg}");
}

#[skuld::test]
fn shape_rejects_hole_multi_segment_suffix() {
    // semver parses "hole.1.2" as a three-identifier pre-release. Strip
    // "hole." leaves "1.2", which fails u64 parse.
    let err = parse_version_string("1.3.2-hole.1.2").unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("positive integer"), "msg was: {msg}");
}

#[skuld::test]
fn shape_rejects_build_metadata() {
    let err = parse_version_string("1.3.2+build").unwrap_err();
    assert!(format!("{err:#}").contains("build metadata"));
}

#[skuld::test]
fn shape_rejects_hole_plus_build_metadata() {
    let err = parse_version_string("1.3.2-hole.1+build").unwrap_err();
    assert!(format!("{err:#}").contains("build metadata"));
}

#[skuld::test]
fn shape_rejects_short_version() {
    let err = parse_version_string("1.3").unwrap_err();
    assert!(format!("{err:#}").contains("not valid semver"));
}

#[skuld::test]
fn shape_rejects_garbage() {
    let err = parse_version_string("garbage").unwrap_err();
    assert!(format!("{err:#}").contains("not valid semver"));
}

// read_version ========================================================================================================

#[skuld::test]
fn read_version_strict_semver_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "5.3.0");
    assert_eq!(read_version(root).unwrap(), Version::new(5, 3, 0));
}

#[skuld::test]
fn read_version_hole_pre_release_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "5.3.0-hole.2");
    let v = read_version(root).unwrap();
    assert_eq!(v.major, 5);
    assert_eq!(v.pre.as_str(), "hole.2");
}

#[skuld::test]
fn read_version_rejects_rc1_pre_release() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "5.3.0-rc1");
    let err = read_version(root).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("hole.N"), "msg was: {msg}");
}

#[skuld::test]
fn read_version_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let err = read_version(root).unwrap_err();
    assert!(format!("{err:#}").contains("failed to read"));
}

#[skuld::test]
fn read_version_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root.join("external").join("v2ray-plugin").join("version.toml"),
        "other = \"hi\"\n",
    );
    let err = read_version(root).unwrap_err();
    assert!(format!("{err:#}").contains("no `version` key"));
}

// validate_against_tag: sequence rule =================================================================================

#[skuld::test]
fn sequence_first_hole_release_accepted() {
    // Bootstrap: no tags exist, current is X.Y.Z-hole.1 → accept.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.1");
    init_git_repo(root);

    let v = validate_against_tag(root, false).unwrap();
    assert_eq!(v.pre.as_str(), "hole.1");
}

#[skuld::test]
fn sequence_bare_release_accepted_no_constraint() {
    // Bare X.Y.Z: shape-only, no sequence check.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.2");
    init_git_repo(root);
    create_tag(root, "releases/v2ray-plugin/v1.3.3-hole.2");

    validate_against_tag(root, false).unwrap();
}

#[skuld::test]
fn sequence_increment_within_base_accepted() {
    // Prior hole.1 exists, current hole.2 → accept.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.2");
    init_git_repo(root);
    create_tag(root, "releases/v2ray-plugin/v1.3.3-hole.1");

    let v = validate_against_tag(root, false).unwrap();
    assert_eq!(v.pre.as_str(), "hole.2");
}

#[skuld::test]
fn sequence_equal_to_latest_accepted() {
    // After-release stable state: version.toml equals the most recent
    // same-base hole.N tag. This is valid until the next bump (the
    // maintainer hasn't decided what comes next yet). Mirrors the
    // hole/garter/galoshes validator's "Cargo.toml == nearest tag" path.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.1");
    init_git_repo(root);
    create_tag(root, "releases/v2ray-plugin/v1.3.3-hole.1");

    let v = validate_against_tag(root, false).unwrap();
    assert_eq!(v.pre.as_str(), "hole.1");
}

#[skuld::test]
fn sequence_new_base_after_hole_iterations_accepted() {
    // Prior 1.3.3-hole.2, current 1.3.4-hole.1 → accept (new base, no
    // same-base hole.K → max_existing = 0 → expected N = 1).
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.4-hole.1");
    init_git_repo(root);
    create_tag(root, "releases/v2ray-plugin/v1.3.3-hole.2");

    validate_against_tag(root, false).unwrap();
}

#[skuld::test]
fn sequence_skip_in_sequence_rejected() {
    // Prior hole.1, current hole.3 → reject (skipped hole.2).
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.3");
    init_git_repo(root);
    create_tag(root, "releases/v2ray-plugin/v1.3.3-hole.1");

    let err = validate_against_tag(root, false).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("sequence violation"), "msg was: {msg}");
    assert!(msg.contains("hole.2"), "expected hole.2 (max+1) in: {msg}");
}

#[skuld::test]
fn sequence_start_above_one_rejected() {
    // No prior tags, current hole.5 → reject (max_existing = 0, expected 1, got 5).
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.5");
    init_git_repo(root);

    let err = validate_against_tag(root, false).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("sequence violation"), "msg was: {msg}");
    assert!(msg.contains("hole.1"), "expected hole.1 in: {msg}");
}

#[skuld::test]
fn sequence_regression_rejected() {
    // Prior hole.2, current hole.1 → reject (regression, max+1 = 3 ≠ 1).
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.1");
    init_git_repo(root);
    create_tag(root, "releases/v2ray-plugin/v1.3.3-hole.1");
    empty_commit(root, "next");
    create_tag(root, "releases/v2ray-plugin/v1.3.3-hole.2");

    let err = validate_against_tag(root, false).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("sequence violation"), "msg was: {msg}");
}

// validate_against_tag: --exact path ==================================================================================

#[skuld::test]
fn exact_passes_when_tag_matches() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.1");
    init_git_repo(root);
    create_tag(root, "releases/v2ray-plugin/v1.3.3-hole.1");

    let v = validate_against_tag(root, true).unwrap();
    assert_eq!(v.pre.as_str(), "hole.1");
}

#[skuld::test]
fn exact_errors_without_tag() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.1");
    init_git_repo(root);

    let err = validate_against_tag(root, true).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("no `releases/v2ray-plugin/v...` tag yet"),
        "msg was: {msg}"
    );
}

#[skuld::test]
fn exact_errors_on_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.2");
    init_git_repo(root);
    create_tag(root, "releases/v2ray-plugin/v1.3.3-hole.1");

    let err = validate_against_tag(root, true).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("!= tag version"), "msg was: {msg}");
}

// Tag-glob round-trip =================================================================================================
//
// Protects against future regressions in Group::tag_glob's interaction
// with fnmatch on -hole.N suffixed tags. The tag-glob is `releases/
// v2ray-plugin/v[0-9]*.[0-9]*.[0-9]*` (shell glob); we rely on the
// trailing `*` absorbing the `-hole.N` portion. If git's fnmatch ever
// changes this behavior, this test fires.

#[skuld::test]
fn tag_glob_round_trip_includes_hole_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.1");
    init_git_repo(root);
    create_tag(root, "releases/v2ray-plugin/v1.3.3-hole.1");

    let tags = ancestor_tags(root, Group::V2rayPlugin).unwrap();
    assert_eq!(tags.len(), 1, "expected 1 tag, got {:?}", tags);
    assert_eq!(tags[0].1, "releases/v2ray-plugin/v1.3.3-hole.1");
    assert_eq!(tags[0].0.pre.as_str(), "hole.1");
}

#[skuld::test]
fn tag_glob_round_trip_includes_bare_and_hole() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.2");
    init_git_repo(root);
    create_tag(root, "releases/v2ray-plugin/v1.3.2");
    empty_commit(root, "next");
    create_tag(root, "releases/v2ray-plugin/v1.3.3-hole.1");

    let tags = ancestor_tags(root, Group::V2rayPlugin).unwrap();
    let names: Vec<&str> = tags.iter().map(|(_, n)| n.as_str()).collect();
    assert!(
        names.contains(&"releases/v2ray-plugin/v1.3.2"),
        "missing v1.3.2 in {names:?}"
    );
    assert!(
        names.contains(&"releases/v2ray-plugin/v1.3.3-hole.1"),
        "missing v1.3.3-hole.1 in {names:?}"
    );
}
