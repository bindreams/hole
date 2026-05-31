use crate::ex_ray_version::*;
use crate::test_support::{create_tag, empty_commit, init_git_repo};
use crate::version::{validate_against_tag, Group};
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
        root.join("crates").join("ex-ray").join("version.toml"),
        &format!("version = \"{version}\"\n"),
    );
}

// read_version ========================================================================================================

#[skuld::test]
fn read_version_strict_semver_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "0.1.0");
    assert_eq!(read_version(root).unwrap(), Version::new(0, 1, 0));
}

#[skuld::test]
fn read_version_nonzero_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "2.5.3");
    assert_eq!(read_version(root).unwrap(), Version::new(2, 5, 3));
}

#[skuld::test]
fn read_version_rejects_pre_release() {
    // Pre-release / lineage suffixes are rejected; ex-ray is plain strict semver.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.3.3-hole.1");
    let err = read_version(root).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("strict MAJOR.MINOR.PATCH"), "msg was: {msg}");
}

#[skuld::test]
fn read_version_rejects_build_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "1.0.0+build");
    let err = read_version(root).unwrap_err();
    assert!(format!("{err:#}").contains("strict MAJOR.MINOR.PATCH"));
}

#[skuld::test]
fn read_version_rejects_garbage() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "garbage");
    let err = read_version(root).unwrap_err();
    assert!(format!("{err:#}").contains("not valid semver"));
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
        root.join("crates").join("ex-ray").join("version.toml"),
        "other = \"hi\"\n",
    );
    let err = read_version(root).unwrap_err();
    assert!(format!("{err:#}").contains("no `version` key"));
}

// validate_against_tag: generic (plain-semver) path ===================================================================
//
// ex-ray validates identically to hole/garter/galoshes — the only
// difference is the version source (version.toml vs Cargo.toml). These
// tests confirm the generic `is_valid_next` path is wired up for ExRay.

#[skuld::test]
fn validate_bootstrap_no_tag_accepts_anything() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "0.1.0");
    init_git_repo(root);

    let resolved = validate_against_tag(root, Group::ExRay, false).unwrap();
    assert_eq!(resolved, Version::new(0, 1, 0));
}

#[skuld::test]
fn validate_bootstrap_no_tag_with_exact_errors() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "0.1.0");
    init_git_repo(root);

    let err = validate_against_tag(root, Group::ExRay, true).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("no `releases/ex-ray/v...` tag yet"), "msg was: {msg}");
}

#[skuld::test]
fn validate_exact_passes_when_tag_matches() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "0.1.0");
    init_git_repo(root);
    create_tag(root, "releases/ex-ray/v0.1.0");

    let v = validate_against_tag(root, Group::ExRay, true).unwrap();
    assert_eq!(v, Version::new(0, 1, 0));
}

#[skuld::test]
fn validate_exact_errors_on_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "0.2.0");
    init_git_repo(root);
    create_tag(root, "releases/ex-ray/v0.1.0");

    let err = validate_against_tag(root, Group::ExRay, true).unwrap_err();
    assert!(format!("{err:#}").contains("!= tag version"));
}

#[skuld::test]
fn validate_one_bump_ahead_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "0.2.0");
    init_git_repo(root);
    create_tag(root, "releases/ex-ray/v0.1.0");
    empty_commit(root, "next");

    let v = validate_against_tag(root, Group::ExRay, false).unwrap();
    assert_eq!(v, Version::new(0, 2, 0));
}

#[skuld::test]
fn validate_double_bump_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_version_toml(root, "0.1.2");
    init_git_repo(root);
    create_tag(root, "releases/ex-ray/v0.1.0");
    empty_commit(root, "next");

    let err = validate_against_tag(root, Group::ExRay, false).unwrap_err();
    assert!(format!("{err:#}").contains("not a valid successor"));
}
