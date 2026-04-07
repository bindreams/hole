use crate::version::*;
use semver::Version;

fn v(major: u64, minor: u64, patch: u64) -> Version {
    Version::new(major, minor, patch)
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

// cargo_toml_version ==================================================================================================

#[skuld::test]
fn cargo_toml_version_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    std::fs::write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a", "b"]
"#,
    )
    .unwrap();

    for member in ["a", "b"] {
        std::fs::create_dir_all(root.join(member)).unwrap();
        std::fs::write(
            root.join(member).join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"1.2.3\"\n",
        )
        .unwrap();
    }

    let v = cargo_toml_version(root).unwrap();
    assert_eq!(v, Version::new(1, 2, 3));
}

#[skuld::test]
fn cargo_toml_version_inconsistent_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    std::fs::write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a", "b"]
"#,
    )
    .unwrap();

    std::fs::create_dir_all(root.join("a")).unwrap();
    std::fs::write(
        root.join("a").join("Cargo.toml"),
        "[package]\nname = \"a\"\nversion = \"1.2.3\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("b")).unwrap();
    std::fs::write(
        root.join("b").join("Cargo.toml"),
        "[package]\nname = \"b\"\nversion = \"1.2.4\"\n",
    )
    .unwrap();

    let err = cargo_toml_version(root).unwrap_err();
    assert!(err.to_string().contains("inconsistent"));
}

#[skuld::test]
fn cargo_toml_version_rejects_pre_release() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    std::fs::write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["a"]
"#,
    )
    .unwrap();
    std::fs::create_dir_all(root.join("a")).unwrap();
    std::fs::write(
        root.join("a").join("Cargo.toml"),
        "[package]\nname = \"a\"\nversion = \"1.2.3-beta\"\n",
    )
    .unwrap();

    let err = cargo_toml_version(root).unwrap_err();
    assert!(err.to_string().contains("strict MAJOR.MINOR.PATCH"));
}

#[skuld::test]
fn cargo_toml_version_rejects_glob_members() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["crates/*"]
"#,
    )
    .unwrap();
    let err = cargo_toml_version(root).unwrap_err();
    assert!(err.to_string().contains("glob"));
}

// display_version =====================================================================================================
//
// We don't unit-test display_version directly because it shells out to `git`
// and depends on the on-disk state of an actual repo. The fallback to
// "0.0.0-unknown" on failure means it can be called from build.rs without
// risk of panic, which is the contract that matters.
