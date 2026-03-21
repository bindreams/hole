use super::*;

// parse =====

#[skuld::test]
fn parse_bare_version() {
    let v = ReleaseVersion::parse("1.2.3").unwrap();
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 2);
    assert_eq!(v.patch, 3);
}

#[skuld::test]
fn parse_v_prefix() {
    let v = ReleaseVersion::parse("v1.2.3").unwrap();
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 2);
    assert_eq!(v.patch, 3);
}

#[skuld::test]
fn parse_v_prefix_equals_bare() {
    let a = ReleaseVersion::parse("v1.2.3").unwrap();
    let b = ReleaseVersion::parse("1.2.3").unwrap();
    assert_eq!(a, b);
}

#[skuld::test]
fn parse_rejects_prerelease() {
    assert!(ReleaseVersion::parse("1.2.3-alpha").is_err());
}

#[skuld::test]
fn parse_rejects_build_metadata() {
    assert!(ReleaseVersion::parse("1.2.3+build").is_err());
}

#[skuld::test]
fn parse_rejects_two_components() {
    assert!(ReleaseVersion::parse("1.2").is_err());
}

#[skuld::test]
fn parse_rejects_leading_zero() {
    assert!(ReleaseVersion::parse("01.2.3").is_err());
}

#[skuld::test]
fn parse_rejects_empty() {
    assert!(ReleaseVersion::parse("").is_err());
}

#[skuld::test]
fn parse_rejects_garbage() {
    assert!(ReleaseVersion::parse("not-a-version").is_err());
}

// from_build_version =====

#[skuld::test]
fn from_build_version_release() {
    let (v, is_snapshot) = ReleaseVersion::from_build_version("0.1.0").unwrap();
    assert_eq!(v, ReleaseVersion::parse("0.1.0").unwrap());
    assert!(!is_snapshot);
}

#[skuld::test]
fn from_build_version_snapshot() {
    let (v, is_snapshot) = ReleaseVersion::from_build_version("0.1.0-snapshot+git.abc123def456").unwrap();
    assert_eq!(v, ReleaseVersion::parse("0.1.0").unwrap());
    assert!(is_snapshot);
}

#[skuld::test]
fn from_build_version_snapshot_dirty() {
    let (v, is_snapshot) = ReleaseVersion::from_build_version("0.1.0-snapshot+git.abc123def456.dirty").unwrap();
    assert_eq!(v, ReleaseVersion::parse("0.1.0").unwrap());
    assert!(is_snapshot);
}

#[skuld::test]
fn from_build_version_dirty_on_tag() {
    let (v, is_snapshot) = ReleaseVersion::from_build_version("0.1.0.dirty").unwrap();
    assert_eq!(v, ReleaseVersion::parse("0.1.0").unwrap());
    assert!(!is_snapshot);
}

#[skuld::test]
fn from_build_version_rejects_garbage() {
    assert!(ReleaseVersion::from_build_version("not-a-version").is_err());
}

// Ordering =====

#[skuld::test]
fn ordering_patch() {
    let a = ReleaseVersion::parse("0.1.0").unwrap();
    let b = ReleaseVersion::parse("0.1.1").unwrap();
    assert!(a < b);
}

#[skuld::test]
fn ordering_minor() {
    let a = ReleaseVersion::parse("0.1.0").unwrap();
    let b = ReleaseVersion::parse("0.2.0").unwrap();
    assert!(a < b);
}

#[skuld::test]
fn ordering_major() {
    let a = ReleaseVersion::parse("0.2.0").unwrap();
    let b = ReleaseVersion::parse("1.0.0").unwrap();
    assert!(a < b);
}

#[skuld::test]
fn ordering_chain() {
    let a = ReleaseVersion::parse("0.1.0").unwrap();
    let b = ReleaseVersion::parse("0.2.0").unwrap();
    let c = ReleaseVersion::parse("1.0.0").unwrap();
    assert!(a < b);
    assert!(b < c);
}

// Display =====

#[skuld::test]
fn display_no_v_prefix() {
    let v = ReleaseVersion::parse("v1.2.3").unwrap();
    assert_eq!(v.to_string(), "1.2.3");
}

#[skuld::test]
fn display_roundtrip() {
    let v = ReleaseVersion::parse("1.2.3").unwrap();
    assert_eq!(v.to_string(), "1.2.3");
}
