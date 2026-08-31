//! Unit tests for [`crate::golangci_lint`]'s cache decision.

use std::fs;

use crate::golangci_lint::cache_is_valid;

const SHA: &str = "b1946ac92492d2347c6235b4d2611184";

/// (binary, sentinel) inside a fresh temp dir, neither created yet.
fn paths(dir: &tempfile::TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        dir.path().join("golangci-lint"),
        dir.path().join("golangci-lint.verified"),
    )
}

#[skuld::test]
fn a_matching_sentinel_is_a_cache_hit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (bin, sentinel) = paths(&dir);
    fs::write(&bin, b"binary").expect("write bin");
    fs::write(&sentinel, SHA).expect("write sentinel");
    assert!(cache_is_valid(&bin, &sentinel, SHA));
}

/// The sentinel is written after the binary, so an interrupted run leaves the
/// binary with no sentinel — which must not read as verified.
#[skuld::test]
fn a_binary_with_no_sentinel_is_not_verified() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (bin, sentinel) = paths(&dir);
    fs::write(&bin, b"binary").expect("write bin");
    assert!(!cache_is_valid(&bin, &sentinel, SHA));
}

/// A sentinel left behind by a previous pin records a different hash. This is
/// what makes a `VERSION` bump re-download rather than trust a stale binary.
#[skuld::test]
fn a_sentinel_from_another_pin_is_not_verified() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (bin, sentinel) = paths(&dir);
    fs::write(&bin, b"binary").expect("write bin");
    fs::write(&sentinel, "0000000000000000000000000000000000000000").expect("write sentinel");
    assert!(!cache_is_valid(&bin, &sentinel, SHA));
}

#[skuld::test]
fn a_sentinel_with_no_binary_is_not_verified() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (bin, sentinel) = paths(&dir);
    fs::write(&sentinel, SHA).expect("write sentinel");
    assert!(!cache_is_valid(&bin, &sentinel, SHA));
}

/// The sentinel is written without a trailing newline, but an editor or a
/// `echo` redirect can add one; a hit must not hinge on that.
#[skuld::test]
fn surrounding_whitespace_in_the_sentinel_is_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (bin, sentinel) = paths(&dir);
    fs::write(&bin, b"binary").expect("write bin");
    fs::write(&sentinel, format!("  {SHA}\n")).expect("write sentinel");
    assert!(cache_is_valid(&bin, &sentinel, SHA));
}
