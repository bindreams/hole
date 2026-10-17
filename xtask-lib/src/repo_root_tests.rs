use std::path::{Path, PathBuf};

use crate::repo_root::{hole_root_for_launch, repo_root_from};

/// A directory with a `[workspace]` manifest; `crates/hole` too when `hole`.
fn workspace(hole: bool) -> tempfile::TempDir {
    let ws = tempfile::tempdir().unwrap();
    std::fs::write(ws.path().join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    if hole {
        std::fs::create_dir_all(ws.path().join("crates").join("hole")).unwrap();
    }
    ws
}

fn same(found: &Path, expected: &Path) -> bool {
    found.canonicalize().unwrap() == expected.canonicalize().unwrap()
}

fn lookup(manifest: Option<&Path>, exe: Option<&Path>, cwd: Option<&Path>) -> anyhow::Result<PathBuf> {
    hole_root_for_launch(manifest, exe, cwd)
}

#[skuld::test]
fn finds_workspace_root_from_nested_member() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    let member = root.path().join("crates").join("dev-console");
    std::fs::create_dir_all(&member).unwrap();
    std::fs::write(member.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    let found = repo_root_from(&member).unwrap();
    assert_eq!(found.canonicalize().unwrap(), root.path().canonicalize().unwrap());
}

#[skuld::test]
fn rejects_tree_without_workspace_manifest() {
    let dir = tempfile::tempdir().unwrap();
    assert!(repo_root_from(dir.path()).is_err());
}

#[skuld::test]
fn ignores_non_workspace_manifests_on_the_way_up() {
    // A [package]-only Cargo.toml between the start dir and the real root
    // must not be mistaken for the workspace root.
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    let mid = root.path().join("crates");
    std::fs::create_dir_all(mid.join("inner")).unwrap();
    std::fs::write(mid.join("Cargo.toml"), "[package]\nname = \"mid\"\n").unwrap();
    let found = repo_root_from(&mid.join("inner")).unwrap();
    assert_eq!(found.canonicalize().unwrap(), root.path().canonicalize().unwrap());
}

#[skuld::test]
fn launch_lookup_prefers_the_manifest_dir_over_the_exe_and_cwd() {
    let manifest = workspace(true);
    let exe = workspace(true);
    let cwd = workspace(true);
    let found = lookup(Some(manifest.path()), Some(exe.path()), Some(cwd.path())).unwrap();
    assert!(same(&found, manifest.path()), "{found:?}");
}

#[skuld::test]
fn launch_lookup_prefers_the_exe_over_a_cwd_inside_another_workspace() {
    // Where the exe sits in the hole root, a cwd in some other workspace
    // (hole or not) must not be taken instead.
    let exe = workspace(true);
    for other in [workspace(false), workspace(true)] {
        let found = lookup(None, Some(exe.path()), Some(other.path())).unwrap();
        assert!(same(&found, exe.path()), "{found:?}");
    }
}

#[skuld::test]
fn launch_lookup_falls_back_to_the_cwd_when_the_exe_is_outside_every_hole_root() {
    let cwd = workspace(true);
    let no_workspace = tempfile::tempdir().unwrap();
    let non_hole = workspace(false);
    // Exe outside any workspace, and exe in a non-hole workspace: both fall through.
    for exe in [no_workspace.path(), non_hole.path()] {
        let found = lookup(None, Some(exe), Some(cwd.path())).unwrap();
        assert!(same(&found, cwd.path()), "{found:?}");
    }
}

#[skuld::test]
fn launch_lookup_skips_a_manifest_dir_that_is_not_a_hole_root() {
    let manifest = workspace(false);
    let exe = workspace(true);
    let found = lookup(Some(manifest.path()), Some(exe.path()), None).unwrap();
    assert!(same(&found, exe.path()), "{found:?}");
}

#[skuld::test]
fn launch_lookup_errors_naming_every_candidate_when_none_is_a_hole_root() {
    let manifest = workspace(false);
    let cwd = workspace(false);
    let exe = tempfile::tempdir().unwrap();
    let err = lookup(Some(manifest.path()), Some(exe.path()), Some(cwd.path()))
        .unwrap_err()
        .to_string();
    for needle in [
        "CARGO_MANIFEST_DIR",
        "executable",
        "working directory",
        &manifest.path().display().to_string(),
        &exe.path().display().to_string(),
        &cwd.path().display().to_string(),
    ] {
        assert!(err.contains(needle), "{needle:?} missing from: {err}");
    }
}

#[skuld::test]
fn launch_lookup_errors_when_no_candidate_exists() {
    assert!(lookup(None, None, None).is_err());
}
