use std::path::{Path, PathBuf};

use crate::repo_root::{hole_root_for_launch, repo_root_from, workspace_root_for};

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

/// A standalone launch: no handoff from xtask.
fn lookup(manifest: Option<&Path>, exe: Option<&Path>, cwd: Option<&Path>) -> anyhow::Result<PathBuf> {
    hole_root_for_launch(None, manifest, exe, cwd)
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
fn a_hand_run_prefers_the_exe_over_a_cwd_inside_another_workspace() {
    // No handoff: where the exe sits in a hole root, a cwd in some other
    // workspace (hole or not) must not be taken instead.
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

// The handoff from `cargo xtask` --------------------------------------------------------------------------------------

#[skuld::test]
fn the_handoff_beats_a_manifest_dir_exe_and_cwd_that_are_all_hole_roots() {
    // The `target/` redirected into another checkout case: the exe (and
    // manifest dir) sit in hole root A, xtask pinned B.
    let pinned = workspace(true);
    let (manifest, exe, cwd) = (workspace(true), workspace(true), workspace(true));
    let found = hole_root_for_launch(
        Some(pinned.path()),
        Some(manifest.path()),
        Some(exe.path()),
        Some(cwd.path()),
    )
    .unwrap();
    assert!(same(&found, pinned.path()), "{found:?}");
}

#[skuld::test]
fn the_handoff_is_taken_with_no_other_location_available() {
    let pinned = workspace(true);
    let found = hole_root_for_launch(Some(pinned.path()), None, None, None).unwrap();
    assert!(same(&found, pinned.path()), "{found:?}");
}

#[skuld::test]
fn the_handoff_resolves_a_worktree_nested_in_the_checkout_the_exe_sits_in() {
    // This project's layout: worktrees live under the main checkout's `.tmp/`
    // and share its target directory, so the exe's walk-up reaches the main
    // checkout while xtask pinned the worktree.
    let main = workspace(true);
    let worktree = main.path().join(".tmp").join("claude").join("wt").join("pinned");
    std::fs::create_dir_all(worktree.join("crates").join("hole")).unwrap();
    std::fs::write(worktree.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    let exe = main.path().join(".tmp").join("shared").join("debug");
    std::fs::create_dir_all(&exe).unwrap();

    let found = hole_root_for_launch(Some(&worktree), None, Some(&exe), Some(&worktree)).unwrap();
    assert!(same(&found, &worktree), "{found:?}");
    // Without the handoff, the exe's walk-up wins: the ambient signals alone
    // cannot tell this launch from a hand run of the main checkout's binary.
    let found = lookup(None, Some(&exe), Some(&worktree)).unwrap();
    assert!(same(&found, main.path()), "{found:?}");
}

#[skuld::test]
fn a_handoff_that_is_not_a_hole_root_is_an_error_naming_it_never_a_fallback() {
    let hole = workspace(true); // a perfectly good exe, manifest dir and cwd
    let non_hole = workspace(false);
    let nested = hole.path().join("crates");
    let missing = hole.path().join("no-such-dir");
    let relative = Path::new("crates/hole");
    let empty = Path::new("");
    for bad in [non_hole.path(), nested.as_path(), missing.as_path(), relative, empty] {
        let err = hole_root_for_launch(Some(bad), Some(hole.path()), Some(hole.path()), Some(hole.path()))
            .expect_err(&format!("{bad:?} is not a hole root"))
            .to_string();
        assert!(err.contains("HOLE_DEV_REPO_ROOT"), "{bad:?}: {err}");
        assert!(err.contains(&bad.display().to_string()), "{bad:?}: {err}");
    }
}

// Unix only: the relative spelling below assumes one filesystem root.
#[cfg(unix)]
#[skuld::test]
fn a_relative_handoff_is_an_error_even_when_it_names_a_hole_root_from_the_cwd() {
    let hole = workspace(true);
    // `hole` spelled relative to the test's cwd, so it does resolve to a hole root.
    let cwd = std::env::current_dir().unwrap();
    let mut relative = PathBuf::new();
    for _ in cwd.components().skip(1) {
        relative.push("..");
    }
    relative.push(hole.path().strip_prefix("/").unwrap());
    assert!(
        relative.join("crates").join("hole").is_dir(),
        "HARNESS: {relative:?} must name the hole root from the cwd"
    );
    let err = hole_root_for_launch(Some(&relative), Some(hole.path()), Some(hole.path()), Some(hole.path()))
        .expect_err("a relative handoff must be refused")
        .to_string();
    assert!(err.contains("HOLE_DEV_REPO_ROOT"), "{err}");
}

// A relative `CARGO_MANIFEST_DIR` -------------------------------------------------------------------------------------

/// A hand-set value is judged against the cwd here and again after
/// dev-console changes into the root, so it is refused rather than skipped:
/// the exe and cwd would otherwise mask it in some launches and not others.
#[skuld::test]
fn a_relative_or_empty_manifest_dir_is_an_error_naming_the_variable_never_a_fallback() {
    let hole = workspace(true); // a perfectly good exe and cwd
    for bad in [Path::new("crates/foo"), Path::new("")] {
        let err = lookup(Some(bad), Some(hole.path()), Some(hole.path()))
            .expect_err(&format!("{bad:?} is not absolute"))
            .to_string();
        assert!(err.contains("CARGO_MANIFEST_DIR"), "{bad:?}: {err}");
        assert!(err.contains(&bad.display().to_string()), "{bad:?}: {err}");
    }
}

// Unix only: the relative spelling below assumes one filesystem root.
#[cfg(unix)]
#[skuld::test]
fn a_relative_manifest_dir_is_an_error_even_when_it_names_a_hole_root_from_the_cwd() {
    let hole = workspace(true);
    let cwd = std::env::current_dir().unwrap();
    let mut relative = PathBuf::new();
    for _ in cwd.components().skip(1) {
        relative.push("..");
    }
    relative.push(hole.path().strip_prefix("/").unwrap());
    assert!(
        relative.join("crates").join("hole").is_dir(),
        "HARNESS: {relative:?} must name the hole root from the cwd"
    );
    let err = lookup(Some(&relative), Some(hole.path()), Some(hole.path()))
        .expect_err("a relative CARGO_MANIFEST_DIR must be refused")
        .to_string();
    assert!(err.contains("CARGO_MANIFEST_DIR"), "{err}");
}

/// The handoff is checked first, so a valid one never reaches the manifest dir.
#[skuld::test]
fn a_valid_handoff_is_unaffected_by_a_relative_manifest_dir() {
    let pinned = workspace(true);
    let found = hole_root_for_launch(Some(pinned.path()), Some(Path::new("crates/foo")), None, None).unwrap();
    assert!(same(&found, pinned.path()), "{found:?}");
}

// `repo_root` (any workspace) -----------------------------------------------------------------------------------------

#[skuld::test]
fn the_workspace_lookup_prefers_an_absolute_manifest_dir_and_falls_back_to_the_exe() {
    let manifest = workspace(false);
    let exe = workspace(false);
    let found = workspace_root_for(Some(manifest.path()), || Ok(Some(exe.path().to_path_buf()))).unwrap();
    assert!(same(&found, manifest.path()), "{found:?}");

    // An absolute manifest dir outside every workspace, or none at all: the exe.
    let none = tempfile::tempdir().unwrap();
    for manifest in [Some(none.path()), None] {
        let found = workspace_root_for(manifest, || Ok(Some(exe.path().to_path_buf()))).unwrap();
        assert!(same(&found, exe.path()), "{found:?}");
    }
}

#[skuld::test]
fn the_workspace_lookup_asks_for_the_exe_only_when_the_manifest_dir_does_not_answer() {
    let manifest = workspace(false);
    let found = workspace_root_for(Some(manifest.path()), || {
        panic!("the exe was looked up although the manifest dir answered")
    })
    .unwrap();
    assert!(same(&found, manifest.path()), "{found:?}");

    // Asked, and failing: its error is the answer, as when `current_exe` fails.
    let none = tempfile::tempdir().unwrap();
    for manifest in [Some(none.path()), None] {
        let err = workspace_root_for(manifest, || Err(anyhow::anyhow!("no exe here")))
            .expect_err("the exe lookup failed")
            .to_string();
        assert!(err.contains("no exe here"), "{err}");
    }
}

#[skuld::test]
fn the_workspace_lookup_refuses_a_relative_or_empty_manifest_dir_naming_the_variable() {
    let ws = workspace(false); // the exe would answer if the bad value were skipped
    for bad in [Path::new("crates/foo"), Path::new("")] {
        let err = workspace_root_for(Some(bad), || Ok(Some(ws.path().to_path_buf())))
            .expect_err(&format!("{bad:?} is not absolute"))
            .to_string();
        assert!(err.contains("CARGO_MANIFEST_DIR"), "{bad:?}: {err}");
        assert!(err.contains(&bad.display().to_string()), "{bad:?}: {err}");
    }
}

// Unix only: the relative spelling below assumes one filesystem root.
#[cfg(unix)]
#[skuld::test]
fn the_workspace_lookup_refuses_a_relative_manifest_dir_that_names_a_workspace_from_the_cwd() {
    let ws = workspace(false);
    let cwd = std::env::current_dir().unwrap();
    let mut relative = PathBuf::new();
    for _ in cwd.components().skip(1) {
        relative.push("..");
    }
    relative.push(ws.path().strip_prefix("/").unwrap());
    assert!(
        relative.join("Cargo.toml").is_file(),
        "HARNESS: {relative:?} must name the workspace from the cwd"
    );
    let err = workspace_root_for(Some(&relative), || Ok(Some(ws.path().to_path_buf())))
        .expect_err("a relative CARGO_MANIFEST_DIR must be refused")
        .to_string();
    assert!(err.contains("CARGO_MANIFEST_DIR"), "{err}");
}
