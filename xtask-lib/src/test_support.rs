//! Test-only helpers shared across `version_tests.rs` and
//! `v2ray_plugin_version_tests.rs`. Compiled only under `#[cfg(test)]`.

use std::path::Path;
use std::process::Command;

/// Initialize a minimal git repo in `root` and commit any files present.
///
/// Used by tests that exercise tag-based behavior under a tempdir. Mirrors
/// the same configuration used elsewhere in the workspace test suite.
pub(crate) fn init_git_repo(root: &Path) {
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

/// Create an annotated tag at HEAD in the repo at `root`.
pub(crate) fn create_tag(root: &Path, tag: &str) {
    let s = Command::new("git")
        .args(["tag", tag])
        .current_dir(root)
        .status()
        .unwrap();
    assert!(s.success(), "git tag {tag} failed in {}", root.display());
}

/// Make an empty commit so subsequent tags point to distinct commits when needed.
pub(crate) fn empty_commit(root: &Path, msg: &str) {
    let s = Command::new("git")
        .args(["commit", "--allow-empty", "--quiet", "-m", msg])
        .current_dir(root)
        .status()
        .unwrap();
    assert!(s.success(), "git empty commit failed in {}", root.display());
}
