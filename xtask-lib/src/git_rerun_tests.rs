use std::path::{Path, PathBuf};
use std::process::Command;

use crate::git_rerun::{read_head, rerun_paths, tracked_or_nearest_ancestor, write_rerun_if_changed};

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(["-c", "user.email=t@example.invalid", "-c", "user.name=T"])
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {} failed in {}", args.join(" "), dir.display());
}

/// A repo with one commit on branch `work`.
fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f"), "x").unwrap();
    git(dir.path(), &["init", "--quiet", "--initial-branch=work"]);
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "--quiet", "-m", "init"]);
    dir
}

fn git_dir(root: &Path) -> PathBuf {
    root.join(".git").canonicalize().unwrap()
}

fn canon(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.into_iter().map(|p| p.canonicalize().unwrap()).collect()
}

/// A `rerun-if-changed` on a missing path makes cargo treat the build script as
/// changed on every invocation, so no path may be reported unless it exists.
fn assert_all_exist(paths: &[PathBuf]) {
    for p in paths {
        assert!(p.exists(), "{} is reported but does not exist", p.display());
    }
}

#[skuld::test]
fn a_loose_ref_repo_reports_head_and_the_branch_ref_and_nothing_missing() {
    let r = repo();
    let paths = rerun_paths(r.path()).unwrap();
    assert_all_exist(&paths);
    let paths = canon(paths);
    assert!(paths.contains(&git_dir(r.path()).join("HEAD")));
    assert!(paths.contains(&git_dir(r.path()).join("refs/heads/work")));
}

#[skuld::test]
fn packed_refs_is_reported_only_once_it_exists() {
    let r = repo();
    let packed = git_dir(r.path()).join("packed-refs");
    assert!(!packed.exists(), "fixture: a fresh repo has no packed-refs");
    assert!(!canon(rerun_paths(r.path()).unwrap()).contains(&packed));

    git(r.path(), &["pack-refs", "--all"]);
    assert!(canon(rerun_paths(r.path()).unwrap()).contains(&packed));
}

/// After `git pack-refs` the branch ref has no loose file, but a later commit
/// writes one inside `refs/heads`, so that directory stands in for the file.
#[skuld::test]
fn a_packed_branch_ref_is_tracked_through_the_nearest_existing_ancestor() {
    let r = repo();
    git(r.path(), &["pack-refs", "--all"]);
    let loose = git_dir(r.path()).join("refs/heads/work");
    assert!(!loose.exists(), "fixture: pack-refs --all removes the loose ref");

    let paths = rerun_paths(r.path()).unwrap();
    assert_all_exist(&paths);
    let paths = canon(paths);
    assert!(
        paths.iter().any(|p| loose.starts_with(p) && p != &git_dir(r.path())),
        "no tracked path covers a new loose {}: {paths:?}",
        loose.display()
    );
}

#[skuld::test]
fn a_detached_head_reports_no_branch_ref() {
    let r = repo();
    git(r.path(), &["checkout", "--quiet", "--detach"]);
    let paths = rerun_paths(r.path()).unwrap();
    assert_all_exist(&paths);
    assert!(!canon(paths).contains(&git_dir(r.path()).join("refs/heads/work")));
}

/// In a linked worktree `.git` is a file: HEAD lives in the worktree's own git
/// dir, refs in the common one.
#[skuld::test]
fn a_linked_worktree_resolves_its_git_dirs_instead_of_dot_git() {
    let r = repo();
    let wt_parent = tempfile::tempdir().unwrap();
    let wt = wt_parent.path().join("wt");
    git(
        r.path(),
        &["worktree", "add", "--quiet", "-b", "other", wt.to_str().unwrap()],
    );
    assert!(wt.join(".git").is_file(), "fixture: a linked worktree's .git is a file");

    let paths = rerun_paths(&wt).unwrap();
    assert!(!paths.is_empty());
    assert_all_exist(&paths);
    let paths = canon(paths);
    let head = git_dir(r.path()).join("worktrees/wt/HEAD");
    assert!(paths.contains(&head), "{head:?} missing from {paths:?}");
    assert!(paths.contains(&git_dir(r.path()).join("refs/heads/other")));
}

#[skuld::test]
fn the_nearest_existing_ancestor_stops_at_the_floor() {
    let dir = tempfile::tempdir().unwrap();
    let floor = dir.path().join("refs");
    std::fs::create_dir_all(floor.join("heads")).unwrap();

    let present = floor.join("heads/a");
    std::fs::write(&present, "").unwrap();
    assert_eq!(tracked_or_nearest_ancestor(&present, &floor), Some(present.clone()));

    let missing = floor.join("heads/x/y/z");
    assert_eq!(tracked_or_nearest_ancestor(&missing, &floor), Some(floor.join("heads")));

    let gone = floor.join("gone/x");
    assert_eq!(tracked_or_nearest_ancestor(&gone, &floor), Some(floor.clone()));

    std::fs::remove_dir_all(&floor).unwrap();
    assert_eq!(tracked_or_nearest_ancestor(&missing, &floor), None);
}

/// The version stamp counts commits since a tag, so creating one must rerun it.
#[skuld::test]
fn a_new_tag_lands_under_a_tracked_path() {
    let r = repo();
    let paths = canon(rerun_paths(r.path()).unwrap());
    let new_tag = git_dir(r.path()).join("refs/tags/new");
    assert!(
        paths.iter().any(|p| new_tag.starts_with(p) && p != &git_dir(r.path())),
        "no tracked path covers {}: {paths:?}",
        new_tag.display()
    );
}

/// Only a missing HEAD means "no HEAD to track" (a linked worktree's `.git` is a
/// file). Any other read failure is an error, or the stamp would silently stop
/// following commits.
#[skuld::test]
fn only_a_missing_head_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read_head(&dir.path().join("HEAD")).unwrap(), None);

    let head = dir.path().join("HEAD");
    std::fs::write(&head, "ref: refs/heads/work\n").unwrap();
    assert_eq!(read_head(&head).unwrap().as_deref(), Some("ref: refs/heads/work\n"));

    // A directory where the file belongs fails to read with a kind other than NotFound.
    let not_a_file = dir.path().join("dir");
    std::fs::create_dir(&not_a_file).unwrap();
    let err = read_head(&not_a_file).unwrap_err();
    assert!(format!("{err:#}").contains("dir"), "{err:#}");
}

fn emitted(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    write_rerun_if_changed(root, &mut out).unwrap();
    String::from_utf8(out).unwrap().lines().map(str::to_string).collect()
}

/// One `cargo:rerun-if-changed=<path>` line per tracked path, and nothing else.
#[skuld::test]
fn the_emitted_lines_are_one_rerun_directive_per_tracked_path() {
    let r = repo();
    let want: Vec<String> = rerun_paths(r.path())
        .unwrap()
        .iter()
        .map(|p| format!("cargo:rerun-if-changed={}", p.display()))
        .collect();
    assert!(want.len() >= 2, "fixture: HEAD and a branch ref at least");
    assert_eq!(emitted(r.path()), want);
}

/// Outside a repository git cannot answer: the build script must print a
/// warning and carry on, not panic and not print a rerun path.
#[skuld::test]
fn outside_a_repository_the_emission_is_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let lines = emitted(dir.path());
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].starts_with("cargo:warning=cannot resolve git paths for the version stamp: "),
        "{lines:?}"
    );
}
