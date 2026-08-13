use std::path::Path;
use std::process::Command;

use super::git_util::{disclose_prior_commit, run_git};

fn git(cwd: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| panic!("failed to run git {args:?} in {}: {e}", cwd.display()));
    assert!(status.success(), "git {args:?} failed in {}", cwd.display());
}

#[skuld::test]
fn run_git_failure_message_includes_stdout_not_just_stderr() {
    // `git commit` with nothing staged reports the actual reason ("nothing
    // to commit, working tree clean") on stdout, with an empty stderr —
    // run_git's failure message must not drop it.
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    std::fs::write(dir.path().join("f.txt"), "content\n").unwrap();
    git(dir.path(), &["add", "f.txt"]);
    git(dir.path(), &["commit", "-m", "initial"]);

    let err = run_git(dir.path(), &["commit", "-m", "nothing to see here"])
        .expect_err("commit with nothing staged should fail");
    let message = format!("{err:#}");
    assert!(
        message.contains("nothing to commit"),
        "the stdout-only failure reason must be included: {message}"
    );
}

#[skuld::test]
fn disclose_prior_commit_names_the_sha_and_the_reset_command() {
    let err = anyhow::anyhow!("go mod tidy failed");

    let disclosed = disclose_prior_commit(err, "abc1234", "the VENDORING.md version-note commit");

    let message = format!("{disclosed:#}");
    assert!(message.contains("abc1234"), "the commit sha should be named: {message}");
    assert!(
        message.contains("git reset --hard abc1234~1"),
        "the recovery command should be exact: {message}"
    );
    assert!(
        message.contains("the VENDORING.md version-note commit"),
        "the caller-supplied description should be included: {message}"
    );
    assert!(
        message.contains("go mod tidy failed"),
        "the original error must survive: {message}"
    );
}
