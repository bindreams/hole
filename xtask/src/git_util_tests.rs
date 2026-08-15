use std::path::Path;
use std::process::Command;

use super::git_util::{
    disclose_prior_commit, head_blob_hash_or_deleted, index_blob_hash_or_deleted, merge_skip_value, run_git,
    run_git_with_env,
};

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

#[skuld::test]
fn run_git_with_env_forwards_env_vars_to_the_git_subprocess() {
    // A pre-commit hook that records the env var it actually saw proves the
    // env reaches a child process git itself launches (the hook), not just
    // the immediate `git` invocation — exactly the path the SKIP fix relies
    // on (git-subrepo's own internal `git commit` inherits it the same way).
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);

    let hooks_dir = dir.path().join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();
    let captured_path = dir.path().join("captured-env.txt");
    let captured_path_str = captured_path.display().to_string().replace('\\', "/");
    std::fs::write(
        hooks_dir.join("pre-commit"),
        format!("#!/bin/sh\nprintf '%s' \"$XTASK_TEST_VAR\" > \"{captured_path_str}\"\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(hooks_dir.join("pre-commit"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    std::fs::write(dir.path().join("f.txt"), "content\n").unwrap();
    git(dir.path(), &["add", "f.txt"]);
    run_git_with_env(
        dir.path(),
        &["commit", "-m", "test"],
        &[("XTASK_TEST_VAR", "hello-from-run-git-with-env")],
    )
    .expect("commit should succeed");

    let captured = std::fs::read_to_string(&captured_path).unwrap();
    assert_eq!(captured, "hello-from-run-git-with-env");
}

#[skuld::test]
fn run_git_with_env_bails_on_failure_like_run_git() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    std::fs::write(dir.path().join("f.txt"), "content\n").unwrap();
    git(dir.path(), &["add", "f.txt"]);
    git(dir.path(), &["commit", "-m", "initial"]);

    let err = run_git_with_env(
        dir.path(),
        &["commit", "-m", "nothing to see here"],
        &[("SOME_VAR", "1")],
    )
    .expect_err("commit with nothing staged should fail");
    assert!(
        format!("{err:#}").contains("nothing to commit"),
        "same bail-on-failure contract as run_git, including stdout: {err:#}"
    );
}

#[skuld::test]
fn merge_skip_value_appends_when_nothing_pre_existing() {
    assert_eq!(
        merge_skip_value(None, "check-vendoring-integrity"),
        "check-vendoring-integrity"
    );
    assert_eq!(
        merge_skip_value(Some(""), "check-vendoring-integrity"),
        "check-vendoring-integrity"
    );
}

#[skuld::test]
fn merge_skip_value_unions_with_a_pre_existing_value_as_a_comma_join() {
    assert_eq!(
        merge_skip_value(Some("cargo-fmt"), "check-vendoring-integrity"),
        "cargo-fmt,check-vendoring-integrity"
    );
    assert_eq!(
        merge_skip_value(Some("cargo-fmt,cargo-clippy"), "check-vendoring-integrity"),
        "cargo-fmt,cargo-clippy,check-vendoring-integrity"
    );
}

#[skuld::test]
fn index_blob_hash_or_deleted_returns_the_staged_blob_hash_for_a_present_file() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    std::fs::write(dir.path().join("f.txt"), "hello\n").unwrap();
    git(dir.path(), &["add", "f.txt"]);

    let output = Command::new("git")
        .args(["rev-parse", ":./f.txt"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let expected = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let actual = index_blob_hash_or_deleted(dir.path(), "f.txt").unwrap();
    assert_eq!(actual, expected);
}

#[skuld::test]
fn index_blob_hash_or_deleted_returns_deleted_sentinel_for_an_unstaged_file() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);

    let actual = index_blob_hash_or_deleted(dir.path(), "missing.txt").unwrap();
    assert_eq!(actual, "<deleted>");
}

#[skuld::test]
fn head_blob_hash_or_deleted_returns_the_committed_blob_hash_for_a_present_file() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    std::fs::write(dir.path().join("f.txt"), "hello\n").unwrap();
    git(dir.path(), &["add", "f.txt"]);
    git(dir.path(), &["commit", "-m", "initial"]);

    // This fixture never crosses a checkout boundary between write and
    // read, so a plain (filtered) `hash-object` call agrees with the
    // committed blob here regardless of platform — the smudge-immunity
    // this helper actually exists for is covered by the dedicated autocrlf
    // fixture below, which does cross that boundary.
    let output = Command::new("git")
        .args(["hash-object", "f.txt"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let expected = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let actual = head_blob_hash_or_deleted(dir.path(), "f.txt").unwrap();
    assert_eq!(actual, expected);
}

#[skuld::test]
fn head_blob_hash_or_deleted_returns_deleted_sentinel_for_a_path_not_in_head() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    std::fs::write(dir.path().join("other.txt"), "x\n").unwrap();
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-m", "initial"]);

    let actual = head_blob_hash_or_deleted(dir.path(), "missing.txt").unwrap();
    assert_eq!(actual, "<deleted>");
}

// The real bug this pair of helpers exists to fix: a checkout between
// write-time and read-time can smudge a text file's line endings on disk
// (Windows' `core.autocrlf=true` — GitHub's windows-latest runners default
// to it) without changing what's actually stored in git. Re-hashing
// filesystem content across that boundary (the old `hash_object_or_deleted`,
// even with `--no-filters`) silently diverges from the canonical blob;
// reading straight from the index/HEAD never does. `core.autocrlf` is set
// locally on the fixture (not globally) so this reproduces deterministically
// on any host, regardless of the developer's own git config.
#[skuld::test]
fn index_blob_hash_or_deleted_is_immune_to_a_prior_checkouts_autocrlf_smudge() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    git(dir.path(), &["config", "core.autocrlf", "true"]);
    std::fs::write(dir.path().join("f.txt"), "line one\nline two\n").unwrap();
    git(dir.path(), &["add", "f.txt"]);
    git(dir.path(), &["commit", "-m", "initial"]);
    let canonical_hash = String::from_utf8_lossy(
        &Command::new("git")
            .args(["rev-parse", "HEAD:./f.txt"])
            .current_dir(dir.path())
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();

    // Simulate what an actual conflict-resolution checkout does: rewrite
    // f.txt from the object database, which smudges it to CRLF on disk
    // under autocrlf=true — confirm the fixture actually reproduces this,
    // not just assume it.
    std::fs::remove_file(dir.path().join("f.txt")).unwrap();
    git(dir.path(), &["checkout", "HEAD", "--", "f.txt"]);
    let on_disk = std::fs::read(dir.path().join("f.txt")).unwrap();
    assert!(
        on_disk.windows(2).any(|w| w == b"\r\n"),
        "fixture didn't reproduce the smudge — checkout should have written CRLF: {on_disk:?}"
    );

    // The writer's real sequence: re-stage (the clean filter recovers the
    // same LF content, so this is a no-op for the index), then read the
    // hash from the index — must equal the canonical hash despite the CRLF
    // currently sitting on disk.
    git(dir.path(), &["add", "-A"]);
    let actual = index_blob_hash_or_deleted(dir.path(), "f.txt").unwrap();
    assert_eq!(actual, canonical_hash);
}
