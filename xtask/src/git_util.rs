//! Small shared helpers for xtask modules that shell out to `git`.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Run `git <args>` in `cwd`, returning trimmed stdout on success and a
/// descriptive error (including stderr) on failure.
pub fn run_git(cwd: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to run git {args:?}"))?;
    if !output.status.success() {
        // Some git commands (notably `git commit`, e.g. on "nothing to
        // commit") report the actual failure reason on stdout, not stderr —
        // include both so the real cause isn't dropped.
        bail!(
            "git {args:?} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Like `run_git`, but returns stdout without `.trim()`-ing it. For a
/// caller whose output format can legitimately start or end with a byte
/// `.trim()` treats as whitespace (e.g. NUL-delimited `-z` output, where a
/// path can start with a literal space), `run_git`'s trim silently
/// corrupts the first/last field — this is the untrimmed escape hatch for
/// that one shape of output, not a general replacement for `run_git`.
pub fn run_git_raw(cwd: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to run git {args:?}"))?;
    if !output.status.success() {
        bail!(
            "git {args:?} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Wraps `err` with a disclosure that an irreversible commit `sha`
/// (described by `what`, e.g. `"the VENDORING.md version-note commit"`)
/// already landed on the branch before this failure, with a
/// `git reset --hard <sha>~1` recovery hint. Every xtask module that
/// commits something and can still fail on a later, independent step
/// needs this same disclosure — never let such a failure propagate bare
/// (see `pull_subrepo.rs`'s equivalent hand-written closures for the
/// convention this centralizes).
pub fn disclose_prior_commit(err: anyhow::Error, sha: &str, what: &str) -> anyhow::Error {
    err.context(format!(
        "{what} {sha} already landed on this branch before this failure — `git reset --hard \
         {sha}~1` undoes it if you want to retry from a clean state"
    ))
}
