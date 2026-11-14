//! Small shared helpers for xtask modules that shell out to `git`.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

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
            "git {args:?} failed ({}):\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Like `run_git`, but sets extra environment variables on the `git`
/// subprocess (which inherits the rest of this process's environment as
/// normal) — same bail-on-failure contract, just with `env` merged in. Used
/// wherever xtask's own code makes a repo-root commit that could otherwise
/// trip this repo's `check-vendoring-integrity` pre-commit hook on an
/// intermediate, not-yet-fully-consistent tree state (see `pull_subrepo.rs`'s
/// module doc and `merge_skip_value` below).
pub fn run_git_with_env(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Result<String> {
    let mut command = Command::new("git");
    command.args(args).current_dir(cwd);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command
        .output()
        .with_context(|| format!("failed to run git {args:?}"))?;
    if !output.status.success() {
        bail!(
            "git {args:?} failed ({}):\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Comma-joins `value` into `existing` (this process's own pre-existing
/// `SKIP` env var value, if any — pre-commit/prek's own multi-value
/// convention). Pure and side-effect-free so it's testable without mutating
/// process-global env state; call sites read `std::env::var("SKIP")`
/// themselves and pass the result in, e.g.
/// `merge_skip_value(std::env::var("SKIP").ok().as_deref(), "check-vendoring-integrity")`.
/// Exists so injecting our own hook id into a child git process's `SKIP`
/// (to let its own internal commits through an intermediate-inconsistent
/// tree state) never silently clobbers a developer's own unrelated `SKIP`
/// export.
pub fn merge_skip_value(existing: Option<&str>, value: &str) -> String {
    match existing {
        Some(existing) if !existing.is_empty() => format!("{existing},{value}"),
        _ => value.to_string(),
    }
}

/// The git blob hash `spec` resolves to (e.g. `:./foo` for the current
/// index, `HEAD:./foo` for the last commit), or the literal string
/// `<deleted>` if it doesn't resolve to anything. Reads straight from the
/// object database rather than re-hashing filesystem content, so it's the
/// shared primitive behind `index_blob_hash_or_deleted`/
/// `head_blob_hash_or_deleted` below.
fn resolved_blob_hash_or_deleted(cwd: &Path, spec: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "-q", spec])
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to run `git rev-parse {spec}` in {}", cwd.display()))?;
    if output.status.success() {
        Ok(String::from_utf8(output.stdout)
            .with_context(|| format!("`git rev-parse {spec}` produced non-UTF-8 output"))?
            .trim()
            .to_string())
    } else {
        Ok("<deleted>".to_string())
    }
}

/// The git blob hash `relative_path` is *staged* at right now (index stage
/// 0), or the literal string `<deleted>` if it isn't staged — the
/// sentinel-writing primitive `pull_subrepo::conflict::force_commit_conflicted`
/// uses immediately after its own `git add -A`, before committing. Reading
/// from the index (not re-hashing the filesystem) yields exactly the blob
/// `git commit` is about to store, whatever the on-disk bytes look like: a
/// checkout inside git-subrepo's temp worktree may have smudged them (Windows
/// `core.autocrlf=true` converts LF to CRLF).
pub fn index_blob_hash_or_deleted(cwd: &Path, relative_path: &str) -> Result<String> {
    resolved_blob_hash_or_deleted(cwd, &format!(":./{relative_path}"))
}

/// The git blob hash `relative_path` has in `HEAD`, or the literal string
/// `<deleted>` if `HEAD` has no such path — `finish_vendor_bump::run`'s
/// sentinel-clearing check uses this once a human's own resolution has been
/// committed (`VENDORING.md` documents the hand-resolution steps: commit
/// before running `finish-vendor-bump`). Like `index_blob_hash_or_deleted`,
/// it reads git's object database rather than re-hashing the working tree,
/// so checkout smudging and `.gitattributes` or `core.autocrlf` differences
/// between worktrees cannot change the result. `git subrepo commit`'s fold-in
/// is a tree-level merge, not a checkout-and-rewrite, so a blob the temp
/// worktree's index recorded and this `HEAD` read in the main worktree agree
/// for unchanged content on any platform.
pub fn head_blob_hash_or_deleted(cwd: &Path, relative_path: &str) -> Result<String> {
    resolved_blob_hash_or_deleted(cwd, &format!("HEAD:./{relative_path}"))
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
            "git {args:?} failed ({}):\nstdout:\n{}\nstderr:\n{}",
            output.status,
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
