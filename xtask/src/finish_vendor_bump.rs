//! `cargo xtask finish-vendor-bump` — the VENDORING.md "step 3" work that
//! stays separate from `pull_subrepo`: the version note, the outer
//! `go.mod`, and the identity build/test check. A human who resolved a
//! real conflict by hand runs this on its own once they're done.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::git_util::{head_blob_hash_or_deleted, run_git, run_git_with_env};
use crate::pull_subrepo::{gitrepo_field, skip_check_vendoring_integrity};

#[cfg(test)]
#[path = "finish_vendor_bump/test_support.rs"]
pub(crate) mod test_support;

#[derive(Debug)]
pub enum IdentityCheckOutcome {
    Passed,
    Failed { detail: String },
}

pub fn run(repo_root: &Path, subdir: &str, dep_name: &str, new_tag: &str) -> Result<IdentityCheckOutcome> {
    // `dep_name` and `subdir` are two independent CLI/API arguments only
    // because every real caller (the CI workflow and a human running this by
    // hand) always computes both from the same `<name>` — this cross-check is
    // what keeps a copy-paste/typo mismatch between them from being silently
    // accepted rather than rejecting the whole point of having both.
    let expected_dep_name = Path::new(subdir)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("`{subdir}` has no final path component to use as a dependency name"))?;
    if expected_dep_name != dep_name {
        bail!(
            "`dep_name` (`{dep_name}`) doesn't match `subdir`'s final path component \
             (`{expected_dep_name}`) — check for a copy-paste mismatch between the two arguments"
        );
    }

    ensure_gitrepo_branch_matches(repo_root, subdir, new_tag)?;

    let before_note_commit = run_git(repo_root, &["rev-parse", "HEAD"])?;
    update_vendoring_note_and_commit(repo_root, dep_name, new_tag)?;
    let after_note_commit = run_git(repo_root, &["rev-parse", "HEAD"])?;
    let note_landed = after_note_commit != before_note_commit;

    // Once a commit lands, every later failure in this function must say
    // so — `git_util::disclose_prior_commit`'s convention for an
    // irreversible commit followed by a later, independent failure.
    let disclose_note_commit = |e: anyhow::Error| -> anyhow::Error {
        if note_landed {
            crate::git_util::disclose_prior_commit(e, &after_note_commit, "the VENDORING.md version-note commit")
        } else {
            e
        }
    };

    if let Err(e) = run_go_mod_tidy_and_commit(repo_root, subdir, new_tag) {
        return Err(disclose_note_commit(e));
    }

    let identity_outcome = run_identity_checks(repo_root).map_err(disclose_note_commit)?;
    clear_vendor_conflict_sentinel_if_resolved(repo_root, subdir).map_err(disclose_note_commit)?;
    Ok(identity_outcome)
}

/// After a real conflict was hand-resolved (or `force_commit_conflicted`'s
/// CI-only policy committed one with literal markers for a human to fix
/// later), `<subdir>/.vendor-conflict` may still list every path that was
/// unmerged at commit time, each with its content hash then (or
/// `<deleted>`). A no-op if no sentinel exists.
///
/// Intentionally a "did a human engage with this exact path" check, not "is
/// the resolution correct" — clears the sentinel only once every listed
/// path's *current* hash differs from what was recorded, proving each one
/// was actually touched (re-authored, replaced, or intentionally deleted),
/// not silently inherited from `force_commit_conflicted`'s "ours" content.
/// If even one listed path is unchanged, refuses (naming that path) and
/// leaves the sentinel in place — a human who runs this without touching a
/// silently-wrong "ours" resolution leaves `check-vendoring-integrity` (and
/// therefore `Lint`) red, so auto-merge cannot fire.
fn clear_vendor_conflict_sentinel_if_resolved(repo_root: &Path, subdir: &str) -> Result<()> {
    let dep_dir = repo_root.join(subdir);
    let sentinel_path = dep_dir.join(".vendor-conflict");
    let contents = match std::fs::read_to_string(&sentinel_path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", sentinel_path.display())),
    };

    for line in contents.lines().filter(|l| !l.is_empty()) {
        // `rsplit_once`, not `split_once`: the hash never contains a tab, so splitting
        // from the right is unambiguous and correct even for a path containing one.
        let Some((path, recorded_hash)) = line.rsplit_once('\t') else {
            bail!(
                "{} has a malformed line (expected `<path>\\t<hash>`): {line:?}",
                sentinel_path.display()
            );
        };
        let current_hash = head_blob_hash_or_deleted(&dep_dir, path)?;
        if current_hash == recorded_hash {
            bail!(
                "`{subdir}/.vendor-conflict` still lists `{path}` as unchanged since the conflicted \
                 commit (recorded `{recorded_hash}`, still `{current_hash}`) — this sentinel isn't \
                 cleared by re-saving byte-identical content (that hashes the same and loops forever); \
                 either genuinely change `{path}`, or, once you've confirmed it's actually fine as-is \
                 (no change needed), remove `{subdir}/.vendor-conflict` by hand; every other listed \
                 path may already be fine, but this one specifically was never actually engaged with"
            );
        }
    }

    let sentinel_rel = format!("{subdir}/.vendor-conflict");
    std::fs::remove_file(&sentinel_path).with_context(|| format!("failed to remove {}", sentinel_path.display()))?;
    run_git(repo_root, &["add", "--", &sentinel_rel])
        .with_context(|| format!("`{sentinel_rel}` was already deleted on disk before this failure"))?;
    commit_if_staged(
        repo_root,
        &[sentinel_rel.as_str()],
        "chore(ex-ray): clear vendor-conflict sentinel after hand resolution",
    )
    .with_context(|| format!("`{sentinel_rel}`'s removal was already staged before this failure"))
}

/// Best-effort cross-check: when `<subdir>/.gitrepo` exists (git-subrepo's
/// own descriptor for the commit/branch it's pinned to), its `branch`
/// field must already equal `new_tag` before this function commits
/// anything under that claim. A human who resolves a `pull-subrepo`
/// conflict by hand and skips the documented `.gitrepo` `branch` fixup
/// (see `pull-subrepo`'s own conflict message) would otherwise get a
/// silently wrong VENDORING.md/go.mod commit with a passing identity
/// check — nothing in that check inspects a version string. Silently
/// skipped for a vendored dep with no `.gitrepo` at all (not git-subrepo
/// managed) — this module still doesn't require any particular vendoring
/// mechanism.
fn ensure_gitrepo_branch_matches(repo_root: &Path, subdir: &str, new_tag: &str) -> Result<()> {
    let gitrepo_path = repo_root.join(subdir).join(".gitrepo");
    if !gitrepo_path.exists() {
        return Ok(());
    }
    let contents =
        std::fs::read_to_string(&gitrepo_path).with_context(|| format!("failed to read {}", gitrepo_path.display()))?;
    let branch = gitrepo_field(&contents, "branch");
    match branch.as_deref() {
        Some(b) if b == new_tag => Ok(()),
        Some(b) => bail!(
            "{} still records `branch = {b}`, not the requested `{new_tag}` — if you resolved a \
             `pull-subrepo` conflict by hand, its own conflict message asked you to fix and \
             commit this field first",
            gitrepo_path.display()
        ),
        None => bail!("{} has no `branch = ` line", gitrepo_path.display()),
    }
}

/// Locates `dep_name`'s `## \`<dep>/\` — pinned **<version>**` heading in
/// `VENDORING.md`'s `contents` and returns the byte range of just the
/// version text between the two `**` markers. Shared by the writer
/// (`update_vendoring_note_and_commit`, which splices a new version into
/// this exact range) and the reader
/// (`check_vendoring_integrity::check_vendoring_md_version`, which only
/// needs the version string out of it) — one parser for this heading
/// format, not two. `Ok(None)` means the heading doesn't exist for this dep
/// at all; `Err` means it does, but is malformed (missing the closing `**`
/// on the same line).
pub(crate) fn find_vendoring_heading_version_range(contents: &str, dep_name: &str) -> Result<Option<(usize, usize)>> {
    let heading_prefix = format!("## `{dep_name}/` — pinned **");
    let Some(start) = contents.find(&heading_prefix) else {
        return Ok(None);
    };
    let version_start = start + heading_prefix.len();
    // Bounded to the heading's own line: VENDORING.md documents multiple
    // deps, each with its own bold-marked version further down the file —
    // an unbounded search for the closing `**` would skip past a
    // malformed heading (missing its own `**`) and latch onto one of
    // those instead, silently splicing out everything in between.
    let heading_rest = &contents[version_start..];
    let line_end = heading_rest.find('\n').unwrap_or(heading_rest.len());
    let Some(version_end_offset) = heading_rest[..line_end].find("**") else {
        bail!("malformed VENDORING.md heading for `{dep_name}` (no closing `**` on the heading line)");
    };
    Ok(Some((version_start, version_start + version_end_offset)))
}

/// Split out of `run` so tests can exercise the version-note rewrite
/// without a real Go toolchain / vendored module tree.
pub fn update_vendoring_note_and_commit(repo_root: &Path, dep_name: &str, new_tag: &str) -> Result<()> {
    let path = repo_root.join("crates/ex-ray/third_party/VENDORING.md");
    let contents = std::fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;

    let Some((version_start, version_end)) = find_vendoring_heading_version_range(&contents, dep_name)? else {
        bail!("VENDORING.md has no `## `{dep_name}/` — pinned **` heading to update");
    };

    let updated = format!("{}{new_tag}{}", &contents[..version_start], &contents[version_end..]);
    std::fs::write(&path, updated).with_context(|| format!("failed to write {}", path.display()))?;

    run_git(repo_root, &["add", "crates/ex-ray/third_party/VENDORING.md"])
        .with_context(|| format!("{} was already rewritten on disk before this failure", path.display()))?;
    commit_if_staged(
        repo_root,
        &["crates/ex-ray/third_party/VENDORING.md"],
        &format!("docs: note {dep_name} {new_tag} in VENDORING.md"),
    )
    .with_context(|| {
        format!(
            "{} was already rewritten on disk and staged before this failure",
            path.display()
        )
    })
}

/// Bumps `crates/ex-ray/go.mod`'s `require` entry for `<subdir>`'s Go
/// module to `new_tag` via `go mod edit -require` (the Go toolchain's own
/// AST-driven editor, not a hand-rolled line parser — a naive per-line
/// filter matching `module_path` as a string prefix would misfire on a
/// `replace`/`exclude` block entry for the same module and silently
/// corrupt the wrong directive; `pull_subrepo/conflict.rs`'s
/// `go_mod_replace_directives` already documents why a naive per-line
/// filter is wrong for go.mod). Then `go mod tidy`. The module's `replace`
/// directive means Go itself never touches this version string for a
/// locally-replaced module, so it would otherwise silently keep
/// advertising the old tag. The module path is read from the vendored
/// dep's own `go.mod` `module` line rather than hardcoded.
fn run_go_mod_tidy_and_commit(repo_root: &Path, subdir: &str, new_tag: &str) -> Result<()> {
    let module_path = read_module_path(&repo_root.join(subdir).join("go.mod"))?;
    let ex_ray_go_mod = repo_root.join("crates/ex-ray/go.mod");
    let ex_ray_go_sum = repo_root.join("crates/ex-ray/go.sum");
    let ex_ray_dir = repo_root.join("crates/ex-ray");

    let original_go_mod = std::fs::read_to_string(&ex_ray_go_mod)
        .with_context(|| format!("failed to read {}", ex_ray_go_mod.display()))?;
    // `None` means no go.sum existed before this function touched anything
    // — restoring "the original state" then means removing whatever
    // `go mod tidy` wrote, not leaving an empty file behind. A read
    // failure for any OTHER reason (permissions, a transient I/O error)
    // must not be folded into that same "absent" meaning — the file may
    // well exist, and `restore_go_sum` would otherwise delete real,
    // pre-existing content it merely failed to read.
    let original_go_sum = match std::fs::read_to_string(&ex_ray_go_sum) {
        Ok(content) => Some(content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", ex_ray_go_sum.display())),
    };

    // `go mod edit -require` upserts: if `module_path` were not already
    // required at all (e.g. a typo'd `subdir`), it would silently ADD a
    // new require line rather than reporting a mistake. Refuse up front
    // instead — every real caller targets a dep already required.
    if resolved_module_version(&ex_ray_dir, &module_path)?.is_none() {
        bail!(
            "`{module_path}` has no require line in {} — refusing to add one; check that `{subdir}` \
             is the intended vendored dep",
            ex_ray_go_mod.display()
        );
    }

    run_go_mod_edit(&ex_ray_dir, &format!("-require={module_path}@{new_tag}"))?;

    if let Err(e) = run_go_mod_tidy(&ex_ray_dir) {
        // Leave the tree as it was found rather than with a half-applied,
        // uncommitted rewrite. Restore failures are folded into the same
        // error so they're never silently dropped.
        let mut restore_failures = Vec::new();
        if let Err(restore_err) = std::fs::write(&ex_ray_go_mod, &original_go_mod) {
            restore_failures.push(format!("{}: {restore_err}", ex_ray_go_mod.display()));
        }
        if let Err(restore_err) = restore_go_sum(&ex_ray_go_sum, &original_go_sum) {
            restore_failures.push(format!("{}: {restore_err}", ex_ray_go_sum.display()));
        }
        return Err(if restore_failures.is_empty() {
            e
        } else {
            e.context(format!(
                "also failed to restore the original state, so it's left modified on disk, \
                 uncommitted: {}",
                restore_failures.join("; ")
            ))
        });
    }

    // MVS can raise a require above what was just written — e.g. a
    // replaced sibling module's own go.mod requiring the same dependency
    // at a higher version (confirmed empirically: rewriting a direct
    // require down while a replaced dependency's go.mod still demands
    // higher makes `go mod tidy` silently pick the higher one; mirrors the
    // real utls/v2ray-core shape). Catch that rather than committing a
    // version nobody asked for. `go list -m` asks the Go toolchain what
    // the build list actually resolved to, rather than re-parsing go.mod.
    match resolved_module_version(&ex_ray_dir, &module_path)? {
        Some(v) if v == new_tag => {}
        Some(v) => bail!(
            "`go mod tidy` changed `{module_path}`'s resolved version from the requested \
             `{new_tag}` to `{v}` — some other module in the graph (e.g. a `replace`d sibling's \
             own go.mod) requires at least `{v}`; go.mod (and go.sum, if `go mod tidy` touched \
             it) have been left at that mismatched, uncommitted state rather than silently \
             committing a version nobody asked for"
        ),
        None => bail!(
            "`{module_path}` is no longer required after `go mod tidy` — crates/ex-ray's own Go \
             sources may not actually import it; go.mod (and go.sum, if `go mod tidy` touched it) \
             have been left in that uncommitted state"
        ),
    }

    // `go.sum` not existing on disk isn't the same as "nothing to do with
    // it": a module whose only requirement is satisfied by a local
    // `replace` directory produces none (so a fresh repo never had one),
    // but a `go.sum` that IS tracked in git and happens to be missing from
    // disk still needs that deletion staged and committed, not silently
    // left dangling. `git add` on a pathspec matching neither disk nor the
    // index is a hard error, so both conditions are checked.
    let go_sum_rel = "crates/ex-ray/go.sum";
    let go_sum_tracked = !run_git(repo_root, &["ls-files", "--", go_sum_rel])?.is_empty();
    let mut paths: Vec<&str> = vec!["crates/ex-ray/go.mod"];
    if ex_ray_go_sum.exists() || go_sum_tracked {
        paths.push(go_sum_rel);
    }
    let mut add_args = vec!["add"];
    add_args.extend(paths.iter().copied());
    run_git(repo_root, &add_args).with_context(|| {
        format!(
            "{} (and {go_sum_rel} if touched) was already rewritten on disk by `go mod tidy` \
             before this failure",
            ex_ray_go_mod.display()
        )
    })?;
    commit_if_staged(
        repo_root,
        &paths,
        &format!("build(ex-ray): bump {module_path} to {new_tag}"),
    )
    .with_context(|| {
        format!(
            "{} (and {go_sum_rel} if touched) was already rewritten and staged before this \
                 failure",
            ex_ray_go_mod.display()
        )
    })
}

/// Restores `go.sum` to its pre-run content: rewrites it if it existed
/// before, removes it if it didn't (so a fresh `go mod tidy` write isn't
/// left behind as a phantom file). Removing an already-absent file is not
/// an error — `go mod tidy` may not have touched it at all.
fn restore_go_sum(go_sum_path: &Path, original: &Option<String>) -> std::io::Result<()> {
    match original {
        Some(content) => std::fs::write(go_sum_path, content),
        None => match std::fs::remove_file(go_sum_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        },
    }
}

fn run_go_mod_edit(ex_ray_dir: &Path, arg: &str) -> Result<()> {
    let output = Command::new("go")
        .args(["mod", "edit", arg])
        .current_dir(ex_ray_dir)
        .output()
        .with_context(|| format!("failed to run `go mod edit {arg}` in {}", ex_ray_dir.display()))?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "`go mod edit {arg}` failed in {}:\nstdout:\n{}\nstderr:\n{}",
        ex_ray_dir.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_go_mod_tidy(ex_ray_dir: &Path) -> Result<()> {
    let output = Command::new("go")
        .args(["mod", "tidy"])
        .current_dir(ex_ray_dir)
        .output()
        .with_context(|| format!("failed to run `go mod tidy` in {}", ex_ray_dir.display()))?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "`go mod tidy` failed in {}:\nstdout:\n{}\nstderr:\n{}",
        ex_ray_dir.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Asks the Go toolchain what version `module_path` currently resolves to
/// in `ex_ray_dir`'s build list — `Ok(None)` when it isn't required at
/// all, rather than re-parsing go.mod by hand (see `run_go_mod_tidy_and_commit`'s
/// doc comment for why that was wrong).
fn resolved_module_version(ex_ray_dir: &Path, module_path: &str) -> Result<Option<String>> {
    let output = Command::new("go")
        .args(["list", "-m", "-f", "{{.Version}}", module_path])
        .current_dir(ex_ray_dir)
        .output()
        .with_context(|| format!("failed to run `go list -m {module_path}` in {}", ex_ray_dir.display()))?;
    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Ok(if version.is_empty() { None } else { Some(version) });
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("not a known dependency") {
        return Ok(None);
    }
    bail!(
        "`go list -m {module_path}` failed in {}:\nstdout:\n{}\nstderr:\n{stderr}",
        ex_ray_dir.display(),
        String::from_utf8_lossy(&output.stdout)
    );
}

pub(crate) fn read_module_path(go_mod_path: &Path) -> Result<String> {
    let contents =
        std::fs::read_to_string(go_mod_path).with_context(|| format!("failed to read {}", go_mod_path.display()))?;
    contents
        .lines()
        .find_map(|line| line.strip_prefix("module "))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow::anyhow!("{} has no `module` line", go_mod_path.display()))
}

/// Matches `build.yaml`'s `ex-ray-tests` target exactly (what `ci.yaml`'s
/// "Test ex-ray (Go)" job runs): `crates/ex-ray`'s own `go test ./...`,
/// plus a scoped `go test` inside `crates/ex-ray/third_party/v2ray-core`
/// specifically. Both commands are unconditional in build.yaml — this is
/// the single whole-crate CI test target, run identically regardless of
/// which vendored dep a bump touched, so it does NOT scope the second
/// command to whatever `subdir` this `finish-vendor-bump` invocation is
/// for (a utls bump still needs v2ray-core's own scoped tests to have
/// run, exactly as CI would). Not literally `cargo xtask run
/// ex-ray-tests` itself: that needs the full build.yaml environment,
/// unavailable to the fixture repos this module's tests build.
/// `identity_checks_match_the_real_build_yaml_ex_ray_tests_target`
/// (finish_vendor_bump_tests.rs) parses the real build.yaml and fails
/// loudly if that target's `run:` steps ever drift from what's hardcoded
/// here.
pub(crate) fn run_identity_checks(repo_root: &Path) -> Result<IdentityCheckOutcome> {
    let ex_ray_dir = repo_root.join("crates/ex-ray");
    if let Some(detail) = go_command_failure(&ex_ray_dir, &["test", "./..."])? {
        return Ok(IdentityCheckOutcome::Failed { detail });
    }

    let v2ray_core_dir = repo_root.join("crates/ex-ray/third_party/v2ray-core");
    let args = [
        "test",
        "./transport/internet/tls/...",
        "./transport/internet/quic/...",
        "./transport/internet/hysteria2/...",
        "./transport/internet/transportcommon/...",
    ];
    if let Some(detail) = go_command_failure(&v2ray_core_dir, &args)? {
        return Ok(IdentityCheckOutcome::Failed { detail });
    }

    Ok(IdentityCheckOutcome::Passed)
}

/// Returns `Ok(None)` on success, `Ok(Some(detail))` on a go-command
/// failure (not a hard error — the caller still commits; a failing
/// identity check is expected-and-reportable, same policy as CI going
/// red). Includes both stdout and stderr: `go test` failures put the
/// substantive diagnostic (which test failed, assertion diff, panic
/// output) on stdout, not stderr.
fn go_command_failure(cwd: &Path, args: &[&str]) -> Result<Option<String>> {
    let output = Command::new("go")
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to run `go {args:?}` in {}", cwd.display()))?;
    if output.status.success() {
        Ok(None)
    } else {
        Ok(Some(format!(
            "go {args:?} in {}:\nstdout:\n{}\nstderr:\n{}",
            cwd.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

/// `git commit` exits 1 with nothing staged — a no-op run (e.g.
/// re-finishing an already-finished bump) must not treat that as a
/// failure. Scoped to `paths` for both the check and the commit, so a
/// caller (e.g. a human running this mid-conflict-resolution with
/// unrelated files staged) never gets their other staged work swept into
/// this commit.
fn commit_if_staged(repo_root: &Path, paths: &[&str], message: &str) -> Result<()> {
    let mut diff_args = vec!["diff", "--cached", "--name-only", "--"];
    diff_args.extend(paths);
    let staged = run_git(repo_root, &diff_args)?;
    if staged.is_empty() {
        return Ok(());
    }
    let mut commit_args = vec!["commit", "-m", message, "--"];
    commit_args.extend(paths);
    // `run_git_with_env`, not `run_git`: each of this function's callers
    // commits only its own step's changes (the VENDORING.md note, the
    // go.mod bump, the sentinel-clear step below) — an intermediate state
    // the `always_run` `check-vendoring-integrity` hook would otherwise
    // (correctly, but unhelpfully) reject mid-sequence.
    run_git_with_env(repo_root, &commit_args, &[("SKIP", &skip_check_vendoring_integrity())])?;
    Ok(())
}
