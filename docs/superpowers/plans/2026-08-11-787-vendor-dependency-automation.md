# Automated vendored-dependency bumps (#787) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automate bumping the two git-subrepo-vendored deps
(`crates/ex-ray/third_party/{v2ray-core,utls}`) to new upstream tags,
rebasing the local ECH patches through `git subrepo pull`, and landing the
result as a PR that merges automatically when clean+green or sits open/red
when a real conflict or CI failure blocks it — with no self-hosted server.

**Architecture:** Renovate (hosted GitHub App) bumps only the `branch =`
line in each `.gitrepo` via a `customManager` and opens its normal PR. A new
`vendor-bump.yaml` workflow, authenticated as a purpose-built GitHub App
(`nathan-blahaj`, not the default `GITHUB_TOKEN`, so its pushes actually
retrigger CI), runs `cargo xtask pull-subrepo` (a generic, human-usable
wrapper around `git subrepo pull` that fixes the routine squash-merge
parent-staleness automatically and behaves like `git pull` on a real
conflict — stops, uncommitted) followed by `cargo xtask finish-vendor-bump`
(version note + `go.mod` + identity build/test), then pushes. The same App
fixes the identical latent bug in `wix-hash-fixup.yaml`.

**Tech Stack:** Rust (`xtask`, existing `clap`/`anyhow` conventions), GitHub
Actions, Renovate `customManager` (regex), `git-subrepo` 0.4.9.

## Global Constraints

- Both vendored deps track **stable tagged semver releases only** (existing
  `.gitrepo` `branch` values are already tags: `v5.52.0`, `v5.52.0`) —
  Renovate's default semver versioning already excludes pre-releases
  (e.g. v2ray-core's `v5.53.0` pre-release), so no extra config is needed
  for this.
- `cargo xtask pull-subrepo <path> <tag>` must never commit a conflicted
  tree itself — that decision belongs to the caller. It auto-resolves only
  the documented-safe allowlist (`go.mod`, `go.sum`,
  `.github/workflows/*`) to upstream's version; anything else conflicting
  stops the tool with nothing committed, exactly like `git pull`.
- The CI-only "commit despite conflicts" behavior lives in
  `vendor-bump.yaml`, not in the xtask tool.
- Renovate goes dormant on a dependency once a non-Renovate commit lands on
  its branch (confirmed platform behavior) — no coordination code needed
  for that; it's automatic.
- `nathan-blahaj` is the generic bot identity name (not vendor-specific) —
  reused for `wix-hash-fixup.yaml` too. Secrets: `NATHAN_APP_ID`,
  `NATHAN_APP_PRIVATE_KEY`.
- Design doc: `docs/superpowers/specs/2026-08-10-787-vendor-dependency-automation.md`.

______________________________________________________________________

## File Structure

| File                                            | Responsibility                                                                                                                                                                                   |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `xtask/src/git_util.rs`                         | Shared `run_git` helper (shell out, check status, return trimmed stdout) used by `pull_subrepo.rs` and `finish_vendor_bump.rs` — avoids writing it twice.                                        |
| `xtask/src/pull_subrepo.rs`                     | Generic `git subrepo pull` wrapper: dirty-tree guard, automatic squash-merge parent fixup, allowlist conflict auto-resolution, `git-pull`-like stop on real conflicts. No Renovate/CI awareness. |
| `xtask/src/pull_subrepo_tests.rs`               | Fixture-repo integration tests proving the above against a real installed `git subrepo`, including the worktree case.                                                                            |
| `xtask/src/finish_vendor_bump.rs`               | The separate, smaller VENDORING.md "step 3": version note, `go mod tidy`, identity build/test, single commit.                                                                                    |
| `xtask/src/finish_vendor_bump_tests.rs`         | Tests for the above.                                                                                                                                                                             |
| `xtask/src/lib.rs`                              | Modify: two new `Command` variants + dispatch wrappers + module/test-module declarations.                                                                                                        |
| `.github/renovate.json`                         | Modify: `customManager` tracking each `.gitrepo`'s `branch` line + a `packageRules` group.                                                                                                       |
| `.github/actions/mint-nathan-token/action.yaml` | Composite action minting a `nathan-blahaj` installation token from App ID + private key inputs. Shared by both workflows below.                                                                  |
| `.github/workflows/vendor-bump.yaml`            | New workflow: picks up Renovate's `.gitrepo` bump, runs the two xtask commands, pushes via `nathan-blahaj`, comments on real conflicts.                                                          |
| `.github/workflows/wix-hash-fixup.yaml`         | Modify: swap `GITHUB_TOKEN` for `nathan-blahaj`.                                                                                                                                                 |
| `crates/ex-ray/third_party/VENDORING.md`        | Modify: document the new tooling and the CI-only conflict-commit policy.                                                                                                                         |

______________________________________________________________________

### Task 1: One-time manual setup — the `nathan-blahaj` GitHub App

This task cannot be automated or delegated to a subagent — it's interactive
browser setup on github.com, performed by the repo owner. Included here so
nothing is silently skipped and later tasks can assume the secrets exist.

**Files:** none (GitHub UI + repo secrets)

- [ ] **Step 1: Create the App**

Go to https://github.com/settings/apps/new (or your org's equivalent) and
set:

- GitHub App name: `nathan-blahaj`

- Homepage URL: `https://github.com/bindreams/hole` (unused, but required)

- Webhook: uncheck "Active" — this App only mints installation tokens, it
  never receives events.

- Repository permissions: `Contents` → `Read and write`, `Pull requests` →
  `Read and write`. Leave everything else at "No access".

- "Where can this GitHub App be installed?": **Any account** (so it can be
  installed on other repos later without recreating it).

- Click "Create GitHub App".

- [ ] **Step 2: Generate a private key**

On the App's settings page, under "Private keys", click "Generate a private
key". This downloads a `.pem` file — save it somewhere temporary, it's
needed in Step 4.

- [ ] **Step 3: Install the App on `bindreams/hole`**

From the App's settings page, click "Install App", select your account,
choose "Only select repositories", pick `hole`, and confirm.

- [ ] **Step 4: Add repo secrets**

In `bindreams/hole` → Settings → Secrets and variables → Actions, add:

- `NATHAN_APP_ID`: the numeric App ID shown on the App's settings page
  (near the top, labeled "App ID").
- `NATHAN_APP_PRIVATE_KEY`: the full contents of the `.pem` file from
  Step 2 (including the `-----BEGIN/END PRIVATE KEY-----` lines).

Delete the local `.pem` file copy once it's saved as a secret.

- [ ] **Step 5: Confirm**

Reply here (or note in the tracking issue) once done — later tasks that
touch `vendor-bump.yaml`/`wix-hash-fixup.yaml` assume these two secrets
exist.

______________________________________________________________________

### Task 2: Fixture-repo test harness proving `git subrepo pull`'s real behavior

This is the spike the design doc calls out: prove — against the *actually
installed* `git-subrepo` 0.4.9 (`/c/Users/bindreams/opt/git-subrepo/lib/git-subrepo`),
not assumptions — that the squash-merge parent-staleness fixup reliably
auto-resolves (the routine case, given this repo always squash-merges and
deletes branches), and that a real conflict leaves the tree exactly as
`git pull` would, in both a plain checkout and a linked worktree. These
tests will fail against a not-yet-written `pull_subrepo` module — that's
expected; Task 3/4 implement against them.

**Files:**

- Create: `xtask/src/pull_subrepo_tests.rs`
- Create: `xtask/src/pull_subrepo.rs` (empty stub module for now — just
  enough for the test file to compile against a `pub fn run` signature and
  `pub enum Outcome`)
- Modify: `xtask/src/lib.rs:36` (add `pub mod pull_subrepo;` near the other
  `pub mod` declarations) and after the existing `#[cfg(test)]` block
  (`xtask/src/lib.rs:74` area) add:
  ```rust
  #[cfg(test)]
  #[path = "pull_subrepo_tests.rs"]
  mod pull_subrepo_tests;
  ```

**Interfaces:**

- Produces: `pull_subrepo::Outcome` (`Clean` / `Conflicted { worktree: PathBuf, unresolved: Vec<String> }`) and `pull_subrepo::run(repo_root: &Path, subdir: &str, tag: &str) -> anyhow::Result<Outcome>` — the exact signature Task 3/4 implement against and Task 6's CLI wrapper calls.

- [ ] **Step 1: Write the stub module**

`xtask/src/pull_subrepo.rs`:

```rust
//! `cargo xtask pull-subrepo <path> <tag>` — a thin, honest wrapper around
//! `git subrepo pull` that fixes the one squash-merge gotcha this repo
//! hits on every pull (see crates/ex-ray/third_party/VENDORING.md) and
//! otherwise behaves exactly like `git pull`: a real conflict stops here,
//! uncommitted, for a human to resolve. No Renovate/CI awareness — the
//! caller decides `tag`, and the "commit anyway despite conflicts"
//! CI-only policy lives in the calling workflow, not here.

use std::path::{Path, PathBuf};

use anyhow::Result;

pub enum Outcome {
    /// Pull succeeded (cleanly, or after auto-resolving only the
    /// documented-safe allowlist); a new commit updating `<subdir>` now
    /// sits on HEAD.
    Clean,
    /// A conflict remains outside the safe allowlist. Nothing was
    /// committed — the temp merge worktree `git subrepo pull` created is
    /// left exactly as `git merge` would leave a conflicted tree, for a
    /// human to resolve.
    Conflicted { worktree: PathBuf, unresolved: Vec<String> },
}

pub fn run(_repo_root: &Path, _subdir: &str, _tag: &str) -> Result<Outcome> {
    unimplemented!("Task 3/4")
}
```

- [ ] **Step 2: Write the fixture builder + git helpers**

`xtask/src/pull_subrepo_tests.rs`:

```rust
use std::path::{Path, PathBuf};
use std::process::Command;

use super::pull_subrepo::{self, Outcome};

/// Which file (if any) upstream's second tag changes, matched against
/// what our local downstream patch also touches — this is what determines
/// whether the eventual pull hits no conflict, an auto-resolvable one, or
/// a real one.
enum ConflictKind {
    /// v2 changes an unrelated file; our patch doesn't touch it.
    None,
    /// v2 changes `go.mod`, which our downstream commit also edits —
    /// exercises the documented "resolve to theirs" allowlist.
    Allowlisted,
    /// v2 changes `patched.txt`, which our local ECH-style patch also
    /// edits — a real conflict outside the allowlist.
    Real,
}

/// Builds a throwaway upstream + downstream repo pair replicating Hole's
/// actual vendoring pattern: `git subrepo clone` a subdir on a feature
/// branch, add a one-line local patch, squash-merge the branch into main
/// and delete it — exactly the sequence that leaves `.gitrepo`'s `parent`
/// unreachable from HEAD (the documented squash-merge gotcha).
struct Fixture {
    dir: tempfile::TempDir,
    downstream: PathBuf,
}

impl Fixture {
    fn build(conflict: ConflictKind) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let upstream = dir.path().join("upstream");
        let downstream = dir.path().join("downstream");

        git_init(&upstream);
        std::fs::write(upstream.join("patched.txt"), "upstream line one\n").unwrap();
        std::fs::write(upstream.join("go.mod"), "module fixture\n\ngo 1.25\n").unwrap();
        git(&upstream, &["add", "."]);
        git(&upstream, &["commit", "-m", "v1"]);
        git(&upstream, &["tag", "v1"]);

        match conflict {
            ConflictKind::None => {
                std::fs::write(upstream.join("go.mod"), "module fixture\n\ngo 1.26\n").unwrap();
            }
            ConflictKind::Allowlisted => {
                std::fs::write(
                    upstream.join("go.mod"),
                    "module fixture\n\ngo 1.26\n\nrequire upstream/newdep v1.0.0\n",
                )
                .unwrap();
            }
            ConflictKind::Real => {
                std::fs::write(upstream.join("patched.txt"), "upstream line one CHANGED\n").unwrap();
            }
        }
        git(&upstream, &["commit", "-am", "v2"]);
        git(&upstream, &["tag", "v2"]);

        git_init(&downstream);
        std::fs::write(downstream.join("README.md"), "downstream\n").unwrap();
        git(&downstream, &["add", "."]);
        git(&downstream, &["commit", "-m", "initial"]);

        git(&downstream, &["checkout", "-b", "feature"]);
        git(&downstream, &["subrepo", "clone", upstream.to_str().unwrap(), "vendor", "-b", "v1"]);
        std::fs::write(downstream.join("vendor/patched.txt"), "upstream line one\nour local patch\n").unwrap();
        std::fs::write(
            downstream.join("vendor/go.mod"),
            "module fixture\n\ngo 1.25\n\nrequire ourdownstream/patchdep v1.0.0\n",
        )
        .unwrap();
        git(&downstream, &["add", "-A"]);
        git(&downstream, &["commit", "-m", "patch: our local addition"]);

        git(&downstream, &["checkout", "main"]);
        git(&downstream, &["merge", "--squash", "feature"]);
        git(&downstream, &["commit", "-m", "vendor: import + patch (squashed)"]);
        git(&downstream, &["branch", "-D", "feature"]);

        Fixture { dir, downstream }
    }
}

fn git_init(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    git(path, &["init", "--initial-branch=main", "--quiet"]);
    git(path, &["config", "user.email", "fixture@example.com"]);
    git(path, &["config", "user.name", "fixture"]);
}

fn git(cwd: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| panic!("failed to run git {args:?} in {}: {e}", cwd.display()));
    assert!(status.success(), "git {args:?} failed in {}", cwd.display());
}

fn git_output(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git").args(args).current_dir(cwd).output().unwrap();
    assert!(output.status.success(), "git {args:?} failed in {}", cwd.display());
    String::from_utf8(output.stdout).unwrap()
}
```

- [ ] **Step 3: Write the failing tests**

Append to `xtask/src/pull_subrepo_tests.rs`:

```rust
#[skuld::test]
fn clean_pull_after_squash_merge_auto_fixes_stale_parent() {
    let fx = Fixture::build(ConflictKind::None);

    // Sanity: this is the exact routine failure this repo hits on every
    // pull, before any fixup — confirms the fixture actually reproduces
    // the documented gotcha rather than trivially succeeding.
    let raw = Command::new("git")
        .args(["subrepo", "pull", "vendor", "-b", "v2"])
        .current_dir(&fx.downstream)
        .output()
        .unwrap();
    assert!(!raw.status.success(), "fixture should reproduce the stale-parent failure before any fixup");
    assert!(String::from_utf8_lossy(&raw.stderr).contains("is not an ancestor"));
    git(&fx.downstream, &["merge", "--abort"]).unwrap_or(());

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let patched = std::fs::read_to_string(fx.downstream.join("vendor/patched.txt")).unwrap();
    assert!(patched.contains("our local patch"), "local patch must survive the pull: {patched}");

    let gitrepo = std::fs::read_to_string(fx.downstream.join("vendor/.gitrepo")).unwrap();
    assert!(gitrepo.contains("branch = v2"));
}

#[skuld::test]
fn allowlisted_conflict_auto_resolves_to_upstream() {
    let fx = Fixture::build(ConflictKind::Allowlisted);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(go_mod.contains("newdep"), "upstream's go.mod content should win: {go_mod}");
    assert!(!go_mod.contains("patchdep"), "our spurious downstream-only require should not survive: {go_mod}");
}

#[skuld::test]
fn real_conflict_stops_uncommitted_like_git_pull() {
    let fx = Fixture::build(ConflictKind::Real);
    let before_head = git_output(&fx.downstream, &["rev-parse", "HEAD"]);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { unresolved, .. } => {
            assert_eq!(unresolved, vec!["patched.txt".to_string()]);
        }
        Outcome::Clean => panic!("expected a conflict on patched.txt"),
    }

    let after_head = git_output(&fx.downstream, &["rev-parse", "HEAD"]);
    assert_eq!(before_head, after_head, "a real conflict must not commit anything on the downstream repo");
}

#[skuld::test]
fn dirty_tree_is_rejected_before_touching_anything() {
    let fx = Fixture::build(ConflictKind::None);
    std::fs::write(fx.downstream.join("README.md"), "dirty\n").unwrap();

    let result = pull_subrepo::run(&fx.downstream, "vendor", "v2");
    assert!(result.is_err(), "a dirty tree must be rejected up front");

    let readme = std::fs::read_to_string(fx.downstream.join("README.md")).unwrap();
    assert_eq!(readme, "dirty\n", "the dirty file must be untouched");
}

#[skuld::test]
fn works_identically_from_a_linked_worktree() {
    let fx = Fixture::build(ConflictKind::None);
    let worktree_path = fx.dir.path().join("downstream-worktree");
    git(&fx.downstream, &["worktree", "add", worktree_path.to_str().unwrap()]);

    let outcome = pull_subrepo::run(&worktree_path, "vendor", "v2").expect("pull should succeed from a linked worktree");
    assert!(matches!(outcome, Outcome::Clean));
}
```

- [ ] **Step 4: Run the tests to see them fail on the `unimplemented!` stub**

Run: `cargo test -p xtask pull_subrepo 2>&1 | tee /tmp/pull_subrepo_test1.log` (Windows: redirect to a file under the scratch dir instead of `/tmp`, then Read it — never pipe to `tail`).
Expected: the sanity assertions inside `clean_pull_after_squash_merge_auto_fixes_stale_parent` should PASS (proving the fixture reproduces the real gotcha against the actually-installed `git subrepo`), then the test panics on `unimplemented!("Task 3/4")`. If the sanity assertions themselves fail, the fixture doesn't reproduce Hole's real pattern — stop and fix the fixture before proceeding to Task 3, since everything downstream depends on it being accurate.

- [ ] **Step 5: Commit**

```bash
git add xtask/src/pull_subrepo.rs xtask/src/pull_subrepo_tests.rs xtask/src/lib.rs
git commit -m "test(xtask): add fixture-repo tests proving git-subrepo's squash-merge behavior"
```

______________________________________________________________________

### Task 3: `pull_subrepo` — clean pull with automatic stale-parent fixup

Implements enough of `pull_subrepo::run` to pass `clean_pull_after_squash_merge_auto_fixes_stale_parent`, `dirty_tree_is_rejected_before_touching_anything`, and `works_identically_from_a_linked_worktree` from Task 2. Conflict handling (`allowlisted_conflict_auto_resolves_to_upstream`, `real_conflict_stops_uncommitted_like_git_pull`) is Task 4.

The stale-parent fixup replicates `git-subrepo`'s own documented recovery
formula exactly (`/c/Users/bindreams/opt/git-subrepo/lib/git-subrepo:750-768`,
function `subrepo:branch`): the last commit that touched the `.gitrepo`
`commit =` line, walked back one parent, verified as an ancestor of HEAD.

**Files:**

- Modify: `xtask/src/pull_subrepo.rs` (replace the stub)
- Create: `xtask/src/git_util.rs`

**Interfaces:**

- Consumes: nothing from other tasks.

- Produces: `pull_subrepo::{run, Outcome}` (already declared in Task 2; this task fills in the real logic behind it) and `git_util::run_git`, reused by Task 5.

- [ ] **Step 1: Confirm Task 2's tests still fail the same way (baseline)**

Run: `cargo test -p xtask pull_subrepo::clean_pull_after_squash_merge_auto_fixes_stale_parent -- --nocapture`
Expected: FAIL on `unimplemented!`.

- [ ] **Step 2: Extract a shared `run_git` helper**

This is the first of two new modules in this plan that need to shell out
to git and check the result (`finish_vendor_bump.rs` in Task 5 is the
other) — pulling the helper out now avoids writing it twice.

Create `xtask/src/git_util.rs`:

```rust
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
        bail!("git {args:?} failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
```

Add `pub mod git_util;` to `xtask/src/lib.rs` near the other `pub mod`
declarations.

- [ ] **Step 3: Implement the real logic**

Replace `xtask/src/pull_subrepo.rs`'s body (keep the doc comment, `Outcome`
enum, and imports from Task 2, add to them):

```rust
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};

use crate::git_util::run_git;

// ... (Outcome enum from Task 2 stays) ...

pub fn run(repo_root: &Path, subdir: &str, tag: &str) -> Result<Outcome> {
    ensure_clean_tree(repo_root)?;

    let first = run_subrepo_pull(repo_root, subdir, tag)?;
    if first.status.success() {
        return Ok(Outcome::Clean);
    }

    let stderr = String::from_utf8_lossy(&first.stderr).into_owned();
    if stderr.contains("is not an ancestor") {
        fix_stale_parent(repo_root, subdir)?;
        let second = run_subrepo_pull(repo_root, subdir, tag)?;
        if second.status.success() {
            return Ok(Outcome::Clean);
        }
        return handle_conflict(repo_root, subdir, &second.stderr);
    }

    handle_conflict(repo_root, subdir, &first.stderr)
}

fn ensure_clean_tree(repo_root: &Path) -> Result<()> {
    let status = run_git(repo_root, &["status", "--porcelain"])?;
    if !status.is_empty() {
        bail!("working tree is dirty; `git subrepo pull` refuses to run against a dirty tree:\n{status}");
    }
    Ok(())
}

fn run_subrepo_pull(repo_root: &Path, subdir: &str, tag: &str) -> Result<Output> {
    Command::new("git")
        .args(["subrepo", "pull", subdir, "-b", tag])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to run `git subrepo pull {subdir} -b {tag}`"))
}

/// Replicates git-subrepo's own recovery formula for a squash-merge-stale
/// `.gitrepo` `parent` (see `subrepo:branch` in the installed
/// `git-subrepo` script): the last commit that touched the `.gitrepo`
/// file's `commit =` line, walked back one parent. That candidate is
/// always reachable from HEAD by construction (it comes from `git log`
/// starting at HEAD) — the ancestor check here is a defensive
/// double-check, not the primary mechanism, and failing it means
/// something outside the routine squash-merge pattern is going on.
fn fix_stale_parent(repo_root: &Path, subdir: &str) -> Result<()> {
    let gitrepo_rel = format!("{subdir}/.gitrepo");

    let last_sync_commit = run_git(
        repo_root,
        &["log", "-1", "-G", "commit =", "--format=%H", "--", &gitrepo_rel],
    )?;
    if last_sync_commit.is_empty() {
        bail!("could not find a commit that touched `{gitrepo_rel}`'s `commit =` line; cannot compute a replacement `parent`");
    }

    let parent_ref = format!("{last_sync_commit}^");
    let candidate = run_git(repo_root, &["log", "-1", "--format=%H", &parent_ref]).with_context(|| {
        format!("the last sync commit {last_sync_commit} has no parent (it's a root commit) — cannot compute a replacement `.gitrepo` parent")
    })?;

    let is_ancestor = Command::new("git")
        .args(["merge-base", "--is-ancestor", &candidate, "HEAD"])
        .current_dir(repo_root)
        .status()
        .context("git merge-base --is-ancestor failed to run")?;
    if !is_ancestor.success() {
        bail!(
            "computed replacement parent {candidate} is not an ancestor of HEAD — \
             this is not the routine squash-merge case, stopping rather than guessing further"
        );
    }

    let gitrepo_path = repo_root.join(subdir).join(".gitrepo");
    let contents = std::fs::read_to_string(&gitrepo_path)
        .with_context(|| format!("failed to read {}", gitrepo_path.display()))?;
    std::fs::write(&gitrepo_path, replace_gitrepo_field(&contents, "parent", &candidate)?)
        .with_context(|| format!("failed to write {}", gitrepo_path.display()))?;

    run_git(repo_root, &["add", &gitrepo_rel])?;
    run_git(
        repo_root,
        &["commit", "-m", &format!("fix: realign {subdir} subrepo parent after squash-merge")],
    )?;
    Ok(())
}

fn replace_gitrepo_field(contents: &str, field: &str, value: &str) -> Result<String> {
    let prefix = format!("{field} =");
    let mut found = false;
    let lines: Vec<String> = contents
        .lines()
        .map(|line| {
            if line.trim_start().starts_with(&prefix) {
                found = true;
                format!("\t{field} = {value}")
            } else {
                line.to_string()
            }
        })
        .collect();
    if !found {
        bail!("`.gitrepo` has no `{field} = ` line to replace");
    }
    Ok(lines.join("\n") + "\n")
}

fn handle_conflict(_repo_root: &Path, _subdir: &str, stderr: &[u8]) -> Result<Outcome> {
    bail!("git subrepo pull failed: {}", String::from_utf8_lossy(stderr));
}
```

(`handle_conflict` is a placeholder-that-errors-loudly deliberately — Task 4
replaces it with the real allowlist/conflict logic. It's not a silent
placeholder: any conflict test run against it fails loudly with the real
git-subrepo error text, which is itself useful signal.)

- [ ] **Step 4: Run the three in-scope tests**

Run: `cargo test -p xtask pull_subrepo -- --nocapture`
Expected: `clean_pull_after_squash_merge_auto_fixes_stale_parent`,
`dirty_tree_is_rejected_before_touching_anything`, and
`works_identically_from_a_linked_worktree` PASS. The two conflict tests
still FAIL (expected — Task 4).

- [ ] **Step 5: Wire the CLI**

Modify `xtask/src/lib.rs`:

- Near `pub mod upstream_v2ray;` (line 36), confirm `pub mod pull_subrepo;`
  is present (added in Task 2).

- In the `Command` enum (after the `ProvisionUpstreamV2ray` variant, around
  line 146), add:

  ```rust
  /// Pull a vendored git-subrepo to a new upstream tag, fixing the
  /// routine squash-merge parent-staleness gotcha automatically. A real
  /// merge conflict stops here, uncommitted, exactly like `git pull` —
  /// resolve it by hand in the printed temp worktree.
  PullSubrepo {
      /// Path to the subrepo directory, relative to the repo root (e.g.
      /// `crates/ex-ray/third_party/v2ray-core`).
      path: String,
      /// Upstream tag to pull (e.g. `v5.53.0`). Not validated against any
      /// datasource — the caller decides.
      tag: String,
  },
  ```

- In `dispatch` (around line 292, near the `ProvisionUpstreamV2ray` arm),
  add:

  ```rust
  Command::PullSubrepo { path, tag } => run_pull_subrepo(path, tag),
  ```

- Near `run_provision_upstream_v2ray` (line 385), add:

  ```rust
  pub fn run_pull_subrepo(path: String, tag: String) -> Result<()> {
      let repo_root = repo_root()?;
      match pull_subrepo::run(&repo_root, &path, &tag)? {
          pull_subrepo::Outcome::Clean => {
              println!("xtask: pulled {path} to {tag} cleanly");
              Ok(())
          }
          pull_subrepo::Outcome::Conflicted { worktree, unresolved } => {
              bail!(
                  "{path} pull to {tag} has unresolved conflicts in:\n  {}\n\
                   Resolve them in {}, `git add` the resolved files, `git commit`, \
                   then run `git subrepo commit {path}` from the repo root.",
                  unresolved.join("\n  "),
                  worktree.display()
              );
          }
      }
  }
  ```

  (Add `bail` to the existing `use anyhow::{...}` import at the top of
  `lib.rs` if it isn't already imported there.)

- [ ] **Step 6: Manually exercise the CLI once**

Run (from the repo root, in a scratch clone — not against the real vendored
deps yet): `cargo xtask pull-subrepo --help` to confirm it's wired in and
the help text reads sensibly.
Expected: clap-generated help showing `<PATH> <TAG>`.

- [ ] **Step 7: Commit**

```bash
git add xtask/src/pull_subrepo.rs xtask/src/git_util.rs xtask/src/lib.rs
git commit -m "feat(xtask): implement pull-subrepo's clean-pull + stale-parent-fixup path"
```

______________________________________________________________________

### Task 4: `pull_subrepo` — allowlist conflict auto-resolution + real-conflict stop

**Files:**

- Modify: `xtask/src/pull_subrepo.rs` (replace `handle_conflict`)

**Interfaces:**

- Consumes: everything from Task 3 (`run_git`, `Outcome`).

- Produces: the complete `pull_subrepo::run` — nothing further changes its public shape.

- [ ] **Step 1: Confirm the two conflict tests still fail against Task 3's placeholder**

Run: `cargo test -p xtask pull_subrepo::allowlisted_conflict pull_subrepo::real_conflict -- --nocapture`
Expected: both FAIL (currently `handle_conflict` just bails with the raw
git-subrepo error).

- [ ] **Step 2: Implement the real conflict handling**

In `xtask/src/pull_subrepo.rs`, replace the placeholder `handle_conflict`
and add its helpers:

```rust
fn handle_conflict(repo_root: &Path, subdir: &str, stderr: &[u8]) -> Result<Outcome> {
    let stderr_str = String::from_utf8_lossy(stderr);
    if !stderr_str.contains("\"git merge\" command failed") {
        bail!("git subrepo pull failed in an unexpected way:\n{stderr_str}");
    }

    let common_dir = git_common_dir(repo_root)?;
    let worktree = common_dir.join("tmp").join("subrepo").join(subdir);
    if !worktree.exists() {
        bail!(
            "git subrepo reported a merge conflict but the expected temp worktree {} doesn't exist \
             — its internal layout may have changed since git-subrepo 0.4.9",
            worktree.display()
        );
    }

    let conflicted = unmerged_paths(&worktree)?;
    let mut unresolved = Vec::new();
    for path in &conflicted {
        if is_auto_resolvable(path) {
            run_git(&worktree, &["checkout", "--theirs", "--", path])?;
            run_git(&worktree, &["add", "--", path])?;
        } else {
            unresolved.push(path.clone());
        }
    }

    if !unresolved.is_empty() {
        return Ok(Outcome::Conflicted { worktree, unresolved });
    }

    // Every conflict was on the documented-safe allowlist — finish the
    // merge exactly as git-subrepo's own instructions tell a human to.
    // PREK_ALLOW_NO_CONFIG=1 (not --no-verify): this temp worktree is a
    // standalone checkout of just the subrepo content, with no
    // prek.toml of its own.
    let status = Command::new("git")
        .args(["commit", "--no-edit"])
        .current_dir(&worktree)
        .env("PREK_ALLOW_NO_CONFIG", "1")
        .status()
        .context("failed to run git commit in the subrepo temp worktree")?;
    if !status.success() {
        bail!("git commit failed in the subrepo temp worktree {}", worktree.display());
    }

    run_git(repo_root, &["subrepo", "commit", subdir])?;
    Ok(Outcome::Clean)
}

fn is_auto_resolvable(path: &str) -> bool {
    path == "go.mod" || path == "go.sum" || path.starts_with(".github/workflows/")
}

fn unmerged_paths(worktree: &Path) -> Result<Vec<String>> {
    let output = run_git(worktree, &["diff", "--name-only", "--diff-filter=U"])?;
    Ok(output.lines().map(|s| s.to_string()).collect())
}

fn git_common_dir(repo_root: &Path) -> Result<PathBuf> {
    let raw = run_git(repo_root, &["rev-parse", "--git-common-dir"])?;
    let path = PathBuf::from(raw);
    Ok(if path.is_absolute() { path } else { repo_root.join(path) })
}
```

- [ ] **Step 3: Run all `pull_subrepo` tests**

Run: `cargo test -p xtask pull_subrepo -- --nocapture`
Expected: all 5 tests from Task 2 PASS.

- [ ] **Step 4: Commit**

```bash
git add xtask/src/pull_subrepo.rs
git commit -m "feat(xtask): implement pull-subrepo's conflict allowlist + real-conflict stop"
```

______________________________________________________________________

### Task 5: `finish-vendor-bump` — version note, go.mod, identity checks

The remaining VENDORING.md "step 3" work, kept separate from
`pull-subrepo` per the design doc (a human resolving a real conflict by
hand wants to run this same finishing step themselves once they're done —
it shouldn't be bundled with the merge mechanics).

**Files:**

- Create: `xtask/src/finish_vendor_bump.rs`
- Create: `xtask/src/finish_vendor_bump_tests.rs`
- Modify: `xtask/src/lib.rs` (module + test-module declarations, `Command` variant, dispatch, wrapper)

**Interfaces:**

- Consumes: `git_util::run_git` (Task 3).

- Produces: `finish_vendor_bump::{run, IdentityCheckOutcome}` — `run(repo_root: &Path, subdir: &str, dep_name: &str, new_tag: &str) -> Result<IdentityCheckOutcome>`, consumed by Task 8's workflow.

- [ ] **Step 1: Write the failing tests**

`xtask/src/finish_vendor_bump_tests.rs`:

```rust
use std::path::Path;
use std::process::Command;

use super::finish_vendor_bump::{self, IdentityCheckOutcome};

fn git(cwd: &Path, args: &[&str]) {
    let status = Command::new("git").args(args).current_dir(cwd).status().unwrap();
    assert!(status.success(), "git {args:?} failed in {}", cwd.display());
}

fn init_repo_with_vendoring_md(dep_heading: &str, old_version: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let vendoring_dir = dir.path().join("crates/ex-ray/third_party");
    std::fs::create_dir_all(&vendoring_dir).unwrap();
    std::fs::write(
        vendoring_dir.join("VENDORING.md"),
        format!("# Vendoring\n\n## `{dep_heading}/` — pinned **{old_version}** ([upstream](https://example.com))\n\nSome patch notes.\n"),
    )
    .unwrap();
    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-m", "initial"]);
    dir
}

#[skuld::test]
fn updates_the_vendoring_note_and_commits() {
    let dir = init_repo_with_vendoring_md("widget", "v1.0.0");

    // finish_vendor_bump only touches the VENDORING.md note and commits in
    // this test — go.mod tidy / identity checks are exercised separately
    // against the real ex-ray module in Task 11's live verification, since
    // building a full fake Go module here would just re-test `go` itself.
    let outcome = finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0").unwrap();
    let _ = outcome;

    let note = std::fs::read_to_string(dir.path().join("crates/ex-ray/third_party/VENDORING.md")).unwrap();
    assert!(note.contains("pinned **v2.0.0**"), "note should show the new version: {note}");
    assert!(!note.contains("v1.0.0"));

    let log = Command::new("git")
        .args(["log", "-1", "--format=%s"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&log.stdout).contains("widget"));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p xtask finish_vendor_bump -- --nocapture`
Expected: FAIL (module doesn't exist yet).

- [ ] **Step 3: Implement**

`xtask/src/finish_vendor_bump.rs`:

```rust
//! `cargo xtask finish-vendor-bump` — the VENDORING.md "step 3" work that
//! stays separate from `pull_subrepo`: the version note, the outer
//! `go.mod`, and the identity build/test check. A human who resolved a
//! real conflict by hand runs this on its own once they're done.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::git_util::run_git;

pub enum IdentityCheckOutcome {
    Passed,
    Failed { detail: String },
}

pub fn run(repo_root: &Path, subdir: &str, dep_name: &str, new_tag: &str) -> Result<IdentityCheckOutcome> {
    update_vendoring_note_and_commit(repo_root, dep_name, new_tag)?;
    run_go_mod_tidy(&repo_root.join("crates/ex-ray"))?;
    let outcome = run_identity_checks(repo_root, subdir)?;

    run_git(repo_root, &["add", "-A"])?;
    run_git(
        repo_root,
        &["commit", "-m", &format!("build(ex-ray): finish vendoring {dep_name} {new_tag}")],
    )?;

    Ok(outcome)
}

/// Split out of `run` so Task 5's test can exercise the version-note
/// rewrite without a real Go toolchain / vendored module tree.
pub fn update_vendoring_note_and_commit(repo_root: &Path, dep_name: &str, new_tag: &str) -> Result<()> {
    let path = repo_root.join("crates/ex-ray/third_party/VENDORING.md");
    let contents = std::fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;

    let heading_prefix = format!("## `{dep_name}/` — pinned **");
    let Some(start) = contents.find(&heading_prefix) else {
        bail!("VENDORING.md has no `{heading_prefix}` heading to update");
    };
    let version_start = start + heading_prefix.len();
    let Some(version_end_offset) = contents[version_start..].find("**") else {
        bail!("malformed VENDORING.md heading for `{dep_name}` (no closing `**`)");
    };
    let version_end = version_start + version_end_offset;

    let updated = format!("{}{new_tag}{}", &contents[..version_start], &contents[version_end..]);
    std::fs::write(&path, updated).with_context(|| format!("failed to write {}", path.display()))?;

    run_git(repo_root, &["add", "crates/ex-ray/third_party/VENDORING.md"])?;
    run_git(repo_root, &["commit", "-m", &format!("docs: note {dep_name} {new_tag} in VENDORING.md")])?;
    Ok(())
}

fn run_go_mod_tidy(module_dir: &Path) -> Result<()> {
    let status = Command::new("go")
        .args(["mod", "tidy"])
        .current_dir(module_dir)
        .status()
        .with_context(|| format!("failed to run `go mod tidy` in {}", module_dir.display()))?;
    if !status.success() {
        bail!("`go mod tidy` failed in {}", module_dir.display());
    }
    Ok(())
}

fn run_identity_checks(repo_root: &Path, subdir: &str) -> Result<IdentityCheckOutcome> {
    let vendored_dir = repo_root.join(subdir);
    if let Some(detail) = go_command_failure(&vendored_dir, &["build", "./..."])? {
        return Ok(IdentityCheckOutcome::Failed { detail });
    }

    let ex_ray_dir = repo_root.join("crates/ex-ray");
    if let Some(detail) = go_command_failure(&ex_ray_dir, &["build", "./..."])? {
        return Ok(IdentityCheckOutcome::Failed { detail });
    }
    if let Some(detail) = go_command_failure(&ex_ray_dir, &["test", "./..."])? {
        return Ok(IdentityCheckOutcome::Failed { detail });
    }

    Ok(IdentityCheckOutcome::Passed)
}

/// Returns `Ok(None)` on success, `Ok(Some(detail))` on a go-command
/// failure (not a hard error — the caller still commits; a failing
/// identity check is expected-and-reportable, same policy as CI going red).
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
            "go {args:?} in {}:\n{}",
            cwd.display(),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p xtask finish_vendor_bump -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Wire the CLI**

Modify `xtask/src/lib.rs`, mirroring Task 3's Step 5 (Wire the CLI) exactly:

- `pub mod finish_vendor_bump;` near the other `pub mod` lines.

- `#[cfg(test)] #[path = "finish_vendor_bump_tests.rs"] mod finish_vendor_bump_tests;` in the test-module block.

- `Command` variant:

  ```rust
  /// Finish a vendor bump after `pull-subrepo` succeeds: update the
  /// VENDORING.md version note, `go mod tidy` the outer module, run the
  /// identity build/test check, and commit — regardless of whether the
  /// identity check passed (a failure is expected-and-reportable, not a
  /// reason to withhold the commit).
  FinishVendorBump {
      /// Path to the subrepo directory, relative to the repo root.
      path: String,
      /// The `.gitrepo` directory name (e.g. `v2ray-core`) — matches the
      /// `## \`<name>/\`` heading in VENDORING.md.
      dep_name: String,
      /// The tag just pulled (e.g. `v5.53.0`).
      tag: String,
  },
  ```

- Dispatch arm:

  ```rust
  Command::FinishVendorBump { path, dep_name, tag } => run_finish_vendor_bump(path, dep_name, tag),
  ```

- Wrapper:

  ```rust
  pub fn run_finish_vendor_bump(path: String, dep_name: String, tag: String) -> Result<()> {
      let repo_root = repo_root()?;
      match finish_vendor_bump::run(&repo_root, &path, &dep_name, &tag)? {
          finish_vendor_bump::IdentityCheckOutcome::Passed => {
              println!("xtask: finished vendoring {dep_name} {tag}, identity checks passed");
              Ok(())
          }
          finish_vendor_bump::IdentityCheckOutcome::Failed { detail } => {
              println!("xtask: finished vendoring {dep_name} {tag}, but identity checks FAILED:\n{detail}");
              Ok(())
          }
      }
  }
  ```

- [ ] **Step 6: Commit**

```bash
git add xtask/src/finish_vendor_bump.rs xtask/src/finish_vendor_bump_tests.rs xtask/src/lib.rs
git commit -m "feat(xtask): add finish-vendor-bump (version note, go.mod tidy, identity checks)"
```

______________________________________________________________________

### Task 6: Renovate `customManager` for `.gitrepo` version tracking

**Files:**

- Modify: `.github/renovate.json`

**Interfaces:** none (config only)

- [ ] **Step 1: Add the customManager**

In `.github/renovate.json`, add to the `customManagers` array (after the
existing `prek.toml` entry, before the closing `]`):

```json
    {
      "customType": "regex",
      "managerFilePatterns": ["/^crates/ex-ray/third_party/.+/\\.gitrepo$/"],
      "matchStrings": [
        "remote\\s*=\\s*(?<packageName>https://github\\.com/\\S+)\\n\\tbranch\\s*=\\s*(?<currentValue>\\S+)"
      ],
      "datasourceTemplate": "github-tags",
      "extractVersionTemplate": "^v?(?<version>.+)$"
    }
```

- [ ] **Step 2: Add the packageRules group**

Add to the `packageRules` array:

```json
    {
      "description": "Vendored git-subrepo deps (v2ray-core, utls): each is its own review-worthy event handled by vendor-bump.yaml, not the generic major-update bucket.",
      "matchFileNames": ["crates/ex-ray/third_party/*/.gitrepo"],
      "groupName": "Vendored dependencies",
      "automerge": false
    }
```

- [ ] **Step 3: Validate the config**

Run: `npx --yes --package renovate -- renovate-config-validator .github/renovate.json`
Expected: `Config validated successfully`. This is a one-off local check —
not being added as a permanent CI step (out of scope for this plan).

- [ ] **Step 4: Commit**

```bash
git add .github/renovate.json
git commit -m "chore(renovate): track vendored .gitrepo tags via customManager"
```

______________________________________________________________________

### Task 7: `mint-nathan-token` composite action

**Files:**

- Create: `.github/actions/mint-nathan-token/action.yaml`

**Interfaces:**

- Produces: `steps.<id>.outputs.token`, consumed by Task 8 and Task 9's workflows.

- [ ] **Step 1: Write the action**

```yaml
name: Mint nathan-blahaj token
description: >-
  Mint a short-lived GitHub App installation token for nathan-blahaj, the
  bot identity used by any workflow that pushes commits and needs those
  pushes to retrigger downstream required-status-check workflows (pushes
  made with the default GITHUB_TOKEN do not retrigger them — GitHub's
  anti-recursion behavior). No server or webhook involved; this just calls
  GitHub's token-minting API with the App's credentials.

inputs:
  app-id:
    description: nathan-blahaj's GitHub App ID (from secrets.NATHAN_APP_ID)
    required: true
  private-key:
    description: nathan-blahaj's GitHub App private key (from secrets.NATHAN_APP_PRIVATE_KEY)
    required: true

outputs:
  token:
    description: Short-lived (1 hour) installation token
    value: ${{ steps.mint.outputs.token }}

runs:
  using: composite
  steps:
    - name: Mint installation token
      id: mint
      uses: actions/create-github-app-token@v2
      with:
        app-id: ${{ inputs.app-id }}
        private-key: ${{ inputs.private-key }}
```

- [ ] **Step 2: Commit**

```bash
git add .github/actions/mint-nathan-token/action.yaml
git commit -m "ci: add mint-nathan-token composite action"
```

______________________________________________________________________

### Task 8: `vendor-bump.yaml` workflow

**Files:**

- Create: `.github/workflows/vendor-bump.yaml`

**Interfaces:**

- Consumes: `cargo xtask pull-subrepo` (Task 4), `cargo xtask finish-vendor-bump` (Task 5), `.github/actions/mint-nathan-token` (Task 7).

- [ ] **Step 1: Write the workflow**

```yaml
name: Vendor bump

on:
  push:
    branches: ["renovate/**"]
    paths: ["crates/ex-ray/third_party/*/.gitrepo"]
  workflow_dispatch:
    inputs:
      dep:
        description: Vendored dep directory name under crates/ex-ray/third_party (e.g. v2ray-core, utls)
        required: true
      tag:
        description: Upstream tag to pull (e.g. v5.53.0)
        required: true

permissions:
  contents: write
  pull-requests: write

concurrency:
  group: vendor-bump-${{ github.ref }}
  cancel-in-progress: false

jobs:
  bump:
    name: Pull + rebase vendored dependency
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Mint nathan-blahaj token
        id: nathan
        uses: ./.github/actions/mint-nathan-token
        with:
          app-id: ${{ secrets.NATHAN_APP_ID }}
          private-key: ${{ secrets.NATHAN_APP_PRIVATE_KEY }}

      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
          token: ${{ steps.nathan.outputs.token }}

      - uses: dtolnay/rust-toolchain@stable
      - uses: actions/setup-go@v7
        with:
          go-version: stable

      - name: Determine dep + tag
        id: target
        run: |
          if [[ -n "${{ inputs.dep }}" ]]; then
            dep="${{ inputs.dep }}"
            tag="${{ inputs.tag }}"
          else
            changed=$(git diff --name-only HEAD^ HEAD -- 'crates/ex-ray/third_party/*/.gitrepo')
            dep=$(basename "$(dirname "$changed")")
            tag=$(sed -n 's/^\tbranch = //p' "$changed")
          fi
          echo "dep=$dep" >> "$GITHUB_OUTPUT"
          echo "tag=$tag" >> "$GITHUB_OUTPUT"
          echo "path=crates/ex-ray/third_party/$dep" >> "$GITHUB_OUTPUT"

      # workflow_dispatch runs against whatever ref was selected when
      # triggering it — which defaults to `main` if the caller doesn't pass
      # `--ref`. Never push straight to main: manual runs always get a
      # disposable scratch branch instead of trusting the dispatch ref.
      - name: Create a scratch branch (workflow_dispatch only)
        if: github.event_name == 'workflow_dispatch'
        id: scratch-branch
        run: |
          branch="vendor-bump-manual/${{ steps.target.outputs.dep }}-${{ steps.target.outputs.tag }}-${{ github.run_id }}"
          git checkout -b "$branch"
          echo "ref_name=$branch" >> "$GITHUB_OUTPUT"

      - name: git identity
        run: |
          git config user.name "nathan-blahaj[bot]"
          git config user.email "nathan-blahaj[bot]@users.noreply.github.com"

      - name: Pull the vendored subrepo
        id: pull
        continue-on-error: true
        run: cargo xtask pull-subrepo "${{ steps.target.outputs.path }}" "${{ steps.target.outputs.tag }}"

      - name: Finish (version note, go.mod, identity checks)
        if: steps.pull.outcome == 'success'
        run: cargo xtask finish-vendor-bump "${{ steps.target.outputs.path }}" "${{ steps.target.outputs.dep }}" "${{ steps.target.outputs.tag }}"

      - name: Commit the conflicted tree anyway (CI-only policy — see VENDORING.md)
        if: steps.pull.outcome == 'failure'
        run: |
          worktree="$(git rev-parse --git-common-dir)/tmp/subrepo/${{ steps.target.outputs.path }}"
          git -C "$worktree" add -A
          PREK_ALLOW_NO_CONFIG=1 git -C "$worktree" commit -m "vendor: conflicted pull of ${{ steps.target.outputs.dep }} ${{ steps.target.outputs.tag }} — needs manual resolution"
          git subrepo commit "${{ steps.target.outputs.path }}"

      - name: Push
        run: git push origin "HEAD:${{ steps.scratch-branch.outputs.ref_name || github.ref_name }}"

      # Only for the real Renovate-triggered flow — a workflow_dispatch
      # scratch-branch run has no associated PR to comment on.
      - name: Comment on the PR if conflicted
        if: steps.pull.outcome == 'failure' && github.event_name == 'push'
        env:
          GH_TOKEN: ${{ steps.nathan.outputs.token }}
        run: |
          pr_number=$(gh pr list --repo "${{ github.repository }}" --head "${{ github.ref_name }}" --json number --jq '.[0].number')
          gh pr comment "$pr_number" --repo "${{ github.repository }}" --body "$(cat <<EOF
          Automated pull of \`${{ steps.target.outputs.dep }}\` to \`${{ steps.target.outputs.tag }}\` hit a real merge conflict outside the auto-resolved allowlist (go.mod/go.sum/.github/workflows). The conflicted tree is committed on this branch.

          To resolve: check out this PR branch, fix the conflicts, then run \`cargo xtask finish-vendor-bump crates/ex-ray/third_party/${{ steps.target.outputs.dep }} ${{ steps.target.outputs.dep }} ${{ steps.target.outputs.tag }}\` and push a normal commit.
          EOF
          )"
```

- [ ] **Step 2: Validate the YAML syntactically**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/vendor-bump.yaml'))"`
Expected: no output (valid YAML). This catches indentation/syntax mistakes
before the first real trigger; it doesn't validate GitHub Actions semantics
(that's Task 11's live verification).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/vendor-bump.yaml
git commit -m "ci: add vendor-bump workflow"
```

______________________________________________________________________

### Task 9: Fix `wix-hash-fixup.yaml`

**Files:**

- Modify: `.github/workflows/wix-hash-fixup.yaml`

- [ ] **Step 1: Swap the token**

Replace the file's contents:

```yaml
name: Update WiX hash

on:
  push:
    branches: ["renovate/**"]
    paths: ["msi-installer/src/msi_installer/wix-toolchain.toml"]

permissions:
  contents: write

jobs:
  fixup:
    name: Update WiX hash
    runs-on: ubuntu-latest
    steps:
      - name: Mint nathan-blahaj token
        id: nathan
        uses: ./.github/actions/mint-nathan-token
        with:
          app-id: ${{ secrets.NATHAN_APP_ID }}
          private-key: ${{ secrets.NATHAN_APP_PRIVATE_KEY }}

      - uses: actions/checkout@v7
        with:
          token: ${{ steps.nathan.outputs.token }}

      - uses: astral-sh/setup-uv@v9.0.0

      - name: Update WiX URL and SHA256
        run: uv run --directory msi-installer upgrade-wix

      - name: Commit if changed
        run: |
          git diff --quiet && exit 0
          git config user.name "nathan-blahaj[bot]"
          git config user.email "nathan-blahaj[bot]@users.noreply.github.com"
          git add msi-installer/src/msi_installer/wix-toolchain.toml
          git commit -m "Update WiX toolchain URL and SHA256"
          git push
```

(Only the token source and the two `git config` identity lines actually
change from the original — everything else is unchanged.)

- [ ] **Step 2: Validate the YAML syntactically**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/wix-hash-fixup.yaml'))"`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/wix-hash-fixup.yaml
git commit -m "ci(wix-hash-fixup): push as nathan-blahaj so CI actually reruns"
```

______________________________________________________________________

### Task 10: Update `VENDORING.md`

**Files:**

- Modify: `crates/ex-ray/third_party/VENDORING.md`

- [ ] **Step 1: Replace the "Bumping a pinned version" section**

Replace the section (currently the last section in the file, from `## Bumping a pinned version` to the end):

```markdown
## Bumping a pinned version

This is automated (issue #787): Renovate opens a PR bumping just the
`branch =` line in a `.gitrepo`, and `.github/workflows/vendor-bump.yaml`
does the rest — `cargo xtask pull-subrepo` followed by
`cargo xtask finish-vendor-bump` — pushing further commits to the same PR.
It merges automatically if the pull is clean and CI is green; it sits open
with a PR comment if a real merge conflict landed outside the auto-resolved
`go.mod`/`go.sum`/`.github/workflows/*` allowlist (upstream's real
authoritative source for the automated policy: the `AUTO_RESOLVE`/
`is_auto_resolvable` logic in `xtask/src/pull_subrepo.rs`).

To do it by hand (same tools the automation uses):

1. `cargo xtask pull-subrepo crates/ex-ray/third_party/<name> <new-tag>`.
   On a real conflict it stops uncommitted, exactly like `git pull`, and
   prints the temp worktree to resolve it in — `cd` there, fix the
   conflicts (`git status` to see them), `git add`, `git commit`, then
   `git subrepo commit crates/ex-ray/third_party/<name>` from the repo
   root.
2. `cargo xtask finish-vendor-bump crates/ex-ray/third_party/<name> <name> <new-tag>`
   — updates this file's version note, runs `go mod tidy`, and runs the
   identity build/test check (`go build`/`go test`), committing regardless
   of whether the identity check passed.
```

- [ ] **Step 2: Commit**

```bash
git add crates/ex-ray/third_party/VENDORING.md
git commit -m "docs: point VENDORING.md's bump instructions at the new automation"
```

______________________________________________________________________

### Task 11: Live end-to-end verification (manual, watched)

Not subagent-executable in the background — per this repo's convention
(`feedback_watch_ci_to_green` / `feedback_live_verification_no_side_effects`),
this must be watched through to a real green (or correctly-red) result, not
declared done from static review.

- [ ] **Step 1: Push the branch and open the PR**

```bash
git push -u origin azhukova/787
gh pr create --title "feat(vendor): automate vendored-dependency bumps" --body "Closes #787. See docs/superpowers/specs/2026-08-10-787-vendor-dependency-automation.md and docs/superpowers/plans/2026-08-11-787-vendor-dependency-automation.md."
```

- [ ] **Step 2: Watch this PR's own CI to green**

Use the `gh-ci` skill/CLI against this PR (not the vendor-bump workflow
yet — this just confirms the new xtask code and workflow YAML don't break
the existing build).

- [ ] **Step 3: Confirm Task 1's secrets are in place**

`gh secret list --repo bindreams/hole` should show `NATHAN_APP_ID` and
`NATHAN_APP_PRIVATE_KEY`. If missing, stop and complete Task 1 first.

- [ ] **Step 4: Dry-run `vendor-bump.yaml` via `workflow_dispatch` on a harmless case**

Once this PR is merged (so the workflow exists on `main`):

```bash
gh workflow run vendor-bump.yaml --repo bindreams/hole -f dep=utls -f tag=v1.8.2
```

(Re-pulling the *current* tag — a deliberate no-op case: proves the App
token, the checkout, and `cargo xtask pull-subrepo`'s early "nothing to
pull" path all work end-to-end without mutating anything real. This runs
on a disposable `vendor-bump-manual/...` scratch branch the workflow
creates itself — never against whatever ref the run was dispatched on —
delete that branch afterward, it has no PR attached.)

Watch the run via `gh run watch`. Expected: `pull-subrepo` reports nothing
to do (git-subrepo's own already-up-to-date short-circuit) and the job
finishes without pushing a new commit.

- [ ] **Step 5: Confirm a real bump reaches auto-merge or a correctly-red PR**

Wait for (or manually trigger against) an actual newer tag — e.g. if
v2ray-core has since cut a release past `v5.52.0`:

```bash
gh workflow run vendor-bump.yaml --repo bindreams/hole -f dep=v2ray-core -f tag=<next tag>
```

Watch: does CI (`ci.yaml`) actually rerun on the pushed commit (confirming
the App-token retrigger works), and does the PR either auto-merge or sit
correctly red/commented? This is the property the whole design rests on —
confirm it live before considering #787 done.

- [ ] **Step 6: Confirm `wix-hash-fixup.yaml` still works**

Wait for (or note for later) the next Renovate WiX-toolchain version bump
PR, and confirm its fixup commit now gets a fresh CI run and can
auto-merge — previously suspected broken (Task 9's fix target).
