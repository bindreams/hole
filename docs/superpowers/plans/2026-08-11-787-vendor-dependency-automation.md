# Automated vendored-dependency bumps (#787) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automate bumping the two git-subrepo-vendored deps
(`crates/ex-ray/third_party/{v2ray-core,utls}`) to new upstream tags,
rebasing the local ECH patches through `git subrepo pull`, and landing the
result as a PR that merges automatically when clean+green or sits open/red
when a real conflict or CI failure blocks it — with no self-hosted server.

**Architecture:** Renovate (hosted GitHub App) bumps only the `branch =`
line in each `.gitrepo` via a `customManager` and opens its normal PR —
without arming auto-merge itself. A new `vendor-bump.yaml` workflow,
authenticated as a purpose-built GitHub App (`nathan-blahaj`, not the
default `GITHUB_TOKEN`, so its pushes actually retrigger CI), runs
`cargo xtask pull-subrepo` (a generic, human-usable wrapper around
`git subrepo pull` that fixes the routine squash-merge parent-staleness
automatically and behaves like `git pull` on a real conflict — stops,
uncommitted) followed by `cargo xtask finish-vendor-bump` (version note +
`go.mod` + identity build/test), pushes, and — only once the real work has
actually landed — arms GitHub-native auto-merge itself via `gh pr merge --auto`. The same App fixes the identical latent bug in
`wix-hash-fixup.yaml`.

**Tech Stack:** Rust (`xtask`, existing `clap`/`anyhow` conventions), GitHub
Actions, Renovate `customManager` (regex), `git-subrepo` 0.4.9.

## Global Constraints

- Both vendored deps track **stable tagged semver releases only** (existing
  `.gitrepo` `branch` values are already tags: `v5.52.0`, `v1.8.2`) —
  Renovate's default semver versioning already excludes pre-releases
  (e.g. v2ray-core's `v5.53.0` pre-release), so no extra config is needed
  for this.
- `cargo xtask pull-subrepo <path> <tag>` must never commit a conflicted
  tree itself — that decision belongs to the caller. It auto-resolves only
  the documented-safe allowlist (`go.mod`, `go.sum`,
  `.github/workflows/*`) to upstream's version; anything else conflicting
  stops the tool with nothing committed on the pull attempt itself, exactly
  like `git pull` (a prior, independent `.gitrepo`-parent-realignment
  commit may already be on the branch when this happens — see Task 4).
- The CI-only "commit despite conflicts" behavior lives in
  `vendor-bump.yaml`, not in the xtask tool.
- Renovate goes dormant on a dependency once a non-Renovate commit lands on
  its branch (confirmed platform behavior) — no coordination code needed
  for that; it's automatic.
- `nathan-blahaj` is the generic bot identity name (not vendor-specific) —
  reused for `wix-hash-fixup.yaml` too. Secrets: `NATHAN_APP_ID`,
  `NATHAN_APP_PRIVATE_KEY`.
- Renovate never arms auto-merge for these PRs itself (no `automerge` in
  its packageRules) — `vendor-bump.yaml` is the sole arming point, and only
  after a clean pull *and* a successful finish, to close the
  premature-merge race described above.
- `vendor-bump.yaml` must never act on its own pushes (it would otherwise
  retrigger itself) and must never treat a non-conflict failure (dirty
  tree, missing `git-subrepo`, bad input) as if it were a real merge
  conflict.
- Design doc: `docs/superpowers/specs/2026-08-10-787-vendor-dependency-automation.md`.

______________________________________________________________________

## File Structure

| File                                            | Responsibility                                                                                                                                                                                                                                                                                                                                                                                                        |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `xtask/src/git_util.rs`                         | Shared `run_git` helper (shell out, check status, return trimmed stdout) used by `pull_subrepo.rs` and `finish_vendor_bump.rs`.                                                                                                                                                                                                                                                                                       |
| `xtask/src/pull_subrepo.rs`                     | Generic `git subrepo pull` wrapper: dirty-tree guard, defensive leftover-worktree cleanup before every attempt, automatic squash-merge parent fixup, allowlist conflict auto-resolution (handling delete/modify conflicts, not just modify/modify, and the `.gitrepo` `branch`-field fixup that path needs — guarded against a no-op empty commit), `git-pull`-like stop on real conflicts. No Renovate/CI awareness. |
| `xtask/src/pull_subrepo_tests.rs`               | Fixture-repo integration tests proving the above against a real installed `git subrepo`: clean, allowlisted, real, mixed (both in one pull), dirty-tree, both from a plain checkout and a linked worktree, and recovery from a leftover worktree left by a prior run.                                                                                                                                                 |
| `xtask/src/finish_vendor_bump.rs`               | The separate, smaller VENDORING.md "step 3" work: version note, outer `go.mod` require-version bump (without double-prefixing `v`) + `go mod tidy`, identity build/test. Commits are guarded against "nothing to commit".                                                                                                                                                                                             |
| `xtask/src/finish_vendor_bump_tests.rs`         | Tests for the above, including the full `run()` sequence end-to-end (not just its sub-steps) and a failing identity check.                                                                                                                                                                                                                                                                                            |
| `xtask/src/lib.rs`                              | Modify: two new `Command` variants + dispatch wrappers + module/test-module declarations.                                                                                                                                                                                                                                                                                                                             |
| `.github/renovate.json`                         | Modify: `customManager` tracking each `.gitrepo`'s `branch` line (capturing `owner/repo`, not a full URL; no `extractVersionTemplate`, since that would strip the `v` this repo's tags and `git subrepo pull -b` both need). No packageRules entry — automerge is armed by the workflow, not Renovate.                                                                                                                |
| `.github/actions/mint-nathan-token/action.yaml` | Composite action minting a `nathan-blahaj` installation token from App ID + private key inputs. Shared by both workflows below.                                                                                                                                                                                                                                                                                       |
| `.github/workflows/vendor-bump.yaml`            | New workflow: picks up Renovate's `.gitrepo` bump, installs `git-subrepo`, runs the two xtask commands, pushes via `nathan-blahaj`, arms auto-merge itself on a clean+finished result, comments on real conflicts. Guards against self-retriggering, branch-synchronization races, and misreading a non-conflict failure as a conflict.                                                                               |
| `.github/workflows/wix-hash-fixup.yaml`         | Modify: swap `GITHUB_TOKEN` for `nathan-blahaj`.                                                                                                                                                                                                                                                                                                                                                                      |
| `crates/ex-ray/third_party/VENDORING.md`        | Modify: document the new tooling, the CI-only conflict-commit policy, and the (broadened, dep-agnostic) identity check — with an accurate justification, not a citation of an unverified CI claim.                                                                                                                                                                                                                    |

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
installed* `git-subrepo` 0.4.9, not assumptions — that the squash-merge
parent-staleness fixup reliably recovers, that a real conflict leaves the
tree exactly as `git pull` would, that a mixed conflict resolves only its
allowlisted part, and that the tool recovers from a leftover worktree a
prior run left behind. All in both a plain checkout and a linked worktree
where relevant.

**A note on how the fixture differs from the design's original assumption**
(discovered by running it for real, not by further reasoning): a *single*
clone-on-a-branch, patch, squash-merge, delete-branch cycle does **not**
naturally produce a stale `.gitrepo` `parent` — the recorded parent is the
commit that existed before the feature branch forked, which stays a valid
ancestor of `main` across a squash merge. Real staleness (which does exist
today — `crates/ex-ray/third_party/utls/.gitrepo`'s current `parent` is
verifiably not an ancestor of this repo's HEAD) comes from a longer,
harder-to-reproduce real history. The fixture instead constructs staleness
directly — rewrites `.gitrepo`'s `parent` to a commit that exists but isn't
reachable from HEAD — which is what actually matters: proving the *fixup
mechanism* recovers correctly, not reproducing the exact multi-PR sequence
that causes staleness in production.

**Files:**

- Create: `xtask/src/pull_subrepo_tests.rs`
- Create: `xtask/src/pull_subrepo.rs` (stub for now — enough for the test
  file to compile against the real public shape)

**Interfaces:**

- Produces: `pull_subrepo::Outcome` (`Clean` / `Conflicted { worktree: PathBuf, unresolved: Vec<String> }`), `pull_subrepo::run(repo_root: &Path, subdir: &str, tag: &str) -> anyhow::Result<Outcome>`, and `pub(crate) fn is_auto_resolvable(path: &str) -> bool` (pure allowlist-membership check, `pub(crate)` so the test file — a sibling module of `pull_subrepo`, not a child — can unit-test it directly).

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
    /// A conflict remains outside the safe allowlist. The pull attempt
    /// itself committed nothing — the temp merge worktree `git subrepo
    /// pull` created is left exactly as `git merge` would leave a
    /// conflicted tree, for a human to resolve. (A prior, independent
    /// `.gitrepo`-parent-realignment commit may already be on the branch
    /// if that fixup ran first — see `fix_stale_parent`.)
    Conflicted { worktree: PathBuf, unresolved: Vec<String> },
}

pub fn run(_repo_root: &Path, _subdir: &str, _tag: &str) -> Result<Outcome> {
    unimplemented!("Task 3/4")
}

pub(crate) fn is_auto_resolvable(_path: &str) -> bool {
    unimplemented!("Task 4")
}
```

- [ ] **Step 2: Write the fixture builder + git helpers**

`xtask/src/pull_subrepo_tests.rs`:

```rust
use std::path::{Path, PathBuf};
use std::process::Command;

use super::pull_subrepo::{self, Outcome};

/// Which upstream file(s) v2 changes, matched against what our local
/// downstream patch also touches — this is what determines whether the
/// eventual pull hits no conflict, an auto-resolvable one, a real one, or
/// both at once.
enum ConflictKind {
    /// v2 changes only `other.txt`, which nothing downstream touches — a
    /// genuinely clean pull.
    None,
    /// v2 rewrites `go.mod`/`go.sum`, which our downstream commit also
    /// edits — exercises the documented "resolve to theirs" allowlist.
    Allowlisted,
    /// v2 rewrites `patched.txt`, which our local ECH-style patch also
    /// edits — a real conflict outside the allowlist.
    Real,
    /// v2 rewrites BOTH `go.mod` (allowlisted) and `patched.txt` (real) —
    /// proves only the real one survives into `Outcome::Conflicted`.
    Mixed,
    /// v2 DELETES `go.sum` entirely while our downstream commit still has
    /// local edits to it — a delete/modify conflict, not the more common
    /// modify/modify case. `checkout --theirs` has no "theirs" blob to
    /// check out here; resolving to theirs means removing the file.
    AllowlistedDelete,
}

/// Builds a throwaway upstream + downstream repo pair replicating Hole's
/// actual vendoring pattern: `git subrepo clone` a subdir on a feature
/// branch, add local patch commits, squash-merge the branch into main and
/// delete it.
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
        std::fs::write(upstream.join("go.sum"), "fixture v1.0.0 h1:abc=\n").unwrap();
        std::fs::write(upstream.join("other.txt"), "unrelated\n").unwrap();
        git(&upstream, &["add", "."]);
        git(&upstream, &["commit", "-m", "v1"]);
        git(&upstream, &["tag", "v1"]);

        match conflict {
            ConflictKind::None => {
                std::fs::write(upstream.join("other.txt"), "unrelated changed\n").unwrap();
            }
            ConflictKind::Allowlisted => {
                std::fs::write(
                    upstream.join("go.mod"),
                    "module fixture\n\ngo 1.26\n\nrequire upstream/newdep v1.0.0\n",
                )
                .unwrap();
                std::fs::write(upstream.join("go.sum"), "fixture v2.0.0 h1:xyz=\n").unwrap();
            }
            ConflictKind::Real => {
                std::fs::write(upstream.join("patched.txt"), "upstream line one CHANGED\n").unwrap();
            }
            ConflictKind::Mixed => {
                std::fs::write(
                    upstream.join("go.mod"),
                    "module fixture\n\ngo 1.26\n\nrequire upstream/newdep v1.0.0\n",
                )
                .unwrap();
                std::fs::write(upstream.join("patched.txt"), "upstream line one CHANGED\n").unwrap();
            }
            ConflictKind::AllowlistedDelete => {
                std::fs::remove_file(upstream.join("go.sum")).unwrap();
                git(&upstream, &["add", "-A"]);
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
        std::fs::write(downstream.join("vendor/go.sum"), "fixture v1.0.0-patched h1:def=\n").unwrap();
        git(&downstream, &["add", "-A"]);
        git(&downstream, &["commit", "-m", "patch: our local addition"]);

        git(&downstream, &["checkout", "main"]);
        git(&downstream, &["merge", "--squash", "feature"]);
        git(&downstream, &["commit", "-m", "vendor: import + patch (squashed)"]);
        git(&downstream, &["branch", "-D", "feature"]);

        Fixture { dir, downstream }
    }

    /// Rewrites `.gitrepo`'s `parent` to a commit that exists but is not
    /// an ancestor of HEAD — see the module-level note on why this is
    /// constructed directly rather than produced naturally by the
    /// clone+patch+squash-merge sequence above.
    fn corrupt_parent(&self) {
        git(&self.downstream, &["checkout", "-b", "throwaway"]);
        std::fs::write(self.downstream.join("README.md"), "throwaway\n").unwrap();
        git(&self.downstream, &["commit", "-am", "throwaway"]);
        let unreachable = git_output(&self.downstream, &["rev-parse", "HEAD"]).trim().to_string();
        git(&self.downstream, &["checkout", "main"]);
        git(&self.downstream, &["branch", "-D", "throwaway"]);

        let gitrepo_path = self.downstream.join("vendor/.gitrepo");
        let contents = std::fs::read_to_string(&gitrepo_path).unwrap();
        let corrupted: String = contents
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("parent =") {
                    format!("\tparent = {unreachable}")
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&gitrepo_path, corrupted).unwrap();
        git(&self.downstream, &["add", "-A"]);
        git(&self.downstream, &["commit", "-m", "test: artificially stale parent"]);
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
    fx.corrupt_parent();

    // Sanity: this reproduces the exact stale-parent failure the fixup
    // exists to recover from. This text is genuinely on stderr (unlike
    // the merge-conflict case in the other tests below, which is on
    // stdout — see pull_subrepo.rs's handle_conflict for why that
    // distinction matters).
    let raw = Command::new("git")
        .args(["subrepo", "pull", "vendor", "-b", "v2"])
        .current_dir(&fx.downstream)
        .output()
        .unwrap();
    assert!(!raw.status.success(), "fixture should reproduce the stale-parent failure before any fixup");
    assert!(String::from_utf8_lossy(&raw.stderr).contains("is not an ancestor"));

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

    let go_sum = std::fs::read_to_string(fx.downstream.join("vendor/go.sum")).unwrap();
    assert!(go_sum.contains("v2.0.0"), "upstream's go.sum content should win: {go_sum}");

    // `git subrepo commit` (the finishing command on the conflict-resolve
    // path, unlike a clean pull which finishes on its own) does NOT
    // update .gitrepo's `branch` field — it stays at v1 even though
    // `commit` and the tree content are v2. Confirms the explicit fixup
    // in handle_conflict.
    let gitrepo = std::fs::read_to_string(fx.downstream.join("vendor/.gitrepo")).unwrap();
    assert!(gitrepo.contains("branch = v2"), "the branch pin must be updated even on the conflict-resolve path: {gitrepo}");
}

#[skuld::test]
fn allowlisted_delete_conflict_removes_the_file_instead_of_erroring() {
    // A delete/modify conflict (upstream deleted, downstream modified) has
    // no "theirs" blob for `git checkout --theirs` to check out — plain
    // `checkout --theirs` fails here. Resolving to theirs means removing
    // the file, since upstream's version of "the file" is "gone".
    let fx = Fixture::build(ConflictKind::AllowlistedDelete);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));
    assert!(!fx.downstream.join("vendor/go.sum").exists(), "go.sum should be removed, matching upstream's deletion");
}

#[skuld::test]
fn mixed_conflict_auto_resolves_the_allowlisted_part_only() {
    let fx = Fixture::build(ConflictKind::Mixed);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { unresolved, .. } => {
            assert_eq!(unresolved, vec!["patched.txt".to_string()], "go.mod should have been auto-resolved, leaving only the real conflict");
        }
        Outcome::Clean => panic!("expected a real conflict on patched.txt to survive"),
    }
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
fn real_conflict_stops_uncommitted_from_a_linked_worktree() {
    // The other two worktree tests (works_identically_from_a_linked_worktree,
    // allowlisted_conflict_resolves_from_a_linked_worktree) only cover
    // outcomes that end Clean. This is the only test that inspects
    // Outcome::Conflicted's `worktree` field and asserts nothing was
    // committed — and it needs to run from a linked worktree too, since
    // that's exactly the scenario a real conflict during an in-worktree
    // bump attempt would hit.
    let fx = Fixture::build(ConflictKind::Real);
    let worktree_path = fx.dir.path().join("downstream-worktree");
    git(&fx.downstream, &["worktree", "add", worktree_path.to_str().unwrap()]);
    let before_head = git_output(&worktree_path, &["rev-parse", "HEAD"]);

    let outcome = pull_subrepo::run(&worktree_path, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { worktree, unresolved } => {
            assert_eq!(unresolved, vec!["patched.txt".to_string()]);
            assert!(worktree.is_dir(), "the reported conflict worktree should exist: {}", worktree.display());
        }
        Outcome::Clean => panic!("expected a conflict on patched.txt"),
    }

    let after_head = git_output(&worktree_path, &["rev-parse", "HEAD"]);
    assert_eq!(before_head, after_head, "a real conflict must not commit anything on the worktree's HEAD");
}

#[skuld::test]
fn a_second_run_recovers_from_a_leftover_conflicted_worktree() {
    let fx = Fixture::build(ConflictKind::Real);

    let first = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("first conflicted run should report Conflicted, not Err");
    assert!(matches!(first, Outcome::Conflicted { .. }));

    // Without cleaning up in between: verified live that git-subrepo
    // refuses a second pull ("There is already a worktree with branch
    // subrepo/vendor") unless the leftover worktree/branch is cleaned
    // first. attempt_pull's defensive `git subrepo clean` before every
    // attempt must recover from this rather than erroring.
    let second = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("second run should also cleanly report Conflicted, not error on the leftover worktree");
    assert!(matches!(second, Outcome::Conflicted { .. }));
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

#[skuld::test]
fn allowlisted_conflict_resolves_from_a_linked_worktree() {
    // Unlike the clean-pull worktree test above, this exercises the
    // git_common_dir / temp-worktree-location code inside handle_conflict
    // — the part of pull_subrepo that's actually worktree-position
    // sensitive (git-subrepo's temp worktree lives under
    // `git rev-parse --git-common-dir`, which differs between a plain
    // checkout and a linked worktree).
    let fx = Fixture::build(ConflictKind::Allowlisted);
    let worktree_path = fx.dir.path().join("downstream-worktree");
    git(&fx.downstream, &["worktree", "add", worktree_path.to_str().unwrap()]);

    let outcome = pull_subrepo::run(&worktree_path, "vendor", "v2").expect("conflict resolution should succeed from a linked worktree");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(worktree_path.join("vendor/go.mod")).unwrap();
    assert!(go_mod.contains("newdep"));
}

#[skuld::test]
fn is_auto_resolvable_covers_the_documented_allowlist() {
    assert!(pull_subrepo::is_auto_resolvable("go.mod"));
    assert!(pull_subrepo::is_auto_resolvable("go.sum"));
    assert!(pull_subrepo::is_auto_resolvable(".github/workflows/ci.yml"));
    assert!(!pull_subrepo::is_auto_resolvable("patched.txt"));
}
```

- [ ] **Step 4: Run the tests to see them fail on the `unimplemented!` stub**

Run: `cargo test -p xtask pull_subrepo 2>&1 | tee /tmp/pull_subrepo_test1.log` (Windows: redirect to a file under the scratch dir instead of `/tmp`, then Read it — never pipe to `tail`).
Expected: the sanity assertions inside `clean_pull_after_squash_merge_auto_fixes_stale_parent` should PASS (proving the fixture reproduces the real stale-parent failure against the actually-installed `git subrepo`), then the test panics on `unimplemented!("Task 3/4")`. `is_auto_resolvable_covers_the_documented_allowlist` panics on the other `unimplemented!`. If any sanity assertion itself fails, the fixture doesn't reproduce the intended condition — stop and fix the fixture before proceeding to Task 3, since everything downstream depends on it being accurate.

- [ ] **Step 5: Wire the module declarations**

Modify `xtask/src/lib.rs`: add `pub mod pull_subrepo;` near the other
`pub mod` declarations, and in the `#[cfg(test)]` block add:

```rust
#[cfg(test)]
#[path = "pull_subrepo_tests.rs"]
mod pull_subrepo_tests;
```

- [ ] **Step 6: Commit**

```bash
git add xtask/src/pull_subrepo.rs xtask/src/pull_subrepo_tests.rs xtask/src/lib.rs
git commit -m "test(xtask): add fixture-repo tests proving git-subrepo's real behavior"
```

______________________________________________________________________

### Task 3: `pull_subrepo` — clean pull with automatic stale-parent fixup

Implements enough of `pull_subrepo::run` to pass
`clean_pull_after_squash_merge_auto_fixes_stale_parent`,
`dirty_tree_is_rejected_before_touching_anything`, and
`works_identically_from_a_linked_worktree` from Task 2. Conflict handling
(Task 4) covers the rest.

The stale-parent fixup replicates `git-subrepo`'s own documented recovery
formula: the last commit that touched the `.gitrepo` `commit =` line,
walked back one parent. Verified against the real installed tool: this is
the exact SHA git-subrepo's own error message suggests, and because it's
derived from `git log` starting at HEAD, it's an ancestor of HEAD by
construction — not a probabilistic check.

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

Replace `xtask/src/pull_subrepo.rs`'s body (keep the doc comment and
`Outcome` enum from Task 2, add to the imports):

```rust
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};

use crate::git_util::run_git;

// ... (Outcome enum from Task 2 stays) ...

pub fn run(repo_root: &Path, subdir: &str, tag: &str) -> Result<Outcome> {
    ensure_clean_tree(repo_root)?;

    let first = attempt_pull(repo_root, subdir, tag)?;
    if first.status.success() {
        run_git(repo_root, &["subrepo", "clean", subdir]).ok();
        return Ok(Outcome::Clean);
    }

    let stderr = String::from_utf8_lossy(&first.stderr);
    if stderr.contains("is not an ancestor") {
        fix_stale_parent(repo_root, subdir)?;
        let second = attempt_pull(repo_root, subdir, tag)?;
        if second.status.success() {
            run_git(repo_root, &["subrepo", "clean", subdir]).ok();
            return Ok(Outcome::Clean);
        }
        return handle_conflict(repo_root, subdir, tag, &second);
    }

    handle_conflict(repo_root, subdir, tag, &first)
}

fn ensure_clean_tree(repo_root: &Path) -> Result<()> {
    let status = run_git(repo_root, &["status", "--porcelain"])?;
    if !status.is_empty() {
        bail!("working tree is dirty; `git subrepo pull` refuses to run against a dirty tree:\n{status}");
    }
    Ok(())
}

/// Runs `git subrepo pull`, first defensively cleaning any worktree/branch
/// left over from a previous attempt. A leftover `subrepo/<subdir>`
/// worktree/branch (left behind by ANY prior pull attempt — successful,
/// conflicted, or interrupted) makes the next `git subrepo pull` fail
/// immediately with "There is already a worktree with branch
/// subrepo/<subdir>", masking the real outcome of this attempt.
/// `git subrepo clean` is a safe no-op when there's nothing to clean, so
/// this is unconditional.
fn attempt_pull(repo_root: &Path, subdir: &str, tag: &str) -> Result<Output> {
    run_git(repo_root, &["subrepo", "clean", subdir]).ok();
    Command::new("git")
        .args(["subrepo", "pull", subdir, "-b", tag])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to run `git subrepo pull {subdir} -b {tag}`"))
}

/// Replicates git-subrepo's own recovery formula for a squash-merge-stale
/// `.gitrepo` `parent` (its own error message suggests exactly this SHA):
/// the last commit that touched the `.gitrepo` file's `commit =` line,
/// walked back one parent. This candidate is always an ancestor of HEAD by
/// construction (it comes from `git log` starting at HEAD). The check
/// below is still a real, always-on `bail!` rather than a `debug_assert!`
/// despite that guarantee: it's the sole guard immediately before an
/// irreversible committed write in unattended CI, where a silently
/// compiled-away check (debug_assert! is a no-op in release builds) is the
/// wrong trade — a crash-in-dev-loop benefit isn't worth a possible
/// silent-corruption path in production.
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
             this should never happen (the last-sync-commit formula guarantees it by \
             construction); something is deeply wrong with this repo's history"
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

fn handle_conflict(_repo_root: &Path, _subdir: &str, _tag: &str, output: &Output) -> Result<Outcome> {
    bail!(
        "git subrepo pull failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
```

(`handle_conflict` is a placeholder-that-errors-loudly deliberately — Task 4
replaces it with the real allowlist/conflict logic.)

- [ ] **Step 4: Run the three in-scope tests**

Run: `cargo test -p xtask pull_subrepo -- --nocapture`
Expected: `clean_pull_after_squash_merge_auto_fixes_stale_parent`,
`dirty_tree_is_rejected_before_touching_anything`, and
`works_identically_from_a_linked_worktree` PASS. The conflict/allowlist
tests still FAIL (expected — Task 4).

- [ ] **Step 5: Wire the CLI**

Modify `xtask/src/lib.rs`:

- Near `pub mod upstream_v2ray;`, confirm `pub mod pull_subrepo;` and
  `pub mod git_util;` are present.

- In the `Command` enum (after the `ProvisionUpstreamV2ray` variant), add:

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

- In `dispatch` (near the `ProvisionUpstreamV2ray` arm), add:

  ```rust
  Command::PullSubrepo { path, tag } => run_pull_subrepo(path, tag),
  ```

- Near `run_provision_upstream_v2ray`, add:

  ```rust
  pub fn run_pull_subrepo(path: String, tag: String) -> Result<()> {
      let repo_root = repo_root()?;
      match pull_subrepo::run(&repo_root, &path, &tag)? {
          pull_subrepo::Outcome::Clean => {
              println!("xtask: pulled {path} to {tag} cleanly");
              Ok(())
          }
          pull_subrepo::Outcome::Conflicted { worktree, unresolved } => {
              eprintln!(
                  "xtask: {path} pull to {tag} has unresolved conflicts in:\n  {}\n\
                   Resolve them in {}, `git add` the resolved files, `git commit`, \
                   then run `git subrepo commit {path}` from the repo root.",
                  unresolved.join("\n  "),
                  worktree.display()
              );
              // Exit code 2 distinguishes "real conflict, worktree left
              // for resolution" from any other failure (which propagates
              // as exit 1 via the `?` above) — vendor-bump.yaml branches
              // on this instead of misapplying conflict-recovery to e.g.
              // a dirty-tree rejection or a missing git-subrepo install.
              std::process::exit(2);
          }
      }
  }
  ```

  (Add `bail` to the existing `use anyhow::{...}` import at the top of
  `lib.rs` if it isn't already imported there.)

- [ ] **Step 6: Manually exercise the CLI once**

Run: `cargo xtask pull-subrepo --help` to confirm it's wired in.
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

- Produces: the complete `pull_subrepo::run` and `is_auto_resolvable` — nothing further changes their public shape.

- [ ] **Step 1: Confirm the conflict tests still fail against Task 3's placeholder**

Run: `cargo test -p xtask pull_subrepo::allowlisted pull_subrepo::real_conflict pull_subrepo::mixed pull_subrepo::is_auto_resolvable -- --nocapture`
Expected: all FAIL (the placeholder `handle_conflict` just bails; `is_auto_resolvable` is still `unimplemented!`).

- [ ] **Step 2: Implement the real conflict handling**

In `xtask/src/pull_subrepo.rs`, replace the placeholder `handle_conflict`
and add its helpers:

- The merge-conflict text (`"git merge" command failed` + the full
  recovery instructions) is on **stdout**. stderr is 0 bytes on a
  conflict — it's reserved for `error()`-raised failures like the
  stale-parent case Task 3 handles on stderr.
- `git subrepo commit <subdir>` (the finishing command used here, on the
  conflict-resolve path) does **not** update `.gitrepo`'s `branch` field —
  it stays at the pre-pull tag even though `commit` and the tree content
  are the new tag. Only `git subrepo pull -b <tag>` finishing on its own
  (Task 3's clean path) does that. This path fixes it up explicitly — but
  guarded: in the real Renovate-triggered flow, `.gitrepo`'s `branch` is
  *already* the new tag (Renovate wrote it before this tool ever ran), so
  the rewrite is a no-op and must not attempt an empty commit (`git commit` with nothing staged exits 1, verified).
- `checkout --theirs <path>` has no "theirs" blob to check out on a
  delete/modify conflict (upstream deleted the file, downstream modified
  it) — resolving to theirs there means removing the file, not checking
  out content that doesn't exist on that side.

```rust
fn handle_conflict(repo_root: &Path, subdir: &str, tag: &str, pull_output: &Output) -> Result<Outcome> {
    let stdout = String::from_utf8_lossy(&pull_output.stdout);
    if !stdout.contains("\"git merge\" command failed") {
        bail!(
            "git subrepo pull failed in an unexpected way:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&pull_output.stderr)
        );
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
            resolve_to_theirs(&worktree, path)?;
        } else {
            unresolved.push(path.clone());
        }
    }

    if !unresolved.is_empty() {
        return Ok(Outcome::Conflicted { worktree, unresolved });
    }

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
    fixup_branch_field_if_needed(repo_root, subdir, tag)?;
    run_git(repo_root, &["subrepo", "clean", subdir]).ok();
    Ok(Outcome::Clean)
}

/// `checkout --theirs` fails on a delete/modify conflict (no "theirs" blob
/// to check out when upstream deleted the file) — verified this is a real
/// possibility for `.github/workflows/*` in particular (upstream renaming
/// or dropping a workflow file is routine). Stage 3 in the index is
/// "theirs" during a merge conflict; if it's absent, theirs deleted the
/// path, and resolving to theirs means removing it.
fn resolve_to_theirs(worktree: &Path, path: &str) -> Result<()> {
    let staged = run_git(worktree, &["ls-files", "-u", "--", path])?;
    let theirs_present = staged
        .lines()
        .any(|line| line.split_whitespace().nth(2).map(|stage| stage == "3").unwrap_or(false));

    if theirs_present {
        run_git(worktree, &["checkout", "--theirs", "--", path])?;
        run_git(worktree, &["add", "--", path])?;
    } else {
        run_git(worktree, &["rm", "--", path])?;
    }
    Ok(())
}

/// See `handle_conflict`'s doc note: `git subrepo commit` doesn't touch
/// `branch`, so this fixes it up — but only if it's actually stale. In
/// the real Renovate flow it already reads `tag` (Renovate wrote it
/// before this tool ran), so rewriting would be a no-op; committing an
/// empty diff fails (`git commit` with nothing staged exits 1, verified),
/// so this only adds+commits when the content genuinely changes.
fn fixup_branch_field_if_needed(repo_root: &Path, subdir: &str, tag: &str) -> Result<()> {
    let gitrepo_path = repo_root.join(subdir).join(".gitrepo");
    let contents = std::fs::read_to_string(&gitrepo_path)
        .with_context(|| format!("failed to read {}", gitrepo_path.display()))?;
    let updated = replace_gitrepo_field(&contents, "branch", tag)?;
    if updated == contents {
        return Ok(());
    }
    std::fs::write(&gitrepo_path, updated).with_context(|| format!("failed to write {}", gitrepo_path.display()))?;
    run_git(repo_root, &["add", &format!("{subdir}/.gitrepo")])?;
    run_git(
        repo_root,
        &["commit", "-m", &format!("fix: record {subdir} subrepo branch as {tag}")],
    )?;
    Ok(())
}

pub(crate) fn is_auto_resolvable(path: &str) -> bool {
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
Expected: all 11 tests from Task 2 PASS.

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

- Produces: `finish_vendor_bump::{run, run_identity_checks, IdentityCheckOutcome}` — `run(repo_root: &Path, subdir: &str, dep_name: &str, new_tag: &str) -> Result<IdentityCheckOutcome>`, consumed by Task 8's workflow. `run_identity_checks` is `pub(crate)` so it can be unit-tested directly.

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

    finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0").unwrap();

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

#[skuld::test]
fn a_second_call_with_no_changes_does_not_fail_on_an_empty_commit() {
    let dir = init_repo_with_vendoring_md("widget", "v1.0.0");
    finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0").unwrap();

    // Calling it again with the SAME target version: the note is already
    // correct, so nothing gets staged. `git commit` with nothing staged
    // exits 1 (verified) — this must be treated as a no-op success, not
    // an error, or every re-run of an already-finished bump (e.g. the
    // workflow's own harmless re-trigger case) fails on an empty commit.
    let result = finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0");
    assert!(result.is_ok(), "a no-op second call must not fail: {result:?}");
}

#[skuld::test]
fn failing_identity_check_is_reported_not_swallowed() {
    let dir = tempfile::tempdir().unwrap();
    let vendored = dir.path().join("vendored");
    std::fs::create_dir_all(&vendored).unwrap();
    std::fs::write(vendored.join("go.mod"), "module broken\n\ngo 1.25\n").unwrap();
    // Deliberate syntax error — go build must fail.
    std::fs::write(vendored.join("main.go"), "package broken\n\nfunc broken( {\n").unwrap();

    let outcome = finish_vendor_bump::run_identity_checks(dir.path(), "vendored").unwrap();
    match outcome {
        IdentityCheckOutcome::Failed { detail } => {
            assert!(detail.contains("build"), "detail should name the failing step: {detail}");
        }
        IdentityCheckOutcome::Passed => panic!("expected the syntax error to fail go build"),
    }
}

/// Exercises the FULL `run()` sequence end-to-end — including
/// `run_go_mod_tidy_and_commit` (never called by the other tests here),
/// the outer `go.mod` require-line rewrite, and all four identity checks
/// (vendored build+test, ex-ray build+test) succeeding. Two real,
/// self-contained Go modules (no external imports, so `go mod tidy`
/// touches nothing over the network) linked by a `replace` directive,
/// exactly like the real `crates/ex-ray` / vendored-dep pair.
#[skuld::test]
fn run_updates_go_mod_and_commits_the_full_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let vendored = dir.path().join("crates/ex-ray/third_party/widget");
    let ex_ray = dir.path().join("crates/ex-ray");
    let vendoring_dir = dir.path().join("crates/ex-ray/third_party");
    std::fs::create_dir_all(&vendored).unwrap();
    std::fs::create_dir_all(&ex_ray).unwrap();

    std::fs::write(vendored.join("go.mod"), "module example.com/widget\n\ngo 1.25\n").unwrap();
    std::fs::write(vendored.join("main.go"), "package widget\n").unwrap();

    std::fs::write(
        vendoring_dir.join("VENDORING.md"),
        "# Vendoring\n\n## `widget/` — pinned **v1.0.0** ([upstream](https://example.com))\n",
    )
    .unwrap();

    std::fs::write(
        ex_ray.join("go.mod"),
        "module example.com/ex-ray\n\ngo 1.25\n\nrequire example.com/widget v1.0.0\n\nreplace example.com/widget => ../../third_party/widget\n",
    )
    .unwrap();
    std::fs::write(
        ex_ray.join("main.go"),
        "package main\n\nimport _ \"example.com/widget\"\n\nfunc main() {}\n",
    )
    .unwrap();

    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-m", "initial"]);

    let outcome = finish_vendor_bump::run(dir.path(), "crates/ex-ray/third_party/widget", "widget", "v2.0.0").unwrap();
    assert!(matches!(outcome, IdentityCheckOutcome::Passed), "expected the minimal fixture to pass all four identity checks");

    let go_mod = std::fs::read_to_string(ex_ray.join("go.mod")).unwrap();
    assert!(
        go_mod.contains("example.com/widget v2.0.0") && !go_mod.contains("vv2.0.0"),
        "require line should be bumped to exactly v2.0.0, not double-prefixed: {go_mod}"
    );

    let note = std::fs::read_to_string(vendoring_dir.join("VENDORING.md")).unwrap();
    assert!(note.contains("pinned **v2.0.0**"));
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
    run_go_mod_tidy_and_commit(repo_root, subdir, new_tag)?;
    run_identity_checks(repo_root, subdir)
}

/// Split out of `run` so tests can exercise the version-note rewrite
/// without a real Go toolchain / vendored module tree.
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
    commit_if_staged(repo_root, &format!("docs: note {dep_name} {new_tag} in VENDORING.md"))
}

/// Rewrites `crates/ex-ray/go.mod`'s `require` line for `<subdir>`'s Go
/// module to `new_tag`, then `go mod tidy`. The module's `replace`
/// directive means Go itself never touches this version string for a
/// locally-replaced module (there's no remote lookup to trigger a
/// rewrite), so it would otherwise silently keep advertising the old tag.
/// The module path is read from the vendored dep's own `go.mod` `module`
/// line rather than hardcoded, so this works for either vendored dep
/// without a name→path lookup table.
fn run_go_mod_tidy_and_commit(repo_root: &Path, subdir: &str, new_tag: &str) -> Result<()> {
    let module_path = read_module_path(&repo_root.join(subdir).join("go.mod"))?;

    let ex_ray_go_mod = repo_root.join("crates/ex-ray/go.mod");
    let contents = std::fs::read_to_string(&ex_ray_go_mod)
        .with_context(|| format!("failed to read {}", ex_ray_go_mod.display()))?;
    let updated = rewrite_require_version(&contents, &module_path, new_tag)?;
    std::fs::write(&ex_ray_go_mod, updated).with_context(|| format!("failed to write {}", ex_ray_go_mod.display()))?;

    let ex_ray_dir = repo_root.join("crates/ex-ray");
    let status = Command::new("go")
        .args(["mod", "tidy"])
        .current_dir(&ex_ray_dir)
        .status()
        .with_context(|| format!("failed to run `go mod tidy` in {}", ex_ray_dir.display()))?;
    if !status.success() {
        bail!("`go mod tidy` failed in {}", ex_ray_dir.display());
    }

    run_git(repo_root, &["add", "crates/ex-ray/go.mod", "crates/ex-ray/go.sum"])?;
    commit_if_staged(repo_root, &format!("build(ex-ray): bump {module_path} to {new_tag}"))
}

fn read_module_path(go_mod_path: &Path) -> Result<String> {
    let contents = std::fs::read_to_string(go_mod_path)
        .with_context(|| format!("failed to read {}", go_mod_path.display()))?;
    contents
        .lines()
        .find_map(|line| line.strip_prefix("module "))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow::anyhow!("{} has no `module` line", go_mod_path.display()))
}

/// `new_tag` already carries its own `v` prefix (e.g. `v5.53.0` — the
/// literal `.gitrepo`/tag value, never stripped: see the Renovate
/// customManager's lack of `extractVersionTemplate`). go.mod's own syntax
/// separately always has a literal `v` before a require line's version
/// number regardless — `prefix` below matches THAT syntax marker to find
/// the line, then the replacement text supplies `new_tag` (which already
/// has its `v`) directly, without adding a second one.
fn rewrite_require_version(contents: &str, module_path: &str, new_tag: &str) -> Result<String> {
    let prefix = format!("{module_path} v");
    let mut found = false;
    let lines: Vec<String> = contents
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with(&prefix) {
                found = true;
                let indent = &line[..line.len() - trimmed.len()];
                let rest = trimmed
                    .strip_prefix(&prefix)
                    .and_then(|s| s.split_once(char::is_whitespace))
                    .map(|(_, r)| r)
                    .unwrap_or("");
                if rest.is_empty() {
                    format!("{indent}{module_path} {new_tag}")
                } else {
                    format!("{indent}{module_path} {new_tag} {rest}")
                }
            } else {
                line.to_string()
            }
        })
        .collect();
    if !found {
        bail!("`{module_path}` has no versioned require line in this go.mod");
    }
    Ok(lines.join("\n") + "\n")
}

/// `pub(crate)` so a test can exercise a failing identity check directly
/// without needing two full, valid Go module trees — `run` still calls
/// this the same way. Deliberately `./...` on the vendored module itself,
/// not `./transport/...` as VENDORING.md's original manual instructions
/// (written before utls was vendored) named — utls's ECH patch lives at
/// its module root, not under a transport/ dir, so that path doesn't
/// generalize to both deps. `./...` is dep-agnostic and a strict
/// superset. Note: this check is NOT redundant with anything already in
/// `ci.yaml` — checked directly, the only Go test coverage there today is
/// `ex-ray-tests` (`cd crates/ex-ray && go test ./...`), which never runs
/// the vendored module's own test suite; this is genuinely the only place
/// that coverage exists.
pub(crate) fn run_identity_checks(repo_root: &Path, subdir: &str) -> Result<IdentityCheckOutcome> {
    let vendored_dir = repo_root.join(subdir);
    if let Some(detail) = go_command_failure(&vendored_dir, &["build", "./..."])? {
        return Ok(IdentityCheckOutcome::Failed { detail });
    }
    if let Some(detail) = go_command_failure(&vendored_dir, &["test", "./..."])? {
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

/// `git commit` exits 1 with nothing staged — a no-op run (e.g.
/// re-finishing an already-finished bump) must not treat that as a
/// failure.
fn commit_if_staged(repo_root: &Path, message: &str) -> Result<()> {
    let staged = run_git(repo_root, &["diff", "--cached", "--name-only"])?;
    if staged.is_empty() {
        return Ok(());
    }
    run_git(repo_root, &["commit", "-m", message])?;
    Ok(())
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p xtask finish_vendor_bump -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Wire the CLI**

Modify `xtask/src/lib.rs`, mirroring Task 3's Step 5 (Wire the CLI):

- `pub mod finish_vendor_bump;` near the other `pub mod` lines.

- `#[cfg(test)] #[path = "finish_vendor_bump_tests.rs"] mod finish_vendor_bump_tests;` in the test-module block.

- `Command` variant:

  ```rust
  /// Finish a vendor bump after `pull-subrepo` succeeds: update the
  /// VENDORING.md version note, bump + `go mod tidy` the outer module,
  /// run the identity build/test check, and commit each step's own
  /// changes — regardless of whether the identity check passed (a
  /// failure is expected-and-reportable, not a reason to withhold the
  /// commit). The process still exits non-zero on a failed identity
  /// check, after committing, so the failure isn't silently swallowed.
  /// Any earlier failure (e.g. a malformed go.mod, `go mod tidy` itself
  /// failing) propagates as a normal error instead — distinguishable from
  /// an identity-check failure since it comes back as `Err` rather than
  /// `Ok(IdentityCheckOutcome::Failed)`.
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
              // The version note / go.mod bump are already committed by
              // this point (finish_vendor_bump::run commits each of its
              // own steps before returning) — this failure must still
              // turn the process (and so the CI step) red so it isn't
              // silently downgraded to a log line. An earlier failure
              // (malformed go.mod, etc.) would have already propagated as
              // an `Err` via the `?` above instead of reaching this arm.
              bail!("identity checks failed after committing the vendor bump for {dep_name} {tag}:\n{detail}");
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
existing `prek.toml` entry, before the closing `]`). Captures only
`owner/repo` after `github.com/` — not the full URL — because the
`github-tags` datasource looks up `https://api.github.com/repos/<packageName>/tags`
and expects exactly that shape (matches this repo's existing WiX
customManager's same capture pattern). Deliberately **no**
`extractVersionTemplate`: this repo's own existing workflow-version
customManager uses that field to *strip* a leading `v` on write-back
(verified: `.github/workflows/ci.yaml`'s `GSUDO_VERSION: "2.6.1"` is
managed by that exact template pattern, and gerardog/gsudo's real tags are
`v2.6.1` — the `v` is gone after Renovate writes it). Both `.gitrepo`
files need the `v` kept (`branch = v5.52.0`, matching the real git tag
`git subrepo pull -b` needs), so this customManager must not strip it —
letting the datasource's own versioning handle the `v`-prefixed tag
directly is correct and is what's needed here, unlike the WiX/gsudo case:

```json
    {
      "customType": "regex",
      "managerFilePatterns": ["/^crates/ex-ray/third_party/.+/\\.gitrepo$/"],
      "matchStrings": [
        "remote\\s*=\\s*https://github\\.com/(?<packageName>[^/\\s]+/[^/\\s]+)\\n\\tbranch\\s*=\\s*(?<currentValue>\\S+)"
      ],
      "datasourceTemplate": "github-tags"
    }
```

No `packageRules` entry for these deps — unlike round 1 of this plan,
automerge is **not** armed by Renovate for this dependency at all (see
Task 8's "Arm auto-merge" step and the note in Global Constraints on why:
arming it at PR-creation time races with the actual vendor-bump work,
since CI trivially passes on Renovate's branch-only, content-unchanged
commit).

- [ ] **Step 2: Validate the config**

Run: `npx --yes --package renovate -- renovate-config-validator .github/renovate.json`
Expected: `Config validated successfully`. This is a one-off local schema
check, not a dry-run against the real GitHub-tags lookup — it would not
have caught the `packageName`-is-a-URL or `extractVersionTemplate`
write-back bugs earlier rounds of review found. Whether to add a
*permanent* `renovate-config-validator` CI step (so a future
`renovate.json` edit that breaks lookup silently gets a red check instead
of quietly never firing) is an open question for you, not decided here —
flag it when this plan is reviewed.

- [ ] **Step 3: Commit**

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

- Consumes: `cargo xtask pull-subrepo` (Task 4, exit codes 0/2/other), `cargo xtask finish-vendor-bump` (Task 5), `.github/actions/mint-nathan-token` (Task 7).

- [ ] **Step 1: Write the workflow**

Fixes verified or reasoned through below, none assumed:

- **Self-retrigger**: this workflow's own successful push matches its own
  `push`+`paths` trigger (App-token pushes aren't exempt from
  retriggering — that's the whole point of using one). The job-level
  `if:` guard checks the pushing commit's author name against exactly
  what the "git identity" step sets later in this same file.
- **Conflict vs. other failure**: the Pull step captures
  `cargo xtask pull-subrepo`'s actual exit code (0 clean / 2 real conflict
  per Task 4's `std::process::exit(2)` / anything else a genuine
  unexpected failure) instead of GitHub Actions' coarse step outcome, so
  only a real conflict routes into conflict recovery.
- **Branch-synchronization**: Renovate can force-push this same branch at
  any point (its default `rebaseWhen: auto` rebases open PRs whenever
  `main` moves) — including while this job is mid-run. Diffing against
  `github.event.before` (which may reference a commit no longer reachable
  from any ref after a force-push) is fragile; diffing against `origin/main`'s
  merge-base instead only depends on this run's own fetched history and
  stays correct regardless of how many times the branch was rewritten.
  `cancel-in-progress: true` additionally means a fresh push preempts an
  in-flight run whose work is about to be superseded anyway, rather than
  letting it finish and then queuing a redundant second run; the final
  `git push` stays a plain (non-force) push, so if a race still slips
  through despite this, it fails loudly (rejected push) instead of
  silently overwriting Renovate's newer intent.
- **Auto-merge timing**: arming GitHub-native auto-merge is done by this
  workflow itself, via `gh pr merge --auto`, only after a clean pull *and*
  a successful finish — never by Renovate at PR-creation time (see Global
  Constraints for why that races).
- **`workflow_dispatch` safety**: a manual run executes against whatever
  ref was selected when triggering it, which defaults to `main` if the
  caller doesn't pass `--ref` — never push straight to main. Manual runs
  always get a disposable scratch branch instead.
- **Empty `gh pr list` results**: `--jq '.[0].number // empty'` (not
  `.[0].number` alone) so a branch with no open PR yields an empty string,
  not the literal text `null` fed into a following command.

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
  cancel-in-progress: true

jobs:
  bump:
    name: Pull + rebase vendored dependency
    runs-on: ubuntu-latest
    timeout-minutes: 30
    # Self-retrigger guard — see Step 1's intro above the code block.
    if: github.event_name != 'push' || github.event.head_commit.author.name != 'nathan-blahaj[bot]'
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

      - name: Ensure origin/main is available
        run: git fetch origin main --quiet

      - uses: dtolnay/rust-toolchain@stable
      - uses: actions/setup-go@v7
        with:
          go-version: stable

      # git-subrepo isn't part of the ubuntu-latest image or any
      # apt/npm/go package — it's a bash-script tool installed by cloning
      # it and putting its lib/ dir (containing an executable named
      # `git-subrepo`) on PATH, exactly how `git <subcommand>` dispatch
      # finds any git-<name> executable on PATH. Pinned to 0.4.9 to match
      # the version this workflow's fixup logic targets — confirm this tag
      # exists on first real run.
      - name: Install git-subrepo 0.4.9
        run: |
          git clone --branch 0.4.9 --depth 1 https://github.com/ingydotnet/git-subrepo /opt/git-subrepo
          echo "/opt/git-subrepo/lib" >> "$GITHUB_PATH"

      - name: Determine dep + tag
        id: target
        env:
          INPUT_DEP: ${{ inputs.dep }}
          INPUT_TAG: ${{ inputs.tag }}
        run: |
          if [[ -n "$INPUT_DEP" ]]; then
            dep="$INPUT_DEP"
            tag="$INPUT_TAG"
          else
            # Diffing against origin/main's merge-base (not
            # github.event.before/after) survives Renovate force-pushing
            # this branch at any point — it only depends on this run's own
            # fetched history, not on a possibly-now-unreachable SHA from
            # the triggering event.
            changed=$(git diff --name-only origin/main...HEAD -- 'crates/ex-ray/third_party/*/.gitrepo')
            if [[ -z "$changed" ]]; then
              count=0
            else
              count=$(printf '%s\n' "$changed" | wc -l)
            fi
            if [[ "$count" -ne 1 ]]; then
              echo "::error::expected exactly one changed .gitrepo relative to main, got $count: $changed"
              exit 1
            fi
            dep=$(basename "$(dirname "$changed")")
            tag=$(sed -n 's/^\tbranch = //p' "$changed")
          fi

          # Inputs are used in shell commands and a branch name below —
          # validate before use rather than trusting workflow_dispatch
          # input or .gitrepo content verbatim.
          if ! [[ "$dep" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
            echo "::error::invalid dep name: $dep"
            exit 1
          fi
          if ! [[ "$tag" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
            echo "::error::invalid tag: $tag"
            exit 1
          fi

          echo "dep=$dep" >> "$GITHUB_OUTPUT"
          echo "tag=$tag" >> "$GITHUB_OUTPUT"
          echo "path=crates/ex-ray/third_party/$dep" >> "$GITHUB_OUTPUT"

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
        run: |
          set +e
          cargo xtask pull-subrepo "${{ steps.target.outputs.path }}" "${{ steps.target.outputs.tag }}"
          code=$?
          set -e
          if [[ "$code" -eq 0 ]]; then
            echo "result=clean" >> "$GITHUB_OUTPUT"
          elif [[ "$code" -eq 2 ]]; then
            echo "result=conflicted" >> "$GITHUB_OUTPUT"
          else
            exit "$code"
          fi

      - name: Finish (version note, go.mod, identity checks)
        id: finish
        if: steps.pull.outputs.result == 'clean'
        continue-on-error: true
        run: cargo xtask finish-vendor-bump "${{ steps.target.outputs.path }}" "${{ steps.target.outputs.dep }}" "${{ steps.target.outputs.tag }}"

      - name: Commit the conflicted tree anyway (CI-only policy — see VENDORING.md)
        if: steps.pull.outputs.result == 'conflicted'
        run: |
          worktree="$(git rev-parse --git-common-dir)/tmp/subrepo/${{ steps.target.outputs.path }}"
          git -C "$worktree" add -A
          PREK_ALLOW_NO_CONFIG=1 git -C "$worktree" commit -m "vendor: conflicted pull of ${{ steps.target.outputs.dep }} ${{ steps.target.outputs.tag }} — needs manual resolution"
          git subrepo commit "${{ steps.target.outputs.path }}"

      - name: Push
        if: steps.pull.outputs.result == 'clean' || steps.pull.outputs.result == 'conflicted'
        run: git push origin "HEAD:${{ steps.scratch-branch.outputs.ref_name || github.ref_name }}"

      # Only for the real Renovate-triggered flow — a workflow_dispatch
      # scratch-branch run has no associated PR.
      - name: Find the PR for this branch
        if: github.event_name == 'push' && (steps.pull.outputs.result == 'clean' || steps.pull.outputs.result == 'conflicted')
        id: find-pr
        env:
          GH_TOKEN: ${{ steps.nathan.outputs.token }}
        run: |
          pr_number=$(gh pr list --repo "${{ github.repository }}" --head "${{ github.ref_name }}" --json number --jq '.[0].number // empty')
          echo "pr_number=$pr_number" >> "$GITHUB_OUTPUT"

      # Only arms auto-merge once the real work has landed: a clean pull
      # AND a successful finish. This is the sole point anything arms
      # auto-merge — Renovate itself never does (see Global Constraints).
      - name: Arm auto-merge
        if: steps.pull.outputs.result == 'clean' && steps.finish.outcome == 'success' && steps.find-pr.outputs.pr_number != ''
        env:
          GH_TOKEN: ${{ steps.nathan.outputs.token }}
        run: gh pr merge --auto --squash "${{ steps.find-pr.outputs.pr_number }}" --repo "${{ github.repository }}"

      - name: Comment on the PR if conflicted
        if: steps.pull.outputs.result == 'conflicted' && steps.find-pr.outputs.pr_number != ''
        env:
          GH_TOKEN: ${{ steps.nathan.outputs.token }}
        run: |
          gh pr comment "${{ steps.find-pr.outputs.pr_number }}" --repo "${{ github.repository }}" --body "$(cat <<EOF
          Automated pull of \`${{ steps.target.outputs.dep }}\` to \`${{ steps.target.outputs.tag }}\` hit a real merge conflict outside the auto-resolved allowlist (go.mod/go.sum/.github/workflows). The conflicted tree is committed on this branch.

          To resolve: check out this PR branch, fix the conflicts, then run \`cargo xtask finish-vendor-bump crates/ex-ray/third_party/${{ steps.target.outputs.dep }} ${{ steps.target.outputs.dep }} ${{ steps.target.outputs.tag }}\` and push a normal commit.
          EOF
          )"

      - name: Fail the job if Finish failed
        if: steps.finish.outcome == 'failure'
        run: |
          echo "::error::the 'Finish' step failed — see its log above for the reason (an identity-check failure, or an earlier error like a malformed go.mod/VENDORING.md heading). Any commits it made before failing were still pushed."
          exit 1
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

(Note this workflow's own trigger is `paths: [wix-toolchain.toml]`, and its own
commits never touch that file's *content* in a way that would re-match
after the fact — the `git diff --quiet && exit 0` guard already makes a
second run of this specific workflow a no-op, so it doesn't need the same
self-retrigger guard `vendor-bump.yaml` needs.)

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

This is automated: Renovate opens a PR bumping just the `branch =` line in
a `.gitrepo`, and `.github/workflows/vendor-bump.yaml` does the rest —
`cargo xtask pull-subrepo` followed by `cargo xtask finish-vendor-bump` —
pushing further commits to the same PR, then arming auto-merge itself once
that succeeds. It merges automatically if the pull is clean and CI is
green; it sits open with a PR comment if a real merge conflict landed
outside the auto-resolved `go.mod`/`go.sum`/`.github/workflows/*` allowlist
(the authoritative policy lives in `xtask/src/pull_subrepo.rs`'s
`is_auto_resolvable`).

`pull-subrepo`'s "nothing committed" guarantee on a real conflict is about
the pull attempt itself, not the whole run: if the routine squash-merge
parent fixup ran first (see below), that's a separate, independently valid
commit that stays even if the pull then hits a real conflict.

To do it by hand (same tools the automation uses):

1. `cargo xtask pull-subrepo crates/ex-ray/third_party/<name> <new-tag>`.
   On a real conflict it stops uncommitted, exactly like `git pull`, and
   prints the temp worktree to resolve it in — `cd` there, fix the
   conflicts (`git status` to see them), `git add`, `git commit`, then
   `git subrepo commit crates/ex-ray/third_party/<name>` from the repo
   root.
2. `cargo xtask finish-vendor-bump crates/ex-ray/third_party/<name> <name> <new-tag>`
   — updates this file's version note, bumps the outer `go.mod` require
   line and runs `go mod tidy`, and runs the identity build/test check
   (`go build ./...` and `go test ./...`, both in the vendored module and
   in `crates/ex-ray`), committing regardless of whether the identity
   check passed. The vendored-module test is the *only* place that code's
   own test suite runs in this project — `ci.yaml`'s `ex-ray-tests` job
   never runs it directly, only `crates/ex-ray`'s own tests (which
   exercise the vendored code transitively, not its own internal tests).
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
token, the `git-subrepo` install, the checkout, and
`cargo xtask pull-subrepo`'s already-up-to-date short-circuit all work
end-to-end without mutating anything real. This runs on a disposable
`vendor-bump-manual/...` scratch branch the workflow creates itself —
never against whatever ref the run was dispatched on — delete that branch
afterward, it has no PR attached.)

Watch the run via `gh run watch`. Expected: the Pull step's `result`
output is `clean` (git-subrepo's own "already up to date" short-circuit,
exit 0) and the job finishes without pushing a new commit (nothing was
staged, so `finish-vendor-bump`'s commits are no-ops per Task 5's
`commit_if_staged` guard). No PR exists for the scratch branch, so "Find
the PR" / "Arm auto-merge" naturally no-op too.

- [ ] **Step 5: Confirm a real bump reaches auto-merge or a correctly-red PR, and does NOT self-retrigger**

Wait for (or manually trigger against) an actual newer tag — e.g. if
v2ray-core has since cut a release past `v5.52.0`:

```bash
gh workflow run vendor-bump.yaml --repo bindreams/hole -f dep=v2ray-core -f tag=<next tag>
```

Watch: does CI (`ci.yaml`) actually rerun on the pushed commit (confirming
the App-token retrigger works), does the PR either auto-merge (confirm via
`gh pr view` that auto-merge was armed and it eventually merged, not that
it merged suspiciously early on Renovate's original branch-only commit) or
sit correctly red/commented, and — check the Actions run list for this
branch — does `vendor-bump.yaml` run exactly once (not loop on its own
push, confirming the job-level actor guard works)? This is the property
the whole design rests on — confirm it live before considering #787 done.

- [ ] **Step 6: Confirm `wix-hash-fixup.yaml` still works**

Wait for (or note for later) the next Renovate WiX-toolchain version bump
PR, and confirm its fixup commit now gets a fresh CI run and can
auto-merge — previously suspected broken (Task 9's fix target).
