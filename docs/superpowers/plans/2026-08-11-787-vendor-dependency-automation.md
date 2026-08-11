# Automated vendored-dependency bumps (#787) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automate bumping the two git-subrepo-vendored deps
(`crates/ex-ray/third_party/{v2ray-core,utls}`) to new upstream tags,
rebasing the local ECH patches through `git subrepo pull`, and landing the
result as a PR that merges automatically when clean+green or sits open/red
when a real conflict or CI failure blocks it — with no self-hosted server.

**Architecture:** Renovate (hosted GitHub App) bumps only the `branch =`
line in each `.gitrepo` via a `customManager` and opens its normal PR,
explicitly excluded from this repo's existing unscoped "major updates"
automerge rule. A `vendor-bump.yaml` workflow, authenticated as a
purpose-built GitHub App (`nathan-blahaj`, not the default `GITHUB_TOKEN`,
so its pushes actually retrigger CI), runs `cargo xtask pull-subrepo` (a
generic, human-usable wrapper around `git subrepo pull` that fixes the
routine squash-merge parent-staleness automatically and behaves like
`git pull` on a real conflict — stops, uncommitted) followed by
`cargo xtask finish-vendor-bump` (version note + `go.mod` + the identity
check `ci.yaml`'s "Test ex-ray (Go)" job itself runs), pushes, and arms
GitHub-native auto-merge itself via `gh pr merge --auto` — both
opportunistically right after a clean push, and via a second, lightweight
job that fires whenever Renovate's own (rate-limited, sometimes delayed)
PR-creation call finally happens. "Test ex-ray (Go)" is added to the
repo's required-status-checks ruleset as one-time manual setup, so
auto-merge cannot fire without the one check that actually validates the
vendored code. The same App fixes the identical latent bug in
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
  the documented-safe allowlist (`.github/workflows/*` unconditionally;
  `go.mod`/`go.sum` only when doing so provably doesn't drop a downstream-only
  `replace` directive) to upstream's version; anything else conflicting
  stops the tool with nothing committed on the pull attempt itself, exactly
  like `git pull` (a prior, independent `.gitrepo`-parent-realignment
  commit may already be on the branch when this happens — see Task 4).
- The CI-only "commit despite conflicts" behavior is a **separate** xtask
  command (`force-commit-conflicted-subrepo`), not a flag on `pull-subrepo`
  — the tool that resolves conflicts never commits one, full stop, but the
  workflow needs a testable, non-bash-reimplemented way to do the CI-only
  thing.
- Renovate never arms auto-merge for these PRs itself — this repo's
  existing `packageRules` already has an unscoped `"matchUpdateTypes": ["major"], "automerge": true` rule that would otherwise also match a
  major `.gitrepo` bump, so Task 6 adds
  an explicit, later-in-array override. `vendor-bump.yaml` is the sole
  arming point, and only after a clean pull *and* a successful finish.
- `nathan-blahaj` is the generic bot identity name (not vendor-specific) —
  reused for `wix-hash-fixup.yaml` too. Secrets: `NATHAN_APP_ID`,
  `NATHAN_APP_PRIVATE_KEY`.
- `vendor-bump.yaml`'s main job must never act on its own pushes (it would
  otherwise retrigger itself) and must never treat a non-conflict failure
  (dirty tree, missing `git-subrepo`, bad input) as if it were a real
  merge conflict. `cancel-in-progress` stays `false`: combined with the
  self-retrigger guard, a `true` value creates a race where the workflow's
  own push cancels itself before it can arm auto-merge (GitHub evaluates
  concurrency before the job-level `if:` guard) — a plain, non-force
  `git push` failing loudly on an actual Renovate force-push mid-run is
  the correct, safe fallback instead.
- "Test ex-ray (Go)" (the only CI job that exercises the vendored code's
  own tests) is not currently a required status check on `main`'s ruleset
  — added as one-time manual setup (Task 1), since without it auto-merge
  could fire on a vendor bump that breaks the ECH gate/patches with no
  check catching it.
- Design doc: `docs/superpowers/specs/2026-08-10-787-vendor-dependency-automation.md`.

______________________________________________________________________

## File Structure

| File                                            | Responsibility                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `xtask/src/git_util.rs`                         | Shared `run_git` helper (shell out, check status, return trimmed stdout) used by `pull_subrepo.rs` and `finish_vendor_bump.rs`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `xtask/src/pull_subrepo.rs`                     | Generic `git subrepo pull` wrapper: dirty-tree guard, defensive leftover-worktree cleanup before every attempt, automatic squash-merge parent fixup, allowlist conflict auto-resolution (handling delete/modify conflicts and preserving downstream-only `go.mod` `replace` directives, not blindly overwriting), the `.gitrepo` `branch`-field fixup that path needs (applied on both the resolved-clean and the still-conflicted path), `git-pull`-like stop on real conflicts. Also `force_commit_conflicted`, a separate function (not reachable from `run`) backing the CI-only policy. No Renovate/CI awareness in `run` itself. |
| `xtask/src/pull_subrepo_tests.rs`               | Fixture-repo integration tests proving the above against a real installed `git subrepo`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `xtask/src/finish_vendor_bump.rs`               | The separate, smaller VENDORING.md "step 3" work: version note, outer `go.mod` require-version bump + `go mod tidy`, the identity check matching `build.yaml`'s `ex-ray-tests` target exactly. Commits are guarded against "nothing to commit" and scoped to only the paths each step itself staged.                                                                                                                                                                                                                                                                                                                                   |
| `xtask/src/finish_vendor_bump_tests.rs`         | Tests for the above, including the full `run()` sequence end-to-end and a failing identity check.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `xtask/src/lib.rs`                              | Modify: three new `Command` variants + dispatch wrappers + module/test-module declarations.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `.github/renovate.json`                         | Modify: `customManager` tracking each `.gitrepo`'s `branch` line (capturing `owner/repo`, not a full URL; no `extractVersionTemplate`). New `packageRules` entry explicitly disabling automerge for these deps, placed after the existing unscoped major-updates automerge rule so it correctly overrides it.                                                                                                                                                                                                                                                                                                                          |
| `.github/actions/mint-nathan-token/action.yaml` | Composite action minting a `nathan-blahaj` installation token from App ID + private key inputs. Shared by both workflows below.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `.github/workflows/vendor-bump.yaml`            | New workflow, two jobs: `bump` (push/workflow_dispatch-triggered — does the real work, pushes, opportunistically arms auto-merge) and `arm-on-pr-open` (pull_request-triggered — a lightweight catch-up that arms auto-merge once Renovate's own, sometimes-delayed, PR-creation call happens).                                                                                                                                                                                                                                                                                                                                        |
| `.github/workflows/ci.yaml`                     | Modify: `test-tooling` job (which runs `xtask`'s own tests) gets a `git-subrepo` install step, matching what the new fixture tests need.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `.github/workflows/wix-hash-fixup.yaml`         | Modify: swap `GITHUB_TOKEN` for `nathan-blahaj`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `crates/ex-ray/third_party/VENDORING.md`        | Modify: document the new tooling, the CI-only conflict-commit policy, and the identity check (matching `build.yaml`'s real `ex-ray-tests` scope, not a broader claim).                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

______________________________________________________________________

### Task 1: One-time manual setup — GitHub App + required status check

This task cannot be automated or delegated to a subagent — it's interactive
browser/GitHub-UI setup, performed by the repo owner. Included here so
nothing is silently skipped and later tasks can assume it's done.

**Files:** none (GitHub UI + repo secrets + branch ruleset)

- [ ] **Step 1: Create the `nathan-blahaj` App**

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

- [ ] **Step 5: Add "Test ex-ray (Go)" as a required status check**

In `bindreams/hole` → Settings → Rules → Rulesets → "Default Branch", edit
the `required_status_checks` rule and add `Test ex-ray (Go)` (the exact
context name of `ci.yaml`'s `test-ex-ray` job) to the list. This is the
*only* CI job that exercises the vendored/patched Go code at all — without
it in the required list, `gh pr merge --auto` can fire on a vendor bump
that silently breaks the ECH fail-closed gate or the ECH-retry patches,
since every other required check builds crates that never touch the
vendored Go module.

- [ ] **Step 6: Confirm**

Reply here (or note in the tracking issue) once done — later tasks that
touch `vendor-bump.yaml`/`wix-hash-fixup.yaml` assume the secrets exist,
and Task 11's live verification assumes the required-check change is live.

______________________________________________________________________

### Task 2: Fixture-repo test harness proving `git subrepo pull`'s real behavior

This is the spike the design doc calls out: prove — against the *actually
installed* `git-subrepo` 0.4.9, not assumptions — that the squash-merge
parent-staleness fixup reliably recovers, that a real conflict leaves the
tree exactly as `git pull` would, that a mixed conflict resolves only its
allowlisted part, that a `go.mod` conflict never silently drops a
downstream-only `replace` directive, and that the tool recovers from a
leftover worktree a prior run left behind. All in both a plain checkout
and a linked worktree where relevant.

**A note on how the fixture differs from the design's original assumption**
(a single clone-on-a-branch, patch, squash-merge, delete-branch cycle does
**not** naturally produce a stale `.gitrepo` `parent` — the recorded parent
is the commit that existed before the feature branch forked, which stays a
valid ancestor of `main` across a squash merge; real staleness comes from a
longer, harder-to-reproduce real history — `crates/ex-ray/third_party/utls/.gitrepo`'s
current `parent` is not an ancestor of this repo's HEAD today). The fixture
instead constructs staleness directly — rewrites `.gitrepo`'s `parent` to a
commit that exists but isn't reachable from HEAD — which is what actually
matters: proving the *fixup mechanism* recovers correctly.

**Files:**

- Create: `xtask/src/pull_subrepo_tests.rs`
- Create: `xtask/src/pull_subrepo.rs` (stub for now — enough for the test
  file to compile against the real public shape)

**Interfaces:**

- Produces: `pull_subrepo::Outcome` (`Clean` / `Conflicted { worktree: PathBuf, unresolved: Vec<String> }`), `pull_subrepo::run(repo_root: &Path, subdir: &str, tag: &str) -> anyhow::Result<Outcome>`, `pull_subrepo::force_commit_conflicted(repo_root: &Path, subdir: &str, tag: &str) -> anyhow::Result<()>`, and `pub(crate) fn is_auto_resolvable(path: &str) -> bool`.

- [ ] **Step 1: Write the stub module**

`xtask/src/pull_subrepo.rs`:

```rust
//! `cargo xtask pull-subrepo <path> <tag>` — a thin, honest wrapper around
//! `git subrepo pull` that fixes the one squash-merge gotcha this repo
//! hits on every pull (see crates/ex-ray/third_party/VENDORING.md) and
//! otherwise behaves exactly like `git pull`: a real conflict stops here,
//! uncommitted, for a human to resolve. No Renovate/CI awareness — the
//! caller decides `tag`, and the "commit anyway despite conflicts"
//! CI-only policy is `force_commit_conflicted`, a separate function `run`
//! never calls.

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

pub fn force_commit_conflicted(_repo_root: &Path, _subdir: &str, _tag: &str) -> Result<()> {
    unimplemented!("Task 4")
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
/// downstream patch also touches.
enum ConflictKind {
    /// v2 changes only `other.txt`, which nothing downstream touches — a
    /// genuinely clean pull.
    None,
    /// v2 rewrites `go.mod`/`go.sum` (no downstream-only `replace` line
    /// involved), which our downstream commit also edits — exercises the
    /// documented "resolve to theirs" allowlist.
    Allowlisted,
    /// v2 rewrites `go.mod`, but our downstream version carries a
    /// `replace` line theirs doesn't — resolving to theirs would silently
    /// drop it. Must NOT auto-resolve.
    AllowlistedWithReplace,
    /// v2 DELETES `go.sum` entirely while our downstream commit still has
    /// local edits to it — a delete/modify conflict.
    AllowlistedDelete,
    /// v2 rewrites `patched.txt`, which our local ECH-style patch also
    /// edits — a real conflict outside the allowlist.
    Real,
    /// v2 rewrites BOTH `go.mod` (allowlisted) and `patched.txt` (real).
    Mixed,
    /// v2 rewrites both `patched.txt` and a second file, `also_patched.txt`
    /// — two real conflicts in the same pull.
    TwoReal,
}

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
        std::fs::write(upstream.join("also_patched.txt"), "upstream other line\n").unwrap();
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
            ConflictKind::Allowlisted | ConflictKind::AllowlistedWithReplace => {
                std::fs::write(
                    upstream.join("go.mod"),
                    "module fixture\n\ngo 1.26\n\nrequire upstream/newdep v1.0.0\n",
                )
                .unwrap();
                std::fs::write(upstream.join("go.sum"), "fixture v2.0.0 h1:xyz=\n").unwrap();
            }
            ConflictKind::AllowlistedDelete => {
                std::fs::remove_file(upstream.join("go.sum")).unwrap();
                git(&upstream, &["add", "-A"]);
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
            ConflictKind::TwoReal => {
                std::fs::write(upstream.join("patched.txt"), "upstream line one CHANGED\n").unwrap();
                std::fs::write(upstream.join("also_patched.txt"), "upstream other line CHANGED\n").unwrap();
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
        std::fs::write(downstream.join("vendor/also_patched.txt"), "upstream other line\nour other local patch\n").unwrap();

        let go_mod_content = if matches!(conflict, ConflictKind::AllowlistedWithReplace) {
            "module fixture\n\ngo 1.25\n\nrequire ourdownstream/patchdep v1.0.0\n\nreplace ourdownstream/loadbearing => ../loadbearing\n"
        } else {
            "module fixture\n\ngo 1.25\n\nrequire ourdownstream/patchdep v1.0.0\n"
        };
        std::fs::write(downstream.join("vendor/go.mod"), go_mod_content).unwrap();
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
fn clean_pull_on_the_very_first_attempt_from_a_plain_checkout() {
    // The most common real-world case (no staleness, no dirty tree, no
    // worktree) has no other direct test — every other ConflictKind::None
    // test also corrupts the parent or dirties the tree first.
    let fx = Fixture::build(ConflictKind::None);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("pull should succeed");
    assert!(matches!(outcome, Outcome::Clean));
}

#[skuld::test]
fn clean_pull_after_squash_merge_auto_fixes_stale_parent() {
    let fx = Fixture::build(ConflictKind::None);
    fx.corrupt_parent();

    // Sanity check: this reproduces the exact stale-parent failure the
    // fixup exists to recover from (stdout/stderr distinction is
    // documented in pull_subrepo.rs's handle_conflict).
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
fn allowlisted_go_mod_conflict_declines_when_a_downstream_replace_would_be_lost() {
    // Blindly `checkout --theirs go.mod` takes the WHOLE file from
    // upstream, discarding any of our own load-bearing lines regardless
    // of where the actual conflicting hunk was — e.g. v2ray-core's real
    // go.mod carries a downstream-only `replace .../utls => ../utls` that
    // upstream never has. This must NOT be silently dropped.
    let fx = Fixture::build(ConflictKind::AllowlistedWithReplace);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { unresolved, .. } => {
            assert_eq!(unresolved, vec!["go.mod".to_string()], "go.mod must be treated as unresolved when a downstream replace would be lost");
        }
        Outcome::Clean => panic!("expected go.mod to be left for a human, not silently resolved"),
    }
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
    // The other worktree tests below only cover outcomes that end Clean.
    // This is the only test that inspects Outcome::Conflicted's
    // `worktree` field and asserts nothing was committed — needs to run
    // from a linked worktree too.
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
fn two_real_conflicts_are_both_reported() {
    let fx = Fixture::build(ConflictKind::TwoReal);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { mut unresolved, .. } => {
            unresolved.sort();
            assert_eq!(unresolved, vec!["also_patched.txt".to_string(), "patched.txt".to_string()]);
        }
        Outcome::Clean => panic!("expected both files to conflict"),
    }
}

#[skuld::test]
fn refuses_to_run_when_a_conflict_resolution_is_already_in_progress() {
    let fx = Fixture::build(ConflictKind::Real);

    let first = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("first conflicted run should report Conflicted, not Err");
    assert!(matches!(first, Outcome::Conflicted { .. }));

    // Simulate the human being mid-resolution: the worktree pull_subrepo::run
    // left behind still has unmerged patched.txt in it. Running again
    // without cleaning up first must refuse, not silently `git subrepo
    // clean` it out from under them — `git subrepo clean` skips
    // git-subrepo's own working-copy-clean guard, so it would otherwise
    // delete their in-progress resolution with no confirmation.
    let result = pull_subrepo::run(&fx.downstream, "vendor", "v2");
    assert!(result.is_err(), "must refuse rather than silently discard an in-progress resolution");

    // The conflict markers must still be there — proving nothing got wiped.
    let worktree = fx.dir.path().join("downstream/.git/tmp/subrepo/vendor");
    let patched = std::fs::read_to_string(worktree.join("patched.txt")).unwrap();
    assert!(patched.contains("<<<<<<<"), "the in-progress resolution's conflict markers must survive: {patched}");
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
    // Exercises the git_common_dir / temp-worktree-location code inside
    // handle_conflict — the part of pull_subrepo that's actually
    // worktree-position sensitive.
    let fx = Fixture::build(ConflictKind::Allowlisted);
    let worktree_path = fx.dir.path().join("downstream-worktree");
    git(&fx.downstream, &["worktree", "add", worktree_path.to_str().unwrap()]);

    let outcome = pull_subrepo::run(&worktree_path, "vendor", "v2").expect("conflict resolution should succeed from a linked worktree");
    assert!(matches!(outcome, Outcome::Clean));

    let go_mod = std::fs::read_to_string(worktree_path.join("vendor/go.mod")).unwrap();
    assert!(go_mod.contains("newdep"));
}

#[skuld::test]
fn force_commit_conflicted_commits_the_conflicted_tree_and_fixes_the_branch_field() {
    let fx = Fixture::build(ConflictKind::Real);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").unwrap();
    assert!(matches!(outcome, Outcome::Conflicted { .. }));

    pull_subrepo::force_commit_conflicted(&fx.downstream, "vendor", "v2").expect("force-commit should succeed even with conflict markers present");

    let gitrepo = std::fs::read_to_string(fx.downstream.join("vendor/.gitrepo")).unwrap();
    assert!(gitrepo.contains("branch = v2"), "branch field must be fixed even on the forced-conflicted-commit path: {gitrepo}");

    let patched = std::fs::read_to_string(fx.downstream.join("vendor/patched.txt")).unwrap();
    assert!(patched.contains("<<<<<<<"), "conflict markers should be literally committed, per the CI-only policy: {patched}");
}

#[skuld::test]
fn force_commit_conflicted_preserves_already_resolved_allowlisted_files() {
    // The real CI path always follows a pull-subrepo call that returned
    // exit code 2, which can leave a worktree mixing already-resolved
    // allowlisted files (go.mod, auto-resolved by handle_conflict before
    // it ever reports Conflicted) with still-conflicted real ones — not
    // just a single conflicted file like the test above.
    let fx = Fixture::build(ConflictKind::Mixed);
    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").unwrap();
    match outcome {
        Outcome::Conflicted { unresolved, .. } => assert_eq!(unresolved, vec!["patched.txt".to_string()]),
        Outcome::Clean => panic!("expected patched.txt to remain conflicted"),
    }

    pull_subrepo::force_commit_conflicted(&fx.downstream, "vendor", "v2").expect("force-commit should succeed on a mixed conflict");

    let go_mod = std::fs::read_to_string(fx.downstream.join("vendor/go.mod")).unwrap();
    assert!(
        go_mod.contains("newdep") && !go_mod.contains("<<<<<<<"),
        "go.mod should already be cleanly resolved to upstream, not committed with markers: {go_mod}"
    );

    let patched = std::fs::read_to_string(fx.downstream.join("vendor/patched.txt")).unwrap();
    assert!(patched.contains("<<<<<<<"), "patched.txt's real conflict markers should be committed literally: {patched}");
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
Expected: `clean_pull_on_the_very_first_attempt_from_a_plain_checkout` panics on `unimplemented!`. The sanity assertions inside `clean_pull_after_squash_merge_auto_fixes_stale_parent` PASS (proving the fixture reproduces the real stale-parent failure), then it panics on `unimplemented!` too. `is_auto_resolvable_covers_the_documented_allowlist` panics on its own `unimplemented!`. If any sanity assertion itself fails, stop and fix the fixture before proceeding — everything downstream depends on it being accurate.

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
`clean_pull_on_the_very_first_attempt_from_a_plain_checkout`,
`clean_pull_after_squash_merge_auto_fixes_stale_parent`,
`dirty_tree_is_rejected_before_touching_anything`, and
`works_identically_from_a_linked_worktree` from Task 2. Conflict handling
(Task 4) covers the rest.

The stale-parent fixup replicates `git-subrepo`'s own documented recovery
formula: the last commit that touched the `.gitrepo` `commit =` line,
walked back one parent — the exact SHA git-subrepo's own error message
suggests. Because it's derived from `git log` starting at HEAD, it's an
ancestor of HEAD by construction.

**Files:**

- Modify: `xtask/src/pull_subrepo.rs` (replace the stub)
- Create: `xtask/src/git_util.rs`

**Interfaces:**

- Consumes: nothing from other tasks.

- Produces: `pull_subrepo::{run, Outcome}` (already declared in Task 2; this task fills in the real logic behind it) and `git_util::run_git`, reused by Task 5.

- [ ] **Step 1: Confirm Task 2's tests still fail the same way (baseline)**

Run: `cargo test -p xtask pull_subrepo::clean_pull -- --nocapture`
Expected: both `clean_pull_*` tests FAIL on `unimplemented!`.

- [ ] **Step 2: Extract a shared `run_git` helper**

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
    ensure_no_in_progress_conflict_resolution(repo_root, subdir)?;

    let first = attempt_pull(repo_root, subdir, tag)?;
    if first.status.success() {
        best_effort_clean(repo_root, subdir);
        return Ok(Outcome::Clean);
    }

    let stderr = String::from_utf8_lossy(&first.stderr);
    if stderr.contains("is not an ancestor") {
        fix_stale_parent(repo_root, subdir)?;
        let second = attempt_pull(repo_root, subdir, tag)?;
        if second.status.success() {
            best_effort_clean(repo_root, subdir);
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

/// `attempt_pull`'s defensive pre-clean (below) would otherwise silently
/// `rm -rf` a worktree a human is actively resolving a real conflict in —
/// `git subrepo clean` is the one git-subrepo subcommand that skips the
/// tool's own working-copy-clean guard, so it deletes an in-progress
/// resolution with no confirmation. Called once at the very start of
/// `run`, before any cleaning happens: refuses if a leftover worktree from
/// a *previous* invocation has real, unfinished content in it (unmerged
/// paths, or anything staged/modified) rather than silently discarding it.
/// A worktree with nothing in `git status --porcelain` is safe to treat as
/// stale-but-harmless and gets cleaned normally by `attempt_pull`.
fn ensure_no_in_progress_conflict_resolution(repo_root: &Path, subdir: &str) -> Result<()> {
    let common_dir = git_common_dir(repo_root)?;
    let worktree = common_dir.join("tmp").join("subrepo").join(subdir);
    if !worktree.exists() {
        return Ok(());
    }
    let status = run_git(&worktree, &["status", "--porcelain"])?;
    if !status.is_empty() {
        bail!(
            "a conflict-resolution worktree already exists at {} with in-progress changes — \
             finish resolving it there, or run `git subrepo clean {subdir}` yourself first \
             to discard it if it's stale",
            worktree.display()
        );
    }
    Ok(())
}

/// Runs `git subrepo pull`, first defensively cleaning any worktree/branch
/// left over from a previous attempt *within this same `run` call* (the
/// stale-parent-fixup retry can follow a first attempt that failed before
/// ever creating a worktree — see `fix_stale_parent`'s doc comment — so
/// this is always safe to call unconditionally here; genuine in-progress
/// human work from a *prior, separate* invocation is what
/// `ensure_no_in_progress_conflict_resolution` above guards, once, before
/// either call). A leftover `subrepo/<subdir>` worktree/branch makes the
/// next `git subrepo pull` fail immediately with "There is already a
/// worktree with branch subrepo/<subdir>", masking the real outcome of
/// this attempt.
fn attempt_pull(repo_root: &Path, subdir: &str, tag: &str) -> Result<Output> {
    best_effort_clean(repo_root, subdir);
    Command::new("git")
        .args(["subrepo", "pull", subdir, "-b", tag])
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("failed to run `git subrepo pull {subdir} -b {tag}`"))
}

/// `git subrepo clean` is a safe no-op when there's nothing to clean. If it
/// fails for a real reason, a debug trace is left so a subsequent
/// "already a worktree" pull failure is correlatable back to it — every
/// call site in this module uses this helper rather than a bare `.ok()`,
/// so none of them silently swallow a genuine clean failure.
fn best_effort_clean(repo_root: &Path, subdir: &str) {
    if let Err(e) = run_git(repo_root, &["subrepo", "clean", subdir]) {
        eprintln!("xtask: debug: `git subrepo clean {subdir}` failed (may be benign): {e}");
    }
}

fn git_common_dir(repo_root: &Path) -> Result<PathBuf> {
    let raw = run_git(repo_root, &["rev-parse", "--git-common-dir"])?;
    let path = PathBuf::from(raw);
    Ok(if path.is_absolute() { path } else { repo_root.join(path) })
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
/// wrong trade.
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

pub fn force_commit_conflicted(_repo_root: &Path, _subdir: &str, _tag: &str) -> Result<()> {
    unimplemented!("Task 4")
}
```

(`handle_conflict` is a placeholder-that-errors-loudly deliberately — Task 4
replaces it with the real allowlist/conflict logic.)

- [ ] **Step 4: Run the three in-scope tests**

Run: `cargo test -p xtask pull_subrepo -- --nocapture`
Expected: `clean_pull_on_the_very_first_attempt_from_a_plain_checkout`,
`clean_pull_after_squash_merge_auto_fixes_stale_parent`,
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

### Task 4: `pull_subrepo` — allowlist conflict auto-resolution, real-conflict stop, and the CI-only force-commit

**Files:**

- Modify: `xtask/src/pull_subrepo.rs` (replace `handle_conflict` and the `force_commit_conflicted` stub)
- Modify: `xtask/Cargo.toml` (add `serde_json` if not already a dependency — needed to parse `go mod edit -json`'s output for the `go.mod` `replace`-directive preservation check; adding a dependency for this is preferable to hand-rolling a go.mod parser)

**Interfaces:**

- Consumes: everything from Task 3 (`run_git`, `Outcome`, `replace_gitrepo_field`).

- Produces: the complete `pull_subrepo::{run, force_commit_conflicted, is_auto_resolvable}` — nothing further changes their public shape.

- [ ] **Step 1: Confirm the conflict tests still fail against Task 3's placeholder**

Run: `cargo test -p xtask pull_subrepo::allowlisted pull_subrepo::real_conflict pull_subrepo::mixed pull_subrepo::two_real pull_subrepo::force_commit pull_subrepo::is_auto_resolvable -- --nocapture`
Expected: all FAIL.

- [ ] **Step 2: Implement the real conflict handling**

In `xtask/src/pull_subrepo.rs`, replace the placeholder `handle_conflict`
and `force_commit_conflicted`, and add their helpers. Facts driving the
implementation below:

- The merge-conflict text (`"git merge" command failed` + the full
  recovery instructions) is on **stdout**. stderr is 0 bytes on a
  conflict — it's reserved for `error()`-raised failures like the
  stale-parent case Task 3 handles on stderr.
- `git subrepo commit <subdir>` (the finishing command used here, on
  *both* the conflict-resolve path and the CI force-commit path) does
  **not** update `.gitrepo`'s `branch` field — it stays at the pre-pull
  tag even though `commit` and the tree content are the new tag. Only
  `git subrepo pull -b <tag>` finishing on its own (Task 3's clean path)
  does that. Both paths here fix it up explicitly, guarded against an
  empty-commit failure (in the real Renovate flow `.gitrepo`'s `branch`
  is already the new tag, since Renovate wrote it before this tool ran,
  so the rewrite is frequently a no-op — `git commit` with nothing staged
  exits 1).
- `checkout --theirs <path>` has no "theirs" blob to check out on a
  delete/modify conflict (upstream deleted the file, downstream modified
  it) — resolving to theirs there means removing the file.
- Blindly `checkout --theirs go.mod` takes the *whole file* from
  upstream, discarding anything downstream-only regardless of where the
  actual conflicting hunk was — including a `replace` directive that has
  nothing to do with the conflict itself. Before resolving `go.mod`,
  checks every `replace` line in *our* version survives in *theirs*; if
  not, declines (treats it as a real, unresolved conflict) rather than
  silently losing it.

```rust
fn handle_conflict(repo_root: &Path, subdir: &str, tag: &str, pull_output: &Output) -> Result<Outcome> {
    let stdout = String::from_utf8_lossy(&pull_output.stdout);
    if !stdout.contains("\"git merge\" command failed") {
        bail!(
            "git subrepo pull failed in an unexpected way:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&pull_output.stderr)
        );
    }

    let worktree = conflict_worktree(repo_root, subdir)?;
    let conflicted = unmerged_paths(&worktree)?;
    let mut unresolved = Vec::new();
    for path in &conflicted {
        if is_auto_resolvable(path) && resolve_to_theirs(&worktree, path)? {
            continue;
        }
        unresolved.push(path.clone());
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
    fixup_branch_field_if_needed(repo_root, subdir, tag)?;
    best_effort_clean(repo_root, subdir);
    Ok(Outcome::Clean)
}

/// The CI-only "commit despite conflicts" policy — deliberately NOT
/// reachable from `run`/`handle_conflict`, so `pull-subrepo` itself never
/// commits a conflicted tree. Kept in Rust (not reimplemented in the
/// calling workflow's YAML/bash) so the worktree-path derivation and
/// branch-field fixup stay the same tested code path as everything else
/// in this module, instead of a second, untested implementation drifting
/// from the first.
pub fn force_commit_conflicted(repo_root: &Path, subdir: &str, tag: &str) -> Result<()> {
    let worktree = conflict_worktree(repo_root, subdir)?;
    run_git(&worktree, &["add", "-A"])?;
    let status = Command::new("git")
        .args(["commit", "-m", &format!("vendor: conflicted pull of {subdir} {tag} — needs manual resolution")])
        .current_dir(&worktree)
        .env("PREK_ALLOW_NO_CONFIG", "1")
        .status()
        .context("failed to run git commit in the subrepo temp worktree")?;
    if !status.success() {
        bail!("git commit failed in the subrepo temp worktree {}", worktree.display());
    }
    run_git(repo_root, &["subrepo", "commit", subdir])?;
    fixup_branch_field_if_needed(repo_root, subdir, tag)?;
    best_effort_clean(repo_root, subdir);
    Ok(())
}

fn conflict_worktree(repo_root: &Path, subdir: &str) -> Result<PathBuf> {
    let common_dir = git_common_dir(repo_root)?;
    let worktree = common_dir.join("tmp").join("subrepo").join(subdir);
    if !worktree.exists() {
        bail!(
            "no conflicted subrepo temp worktree found at {} — its internal layout may have \
             changed since git-subrepo 0.4.9, or there's nothing to commit",
            worktree.display()
        );
    }
    Ok(worktree)
}

/// Resolves a conflicted path to upstream's ("theirs") version. Returns
/// `Ok(true)` if resolved, `Ok(false)` if it declined (only for `go.mod`
/// where taking theirs would drop a downstream-only `replace` line) — the
/// caller treats a decline as a real, unresolved conflict rather than
/// silently losing content.
fn resolve_to_theirs(worktree: &Path, path: &str) -> Result<bool> {
    let staged = run_git(worktree, &["ls-files", "-u", "--", path])?;
    let theirs_present = staged
        .lines()
        .any(|line| line.split_whitespace().nth(2).map(|stage| stage == "3").unwrap_or(false));

    if !theirs_present {
        run_git(worktree, &["rm", "--", path])?;
        return Ok(true);
    }

    if path == "go.mod" {
        let ours = run_git(worktree, &["show", ":2:go.mod"])?;
        let theirs = run_git(worktree, &["show", ":3:go.mod"])?;
        let our_replaces = go_mod_replace_paths(&ours)?;
        let their_replaces = go_mod_replace_paths(&theirs)?;
        let lost_a_replace = our_replaces.iter().any(|p| !their_replaces.contains(p));
        if lost_a_replace {
            return Ok(false);
        }
    }

    run_git(worktree, &["checkout", "--theirs", "--", path])?;
    run_git(worktree, &["add", "--", path])?;
    Ok(true)
}

/// Extracts the `Old.Path` of every `replace` directive in a go.mod's
/// content, via `go mod edit -json` (the Go toolchain's own parser)
/// rather than line-prefix matching — go.mod's block syntax
/// (`replace (\n\tmod => path\n)`) has individual entries that don't start
/// with the literal text `"replace "`, so a naive per-line filter misses
/// them and would silently pass a downstream-only replace hiding inside a
/// block straight through to `checkout --theirs`.
fn go_mod_replace_paths(content: &str) -> Result<Vec<String>> {
    let tmp_dir = tempfile::tempdir().context("failed to create temp dir for go mod edit")?;
    let tmp_path = tmp_dir.path().join("go.mod");
    std::fs::write(&tmp_path, content).context("failed to write temp go.mod")?;
    let output = Command::new("go")
        .args(["mod", "edit", "-json"])
        .arg(&tmp_path)
        .output()
        .context("failed to run `go mod edit -json`")?;
    if !output.status.success() {
        bail!("go mod edit -json failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("failed to parse go mod edit -json output")?;
    let paths = parsed["Replace"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry["Old"]["Path"].as_str())
        .map(|s| s.to_string())
        .collect();
    Ok(paths)
}

/// `git subrepo commit` doesn't touch `branch` (see the doc note above
/// `handle_conflict`), so this fixes it up — but only if it's actually
/// stale, since committing an empty diff fails.
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
```

(`git_common_dir` is already defined in Task 3's code — no need to
redefine it here, `conflict_worktree` above just calls it.)

- [ ] **Step 3: Wire the `force-commit-conflicted-subrepo` CLI command**

Mirroring Task 3 Step 5's pattern exactly, add to `xtask/src/lib.rs`:

```rust
/// The CI-only "commit despite conflicts" policy: force-finishes a
/// conflicted `pull-subrepo` attempt by committing the temp worktree
/// exactly as it sits, conflict markers and all. Never use this outside
/// automation — a human should resolve the conflict properly instead (see
/// `pull-subrepo`'s own error message for how).
ForceCommitConflictedSubrepo {
    path: String,
    tag: String,
},
```

Dispatch arm: `Command::ForceCommitConflictedSubrepo { path, tag } => pull_subrepo::force_commit_conflicted(&repo_root()?, &path, &tag),`

- [ ] **Step 4: Run all `pull_subrepo` tests**

Run: `cargo test -p xtask pull_subrepo -- --nocapture`
Expected: all 16 tests from Task 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add xtask/src/pull_subrepo.rs xtask/src/lib.rs
git commit -m "feat(xtask): implement pull-subrepo's conflict allowlist, real-conflict stop, and force-commit-conflicted-subrepo"
```

______________________________________________________________________

### Task 5: `finish-vendor-bump` — version note, go.mod, identity checks

The remaining VENDORING.md "step 3" work, kept separate from
`pull-subrepo` per the design doc.

**Files:**

- Create: `xtask/src/finish_vendor_bump.rs`
- Create: `xtask/src/finish_vendor_bump_tests.rs`
- Modify: `xtask/src/lib.rs` (module + test-module declarations, `Command` variant, dispatch, wrapper)

**Interfaces:**

- Consumes: `git_util::run_git` (Task 3).

- Produces: `finish_vendor_bump::{run, run_identity_checks, IdentityCheckOutcome}` — `run(repo_root: &Path, subdir: &str, dep_name: &str, new_tag: &str) -> Result<IdentityCheckOutcome>`, consumed by Task 8's workflow.

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

    let result = finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0");
    assert!(result.is_ok(), "a no-op second call must not fail: {result:?}");
}

#[skuld::test]
fn a_second_call_does_not_sweep_up_unrelated_staged_files() {
    let dir = init_repo_with_vendoring_md("widget", "v1.0.0");
    finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0").unwrap();

    std::fs::write(dir.path().join("unrelated.txt"), "someone's in-progress work\n").unwrap();
    git(dir.path(), &["add", "unrelated.txt"]);

    finish_vendor_bump::update_vendoring_note_and_commit(dir.path(), "widget", "v2.0.0").unwrap();

    let status = Command::new("git").args(["status", "--porcelain"]).current_dir(dir.path()).output().unwrap();
    let status_str = String::from_utf8_lossy(&status.stdout);
    assert!(status_str.contains("unrelated.txt"), "unrelated staged file must survive untouched, not swept into the docs commit: {status_str}");
}

#[skuld::test]
fn failing_identity_check_is_reported_not_swallowed() {
    let dir = tempfile::tempdir().unwrap();
    let vendored = dir.path().join("vendored");
    let ex_ray = dir.path().join("crates/ex-ray");
    std::fs::create_dir_all(&vendored).unwrap();
    std::fs::create_dir_all(&ex_ray).unwrap();
    std::fs::write(ex_ray.join("go.mod"), "module example.com/ex-ray\n\ngo 1.25\n").unwrap();
    // Deliberate syntax error — the very first check (crates/ex-ray's own
    // go test ./...) must fail on this.
    std::fs::write(ex_ray.join("main.go"), "package main\n\nfunc broken( {\n").unwrap();

    let outcome = finish_vendor_bump::run_identity_checks(dir.path(), "vendored").unwrap();
    match outcome {
        IdentityCheckOutcome::Failed { detail } => {
            assert!(detail.contains("test"), "detail should name the failing step: {detail}");
        }
        IdentityCheckOutcome::Passed => panic!("expected the syntax error to fail"),
    }
}

/// Exercises the FULL `run()` sequence end-to-end — including
/// `run_go_mod_tidy_and_commit`, the outer `go.mod` require-line rewrite,
/// and `run_identity_checks` reaching `IdentityCheckOutcome::Passed`. Two
/// real, self-contained Go modules (no external imports, so `go mod tidy`
/// touches nothing over the network) linked by a `replace` directive,
/// mirroring the real `crates/ex-ray` / vendored-dep pair. No
/// `transport/internet/tls` directory here, so the v2ray-core-specific
/// scoped test is correctly skipped (see run_identity_checks).
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
        "module example.com/ex-ray\n\ngo 1.25\n\nrequire example.com/widget v1.0.0\n\nreplace example.com/widget => ./third_party/widget\n",
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
    assert!(matches!(outcome, IdentityCheckOutcome::Passed), "expected the minimal fixture to pass identity checks");

    let go_mod = std::fs::read_to_string(ex_ray.join("go.mod")).unwrap();
    assert!(
        go_mod.contains("example.com/widget v2.0.0") && !go_mod.contains("vv2.0.0"),
        "require line should be bumped to exactly v2.0.0, not double-prefixed: {go_mod}"
    );

    let note = std::fs::read_to_string(vendoring_dir.join("VENDORING.md")).unwrap();
    assert!(note.contains("pinned **v2.0.0**"));

    // Re-run with the same target: proves the go.mod/go.sum commit path's
    // own commit_if_staged guard (distinct call site from the
    // VENDORING.md note's) also survives a no-op re-run.
    let second = finish_vendor_bump::run(dir.path(), "crates/ex-ray/third_party/widget", "widget", "v2.0.0");
    assert!(second.is_ok(), "a second, no-op run must not fail on an empty go.mod/go.sum commit: {second:?}");
}

/// v2ray-core's real `ex-ray-tests` scope (build.yaml) additionally runs a
/// scoped test inside the vendored module itself, detected by the
/// presence of `transport/internet/tls` — not hardcoded to a dep name, so
/// utls (which has no such directory) correctly skips it. All four scoped
/// directories are created here (not just `tls`): `go test` against a
/// mix of existing and nonexistent package patterns fails on the missing
/// ones regardless of whether the present package's own tests pass —
/// creating only one directory would make this test's assertion pass for
/// the wrong reason (a "no such directory" artifact, not the deliberate
/// failure actually being detected).
#[skuld::test]
fn identity_check_runs_the_scoped_vendored_test_when_present() {
    let dir = tempfile::tempdir().unwrap();
    let vendored = dir.path().join("vendored");
    let ex_ray = dir.path().join("crates/ex-ray");
    std::fs::create_dir_all(&vendored).unwrap();
    std::fs::create_dir_all(&ex_ray).unwrap();
    std::fs::write(ex_ray.join("go.mod"), "module example.com/ex-ray\n\ngo 1.25\n").unwrap();
    std::fs::write(ex_ray.join("main.go"), "package main\n\nfunc main() {}\n").unwrap();

    std::fs::write(vendored.join("go.mod"), "module example.com/vendored\n\ngo 1.25\n").unwrap();
    for pkg in ["tls", "quic", "hysteria2", "transportcommon"] {
        let pkg_dir = vendored.join("transport/internet").join(pkg);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join(format!("{pkg}.go")), format!("package {pkg}\n")).unwrap();
    }
    std::fs::write(
        vendored.join("transport/internet/tls/tls_test.go"),
        "package tls\n\nimport \"testing\"\n\nfunc TestBroken(t *testing.T) { t.Fatal(\"deliberate failure\") }\n",
    )
    .unwrap();

    let outcome = finish_vendor_bump::run_identity_checks(dir.path(), "vendored").unwrap();
    match outcome {
        IdentityCheckOutcome::Failed { detail } => {
            assert!(detail.contains("deliberate failure"), "the scoped vendored test's own failure should surface, not a missing-directory artifact: {detail}");
        }
        IdentityCheckOutcome::Passed => panic!("expected the deliberately failing scoped test to be exercised and fail"),
    }
}

#[skuld::test]
fn identity_check_passes_when_all_scoped_vendored_tests_pass() {
    let dir = tempfile::tempdir().unwrap();
    let vendored = dir.path().join("vendored");
    let ex_ray = dir.path().join("crates/ex-ray");
    std::fs::create_dir_all(&vendored).unwrap();
    std::fs::create_dir_all(&ex_ray).unwrap();
    std::fs::write(ex_ray.join("go.mod"), "module example.com/ex-ray\n\ngo 1.25\n").unwrap();
    std::fs::write(ex_ray.join("main.go"), "package main\n\nfunc main() {}\n").unwrap();

    std::fs::write(vendored.join("go.mod"), "module example.com/vendored\n\ngo 1.25\n").unwrap();
    for pkg in ["tls", "quic", "hysteria2", "transportcommon"] {
        let pkg_dir = vendored.join("transport/internet").join(pkg);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join(format!("{pkg}.go")), format!("package {pkg}\n")).unwrap();
    }

    let outcome = finish_vendor_bump::run_identity_checks(dir.path(), "vendored").unwrap();
    assert!(matches!(outcome, IdentityCheckOutcome::Passed));
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
    commit_if_staged(repo_root, &["crates/ex-ray/third_party/VENDORING.md"], &format!("docs: note {dep_name} {new_tag} in VENDORING.md"))
}

/// Rewrites `crates/ex-ray/go.mod`'s `require` line for `<subdir>`'s Go
/// module to `new_tag`, then `go mod tidy`. The module's `replace`
/// directive means Go itself never touches this version string for a
/// locally-replaced module, so it would otherwise silently keep
/// advertising the old tag. The module path is read from the vendored
/// dep's own `go.mod` `module` line rather than hardcoded.
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

    // `go.sum` may not exist at all: a module whose only requirement is
    // satisfied by a local `replace` directory produces none. `git add` on
    // a pathspec matching nothing is a hard error (not a no-op), so only
    // add it when it's actually there.
    let mut paths: Vec<&str> = vec!["crates/ex-ray/go.mod"];
    if repo_root.join("crates/ex-ray/go.sum").exists() {
        paths.push("crates/ex-ray/go.sum");
    }
    let mut add_args = vec!["add"];
    add_args.extend(paths.iter().copied());
    run_git(repo_root, &add_args)?;
    commit_if_staged(repo_root, &paths, &format!("build(ex-ray): bump {module_path} to {new_tag}"))
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

/// `new_tag` already carries its own `v` prefix (e.g. `v5.53.0` — never
/// stripped: see the Renovate customManager's lack of
/// `extractVersionTemplate`). go.mod's own syntax separately always has a
/// literal `v` before a require line's version number regardless —
/// `prefix` matches THAT syntax marker to find the line, then the
/// replacement text supplies `new_tag` (already carrying its `v`)
/// directly, without adding a second one.
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

/// Matches `build.yaml`'s `ex-ray-tests` target exactly — the same check
/// `ci.yaml`'s "Test ex-ray (Go)" job runs — rather than a broader,
/// invented scope: `crates/ex-ray`'s own `go test ./...`, plus (only when
/// the vendored dir actually has the directory structure, detected rather
/// than hardcoded by dep name) v2ray-core's scoped
/// `transport/internet/{tls,quic,hysteria2,transportcommon}` test. utls
/// has no such directory — its patch is exercised transitively through
/// v2ray-core's own tests via the go.mod replace directive, matching
/// build.yaml's actual behavior of not testing it standalone. Not
/// literally `cargo xtask run ex-ray-tests` itself: that requires xtask's
/// full build.yaml-driven environment and isn't callable against the
/// fixture repos this module's tests construct — if build.yaml's
/// `ex-ray-tests` target ever changes, update this to match.
pub(crate) fn run_identity_checks(repo_root: &Path, subdir: &str) -> Result<IdentityCheckOutcome> {
    let ex_ray_dir = repo_root.join("crates/ex-ray");
    if let Some(detail) = go_command_failure(&ex_ray_dir, &["test", "./..."])? {
        return Ok(IdentityCheckOutcome::Failed { detail });
    }

    let vendored_dir = repo_root.join(subdir);
    if vendored_dir.join("transport/internet/tls").is_dir() {
        let args = [
            "test",
            "./transport/internet/tls/...",
            "./transport/internet/quic/...",
            "./transport/internet/hysteria2/...",
            "./transport/internet/transportcommon/...",
        ];
        if let Some(detail) = go_command_failure(&vendored_dir, &args)? {
            return Ok(IdentityCheckOutcome::Failed { detail });
        }
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
/// this commit, and this function's own no-op guarantee doesn't get
/// broken just because *something else* happens to be staged.
fn commit_if_staged(repo_root: &Path, paths: &[&str], message: &str) -> Result<()> {
    let mut diff_args = vec!["diff", "--cached", "--name-only", "--"];
    diff_args.extend(paths);
    let staged = run_git(repo_root, &diff_args)?;
    if staged.is_empty() {
        return Ok(());
    }
    let mut commit_args = vec!["commit", "-m", message, "--"];
    commit_args.extend(paths);
    run_git(repo_root, &commit_args)?;
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
  /// changes — regardless of whether the identity check passed. The
  /// process still exits non-zero on a failed identity check, after
  /// committing, so the failure isn't silently swallowed. Any earlier
  /// failure (e.g. a malformed go.mod, `go mod tidy` itself failing)
  /// propagates as a normal error instead — distinguishable from an
  /// identity-check failure since it comes back as `Err` rather than
  /// `Ok(IdentityCheckOutcome::Failed)`.
  FinishVendorBump {
      path: String,
      dep_name: String,
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

### Task 6: Renovate `customManager` + automerge override

**Files:**

- Modify: `.github/renovate.json`

**Interfaces:** none (config only)

- [ ] **Step 1: Add the customManager**

In `.github/renovate.json`, add to the `customManagers` array (after the
existing `prek.toml` entry, before the closing `]`). Captures only
`owner/repo` after `github.com/`, matching this repo's existing WiX
customManager's same capture pattern (the `github-tags` datasource expects
that shape). No `extractVersionTemplate`: this repo's own existing
workflow-version customManager uses that field to strip a leading `v` on
write-back (`.github/workflows/ci.yaml`'s `GSUDO_VERSION: "2.6.1"` is
managed by that exact template pattern, and gerardog/gsudo's real tags are
`v2.6.1`). Both `.gitrepo` files need the `v` kept (`branch = v5.52.0`,
matching the real git tag `git subrepo pull -b` needs), so this
customManager must not strip it:

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

- [ ] **Step 2: Add the automerge-override packageRules entry**

The file's existing `packageRules` array already has an unscoped
`{"matchUpdateTypes": ["major"], "groupName": null, "automerge": true}`
rule, which would otherwise also
match a major `.gitrepo` bump (e.g. v5→v6, v1→v2). Renovate uses
last-match-wins semantics, so add this **after** that rule (append to the
end of the array):

```json
    {
      "description": "Vendored git-subrepo deps (v2ray-core, utls): vendor-bump.yaml is the sole automerge-arming mechanism (see .github/workflows/vendor-bump.yaml), never Renovate itself — arming at PR-creation time races the actual pull/rebase work, since CI trivially passes on Renovate's content-unchanged branch-only commit. This explicitly overrides the file's existing unscoped 'Major updates' automerge:true rule above.",
      "matchFileNames": ["crates/ex-ray/third_party/*/.gitrepo"],
      "automerge": false
    }
```

- [ ] **Step 3: Validate the config**

Run: `npx --yes --package renovate -- renovate-config-validator .github/renovate.json`
Expected: `Config validated successfully`.

**Open question for you, not decided here:** should a *permanent*
`renovate-config-validator` step be added to CI? A permanent validator
would have caught the `packageName`-is-a-URL and `extractVersionTemplate`
write-back mistakes this design made — worth adding to CI? Flag this to
the user explicitly when this plan is reviewed; don't decide silently
either way.

- [ ] **Step 4: Commit**

```bash
git add .github/renovate.json
git commit -m "chore(renovate): track vendored .gitrepo tags via customManager, exclude from automerge"
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

- Consumes: `cargo xtask pull-subrepo` (Task 4, exit codes 0/2/other), `cargo xtask finish-vendor-bump` (Task 5), `cargo xtask force-commit-conflicted-subrepo` (Task 4), `.github/actions/mint-nathan-token` (Task 7).

- [ ] **Step 1: Write the workflow**

Two jobs, not one: `bump` does the real work (push/workflow_dispatch
triggered) and opportunistically arms auto-merge right after a clean push;
`arm-on-pr-open` is a lightweight companion that fires on
`pull_request: [opened, synchronize]` for a `renovate/**` branch, since
Renovate deliberately rate-limits its own PR-creation call
(`prHourlyLimit`/`prConcurrentLimit`, both left at their defaults in this
repo's config) — the branch and its push can exist well before the PR
does, and `bump`'s own "find the PR" step may legitimately come up empty.

`arm-on-pr-open` must **not** simply arm on every `opened`/`synchronize`
event, though — Renovate's own PR-open call (fast, just an API call) can
easily beat `bump`'s pipeline (slow: install git-subrepo, run Go tests,
etc.), so an ungated version of this job would routinely arm auto-merge on
Renovate's bare `.gitrepo`-branch-line-only commit, before `bump` has
pulled anything — exactly the premature-merge race the Renovate
`automerge: false` override (Task 6) exists to prevent, just reintroduced
under a different trigger. It gates on the PR's *current head commit*
having been authored by `nathan-blahaj[bot]` — i.e. that `bump` has
already pushed *something* to this exact commit, whether the outcome was
clean or conflicted (both are safe to arm on: a still-conflicted commit
has literal markers in tracked source, which reliably breaks compilation,
so CI naturally fails and blocks the merge regardless of arming).
Renovate's own commits are never authored that way, so this structurally
can't fire on the dangerous case.

Other fixes below:

- **Self-retrigger**: `bump`'s own successful push matches its own
  `push`+`paths` trigger. The job-level `if:` guard checks the pushing
  commit's author name against exactly what the "git identity" step sets
  later in this same file.
- **No `cancel-in-progress`**: combined with the self-retrigger guard
  above, `cancel-in-progress: true` creates a race — GitHub evaluates
  concurrency *before* the job-level `if:`, so the workflow's own push can
  cancel its own still-running arming steps before they execute. Left at
  the default (`false`); a genuinely stale run instead fails loudly on a
  rejected non-force `git push` if Renovate force-pushed mid-run.
- **Conflict vs. other failure**: the Pull step captures
  `cargo xtask pull-subrepo`'s actual exit code (0 clean / 2 real conflict
  / anything else a genuine unexpected failure) instead of GitHub Actions'
  coarse step outcome, so only a real conflict routes into conflict
  recovery — which now just calls the tested
  `force-commit-conflicted-subrepo` xtask command instead of
  reimplementing worktree-path derivation in bash.
- **Branch-synchronization**: diffs against `origin/main`'s merge-base
  (not `github.event.before`, which may reference a commit no longer
  reachable from any ref after Renovate's routine force-pushes) — only
  depends on this run's own fetched history.
- **`workflow_dispatch` safety**: never pushes to whatever ref the run was
  dispatched against (defaults to `main` without `--ref`) — always a
  disposable scratch branch.
- **Empty `gh pr list` results**: `--jq '.[0].number // empty'` yields an
  empty string, not the literal text `null`.

```yaml
name: Vendor bump

on:
  push:
    branches: ["renovate/**"]
    paths: ["crates/ex-ray/third_party/*/.gitrepo"]
  pull_request:
    types: [opened, synchronize]
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
  # github.head_ref (pull_request) and github.ref_name (push) are both
  # already the bare branch name — github.ref (a push-event fallback some
  # designs use here) is instead the full refs/heads/... form, which would
  # silently put push- and pull_request-triggered runs for the same branch
  # into two different groups.
  group: vendor-bump-${{ github.head_ref || github.ref_name }}
  cancel-in-progress: false

jobs:
  bump:
    name: Pull + rebase vendored dependency
    if: github.event_name != 'pull_request' && (github.event_name != 'push' || github.event.head_commit.author.name != 'nathan-blahaj[bot]')
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
          git clone --branch 0.4.9 --depth 1 https://github.com/ingydotnet/git-subrepo "$RUNNER_TEMP/git-subrepo"
          echo "$RUNNER_TEMP/git-subrepo/lib" >> "$GITHUB_PATH"

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
        run: cargo xtask force-commit-conflicted-subrepo "${{ steps.target.outputs.path }}" "${{ steps.target.outputs.tag }}"

      - name: Push
        if: steps.pull.outputs.result == 'clean' || steps.pull.outputs.result == 'conflicted'
        run: git push origin "HEAD:${{ steps.scratch-branch.outputs.ref_name || github.ref_name }}"

      - name: Find the PR for this branch
        if: github.event_name == 'push' && (steps.pull.outputs.result == 'clean' || steps.pull.outputs.result == 'conflicted')
        id: find-pr
        env:
          GH_TOKEN: ${{ steps.nathan.outputs.token }}
        run: |
          pr_number=$(gh pr list --repo "${{ github.repository }}" --head "${{ github.ref_name }}" --json number --jq '.[0].number // empty')
          echo "pr_number=$pr_number" >> "$GITHUB_OUTPUT"

      - name: Arm auto-merge
        if: steps.pull.outputs.result == 'clean' && steps.finish.outcome == 'success' && steps.find-pr.outputs.pr_number != ''
        env:
          GH_TOKEN: ${{ steps.nathan.outputs.token }}
        run: gh pr merge --auto --squash "${{ steps.find-pr.outputs.pr_number }}" --repo "${{ github.repository }}"

      # Renovate's prHourlyLimit/prConcurrentLimit (both left at defaults
      # here) deliberately create the branch and defer PR creation — this
      # is common, not a narrow race. The arm-on-pr-open job below is the
      # guaranteed catch-up; this is just visibility for the common
      # opportunistic-arm-skipped case.
      - name: Note if no PR exists yet
        if: github.event_name == 'push' && steps.pull.outputs.result == 'clean' && steps.finish.outcome == 'success' && steps.find-pr.outputs.pr_number == ''
        run: echo "::notice::No open PR found yet for this branch — auto-merge will be armed by this workflow's pull_request trigger once Renovate opens it."

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

  arm-on-pr-open:
    name: Arm auto-merge (PR opened/updated)
    if: github.event_name == 'pull_request' && startsWith(github.head_ref, 'renovate/')
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - name: Mint nathan-blahaj token
        id: nathan
        uses: ./.github/actions/mint-nathan-token
        with:
          app-id: ${{ secrets.NATHAN_APP_ID }}
          private-key: ${{ secrets.NATHAN_APP_PRIVATE_KEY }}

      # See the note above the workflow: only arm once `bump` has actually
      # pushed something to this exact commit — never on Renovate's own
      # bare branch-only commit, which would trivially pass CI.
      - name: Check whether bump has already pushed its work
        id: check-head
        env:
          GH_TOKEN: ${{ steps.nathan.outputs.token }}
        run: |
          author=$(gh api "repos/${{ github.repository }}/commits/${{ github.event.pull_request.head.sha }}" --jq '.commit.author.name')
          echo "author=$author" >> "$GITHUB_OUTPUT"

      - name: Arm auto-merge
        if: steps.check-head.outputs.author == 'nathan-blahaj[bot]'
        env:
          GH_TOKEN: ${{ steps.nathan.outputs.token }}
        run: gh pr merge --auto --squash "${{ github.event.pull_request.number }}" --repo "${{ github.repository }}"
```

- [ ] **Step 2: Validate the YAML syntactically**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/vendor-bump.yaml'))"`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/vendor-bump.yaml
git commit -m "ci: add vendor-bump workflow"
```

______________________________________________________________________

### Task 9: Add `git-subrepo` to `test-tooling`'s CI job

`xtask`'s own tests (Task 2's fixture tests) shell out to the real
`git subrepo`, and `xtask` is one of the packages `ci.yaml`'s
`test-tooling` job runs via its nextest archive — without this, those
tests fail (not skip) the moment Task 2 lands, in the standard CI job for
this PR, before the rest of this plan is even implemented.

**Files:**

- Modify: `.github/workflows/ci.yaml`

- [ ] **Step 1: Add the install step**

In `.github/workflows/ci.yaml`'s `test-tooling` job (runs on a
windows/darwin×2/linux×2/windows-arm matrix), add a `git-subrepo` install
step before "Run tests", using `$RUNNER_TEMP` (not a hardcoded `/opt/...`
path) so it works across all runner OSes in the matrix:

```yaml
      - name: Install git-subrepo 0.4.9
        shell: bash
        run: |
          git clone --branch 0.4.9 --depth 1 https://github.com/ingydotnet/git-subrepo "$RUNNER_TEMP/git-subrepo"
          echo "$RUNNER_TEMP/git-subrepo/lib" >> "$GITHUB_PATH"
```

Place it right after the `actions/checkout@v7` step, before `Install nextest`.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yaml
git commit -m "ci(test-tooling): install git-subrepo for xtask's fixture-repo tests"
```

______________________________________________________________________

### Task 10: Fix `wix-hash-fixup.yaml`

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

(Note this workflow's own trigger is `paths: [wix-toolchain.toml]`, and
the `git diff --quiet && exit 0` guard already makes a second run of this
specific workflow a no-op, so it doesn't need `vendor-bump.yaml`'s
self-retrigger guard.)

- [ ] **Step 2: Validate the YAML syntactically**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/wix-hash-fixup.yaml'))"`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/wix-hash-fixup.yaml
git commit -m "ci(wix-hash-fixup): push as nathan-blahaj so CI actually reruns"
```

______________________________________________________________________

### Task 11: Update `VENDORING.md`

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
that succeeds (immediately if Renovate's PR already exists, or via a
separate trigger once it does — Renovate rate-limits its own PR-creation
call, so the branch/push often lands before the PR). It merges
automatically if the pull is clean and CI is green; it sits open with a PR
comment if a real merge conflict landed outside the auto-resolved
`go.mod`/`go.sum`/`.github/workflows/*` allowlist (the authoritative
policy lives in `xtask/src/pull_subrepo.rs`'s `is_auto_resolvable` —
`go.mod` conflicts specifically are only auto-resolved when doing so
wouldn't drop a downstream-only `replace` directive, like the one below).

`pull-subrepo`'s "nothing committed" guarantee on a real conflict is about
the pull attempt itself, not the whole run: if the routine squash-merge
parent fixup ran first, that's a separate, independently valid commit that
stays even if the pull then hits a real conflict.

To do it by hand (same tools the automation uses):

1. `cargo xtask pull-subrepo crates/ex-ray/third_party/<name> <new-tag>`.
   On a real conflict it stops uncommitted, exactly like `git pull`, and
   prints the temp worktree to resolve it in — `cd` there, fix the
   conflicts (`git status` to see them), `git add`, `git commit`, then
   `git subrepo commit crates/ex-ray/third_party/<name>` from the repo
   root.
2. `cargo xtask finish-vendor-bump crates/ex-ray/third_party/<name> <name> <new-tag>`
   — updates this file's version note, bumps the outer `go.mod` require
   line and runs `go mod tidy`, and runs the same identity check
   `ci.yaml`'s "Test ex-ray (Go)" job runs (`build.yaml`'s `ex-ray-tests`
   target: `crates/ex-ray`'s own `go test ./...`, plus — for v2ray-core
   specifically — the scoped `transport/internet/{tls,quic,hysteria2,
   transportcommon}` test), committing regardless of whether it passed.
```

- [ ] **Step 2: Commit**

```bash
git add crates/ex-ray/third_party/VENDORING.md
git commit -m "docs: point VENDORING.md's bump instructions at the new automation"
```

______________________________________________________________________

### Task 12: Live end-to-end verification (manual, watched)

Not subagent-executable in the background — this repo's convention is to
watch a change through to a real green (or correctly-red) result, not
declare done from static review.

- [ ] **Step 1: Push the branch and open the PR**

```bash
git push -u origin azhukova/787
gh pr create --title "feat(vendor): automate vendored-dependency bumps" --body "Closes #787. See docs/superpowers/specs/2026-08-10-787-vendor-dependency-automation.md and docs/superpowers/plans/2026-08-11-787-vendor-dependency-automation.md."
```

- [ ] **Step 2: Watch this PR's own CI to green**

Confirms the new xtask code, `test-tooling`'s `git-subrepo` install, and
the workflow YAML don't break the existing build.

- [ ] **Step 3: Confirm Task 1's secrets and required-check change are in place**

`gh secret list --repo bindreams/hole` should show `NATHAN_APP_ID` and
`NATHAN_APP_PRIVATE_KEY`. Also confirm via `gh api repos/bindreams/hole/rulesets/<id>`
(or the Settings UI) that `Test ex-ray (Go)` now appears in
`required_status_checks`. If either is missing, stop and complete Task 1
first.

- [ ] **Step 4: Dry-run `vendor-bump.yaml` via `workflow_dispatch` on a harmless case**

Once this PR is merged (so the workflow exists on `main`):

```bash
gh workflow run vendor-bump.yaml --repo bindreams/hole -f dep=utls -f tag=v1.8.2
```

(Re-pulling the *current* tag — a deliberate no-op case, on a disposable
`vendor-bump-manual/...` scratch branch — delete it afterward, it has no
PR attached.)

Watch via `gh run watch`. Expected: the Pull step's `result` output is
`clean` (git-subrepo's own already-up-to-date short-circuit) and the job
finishes without pushing a new commit.

- [ ] **Step 5: Confirm a real bump reaches auto-merge or a correctly-red PR, and does NOT self-retrigger**

Wait for (or manually trigger against) an actual newer tag:

```bash
gh workflow run vendor-bump.yaml --repo bindreams/hole -f dep=v2ray-core -f tag=<next tag>
```

Watch: does CI (`ci.yaml`) actually rerun on the pushed commit, does the
PR either auto-merge (via `gh pr view`, confirm auto-merge was armed and
it eventually merged — not suspiciously early on Renovate's original
branch-only commit) or sit correctly red/commented, and does
`vendor-bump.yaml`'s `bump` job run exactly once per push (not loop on its
own push)? If Renovate's PR-creation is delayed, confirm the
`arm-on-pr-open` job fires and arms it once the PR does appear. This is
the property the whole design rests on — confirm it live before
considering #787 done.

- [ ] **Step 6: Confirm a real conflicted bump end-to-end**

If a real conflict doesn't arise naturally, force one: manually edit a
line in `crates/ex-ray/third_party/v2ray-core/patched.go`-equivalent (a
file the ECH patch touches) on a scratch branch matching what upstream's
next release also changes, or use `workflow_dispatch` against a tag known
to conflict with the current patch set. Confirm the PR gets the
conflict-explaining comment, the conflicted tree (with literal markers) is
committed and pushed, and CI goes red on it (build fails on the markers) —
this is the one code path (Task 4's `force_commit_conflicted`, called from
the "Commit the conflicted tree anyway" step) that has unit coverage but
no live-workflow coverage yet.

- [ ] **Step 7: File a tracking issue for `wix-hash-fixup.yaml`'s verification**

Task 10's fix can't be verified within this PR (it depends on Renovate's
own WiX-toolchain version-bump schedule, not something this plan controls)
— file a GitHub issue now to confirm on the next such PR that its fixup
commit gets a fresh CI run and can auto-merge, and link it here so this
doesn't silently fall through unverified.
