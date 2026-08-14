# Automated vendored-dependency bumps (#787) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automate bumping the two git-subrepo-vendored deps
(`crates/ex-ray/third_party/{v2ray-core,utls}`) to new upstream tags,
rebasing the local ECH patches through `git subrepo pull`, and landing the
result as a PR that merges automatically when clean+green or sits open/red
when a real conflict or CI failure blocks it — with no self-hosted server.

**Architecture:** Renovate (hosted GitHub App) bumps only the `branch =`
line in each `.gitrepo` via a `customManager` and opens its normal PR. A
`packageRules` entry arms auto-merge on these files unconditionally (every
update type, not just major — see Global Constraints for why the file's
existing unscoped "major updates" rule alone isn't enough), the same way
this file already arms it per-manager for other dependency groups — no
vendor-specific *gating* logic, just ordinary Renovate config. A
`vendor-bump.yaml` workflow, authenticated as a purpose-built GitHub App
(`nathan-blahaj`, not the default `GITHUB_TOKEN`, so its pushes actually
retrigger CI), runs `cargo xtask pull-subrepo` (a generic, human-usable
wrapper around `git subrepo pull` that fixes the routine squash-merge
parent-staleness automatically and behaves like `git pull` on a real
conflict — stops, uncommitted) followed by `cargo xtask finish-vendor-bump`
(version note + `go.mod` + the identity check `ci.yaml`'s "Test ex-ray
(Go)" job itself runs), then pushes. That's the whole workflow — it never
touches auto-merge itself.

Correctness is enforced entirely by ordinary, repo-wide required checks
that apply to every PR, not a bot-specific "I attest I succeeded" signal:
"Test ex-ray (Go)" (added to the required-status-checks ruleset as
one-time manual setup, since it's the only CI job that exercises the
vendored code's own tests) plus a new `cargo xtask check-vendoring-integrity`
check wired into the existing, already-required `prek` lint job. That
check enforces structural invariants against the actual committed tree —
no merge-conflict markers anywhere under a vendored dep's directory, and
`VENDORING.md`'s noted version plus the outer `go.mod`'s require line both
match `.gitrepo`'s checked-out `branch`, for every dep the check discovers
(a missing `VENDORING.md` heading is itself a violation, not a pass) —
regardless of who or what committed the mismatch. Because these are
ordinary required checks, GitHub's native auto-merge (armed by Renovate
itself, immediately, the moment it opens the PR) simply refuses to merge
until they're green — it already waits for a required check that hasn't
reported yet, and stays armed across every later push `bump` makes, so
there's no premature-arming race to guard against and no reason for
arming to be gated, delayed, or handled by a second job.
The same `nathan-blahaj` App fixes the identical latent bug in
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
- Renovate arms auto-merge for these PRs itself — but **not** via the
  file's existing unscoped `"matchUpdateTypes": ["major"], "automerge": true` rule alone: that rule only fires for major version bumps, and the
  real-world case is the opposite of rare — v2ray-core's actual next tag
  (`v5.53.0`, cited above) is a *minor* bump from the currently-pinned
  `v5.52.0`, and no other existing `packageRules` entry matches the
  `.gitrepo` customManager either (they're all scoped via `matchManagers`
  to `github-actions`/`cargo`/`gomod`/`pep621`/`npm`, none of which is the
  custom regex manager these files use). So Task 6 keeps a
  `.gitrepo`-scoped `packageRules` entry, unconditional on update type
  (`matchFileNames` only, no `matchUpdateTypes`) — this is arming parity
  with every other dependency group in the file (each has its own
  automerge rule), not vendor-specific *gating* logic, so it doesn't
  conflict with the next bullet. This is safe *because* of the checks
  below: GitHub's native auto-merge (which is what Renovate's
  `platformAutomerge` arms) doesn't merge on arming, it merges once every
  required check reports green — including one that hasn't started
  reporting yet — and it stays armed across every subsequent push to the
  PR. Arming on Renovate's own bare, not-yet-pulled `.gitrepo`-only commit
  is therefore harmless: the required checks below correctly stay red
  until `vendor-bump.yaml` actually pulls the dependency and pushes the
  real update — Task 12 Step 5's live verification must confirm this
  against a real *minor* bump specifically, not wait for a hypothetical
  major release.
- No required check may be scoped to one automation's PRs. Whatever a bot
  can commit, a human can too, so a check that only verifies "did the bot
  succeed" (e.g. a bot-authored, bot-reported check-run) misses a human
  making the identical mistake by hand, and it's unnecessary machinery
  besides — every invariant here is instead a structural fact checkable
  directly against the committed tree, so it's enforced by an ordinary
  required check that already applies to every PR:
  - "Test ex-ray (Go)" (the only CI job that exercises the vendored code's
    own tests) is not currently a required status check on `main`'s
    ruleset — added as one-time manual setup (Task 1), since without it a
    vendor bump that breaks the ECH gate/patches could merge with nothing
    catching it.
  - `cargo xtask check-vendoring-integrity` (Task 13) checks, for each
    vendored dep discovered under `crates/ex-ray/third_party/` (dynamic —
    a `.gitrepo`'s mere presence is what makes a directory "a vendored
    dep" to this check): no merge-conflict markers anywhere in its
    directory (catches a real conflict landing outside the scope `Test ex-ray (Go)` compiles, including the CI-only "commit despite
    conflicts" policy's literal markers — scanned byte-for-byte, not as
    UTF-8 text, since the real vendored trees already carry tracked
    binary files, e.g. `utls/logo.png` and its TLS test fixtures, that
    would otherwise hard-error every PR's required `Lint` job, not just
    vendor-bump ones), and `VENDORING.md`'s noted version plus the outer
    `go.mod`'s require line both match `.gitrepo`'s checked-out `branch`
    (catches `finish-vendor-bump` failing partway through and leaving
    stale bookkeeping behind — no markers, nothing a test would notice,
    since the vendored *code* itself would still be fine). A discovered
    dep with no `VENDORING.md` heading at all is itself a violation, not
    a skip — this is what keeps the check red on a third vendored dep's
    Renovate-bare commit; treating an absent heading as "not applicable"
    (the correct behavior for the separate go.mod-require-line check, which
    genuinely doesn't apply to every dep) would silently defeat the arming
    race this whole design relies on staying closed. Wired as an
    `always_run`/`pass_filenames = false` local `prek` hook (matching
    `check-workspace-lints`'s existing pattern) that does its own file
    discovery rather than going through `prek`'s staged-file list — this
    means it runs regardless of `prek.toml`'s top-level `exclude`, which
    still blanket-protects vendored code from every *other* hook
    (formatting/linting), and it needs no new required-status-check
    ruleset entry at all: `prek`'s own CI job ("Lint") is already
    required, so this rides along automatically.
- `vendor-bump.yaml`'s job must never act on its own pushes (it would
  otherwise retrigger itself) and must never treat a non-conflict failure
  (dirty tree, missing `git-subrepo`, bad input) as if it were a real
  merge conflict. `cancel-in-progress` stays `false`, so an in-flight run
  is never torn down mid-`git push` by its own later trigger; a plain,
  non-force `git push` failing loudly on an actual Renovate force-push
  mid-run is the correct, safe fallback instead.
- `nathan-blahaj` is the generic bot identity name (not vendor-specific) —
  reused for `wix-hash-fixup.yaml` too. Secrets: `NATHAN_APP_ID`,
  `NATHAN_APP_PRIVATE_KEY`. Permissions: `Contents` and `Pull requests`
  (`Read and write` each) only — no `Checks` permission, since nothing
  creates or queries a check-run under this design.
- Design doc: `docs/superpowers/specs/2026-08-10-787-vendor-dependency-automation.md`.

______________________________________________________________________

## File Structure

| File                                            | Responsibility                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `xtask/src/git_util.rs`                         | Shared `run_git` helper (shell out, check status, return trimmed stdout) used by `pull_subrepo.rs` and `finish_vendor_bump.rs`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `xtask/src/pull_subrepo.rs`                     | Generic `git subrepo pull` wrapper: dirty-tree guard, subdir normalization + ref-safety guard, in-progress-conflict guard (worktree existence, plus unfolded-branch detection via `refs/subrepo/<subdir>/commit` — deliberately does NOT pre-clean before an attempt, since that would destroy state the guard already decided to leave alone), automatic squash-merge parent fixup with fixup-commit disclosure on any later failure, tag-pin realignment on git-subrepo's up-to-date no-op path, allowlist conflict auto-resolution (handling delete/modify conflicts and preserving downstream-only `go.mod` `replace` directives, not blindly overwriting), the `.gitrepo` `branch`-field fixup that path needs (applied on both the resolved-clean and the still-conflicted path), `git-pull`-like stop on real conflicts. Also `force_commit_conflicted`, a separate function (not reachable from `run`) backing the CI-only policy. No Renovate/CI awareness in `run` itself. |
| `xtask/src/pull_subrepo_tests.rs`               | Fixture-repo integration tests proving the above against a real installed `git subrepo`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `xtask/src/finish_vendor_bump.rs`               | The separate, smaller VENDORING.md "step 3" work: version note, outer `go.mod` require-version bump + `go mod tidy`, the identity check matching `build.yaml`'s `ex-ray-tests` target exactly. Commits are guarded against "nothing to commit" and scoped to only the paths each step itself staged.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `xtask/src/finish_vendor_bump_tests.rs`         | Tests for the above, including the full `run()` sequence end-to-end and a failing identity check.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `xtask/src/lib.rs`                              | Modify: three new `Command` variants + dispatch wrappers + module/test-module declarations.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `xtask/src/check_vendoring_integrity.rs`        | New: walks each `crates/ex-ray/third_party/<dep>/` directory that has a `.gitrepo` (dynamic discovery, no hardcoded dep list), checking for merge-conflict markers in any git-tracked file and cross-checking `VENDORING.md`'s noted version + the outer `go.mod`'s require line (if present) against `.gitrepo`'s `branch` field. Reuses `pull_subrepo::gitrepo_field` and the `go mod edit -json` pattern from `finish_vendor_bump.rs` rather than duplicating either.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `xtask/src/check_vendoring_integrity_tests.rs`  | Fixture-repo tests for the above: a clean tree, a tree with conflict markers, a `VENDORING.md`/`.gitrepo` mismatch, a `go.mod`/`.gitrepo` mismatch, a dep with no `go.mod` require line at all (`utls`-shaped).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `.github/renovate.json`                         | Modify: `customManager` tracking each `.gitrepo`'s `branch` line (capturing `owner/repo`, not a full URL; no `extractVersionTemplate`). `packageRules` entry arming automerge unconditionally (every update type, not just the file's existing major-only rule) for these files — arming parity with the file's other per-manager automerge rules, not vendor-specific gating.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `prek.toml`                                     | Modify: new local hook running `cargo xtask check-vendoring-integrity`, `always_run = true` + `pass_filenames = false` (matching `check-workspace-lints`'s existing pattern) so it's unaffected by the file's top-level `third_party` exclude.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `.github/actions/mint-nathan-token/action.yaml` | Composite action minting a `nathan-blahaj` installation token from App ID + private key inputs. Shared by both workflows below.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `.github/workflows/vendor-bump.yaml`            | New workflow, one job (`bump`, push/workflow_dispatch-triggered): pull, finish (or force-commit on a real conflict), push, comment on the PR if conflicted. No auto-merge arming of any kind — that's entirely Renovate's + GitHub's required-checks' job.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `.github/workflows/ci.yaml`                     | Modify: `test-tooling` job (which runs `xtask`'s own tests) gets a `git-subrepo` install step, matching what the new fixture tests need.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `.github/workflows/wix-hash-fixup.yaml`         | Modify: swap `GITHUB_TOKEN` for `nathan-blahaj`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `crates/ex-ray/third_party/VENDORING.md`        | Modify: document the new tooling, the CI-only conflict-commit policy, and the identity check (matching `build.yaml`'s real `ex-ray-tests` scope, not a broader claim).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

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
  `Read and write`. Leave everything else at "No access" — in particular,
  no `Checks` permission: this design has no check-run of any kind, only
  ordinary required status checks, so nothing ever creates or queries one.

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

- [ ] **Step 5: Add one required status check**

In `bindreams/hole` → Settings → Rules → Rulesets → "Default Branch", edit
the `required_status_checks` rule and add:

- `Test ex-ray (Go)` (the exact context name of `ci.yaml`'s `test-ex-ray`
  job) — the *only* CI job that exercises the vendored/patched Go code at
  all. Without it in the required list, auto-merge can fire on a vendor
  bump that silently breaks the ECH fail-closed gate or the ECH-retry
  patches, since every other required check builds crates that never
  touch the vendored Go module.

No other ruleset entry is needed — see Global Constraints for why
`check-vendoring-integrity` (Task 13) doesn't need one.

- [ ] **Step 6: Confirm**

Reply here (or note in the tracking issue) once done — later tasks that
touch `vendor-bump.yaml`/`wix-hash-fixup.yaml` assume the secrets exist,
and Task 12's live verification assumes the required-check change is live.

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
    /// single-line `replace` directive theirs doesn't — resolving to
    /// theirs would silently drop it. Must NOT auto-resolve.
    AllowlistedWithReplace,
    /// Same as `AllowlistedWithReplace`, but the downstream-only `replace`
    /// is written in go.mod's block form (`replace (\n\t...\n)`) instead
    /// of a single line — the exact syntax a naive line-prefix filter
    /// would miss.
    AllowlistedWithBlockReplace,
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
            ConflictKind::Allowlisted | ConflictKind::AllowlistedWithReplace | ConflictKind::AllowlistedWithBlockReplace => {
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
        } else if matches!(conflict, ConflictKind::AllowlistedWithBlockReplace) {
            "module fixture\n\ngo 1.25\n\nrequire ourdownstream/patchdep v1.0.0\n\nreplace (\n\tourdownstream/loadbearing => ../loadbearing\n)\n"
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
fn allowlisted_go_mod_conflict_declines_when_a_block_form_replace_would_be_lost() {
    // go_mod_replace_directives exists specifically because a naive
    // line-prefix filter misses go.mod's block replace syntax — this test
    // only exercises the single-line form indirectly through the OTHER
    // preservation test above wouldn't have caught a regression back to
    // that naive approach. This one would.
    let fx = Fixture::build(ConflictKind::AllowlistedWithBlockReplace);

    let outcome = pull_subrepo::run(&fx.downstream, "vendor", "v2").expect("a real conflict is a reported Outcome, not an Err");
    match outcome {
        Outcome::Conflicted { unresolved, .. } => {
            assert_eq!(unresolved, vec!["go.mod".to_string()], "go.mod must be treated as unresolved when a block-form downstream replace would be lost");
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
fn an_unexpected_pull_failure_surfaces_as_an_error_not_a_conflict() {
    // A nonexistent tag fails at git-subrepo's fetch step, with neither
    // the stale-parent stderr text nor the merge-conflict stdout text —
    // handle_conflict's catch-all bail branch, otherwise untested by every
    // other ConflictKind (which only ever produce one of those two).
    let fx = Fixture::build(ConflictKind::None);
    let result = pull_subrepo::run(&fx.downstream, "vendor", "this-tag-does-not-exist");
    assert!(result.is_err(), "a nonexistent tag should surface as an Err, not Outcome::Conflicted");
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

- [x] **Step 1: Confirm Task 2's tests still fail the same way (baseline)**

Run: `cargo test -p xtask pull_subrepo::clean_pull -- --nocapture`
Expected: both `clean_pull_*` tests FAIL on `unimplemented!`.

- [x] **Step 2: Extract a shared `run_git` helper**

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

- [x] **Step 3: Implement the real logic**

Implemented in `xtask/src/pull_subrepo.rs` (and `xtask/src/git_util.rs` for
the shared `run_git` helper) — see those files for the real, shipped code
and doc comments; this plan intentionally doesn't duplicate them, to avoid
drift as they evolve. `handle_conflict` and `force_commit_conflicted`
remain deliberate placeholders — Task 4 replaces them with the real
allowlist/conflict logic.

- [x] **Step 4: Run the three in-scope tests**

Run: `cargo test -p xtask pull_subrepo -- --nocapture`
Expected: `clean_pull_on_the_very_first_attempt_from_a_plain_checkout`,
`clean_pull_after_squash_merge_auto_fixes_stale_parent`,
`dirty_tree_is_rejected_before_touching_anything`, and
`works_identically_from_a_linked_worktree` PASS. The conflict/allowlist
tests still FAIL (expected — Task 4).

- [x] **Step 5: Wire the CLI**

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
          pull_subrepo::Outcome::Conflicted {
              worktree,
              unresolved,
              fixup_commit,
          } => {
              eprintln!(
                  "xtask: {path} pull to {tag} has unresolved conflicts in:\n  {}\n\
                   Resolve them in {}, `git add` the resolved files, `git commit`, \
                   then run `git subrepo commit {path}` from the repo root.",
                  unresolved.join("\n  "),
                  worktree.display()
              );
              if let Some(fixup_commit) = fixup_commit {
                  eprintln!(
                      "xtask: note: a `.gitrepo` parent-realignment commit ({fixup_commit}) was \
                       already created on this branch before the conflict."
                  );
              }
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

- [x] **Step 6: Manually exercise the CLI once**

Run: `cargo xtask pull-subrepo --help` to confirm it's wired in.
Expected: clap-generated help showing `<PATH> <TAG>`.

- [x] **Step 7: Commit**

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

- Consumes: everything from Task 3 (`run_git`, `Outcome`, `replace_gitrepo_field`, `git_common_dir`, `ensure_tag_pin_matches`).

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
fn handle_conflict(
    repo_root: &Path,
    subdir: &str,
    tag: &str,
    pull_output: &Output,
    fixup_commit: Option<&str>,
) -> Result<Outcome> {
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
        return Ok(Outcome::Conflicted {
            worktree,
            unresolved,
            fixup_commit: fixup_commit.map(str::to_string),
        });
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
    ensure_tag_pin_matches(repo_root, subdir, tag)?;
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
    ensure_tag_pin_matches(repo_root, subdir, tag)?;
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
        let our_directives = go_mod_replace_directives(&ours)?;
        let their_directives = go_mod_replace_directives(&theirs)?;
        let lost_a_replace = our_directives.iter().any(|d| !their_directives.contains(d));
        if lost_a_replace {
            return Ok(false);
        }
    }

    run_git(worktree, &["checkout", "--theirs", "--", path])?;
    run_git(worktree, &["add", "--", path])?;
    Ok(true)
}

/// Extracts every `replace` directive from a go.mod's content as raw JSON
/// objects, via `go mod edit -json` (the Go toolchain's own parser)
/// rather than line-prefix matching — go.mod's block syntax
/// (`replace (\n\tmod => path\n)`) has individual entries that don't start
/// with the literal text `"replace "`, so a naive per-line filter misses
/// them and would silently pass a downstream-only replace hiding inside a
/// block straight through to `checkout --theirs`. Compares whole
/// directives (old path+version *and* new path+version), not just the
/// replaced module's path: upstream rewriting the *target* of a directive
/// we also carry (e.g. our `=> ../utls` becoming their own
/// `=> some-fork`), while keeping the same left-hand path, would
/// otherwise look unchanged to a path-only comparison and get silently
/// dropped.
fn go_mod_replace_directives(content: &str) -> Result<Vec<serde_json::Value>> {
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
    Ok(parsed["Replace"].as_array().cloned().unwrap_or_default())
}

pub(crate) fn is_auto_resolvable(path: &str) -> bool {
    path == "go.mod" || path == "go.sum" || path.starts_with(".github/workflows/")
}

fn unmerged_paths(worktree: &Path) -> Result<Vec<String>> {
    let output = run_git(worktree, &["diff", "--name-only", "--diff-filter=U"])?;
    Ok(output.lines().map(|s| s.to_string()).collect())
}
```

(`git_common_dir` and `ensure_tag_pin_matches` are already defined in Task
3's code — no need to redefine them here. `conflict_worktree` above calls
the former; `handle_conflict`/`force_commit_conflicted` above call the
latter instead of a separate `fixup_branch_field_if_needed` — it's the
same read-`.gitrepo`/rewrite-`branch`/add/commit-if-changed logic Task 3
already built and tested for its own tag-pin-realignment gap, so this path
reuses it rather than defining a second, functionally identical copy.)

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
Expected: all tests in `pull_subrepo_tests.rs` PASS — the original 18 from
Task 2, plus 10 more Task 3 added while hardening its own guards past the
original brief (see Task 3's commit history for what each covers); confirm
the current count with `grep -c '#\[skuld::test\]' xtask/src/pull_subrepo_tests.rs`
rather than trusting a hardcoded number here, since it'll drift again.

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

/// The FinishVendorBump doc comment (Task 5 Step 5, xtask/src/lib.rs)
/// claims `run()` "commit[s] each step's own changes — regardless of
/// whether the identity check passed." The only prior test reaching
/// `IdentityCheckOutcome::Failed` calls `run_identity_checks` directly,
/// skipping the VENDORING.md/go.mod steps entirely — this exercises the
/// claim through the actual `run()` entry point `cargo xtask
/// finish-vendor-bump` calls.
#[skuld::test]
fn run_commits_earlier_steps_even_when_the_identity_check_fails() {
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
    // Deliberate test failure in crates/ex-ray's own suite — the FIRST
    // check run_identity_checks performs, so VENDORING.md and go.mod are
    // already updated and committed by the time this fails.
    std::fs::write(
        ex_ray.join("main_test.go"),
        "package main\n\nimport \"testing\"\n\nfunc TestBroken(t *testing.T) { t.Fatal(\"deliberate failure\") }\n",
    )
    .unwrap();
    std::fs::write(ex_ray.join("main.go"), "package main\n\nfunc main() {}\n").unwrap();

    git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
    git(dir.path(), &["config", "user.email", "fixture@example.com"]);
    git(dir.path(), &["config", "user.name", "fixture"]);
    git(dir.path(), &["add", "-A"]);
    git(dir.path(), &["commit", "-m", "initial"]);

    let outcome = finish_vendor_bump::run(dir.path(), "crates/ex-ray/third_party/widget", "widget", "v2.0.0").unwrap();
    assert!(matches!(outcome, IdentityCheckOutcome::Failed { .. }), "expected the deliberate test failure to surface");

    let log = Command::new("git")
        .args(["log", "--format=%s"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let messages = String::from_utf8_lossy(&log.stdout);
    assert!(messages.contains("widget"), "the VENDORING.md/go.mod commits must already be on HEAD despite the identity-check failure: {messages}");

    let go_mod = std::fs::read_to_string(ex_ray.join("go.mod")).unwrap();
    assert!(go_mod.contains("v2.0.0"), "go.mod should still be bumped even though the identity check failed: {go_mod}");
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

### Task 6: Renovate `customManager` + unconditional automerge

**Status: implementation already landed, needs its `packageRules` entry
flipped, not removed.** The `customManager` below is already shipped and
correct — nothing to redo. The automerge-override entry that originally
shipped alongside it (`"automerge": false`, a carve-out from the file's
unscoped major-updates rule) needs to become the *opposite*: an
unconditional `"automerge": true` for these files, not scoped to major
updates. Neither a bare revert (delete the entry, fall back to the
existing major-only rule) nor the original carve-out is correct — the
file's unscoped major-updates rule only fires for major semver bumps, and
neither existing `.gitrepo` naturally produces those often (v2ray-core's
actual next tag, `v5.53.0`, is a *minor* bump from `v5.52.0`), and no
other existing `packageRules` entry matches the `.gitrepo` customManager
either (they're all scoped via `matchManagers` to specific ecosystems,
none of which is the custom regex manager `.gitrepo` files use). Without
an unconditional rule, ordinary minor/patch vendor bumps — the common
case — would never get auto-merge armed at all, silently defeating the
plan's own goal.

**Files:**

- Modify: `.github/renovate.json`

**Interfaces:** none (config only)

- [x] **Step 1: Add the customManager** — already done, unchanged. Tracks
  each `.gitrepo`'s `branch` line (capturing `owner/repo`, not a full URL;
  no `extractVersionTemplate`, since both `.gitrepo` files need the `v`
  kept in `branch = v5.52.0`, matching the real git tag `git subrepo pull -b` needs).

- [ ] **Step 2: Flip the automerge entry to unconditional `true`**

Find the entry this task originally added (`"matchFileNames": ["crates/ex-ray/third_party/*/.gitrepo"]`) and replace its
`"description"`/`"automerge"` fields:

```json
    {
      "description": "Vendored git-subrepo deps (v2ray-core, utls): auto-merge armed for every update type, the same way this file already arms it per-manager for other dependency groups — the file's unscoped major-only rule above doesn't reach these (they're a custom regex manager, and a routine bump is typically minor/patch, not major). Safety is entirely the required checks' job (Test ex-ray (Go), and check-vendoring-integrity riding inside Lint), not this rule.",
      "matchFileNames": ["crates/ex-ray/third_party/*/.gitrepo"],
      "automerge": true
    }
```

Leave every other entry (including the unscoped `"matchUpdateTypes": ["major"], "automerge": true` rule) untouched — this entry's own
`matchFileNames` scoping, combined with last-match-wins and its position
at the end of the array, is what makes it the deciding rule for `.gitrepo`
files specifically, regardless of update type.

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
git commit -m "chore(renovate): arm auto-merge for vendored .gitrepo bumps unconditionally, not just major"
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

One job, not two: `bump` does the real work — pull, finish (or
force-commit on a real conflict), push, comment on the PR if conflicted.
It never touches auto-merge in any way — arming (Renovate, Task 6) and
merge-gating (GitHub's required checks, including `check-vendoring-integrity`,
Task 13) are handled entirely as described in the plan's Global
Constraints. No check-run, no second job, no `pull_request` trigger, no
`Checks` permission.

Fixes below (all still apply, independent of the auto-merge redesign):

- **Self-retrigger**: `bump`'s own successful push matches its own
  `push`+`paths` trigger. The job-level `if:` guard checks the pushing
  commit's author name against exactly what the "git identity" step sets
  later in this same file.
- **No `cancel-in-progress`**: an in-flight run should never be torn down
  mid-`git push` by its own later trigger. Left at the default (`false`);
  a genuinely stale run instead fails loudly on a rejected non-force
  `git push` if Renovate force-pushed mid-run.
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
  group: vendor-bump-${{ github.ref_name }}
  cancel-in-progress: false

jobs:
  bump:
    name: Pull + rebase vendored dependency
    if: github.event_name != 'push' || github.event.head_commit.author.name != 'nathan-blahaj[bot]'
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
      # `git-subrepo`) on PATH. Pinned to 0.4.9 to match the version this
      # workflow's fixup logic targets — confirm this tag exists on first
      # real run.
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
        if: github.event_name == 'push' && steps.pull.outputs.result == 'conflicted'
        id: find-pr
        env:
          GH_TOKEN: ${{ steps.nathan.outputs.token }}
        run: |
          pr_number=$(gh pr list --repo "${{ github.repository }}" --head "${{ github.ref_name }}" --json number --jq '.[0].number // empty')
          echo "pr_number=$pr_number" >> "$GITHUB_OUTPUT"

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
a `.gitrepo`, and Renovate arms auto-merge on it unconditionally (`.github/renovate.json`'s
`packageRules` entry for these files), the same way it arms every other
dependency group in this file — nothing vendor-specific decides *whether*
to arm, only *whether it's safe to actually merge* (the required checks
below). `.github/workflows/vendor-bump.yaml`
does the rest: `cargo xtask pull-subrepo` followed by
`cargo xtask finish-vendor-bump`, pushing further commits to the same PR.
It merges automatically once the pull was clean and the required checks
go green — including `cargo xtask check-vendoring-integrity` (part of the
`prek`/`Lint` check), which fails the merge structurally if a conflict
landed outside the auto-resolved `go.mod`/`go.sum`/`.github/workflows/*`
allowlist (the authoritative policy lives in `xtask/src/pull_subrepo.rs`'s
`is_auto_resolvable` — `go.mod` conflicts specifically are only
auto-resolved when doing so wouldn't drop a downstream-only `replace`
directive, like the one below) or if `VENDORING.md`/`go.mod` end up
inconsistent with `.gitrepo`. On a real conflict, `vendor-bump.yaml`
force-commits the conflicted tree (with real markers) and comments on the
PR — auto-merge stays armed but can never fire, since GitHub's own
required checks refuse to go green on a tree with conflict markers in it.

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
3. `git push`. Auto-merge is already armed on the PR (Renovate arms it
   unconditionally at PR-creation time) and stays armed across your push,
   so nothing further is needed — it merges once
   the required checks (including `cargo xtask check-vendoring-integrity`)
   go green on your fix. If it somehow isn't armed, `gh pr merge --auto
   --squash <PR>` arms it yourself.
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
`required_status_checks` (`Lint`, which now also runs `cargo xtask check-vendoring-integrity`, should already be required — confirm it's
still there too). If any is missing, stop and complete Task 1 first.

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

- [ ] **Step 5a: `workflow_dispatch` smoke test against a real newer tag**

```bash
gh workflow run vendor-bump.yaml --repo bindreams/hole -f dep=v2ray-core -f tag=<next tag>
```

This only proves pull → finish → push works end-to-end on a disposable
scratch branch — `workflow_dispatch` runs push to a
`vendor-bump-manual/...` branch that never matches `push:`'s
`branches: ["renovate/**"]` filter, so no second `push` event, no PR, and
no Renovate involvement happens here. It cannot exercise the self-retrigger
guard (nothing to retrigger against) or auto-merge (no PR to arm). Confirm
only: the job succeeds, a new commit lands on the scratch branch, and
`ci.yaml` runs against it for real.

- [ ] **Step 5b: Confirm a real Renovate PR reaches auto-merge or a correctly-red PR, does NOT self-retrigger, and does NOT merge prematurely**

This is the load-bearing property the whole redesign rests on, and the one
thing Step 5a's `workflow_dispatch` path structurally cannot verify — it
needs a real `renovate/**`-branch PR. Either wait for Renovate's own
scheduled run to open one, or force it: push a branch named
`renovate/test-<dep>-<tag>` with only the target `.gitrepo`'s `branch =`
line changed (mimicking exactly what Renovate's own commit would contain),
then `gh pr create` from it.

Watch:

- Right after the PR opens (before `vendor-bump.yaml`'s `bump` job has run
  against it), `gh pr checks` should show `Test ex-ray (Go)` and `Lint`
  both pending/waiting, not passing — confirming auto-merge doesn't fire
  on Renovate's bare, not-yet-pulled commit.

- `gh pr view --json autoMergeRequest` shows auto-merge was armed (by
  Renovate/your test push, not by `vendor-bump.yaml` — it has no arming
  logic).

- Does `vendor-bump.yaml`'s own `push` trigger fire on this branch, does
  `bump` actually pull + push a real commit, does `ci.yaml` rerun on that
  new commit, and does `bump` run exactly once per push (confirm it does
  NOT loop on its own push — the self-retrigger guard).

- The PR either auto-merges (confirm via `gh pr view --json mergedAt` that
  the timestamp lands only after `bump`'s own push and its required
  checks went green on that specific commit, not the instant the PR
  opened) or sits correctly red/commented if `bump` hit a real problem.

- [ ] **Step 6: Confirm a real conflicted bump end-to-end**

Must also use a real `renovate/**`-branch PR (not `workflow_dispatch` —
the "Find the PR"/"Comment on the PR if conflicted" steps are gated on
`github.event_name == 'push'` and a real PR existing; a `workflow_dispatch`
run's scratch branch has no PR at all, per Step 5a, so it cannot exercise
this path). If a real conflict doesn't arise naturally, force one: manually
edit a line in `crates/ex-ray/third_party/v2ray-core/patched.go`-equivalent
(a file the ECH patch touches) on a `renovate/test-...` branch matching
what upstream's next release also changes. Confirm the PR gets the
conflict-explaining comment, the conflicted tree (with literal markers) is
committed and pushed, and CI goes red on it — both the `Lint` job (which
now includes `check-vendoring-integrity`'s conflict-marker scan) and, if
the markers land somewhere it compiles, `Test ex-ray (Go)` too. This is
the one code path (Task 4's `force_commit_conflicted`, called from the
"Commit the conflicted tree anyway" step) that has unit coverage but no
live-workflow coverage yet.

**Known residual gap, not addressed by this plan — surface to the user,
don't decide silently:** `check-vendoring-integrity`'s conflict detection
(Task 13) is marker-text-only. A delete/modify conflict (upstream deletes
a file our patch modifies, or vice versa) produces **no marker text at
all** — `force_commit_conflicted`'s `git add -A` simply stages whatever's
on disk (either a silently-resurrected upstream deletion, or a
silently-dropped local patch), which can pass every required check
(no markers, `VENDORING.md`/`go.mod` consistent, code still compiles) and
auto-merge cleanly despite being a botched resolution. Closing this
requires touching Task 4's already-shipped `force_commit_conflicted` (e.g.
a sentinel file marking "force-committed with unresolved paths," checked
by Task 13) — out of this revision's declared scope, not fixed here. Watch
for it if Step 6's forced conflict happens to land on a delete/modify
shape rather than a content conflict; file a tracking issue either way.

- [ ] **Step 7: File a tracking issue for `wix-hash-fixup.yaml`'s verification**

Task 10's fix can't be verified within this PR (it depends on Renovate's
own WiX-toolchain version-bump schedule, not something this plan controls)
— file a GitHub issue now to confirm on the next such PR that its fixup
commit gets a fresh CI run and can auto-merge, and link it here so this
doesn't silently fall through unverified.

______________________________________________________________________

### Task 13: `check-vendoring-integrity` xtask command + `prek` wiring

**Added after the rest of this plan was implemented and reviewed** — see
the Global Constraints and Task 8's rationale for why. Numbered last to
avoid renumbering already-completed Tasks 9-12, but it is a **prerequisite
for Task 12** (live verification depends on this check actually existing
and being wired into a required CI job) and should be executed before
Task 11 too (`VENDORING.md` documents it). Independent of Tasks 9 and 10 —
can run before or after either.

**Files:**

- Create: `xtask/src/check_vendoring_integrity.rs`
- Create: `xtask/src/check_vendoring_integrity_tests.rs`
- Modify: `xtask/src/lib.rs` (module + test-module declarations, `Command`
  variant, dispatch, wrapper)
- Modify: `prek.toml` (new local hook)

**Interfaces:**

- Consumes: `pull_subrepo::gitrepo_field` (already `pub(crate)`, Task 5's
  fix round), `git_util::run_git`, the `go mod edit -json` pattern
  `finish_vendor_bump.rs` already uses for parsing a `go.mod`'s `require`
  lines (reuse the same approach rather than a second hand-rolled parser).
- Produces: `check_vendoring_integrity::run(repo_root: &Path) -> Result<Vec<String>>` —
  returns a list of human-readable violation messages (empty = clean). A
  `Vec` of findings, not a single "the first thing that's wrong" error:
  a human resolving a conflict by hand benefits from seeing every problem
  at once, not fixing one and re-running to discover the next. Consumed
  by a thin CLI wrapper that prints each violation and exits non-zero if
  the list is non-empty.

**What it checks**, for every subdirectory directly under
`crates/ex-ray/third_party/` that contains a `.gitrepo` file (dynamic
discovery — do not hardcode `v2ray-core`/`utls` by name, matching
`finish_vendor_bump.rs`'s own directory-detection precedent for the
same reason: a third vendored dep must not need this file edited too):

1. **No merge-conflict markers.** For every file `git ls-files` reports as
   tracked under that dependency's directory, check for the three
   standard conflict-marker lines (`<<<<<<< `, `=======`, `>>>>>>> ` — the
   exact prefixes `git merge`/`git subrepo` write) at the start of a line.
   Report the file path and line number for every match found — don't
   stop at the first one, a conflicted pull can produce many. This is the
   one check that must see `force_commit_conflicted`'s literal
   marker-laden commits (the CI-only "commit despite conflicts" policy)
   as well as an ordinary unresolved conflict — both produce the same
   marker text. **Read each file as bytes (`std::fs::read`), not as a
   UTF-8 `String` (`std::fs::read_to_string`), and scan for the marker
   prefixes as byte sequences.** The real vendored trees already carry
   tracked binary files today (`crates/ex-ray/third_party/utls/logo.png`,
   `logo_small.png`, and several `testdata/Client-TLSv1*` raw TLS
   transcripts) — a UTF-8 read hard-errors on their content, and since
   this hook is `always_run` inside the already-required `Lint` job, that
   error would fail every PR in the repo, not just vendor-bump ones. A
   binary file cannot carry a text merge-conflict marker, so skip a file
   only if it fails to decode as UTF-8 at all *after* the byte-level
   marker scan finds nothing — never fail the check itself on decode
   errors.
1. **`VENDORING.md`'s noted version matches `.gitrepo`'s `branch`, and a
   discovered dep with no heading at all is itself a violation.** Parse
   `crates/ex-ray/third_party/VENDORING.md`'s heading for this dep (same
   `## \`<dep>/\` — pinned **<version>**`shape`finish_vendor_bump::update_vendoring_note_and_commit`writes — reuse its parsing logic if it's already factored out as a helper, or factor it out now if not, rather than a second hand-rolled parser for the same heading format) and compare against`gitrepo_field(contents,
   "branch")`. Report a clear mismatch message naming both values if they differ. **If the heading doesn't exist at all for a discovered dep, that absence is itself a reported violation — not a skip.** Unlike check 3 below (where a missing `go.mod`require line genuinely doesn't apply to every dep), a missing`VENDORING.md`heading is exactly the state a Renovate-bare, not-yet-pulled`.gitrepo`commit for a *brand new* third vendored dep would be in if this check treated it as not-applicable — silently passing would let auto-merge fire before`vendor-bump.yaml\` ever pulls anything, defeating the whole design (see
   Global Constraints).
1. **The outer `go.mod`'s require line matches `.gitrepo`'s `branch`, if
   one exists.** Not every vendored dep necessarily has a direct
   `require` line in `crates/ex-ray/go.mod` (it could be `// indirect`,
   or absent if nothing imports it directly) — read the vendored dep's
   own `go.mod` for its module path (same approach
   `finish_vendor_bump::read_module_path` uses — reuse it), then check
   whether `crates/ex-ray/go.mod` has *any* require line (direct or
   `// indirect`) for that module path. If it does, compare its version
   against `.gitrepo`'s `branch`; if it doesn't, this check simply
   doesn't apply to this dep (not a violation — `utls` is currently
   `// indirect` in the real `crates/ex-ray/go.mod`, confirm this
   fixture case is covered by a test).

**Test scenarios** (fixture-repo style, matching
`pull_subrepo/test_support.rs`'s/`finish_vendor_bump/test_support.rs`'s
established pattern — build a small real repo with a `.gitrepo`, a
`VENDORING.md`, and an outer `go.mod`, then run `check_vendoring_integrity::run`
against it for real, not a mock):

- A fully clean, consistent tree → empty violation list.

- Conflict markers present in a tracked file under the dep's directory →
  reported with file:line.

- Conflict markers in an *untracked* file under the dep's directory → NOT
  reported (matches `git ls-files`-scoped discovery, not a filesystem
  walk — an untracked scratch file is not this check's business).

- A tracked, non-UTF-8 binary file under the dep's directory (a real
  fixture with invalid UTF-8 bytes, matching the shape of the real
  `logo.png`/`testdata/Client-*` files) → no error, no false-positive
  violation, and the rest of the check still runs normally for that dep.

- `VENDORING.md`'s noted version doesn't match `.gitrepo`'s `branch` →
  reported, naming both values.

- A discovered dep (has a `.gitrepo`) with no `VENDORING.md` heading for
  it at all → reported as a violation, not skipped.

- The outer `go.mod` has a require line (direct) for the dep whose
  version doesn't match `.gitrepo`'s `branch` → reported.

- The outer `go.mod` has an `// indirect` require line that doesn't match
  → still reported (indirect vs. direct shouldn't matter to this check —
  either way it's a claim about the version in use).

- The outer `go.mod` has *no* require line at all for the dep (the
  `utls`-shaped case) → not reported as a violation; the other checks for
  that dep still run normally.

- Two vendored deps, one clean and one with a violation → only the
  violating one is reported; confirms per-dep isolation and the
  dynamic-discovery loop (not hardcoded to a single dep).

- A repo with zero vendored deps (no `.gitrepo` files under
  `third_party/`) → empty violation list, no error (this check is
  `always_run` in `prek`, so it executes on every commit in every repo
  state, including hypothetically none).

- [ ] **Step 1: Write the failing tests**, following the scenarios above.

- [ ] **Step 2: Run to verify they fail** (module doesn't exist yet).

- [ ] **Step 3: Implement**, per the spec above. Reuse existing helpers
  (`gitrepo_field`, `run_git`, the `go mod edit -json` pattern, `VENDORING.md`
  heading parsing, `read_module_path`) rather than duplicating any of
  them — if a needed helper isn't `pub(crate)` yet, make it so, matching
  how Task 5's fix round already did this for `gitrepo_field`.

- [ ] **Step 4: Run to verify they pass.**

- [ ] **Step 5: Wire the CLI**, mirroring the existing `Command` variants'
  pattern in `xtask/src/lib.rs` (module + test-module declarations,
  `Command::CheckVendoringIntegrity` with no arguments — it always
  operates on the whole repo — dispatch arm, and a wrapper that prints
  every violation and exits non-zero if the list is non-empty, exits 0
  with no output otherwise).

- [ ] **Step 6: Wire `prek.toml`**

Add a new local hook, modeled exactly on `check-workspace-lints`'s
existing pattern (`always_run = true`, `pass_filenames = false`,
`language = "system"`) so it performs its own file discovery and is
unaffected by the file's top-level `exclude` (which continues to protect
vendored code from every *other* hook, unmodified):

```toml
[[repos.hooks]]
id = "check-vendoring-integrity"
name = "check vendored deps for conflict markers and version drift"
entry = "cargo xtask check-vendoring-integrity"
language = "system"
pass_filenames = false
always_run = true
```

- [ ] **Step 7: Validate `prek.toml` + run the hook for real**

Run `cargo xtask run prek` (or `prek run check-vendoring-integrity --all-files`) against this repo's actual current state — expect it to
pass cleanly against the real `v2ray-core`/`utls` vendoring today. This is
the empirical check that the tool works against the real repo, not just
the fixtures.

- [ ] **Step 8: Run this repo's mandatory troyka code review** before
  considering the task done (per this repo's global instructions) — the
  spec above is a design, not grounded, verified code the way Tasks 2-5's
  sketches were after their own 5 review rounds; treat every fact above
  that you can verify empirically (e.g. the exact heading format, the
  exact conflict-marker prefixes, whether `crates/ex-ray/go.mod` really
  does carry an `// indirect` require for `utls` today) as a claim to
  check against the real repo, not an assumption to transcribe.

- [ ] **Step 9: Commit**

```bash
git add xtask/src/check_vendoring_integrity.rs xtask/src/check_vendoring_integrity_tests.rs xtask/src/lib.rs prek.toml
git commit -m "feat(xtask): add check-vendoring-integrity, wire into prek's already-required Lint job"
```
