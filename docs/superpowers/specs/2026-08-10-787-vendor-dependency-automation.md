# Automate vendored dependency bumps (#787)

## Problem

`crates/ex-ray/third_party/{v2ray-core,utls}` are vendored in-tree via
`git-subrepo`, each carrying small local ECH patches (see
`crates/ex-ray/third_party/VENDORING.md`). Bumping either to a new upstream
tag is manual today and has several documented gotchas: a squash-merge (this
repo always squash-merges and deletes branches) rewrites `.gitrepo`'s
recorded `parent`, so every `git subrepo pull` needs a mechanical fixup
before it will even attempt the merge; conflicts in `go.mod`/`go.sum`/
`.github/workflows/*` get resolved to upstream's version; real conflicts
(upstream touching a line our patch also touches) need a human.

Renovate can already do the trivial part (notice a new upstream tag) via a
`customManager`, same as it does for the WiX toolchain version string today.
What it can't do is the actual pull + patch-rebase + build-sanity work, or
push a result that still gets real CI — a workflow pushing with the default
`GITHUB_TOKEN` doesn't retrigger the `pull_request`/`push`-triggered
workflows that populate this repo's required status checks (GitHub's
anti-recursion behavior). This is a **latent bug already present** in
`.github/workflows/wix-hash-fixup.yaml`, which pushes its fixup commit with
`GITHUB_TOKEN` today.

## Goal

A PR shaped like Renovate's own PRs: opens automatically on a new upstream
tag, merges automatically if the pull/rebase/build all succeed and CI is
green, and sits open/red with a clear explanation if a real conflict or a CI
failure blocks it. No self-hosted server.

## Non-goals

- Converting `v2ray-core`/`utls` from git-subrepo (merge-based) vendoring to
  a patch-stack model. Only two small, localized patches exist today;
  revisit only if merge conflicts turn out to be frequent in practice.
- Tracking upstream `main`/head instead of tagged releases. Both upstreams
  cut regular semver tags and that's the standard Go-module consumption
  channel; `.gitrepo` already pins tags (`v5.52.0`, `v1.8.2`) today.
- A scheduled/self-polling workflow that bypasses Renovate. Would duplicate
  polling/scheduling infrastructure Renovate already provides for the rest
  of the dependency set, and remove these two deps from the Renovate
  dashboard, in exchange for a capability (recovering automatically while an
  older-version PR is stuck in conflict) that isn't needed — a stuck
  conflict PR is expected to wait for a human.

## Architecture

```
Renovate (hosted GitHub App)
  -> customManager bumps ONLY the `branch = vX.Y.Z` line in a .gitrepo
  -> opens/updates its normal PR on a renovate/** branch

vendor-bump.yaml (triggered by that push)
  -> auth: nathan-blahaj GitHub App installation token (NOT GITHUB_TOKEN)
  -> cargo xtask pull-subrepo <path> <new tag>
  -> on success: finish VENDORING.md's remaining steps (version note,
     go.mod bump + go mod tidy, identity build/test), commit
  -> on conflict: commit the conflicted tree as-is, comment on the PR
  -> push (App-token push -> retriggers ci.yaml/semantic-pr.yaml for real)

GitHub native auto-merge (armed by Renovate's platformAutomerge)
  -> merges once required checks are green on the new head SHA
  -> otherwise the PR just sits open, same as any other failing PR
```

Renovate itself goes fully dormant on that dependency the moment a
non-Renovate commit lands on the branch (confirmed behavior: it treats this
as manual edits and stops touching the branch/PR, and will not open a
second PR for an even-newer tag while the first sits unresolved — merging
or closing the stuck PR is what lets the next scheduled run pick up
whatever's newest at that point). That's the correct handoff: no race
between Renovate and the workflow.

## Component: the `nathan-blahaj` GitHub App

Purpose-generic name (not vendor-specific) since its role is "push automated
changes on my behalf and have CI actually run for them" — covers this
project and the `wix-hash-fixup.yaml` fix, and can be installed on other
repos (`galoshes`, `postern`) later without recreating it.

- Webhook: disabled. Used only to mint short-lived (1hr) installation
  tokens via `actions/create-github-app-token`; no server, no listener.
- Permissions: `Contents: Read & write`, `Pull requests: Read & write`.
  Nothing else.
- Installable on any account (so it's reusable later), but only actually
  installed on `bindreams/hole` for now.
- Secrets: `NATHAN_APP_ID`, `NATHAN_APP_PRIVATE_KEY`.

This is one-time manual setup (App creation + install + secrets) — not
something scriptable from CI.

## Component: Renovate config

Add a `customManager` to `.github/renovate.json`, one entry covering both
`.gitrepo` files (self-describing — reads `remote` from the same file, no
hardcoded repo names):

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

This edits **only** the `branch` line — `commit`/`parent` are deliberately
left for `vendor-bump.yaml` to fill in, mirroring the existing WiX
URL/hash split (`wix-toolchain.toml`'s customManager bumps the version
string; `wix-hash-fixup.yaml` derives the URL/hash). Default semver
versioning means a pre-release (e.g. v2ray-core's current `v5.53.0`
pre-release ahead of the `v5.52.0` stable tag) is not proposed — matches
existing manual practice of tracking stable tags only.

A `packageRules` entry groups these under their own label (not the generic
"one-PR-per-major" bucket) since, like WiX, each is its own review-worthy
event.

## Component: `cargo xtask pull-subrepo <path> <tag>`

A generic, human-usable primitive — no Renovate awareness, no CI-specific
behavior, no version-guessing (the caller decides `<tag>`). Lives alongside
the existing `xtask/src/upstream_v2ray.rs`-style modules.

1. If `git subrepo pull <path> -b <tag>` first fails with the "not an
   ancestor" squash-merge symptom — **the routine case, expected on every
   run given this repo's always-squash-merge-and-delete-branch policy** —
   take git-subrepo's suggested replacement `parent` SHA, verify it
   (`merge-base --is-ancestor` against HEAD, and against the
   currently-recorded `.gitrepo` `commit` so patch replay is correct),
   write it into `.gitrepo`, commit that fixup (pull refuses a dirty tree),
   retry.
   - Only if git-subrepo's *own suggested SHA* fails that verification —
     genuinely unusual, distinct from the routine squash-merge case above —
     abort with no changes made. This must stay the rare path; the spike
     below is what proves that.
1. Run the pull. Auto-resolve conflicts confined to `go.mod`/`go.sum`/
   `.github/workflows/*` to upstream's version (existing documented
   project policy, not a CI-only shortcut — a human running this manually
   wants the same behavior).
1. Any conflict remaining outside that allowlist: **stop, leave the tree
   exactly as `git pull` would** — unmerged paths present, nothing
   committed, clear message naming the conflicted files, nonzero exit. This
   tool never commits a conflicted tree; that decision belongs to whoever's
   driving it.

VENDORING.md's remaining step (version note, `go.mod` require bump +
`go mod tidy`, identity build/test) is deliberately **not** folded into
this tool — kept as separate, smaller mechanical steps (either a second
thin xtask helper or explicit workflow steps; decide in the implementation
plan).

## Component: `vendor-bump.yaml`

- Trigger: `push: branches: ["renovate/**"], paths: ["crates/ex-ray/third_party/*/.gitrepo"]`
  (same shape as `wix-hash-fixup.yaml`).
- Auth: `nathan-blahaj` installation token via `actions/create-github-app-token`.
- Steps: determine which `.gitrepo` changed and its new tag, run
  `cargo xtask pull-subrepo`, on success finish VENDORING.md's remaining
  step and commit, on failure (`pull-subrepo` exited nonzero, conflicted
  tree) commit the conflicted tree anyway (**this CI-only "commit despite
  conflicts" policy lives here, not in the xtask tool**) and `gh pr comment`
  explaining what's blocked and how to resolve locally. Push via the App
  token either way (except the parent-verification-abort case, which pushes
  nothing).

### End-to-end outcomes

| Outcome                                                        | What happens                                                                                                            |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Clean pull, clean build                                        | commit + push -> CI runs for real on the new head SHA -> auto-merges if green                                           |
| Clean pull, identity check/CI fails                            | commit + push anyway -> PR sits red like any other failing PR, no comment needed                                        |
| Merge conflict outside the allowlist                           | commit the conflicted tree anyway + push + PR comment naming the files and how to resolve locally                       |
| git-subrepo's suggested parent fixup fails verification (rare) | abort, no push, PR comment explaining why; Renovate's original branch-only-bump PR sits unfulfilled until a human looks |

## Component: `wix-hash-fixup.yaml` fix

Mechanical: swap the implicit `GITHUB_TOKEN` `actions/checkout` uses for a
`nathan-blahaj` installation token. Everything else (the `upgrade-wix`
script, the `git diff --quiet && exit 0` idempotency guard) is unchanged —
it already does the right thing, it just needs a push identity that
actually retriggers CI.

## Testing

- **Spike first, before any fixup logic is written**: verify
  `git subrepo pull`'s actual behavior against a fixture history that
  matches Hole's real pattern (squash-merge + delete branch), and
  separately from inside a linked worktree and with a dirty tree. Success
  criterion: the squash-merge parent-staleness fixup reliably auto-resolves
  every time (Level 1 in the design above) — if it doesn't, the "only goes
  red on real conflicts" property breaks (it'd go red on the routine case
  instead), and the design needs rethinking before proceeding.
- `xtask` integration tests for `pull-subrepo` against constructed fixture
  repos: clean pull, stale-parent pull (auto-fixed), allowlist-conflict
  (auto-resolved), real conflict (stops uncommitted, matches `git pull`
  semantics), dirty-tree rejection.
- Workflow-level behavior (App-token retrigger, native auto-merge,
  Renovate's dormancy on an edited branch) is not unit-testable — verified
  live, once, by watching a real bump go end-to-end to either auto-merge or
  a correctly red/commented PR.

## Idempotency / loop safety

App-token pushes are not exempt from retriggering `vendor-bump.yaml` itself
(unlike `GITHUB_TOKEN` pushes). This is safe by construction: re-running
`pull-subrepo` against an already-bumped `.gitrepo` is a no-op pull (nothing
new to merge), so no commit is made, nothing is pushed, and the retrigger
chain terminates after one harmless extra run. Same reasoning already holds
for `wix-hash-fixup.yaml`'s existing `git diff --quiet` guard.
