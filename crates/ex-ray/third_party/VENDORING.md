# Vendoring

Two dependencies are vendored in-tree as
[git-subrepo](https://github.com/ingydotnet/git-subrepo) clones so ex-ray can
patch them for ECH robustness without waiting on upstream. Both are the build
truth via `go.mod` `replace` directives.

## `v2ray-core/` — pinned **v5.52.0** ([v2fly/v2ray-core](https://github.com/v2fly/v2ray-core))

Patched so ex-ray's TLS engine survives real-world ECH:

- `retry_configs` re-dial and `ech=always` fail-closed on the standard engine;
- the **uTLS** fingerprint-mimicry engine carries ECH (so SNI concealment composes
  with a mimicked ClientHello), routed through the same fail-closed gate + retry.

## `utls/` — pinned **v1.8.2** ([refraction-networking/utls](https://github.com/refraction-networking/utls))

Patched so an ECH-rejection retry can succeed. On rejection, uTLS v1.8.2 verifies
the presented outer certificate against `config.ServerName` (the concealed inner
name) instead of the outer public_name, so it always aborts with a
`CertificateVerificationError` and never surfaces the `*utls.ECHRejectionError`
the `retry_configs` recovery needs — the uTLS ECH retry is dead against any real
rejecting server. The one-line patch restores stdlib's behavior (verify against
`c.serverName`, the public_name) in `handshake_client.go`'s ECH-rejected branch
only; the accepted-ECH branch still verifies the inner cert against the inner
name. This keeps outer-cert verification intact, so it is secure (no no-op /
skip-verify workaround): a forged rejection from an attacker without a valid
public_name cert still fails, and the retry that carries the real SNI is only
sent to an authenticated provider.

## Build truth

The in-tree copies are authoritative; nothing fetches the upstream modules or a
fork at build time. `crates/ex-ray/go.mod` (the main module for the binary)
redirects both:

```
replace github.com/v2fly/v2ray-core/v5    => ./third_party/v2ray-core
replace github.com/refraction-networking/utls => ./third_party/utls
```

Go only honors the *main* module's `replace` directives, and CI also builds
`v2ray-core` standalone (`cd third_party/v2ray-core && go test ./...`), so
`v2ray-core/go.mod` carries its own `replace ... => ../utls` for that invocation.
That second replace is a vendoring artifact, not part of the v2ray-core patch set.

Each subrepo's state (remote, upstream commit) lives in its `.gitrepo`. Both
trees are treated as pristine upstream code — excluded from this repo's linters
and formatters (`prek.toml` top-level `exclude`, `.golangci.yml`
`exclusions.paths`). Do not run our style tooling over them.

## The forks are mirrors, not dependencies

`bindreams/v2ray-core` and `bindreams/utls` GitHub forks exist **only** as review
and upstreaming surfaces. Neither is referenced by `go.mod` or on the build path.
Keeping a fork in sync is a manual step done when a patch is ready for review or
for proposing upstream.

## Sync workflow

When a patch lands here and you want it reviewed / upstreamed:

1. Extract the in-tree delta vs the pinned upstream (the commits on top of the pin;
   for utls, the `handshake_client.go` change — exclude the `go.mod` replace).
1. Apply that delta to a feature branch on the matching `bindreams/` fork.
1. Open a fork-internal PR (feature -> fork `main`) for human review.
1. If upstreaming, open a PR from the fork branch to the upstream repo.

One-directional and by hand; the fork is downstream of the subrepo, not the
other way around.

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
   from the repo root: `SKIP=check-vendoring-integrity git subrepo commit crates/ex-ray/third_party/<name>` — the `SKIP` is required if you have
   this repo's git hooks installed (the default): at this exact point
   `.gitrepo`'s `branch` names the new tag while this file and `go.mod`
   still name the old one (step 2 fixes that next), which the
   `check-vendoring-integrity` hook would otherwise correctly, but
   unhelpfully, reject.

   A conflicted commit (by either the automation or a human's own
   force-committed resolution) also carries a `.vendor-conflict` sentinel
   in the dep's own directory, listing every path that needs attention.
   `finish-vendor-bump` (step 2) clears it automatically once every listed
   path's content has genuinely changed since that commit — proof you
   actually touched it, not merely inherited whatever content was
   force-committed. If any listed path is unchanged, it refuses and names
   that path in its error, and the sentinel stays; no separate manual step
   is needed otherwise.

1. `cargo xtask finish-vendor-bump crates/ex-ray/third_party/<name> <name> <new-tag>`
   — updates this file's version note, bumps the outer `go.mod` require
   line and runs `go mod tidy`, and runs the same identity check
   `ci.yaml`'s "Test ex-ray (Go)" job runs (`build.yaml`'s `ex-ray-tests`
   target: `crates/ex-ray`'s own `go test ./...`, plus the scoped
   `transport/internet/{tls,quic,hysteria2,transportcommon}` test in the
   `v2ray-core` directory, unconditionally — including on a `utls` bump,
   since the ECH-retry patch's only coverage lives in that same scoped
   test), committing regardless of whether it passed.

1. `git push`. Auto-merge is already armed on the PR (Renovate arms it
   unconditionally at PR-creation time) and stays armed across your push,
   so nothing further is needed — it merges once
   the required checks (including `cargo xtask check-vendoring-integrity`)
   go green on your fix. If it somehow isn't armed, `gh pr merge --auto --squash <PR>` arms it yourself.
