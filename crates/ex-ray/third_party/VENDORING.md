# Vendoring v2ray-core

`v2ray-core/` is a [git-subrepo](https://github.com/ingydotnet/git-subrepo) clone
of [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core), pinned to **v5.52.0**.
It exists so ex-ray can patch v2ray-core's TLS engine for ECH robustness
(`retry_configs` re-dial, `ech=always` fail-closed) without waiting on upstream.

## Build truth

This in-tree copy is the build truth. `crates/ex-ray/go.mod` redirects the
dependency to it:

```
replace github.com/v2fly/v2ray-core/v5 => ./third_party/v2ray-core
```

CI and local builds compile this source; there is no external build dependency
on a fork or on the upstream module. The subrepo state (remote, upstream commit)
lives in `v2ray-core/.gitrepo`.

The vendored tree is treated as pristine upstream code: it is excluded from this
repo's linters and formatters (`prek.toml` top-level `exclude`,
`.golangci.yml` `exclusions.paths`). Do not run our style tooling over it.

## The fork is a mirror, not a dependency

The [`bindreams/v2ray-core`](https://github.com/bindreams/v2ray-core) GitHub fork
exists **only** as a review and upstreaming surface. It is never referenced by
`go.mod` and is never on the build path; keeping it in sync is a manual,
one-directional step (the fork is downstream of the subrepo). It carries two
first-party patches, extracted on the current pin:

- **`getcertpool-nil-safety`** — guards a nil `*Config` receiver in `getCertPool`
  (reachable: `GetTLSConfig` calls it before its own `if c == nil` check). Fork
  PR: [bindreams/v2ray-core#2](https://github.com/bindreams/v2ray-core/pull/2).
  Its regression test (`config_nil_{other,windows}_test.go`) also lives in-tree.
- **`ech-fail-closed-retry`** — the ECH fail-closed gate + `retry_configs`
  recovery (RFC 9849). It depends on the getCertPool fix (the fail-closed client
  factory exercises the nil-receiver path), so it is **stacked** on it. Fork PR:
  [bindreams/v2ray-core#3](https://github.com/bindreams/v2ray-core/pull/3).

## Sync workflow

Patches are reviewed against a dedicated **review base** on the fork, not the
fork's `master` (which tracks upstream and would swamp the diff):

1. Create `hole/<tag>` on the fork = the pinned upstream tag + **one** labeled
   `ci: enable fork CI` commit (drops the linter's `github.repository` fork-guard
   so lint runs; drops the secret-only codecov step). Head branches off this base,
   so the CI commit never appears in a PR diff.
1. Branch one feature per patch off `hole/<tag>` — or, for a dependent patch, off
   the branch it depends on — and apply that patch's delta only.
1. Open a fork-internal PR per patch targeting its base, so each diff is exactly
   the patch. On a `pull_request` event GitHub runs the workflow from the
   head-merged base, so lint/tests run with the fork-guard lifted.
1. Drive v2ray-core's own `test.yml` + `linter.yml` green. Validate via `lint`,
   the cross-compile `build` matrix, the patched-package tests, and the macOS
   `test` job — v5.52.0's heavy `testing/scenarios` integration suite is flaky on
   hosted runners, independent of any patch.
1. If upstreaming, reuse the patch branch and PR body against `v2fly/v2ray-core`.

This is one-directional and by hand; the fork is downstream of the subrepo, not
the other way around.

## Bumping the pinned version

The pin is v5.52.0 (`.gitrepo` records the upstream commit). To move it:

1. `git subrepo pull crates/ex-ray/third_party/v2ray-core -b <new-tag>`
1. Re-apply / re-review any local patches against the new base (resolve conflicts).
1. Update the version note here and re-run the identity check: from
   `crates/ex-ray`, `go test ./...` plus `golangci-lint run` / `fmt --diff`.
