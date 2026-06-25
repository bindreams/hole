# Vendoring v2ray-core

`v2ray-core/` is a [git-subrepo](https://github.com/ingydotnet/git-subrepo) clone
of [v2fly/v2ray-core](https://github.com/v2fly/v2ray-core), pinned to **v5.51.2**.
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

A `bindreams/v2ray-core` GitHub fork is (or will be) created **only** as a review
and upstreaming surface. It is never referenced by `go.mod` and is never on the
build path. Keeping it in sync is a manual step done when a patch is ready for
human review or for proposing back to v2fly.

## Sync workflow

When a patch lands here and you want it reviewed / upstreamed:

1. Extract the in-tree delta vs pinned upstream (the commits on top of v5.51.2).
1. Apply that delta to a feature branch on the `bindreams/v2ray-core` fork.
1. Open a fork-internal PR (feature -> fork `main`) for human review.
1. If upstreaming, open a PR from the fork branch to `v2fly/v2ray-core`.

This is one-directional and by hand; the fork is downstream of the subrepo, not
the other way around.

## Bumping the pinned version

The pin is v5.51.2 (`.gitrepo` records the upstream commit). To move it:

1. `git subrepo pull crates/ex-ray/third_party/v2ray-core -b <new-tag>`
1. Re-apply / re-review any local patches against the new base (resolve conflicts).
1. Update the version note here and re-run the identity check: from
   `crates/ex-ray`, `go test ./...` plus `golangci-lint run` / `fmt --diff`.
