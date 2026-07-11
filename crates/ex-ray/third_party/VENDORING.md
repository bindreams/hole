# Vendoring

Two dependencies are vendored in-tree as
[git-subrepo](https://github.com/ingydotnet/git-subrepo) clones so ex-ray can
patch them for ECH robustness without waiting on upstream. Both are the build
truth via `go.mod` `replace` directives.

## `v2ray-core/` — pinned **v5.51.2** ([v2fly/v2ray-core](https://github.com/v2fly/v2ray-core))

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

The pins are recorded in each `.gitrepo`. To move one:

1. `git subrepo pull crates/ex-ray/third_party/<name> -b <new-tag>`
1. Re-apply / re-review the local patch against the new base (resolve conflicts).
   For utls, re-confirm the ECH-rejected verify still uses `c.serverName`.
1. Update the version note here and re-run the identity check: from
   `crates/ex-ray`, `go test ./...` plus the vendored `go test ./transport/...`.
