# Releasing

Hole is released as four independent products, each with its own version, tag and GitHub release. This page is for the
person who cuts one: what a release ships, the two workflows that make it, and what each checks before it lets the
release through. Taking a release back is [Rollback](rollback.md).

## The four tracks

A **track** is one product's line of releases. Its tag is `releases/<product>/v<X.Y.Z>`, and a release's files are named
`<product>-<version>-<os>-<arch>[.ext]`.

| Product    | What the release ships                                                                    | Signed   | crates.io |
| ---------- | ----------------------------------------------------------------------------------------- | -------- | --------- |
| `hole`     | The MSI and an update archive for windows/amd64; a DMG and an update archive for each Mac | minisign | No        |
| `galoshes` | The binary, on six platforms                                                              | No       | No        |
| `garter`   | The crates.io library and the `garter` binary on six platforms                            | No       | `garter`  |
| `ex-ray`   | The binary, on six platforms                                                              | No       | No        |

Every release also carries `SHA256SUMS`. The six platforms are `windows`, `linux` and `darwin`, each on `amd64` and
`arm64`. Windows has an installer for `amd64` only: there is no arm64 MSI. {src}`xtask/src/stage_release.rs` (`plan`) is
the one definition of which files a release ships, and `cargo xtask release-assets --tag <tag>` prints the list.

Only `hole` is signed, because it updates itself: the app and the bridge check each download against the signed
`SHA256SUMS` ([key rotation](minisign-key-rotation.md) covers the key). `hole`'s files carry `ex-ray` and `galoshes`, so
its signature covers those copies. The standalone `ex-ray`, `galoshes` and `garter` files are not signed, and the
`SHA256SUMS` beside them is a checksum list only. `garter`'s binary is not inside `hole`.

Each track's versions live in its crates' `[package.metadata.hole-release].group`, and in
{src}`crates/ex-ray/version.toml` for ex-ray; [The workspace](../workspace.md) says how the groups work, and
`cargo xtask version` checks them. Release tags are strict `X.Y.Z`. A tag from before the scheme, `v0.1.0`, is ignored.

## Cutting a release

1. Merge the change that sets the new version to `main`. A draft refuses a commit that is not an ancestor of `main`.
1. Run **Draft Release (`<product>`)** from the Actions tab with the version, e.g. `0.8.0`. It runs all of CI on that
   commit, then creates a *draft* GitHub release with the files CI tested. Nothing is public yet.
1. For `hole` only: sign the draft with `uv run scripts/sign-release.py <version>`. It downloads the draft's
   `SHA256SUMS`, checks that it lists every asset exactly once, signs it with `minisign` and uploads
   `SHA256SUMS.minisig`.
1. Read the draft's notes and files, then run **Publish Release (`<product>`)** with the same version.

The split is deliberate: the draft does everything that can be undone, and publishing does what cannot (the tag, `cargo publish`, the latest-release flip). Publishing re-checks that the release is still a draft and, for `hole`, that
`SHA256SUMS` verifies against the signature. The tag exists only once the release is published, so deleting a draft
removes everything it made.

The notes are built from the commit subjects since the track's previous tag ([Commit
messages](../commit-messages.md)): the highest-versioned release tag of that track that is an ancestor of the commit.
Only commits that touched a file matching the track's `include_paths` in `.github/release-<product>.yaml` are listed, so a
release whose notes look empty touched none of them. The first release of a track prints the config's `initial_release`
text instead. A Downloads table follows, made from the same file list the draft checks.

### `/releases/latest` belongs to hole

Each draft sets `--latest` when it creates the release (`true` for `hole`, `false` for the rest), and publishing sets it
again. Left to itself, GitHub picks the latest release by a semver-and-date heuristic that can promote another product's
release.

## What a draft guarantees

A draft ships what CI tested, because it ships the files the tests ran on and builds nothing itself.

```{dropdown} How a draft is made
The `validate` job of {src}`.github/workflows/reusable-draft-release.yaml` checks that the commit
is on `main` ({src}`.github/actions/verify-release-commit-on-main/action.yaml`), normalizes the version, tags it locally and runs
`cargo xtask version --check --exact --group <product>`, which fails unless the declared version equals the tag. Then it
calls {src}`.github/workflows/ci.yaml` on that commit with `release-tag` set. The call has its own concurrency group, so
two drafts never cancel each other.

Each CI leg creates the tag locally before it builds, so the binaries carry the release version. Right after the tests of
the files a tag's product ships, the leg stages them with `cargo xtask stage-release --lane msi|dmg|plugins` (steps
`release-stage-*` in `ci.yaml`; the DMG stages after the install-and-connect test as well). A leg that passes uploads
`release-<product>-<os>-<arch>`.

The `release` job needs all of CI to have passed. It checks that the downloaded files are exactly what
`cargo xtask release-assets --tag <tag>` lists ({src}`.github/actions/check-release-assets/action.yaml`), hashes them into
`SHA256SUMS`, builds the notes and uploads.
```

Staging checks the files it copies ({src}`xtask/src/stage_release.rs`):

- The Windows update archive is packed from the MSI's payload directory, `target/release/installer-stage`, not from
  `target/release`.
- `hole.exe version` and `garter --version` must print the tag's version, so a build of a dirty tree, which stamps
  `X.Y.Z.dirty`, fails. `garter --help` must exit 0. The galoshes and ex-ray versions are not checked.
- `stage-release` stages only the checkout's own build. The DMG tests take the DMG from `DMG_UNDER_TEST` and the MSI
  tests the MSI from `MSI_UNDER_TEST`, defaulting to the release build's single `.dmg` and to `target/release/hole.msi`;
  a relative path is from the repository root, in the Python harnesses and in xtask alike. The update archive and the
  version probe come from the checkout's build, so `stage-release` refuses a variable that names any other file.

## Publishing garter

`garter` is the one product that also goes to crates.io. [Publishing garter](garter-crates-io.md) covers how, and what
to do when it fails.

## Before a `hole` release

[Ship blockers and stated limits](ship-blockers.md) lists conditions under which a `hole` release must not go out, and
shortfalls that ship on purpose. Read it before running a `hole` draft.
