# Contributing to Hole

Product overview and install live in [README.md](README.md). This file holds what
the contributor docs do not: releases, icons and the emergency network reset.
How to set up, build, run and test Hole is in
[docs/contributing/](docs/contributing/index.md).

## Architecture

How Hole is put together is in the contributor docs, starting at
[the architecture overview](docs/contributing/architecture/overview.md).

## Releases

Four independent tracks, each tagged `releases/<product>/v<X.Y.Z>`. Each has a
draft+publish workflow pair: the **draft** workflow does all reversible prep
(build, test, hash, upload to a draft release); the **publish** workflow does the
irreversible public actions (tag, `cargo publish`, latest-flip). The split exists
to keep one sanity gate before irreversible work.

| Product    | Artifacts                                     | Signed   | crates.io |
| ---------- | --------------------------------------------- | -------- | --------- |
| `hole`     | MSI + DMG (amd64+arm64) + `SHA256SUMS`        | minisign | No        |
| `galoshes` | 6-platform binaries + `SHA256SUMS`            | No       | No        |
| `garter`   | crates.io lib + 6-platform CLI + `SHA256SUMS` | No       | `garter`  |
| `ex-ray`   | 6-platform binaries + `SHA256SUMS`            | No       | No        |

Asset naming is `<product>-<version>-<os>-<arch>[.ext]`.

- **Only `hole` is signed** — it auto-updates, so supply-chain integrity matters.
  The others are embedded into hole (covered by its signature) or built from
  source by consumers who pin SHA256 against `SHA256SUMS`.
- **`/releases/latest` pinning** — each draft pins `--latest` at
  `gh release create` (`hole=true`, others `false`); without it GitHub's legacy
  semver+date heuristic can promote the wrong track (#308).
- **garter publish is idempotent** — it queries crates.io and skips `cargo publish` if the version exists; a `dry_run` input runs `--dry-run` only.
- **garter publishes by trusted publishing** — no stored token. crates.io's
  trusted publisher for `garter` names repository `bindreams/hole` and workflow
  `publish-release-garter.yaml` (the caller, not the reusable workflow). crates.io
  matches the top-level workflow, so a call through `workflow_call` from another
  workflow is refused unless that one is registered too.
- **garter publishes against crates.io's `cosca`** — the workspace pins a registry
  version, so `cargo package` accepts the dependency.
- **Versions** live in each crate's `[package.metadata.hole-release].group`
  (ex-ray in `crates/ex-ray/version.toml`); validate with `cargo xtask version [--check --group <name> [--exact]]` (release CI uses `--exact`). The legacy
  `v0.1.0` tag predates the scheme and is ignored.
- **A draft ships what CI tested.** Every draft workflow checks that its commit is
  an ancestor of `main` (`.github/actions/verify-release-commit-on-main`), then calls
  `ci.yaml` on it with `release-tag` set (the call has its own concurrency group, so
  two drafts never cancel each other). Each leg creates the tag locally before
  building, so the binaries carry the release version, and stages what the tag's
  product ships right after the tests of those files (the DMG after the
  install-and-connect test as well)
  (`cargo xtask stage-release --lane msi|dmg|plugins`, steps `release-stage-*`; see
  `xtask/src/stage_release.rs`). Only a passing leg uploads
  `release-<track>-<os>-<arch>`; the draft job needs the whole of CI to have passed, checks
  (`.github/actions/check-release-assets`) that the downloaded files are exactly what
  `cargo xtask release-assets --tag <tag>` lists, builds the release notes'
  Downloads table from the same list, then hashes and uploads the files; it builds
  nothing.
- **What staging requires.** The Windows update zip is packed from
  `target/release/installer-stage` (the MSI's payload directory), not from
  `target/release`. `hole.exe version` and `garter --version` must print the tag's
  version, so a build of a dirty tree (`X.Y.Z.dirty`) fails; `garter --help` must
  exit 0. The galoshes and ex-ray versions are not checked.
- **Installer under test.** The DMG tests take the DMG from `DMG_UNDER_TEST`
  (default: the release build's single `.dmg`), the MSI lifecycle tests the MSI from
  `MSI_UNDER_TEST` (default: `target/release/hole.msi`). A relative path in either
  variable is from the repo root, in the Python harnesses and in xtask alike.
  `stage-release` stages only this checkout's own build (the update archive and the
  `hole.exe` probe come from it), so it refuses a variable that names any other
  file.

Rollback, minisign key rotation, and the crates.io dry-run TOCTOU note are in
[RELEASE-OPS.md](RELEASE-OPS.md).

## Icons

Source icons under `crates/hole/icons/` are per-platform SVGs
(`icon-{windows,macos}.svg`, `tray-windows-{light,dark}.svg`, `tray-macos.svg`),
converted to raster by `build.rs` (cached in `.cache/icons/`) — **do not commit
generated raster icons**. `TrayState::Disabled` currently aliases `Enabled` (the
enum is preserved for a future variant). `.cache/icons/icon.ico` is bound by the
MSI as `ARPPRODUCTICON` so Add/Remove Programs matches the app icon (#359).

The macOS tray icon is a [template image]: alpha-only shape, RGB=0, inverted by
the OS to match the menu bar. Runtime icon updates must use
`set_icon_with_as_template(icon, true)` — `TrayIcon::set_icon` hardcodes
`icon_is_template=false` (tray-icon 0.23.1) and turns the icon solid black on
the first state change; `set_icon`/`set_icon_as_template` (tauri and inner
`tray_icon` layers) are clippy-banned (#469).

## Emergency network reset

If routing gets into a bad state during development:

```sh
sudo python scripts/network-reset.py    # macOS
python scripts/network-reset.py         # Windows (run as Administrator)
```

It reads the bridge's route-state file and tears down the exact leaked routes
(reaping plugins by name and stopping ETW sessions as a last resort).

[template image]: https://developer.apple.com/documentation/appkit/nsimage/1520017-template
