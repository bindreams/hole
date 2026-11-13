# Building in detail

[Set up and build](setup.md) gets you a first build. This page covers what you need when that is not enough: choosing a
target, the front-end toggle, the documentation checks, the staged directory and the hardened binaries.

## Targets

{src}`build.yaml` is the one description of the build graph. Each target has a build step, an optional run step and the
targets it depends on. `cargo xtask build <target>` builds a target and its dependencies. `cargo xtask run <target>`
builds the same, then runs it; a run never depends on another run. `cargo xtask list` prints every target and the
platforms it supports.

A few targets to know (`cargo xtask list` has the rest):

- `hole`: builds the workspace in debug and stages it into `target/debug/dist`; its run step is dev mode
  ([Development](development.md)).
- `hole-tests`: builds the Hole test binaries without running them; its run step is the canonical `cargo nextest` run.
- `hole-msi`, `hole-dmg`: the Windows installer and the macOS disk image ([The installers](installers.md)).
- `doc-hole`, `doc-ex-galoshes`: rustdoc with warnings denied, for the crates each platform builds. `doc-hole` is for
  Windows on amd64 and macOS, `doc-ex-galoshes` for Linux and Windows on arm64; the other one is an error on a host.
- `prek`: every pre-commit hook over all files except Clippy, which the `clippy-hole` and `clippy-ex-galoshes` targets
  run.
- The per-crate `*-tests` targets (`garter-tests`, `util-tests` and so on): the crates outside the Hole test lane.

`cargo xtask build hole` and `hole-tests` do not build a release. A release build is `hole-msi` or `hole-dmg`, which run
their own release compile.

## The front-end toggle

`crates/hole` has two build modes, chosen by a Cargo feature:

- **Production** (the default, `tauri/custom-protocol`): the webview loads the front end bundled into the binary, so
  the build embeds `ui/dist/` and fails if it is missing.
- **Dev** (`--no-default-features`): the webview loads Vite's dev server (the `devUrl` in {src}`crates/hole/tauri.conf.json`), and `ui/dist/` is not
  needed.

The `hole` and `hole-tests` targets build in dev mode. `hole-msi` and `hole-dmg` build in production mode and depend on
`frontend-build`, which creates `ui/dist/`.

```{warning}
If you run Cargo yourself, pass `--no-default-features` (for dev) or run `cargo xtask build frontend-build` first. The
build script checks only that `ui/dist/` exists, so an empty directory satisfies it, and a production build from that
tree ships a blank dashboard without an error. Never create an empty `ui/dist/` to get a build or a lint through. The
pre-commit Clippy hook and CI's `clippy-hole` both use `--no-default-features`.
```

## Documentation checks

CI builds rustdoc with warnings denied. The commands are the `doc-hole` and `doc-ex-galoshes` targets in
{src}`build.yaml`: libraries and binaries in separate `cargo doc` runs (a plain `cargo doc` skips a binary named like its
crate's library), with `--document-private-items` for every crate except `garter`. `garter` is published, so docs.rs
builds it without private items and its docs may not link one.

A link to an item that is compiled out on some platform, or only under `#[cfg(test)]`, breaks the check on the platforms
where it is absent. Write such a reference in backticks without brackets.

The reasons for each flag are in the module doc of {src}`xtask/src/doc_targets_tests.rs`, which also fails when a
target of a workspace crate is documented by no command.

## The staged directory

`cargo xtask stage` copies a runnable set of files (the BINDIR) into a directory: `hole`, the `ex-ray` and `galoshes`
plugins, debug symbols (`hole.pdb` on Windows, `hole.dSYM` on macOS) and, on Windows, `wintun.dll`. It matches what the
installer puts in `Program Files\hole\bin`.

It exists because on Windows the running bridge locks its own executable, so a bridge cannot run from Cargo's `target/`
directory and be rebuilt. The plugins must sit beside the bridge: a foreground bridge looks there, unless `--plugin-dir`
names another folder.

The list of files, per OS, is one function: `bindir_entries` in {src}`xtask-lib/src/bindir.rs`. The installer manifests
are checked against it, and `cargo xtask bindir-names [--os OS] [--bundle]` prints it as JSON.

## Hardened binaries

The shipped Rust binaries (`hole`, `galoshes`, `garter`) call `libsearch_guard::bins()` in their `build.rs`. On Windows
that has three effects:

- the VC runtime is linked statically. The MSI ships no Visual C++ redistributable, so a dynamic import would stop the
  program starting on a machine without one;
- the loader is told to search System32 only for the executable's imports, so a DLL planted beside the executable is not
  loaded;
- before `main`, the process is told to search System32 only for every `LoadLibrary` call made without flags,
  including calls made inside system DLLs.

`wintun.dll` is loaded by absolute path in {src}`crates/tun-engine/src/device/wintun.rs` before the `tun` crate asks for
it by bare name, and that later request resolves to the module already loaded. Any other DLL a binary needs must be loaded
by absolute path too. ex-ray is a Go binary and is not hardened on Windows.

`libsearch_guard::verify` fails a binary that imports a VC runtime DLL or opts into searching the executable's folder
(on Linux and macOS: `$ORIGIN`, `@executable_path`, `@rpath`). It runs in two places:

- the crates' own tests, on their debug binaries (`hardened_binary.rs` in `crates/hole` and `crates/galoshes`,
  `garter_is_hardened` in `crates/garter-bin`);
- `cargo xtask stage-release`, on the files a release uploads, so the bytes verified are the bytes shipped. The check is
  on the directory an installer is built from, not on the MSI or DMG itself.

Which files are executables, and which toolchain builds each, is stated once per file in `bindir_entries`.
