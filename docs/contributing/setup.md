# Set up and build

This page takes a machine with nothing on it to a first build and a first test run. It assumes Windows 11 on amd64 or
macOS; the commands are the same on both except where a tab says otherwise. `hole`, `hole-tests` and every target that
depends on them are built only on those, so on Linux or Windows on arm64 `cargo xtask build hole` is an error. Those
hosts build the other targets, such as ex-ray, galoshes and garter; `cargo xtask list` shows what each platform supports.

## Install the tools

| Tool                                                     | What needs it                                              | Which version                                                                                                                                                         |
| -------------------------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Git](https://git-scm.com)                               | the checkout; `cargo xtask` reads tags for versions        | any; on Windows, Git for Windows (see the Windows tab)                                                                                                                |
| [rustup](https://rustup.rs)                              | every Rust crate                                           | the `channel` in {src}`rust-toolchain.toml`, with the components it lists                                                                                             |
| [Go](https://go.dev/dl/)                                 | {term}`ex-ray`, which `cargo xtask deps` builds            | the `toolchain` directive in {src}`crates/ex-ray/go.mod`                                                                                                              |
| [Node.js](https://nodejs.org)                            | the front end (`ui/`), Vite, the WebDriver E2E             | the `engines.node` range in {src}`package.json`                                                                                                                       |
| [uv](https://docs.astral.sh/uv/)                         | the installer projects, `scripts/`, the docs build         | any recent                                                                                                                                                            |
| [cargo-nextest](https://nexte.st)                        | running the Rust tests                                     | at least `nextest-version` in {src}`.config/nextest.toml`                                                                                                             |
| [prek](https://prek.j178.dev)                            | the pre-commit hooks in {src}`prek.toml`                   | any recent                                                                                                                                                            |
| [git-subrepo](https://github.com/ingydotnet/git-subrepo) | only `cargo xtask`'s own tests, which drive `pull_subrepo` | the version CI installs (the `Install git-subrepo` step of {src}`.github/workflows/ci.yaml`); on macOS it needs Bash 4 or newer, which Apple's `/usr/bin/bash` is not |

````{tab-set}
---
sync-group: os
---
```{tab-item} Windows
:sync: windows

Rust on Windows links with the Microsoft C++ build tools. If you do not have Visual Studio, install the *Build Tools for
Visual Studio* with the **Desktop development with C++** workload before you run `rustup`.

[WebView2](https://developer.microsoft.com/microsoft-edge/webview2/) is the web engine the Tauri app draws with. Windows
11 ships it.

Install [Git for Windows](https://gitforwindows.org): `cargo xtask` runs the steps of {src}`build.yaml` with its Git Bash,
and with the one `HOLE_BUILD_BASH` names if you set it, and stops with an error if it finds neither. Run commands in
PowerShell or Git Bash. Building needs no elevation; running Hole in dev mode does (see
[Development](development.md)).
```

```{tab-item} macOS
:sync: macos

Install the Xcode command line tools (`xcode-select --install`) for the compiler and linker.

Running Hole in dev mode asks for your `sudo` password once, for the bridge only. Do not run `cargo xtask` itself under
`sudo`.
```
````

```{admonition} Rust and Go are exact pins
---
class: note
---
A new compiler release cannot turn `main` red on its own: Rust and Go are pinned to one version each, and Renovate
proposes a bump as its own pull request, never merged automatically. Node is a range, and `prek`, `nextest`, Python and
`uv` are installed unpinned in CI. If the same commit passes one day and fails the next, check those first.
```

## Build

From a fresh clone:

```sh
git clone https://github.com/bindreams/hole.git
cd hole
cargo xtask build hole
```

`cargo xtask` is a task runner that reads the build graph from {src}`build.yaml`. `build hole` builds what `hole` depends
on first (ex-ray, then {term}`galoshes`, and on Windows `wintun.dll`, downloaded and checksum-verified into `.cache/`),
then compiles the workspace in debug and stages the result into `target/debug/dist`. `cargo xtask list` prints every
target and the platforms it supports.

`cargo xtask deps` builds the same dependencies plus a pinned `golangci-lint`, and stops there.

The first run is slow, because it compiles ex-ray and the whole workspace. Later runs reuse Go's build cache and the
verified download.

To work on the front end, install its dependencies once:

```sh
npm install
```

If you edit `package.json`, commit the resulting `package-lock.json` in the same commit. CI runs a strict `npm ci`, and
rejects a lockfile that does not match.

## Run the tests once

```sh
cargo xtask run hole-tests
```

This is the canonical local test run: `cargo nextest` over the Hole crates, in the shape CI uses. Some of those tests
create a real TUN device and change the machine's routes and firewall, so they need administrator rights. A test that
lacks them fails and says so; it does not skip. To leave them out, set the label filter:

`````{tab-set}
---
sync-group: os
---
````{tab-item} Windows
:sync: windows

```powershell
$env:SKULD_LABELS = "!tun"
cargo xtask run hole-tests
```
````

````{tab-item} macOS
:sync: macos

```sh
SKULD_LABELS='!tun' cargo xtask run hole-tests
```
````
`````

[Testing](testing.md) explains the labels, and what else a test run needs.

## Install the hooks

```sh
prek install
```

installs git hooks of two types, `pre-commit` and `commit-msg` (`default_install_hook_types` in {src}`prek.toml`). The
hooks in `prek.toml` all run before a commit: formatting, Clippy with warnings denied, the Go linter, the docs build and
several repository checks. None uses the `commit-msg` stage, so no commit message is checked on your machine; the format
is checked on the pull request title ([Commit messages](commit-messages.md)). CI runs the same hooks, with Clippy as a
step of its own and the hooks split across runners as [Continuous integration](ci.md) describes.

## Next

- [The workspace](workspace.md) says where things are.
- [Development](development.md) runs Hole from your checkout.
- [Building in detail](build.md) covers the front-end toggle, the documentation checks and the hardened binaries.
