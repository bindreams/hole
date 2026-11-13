# The workspace

Hole is one Cargo workspace plus a Go module and a front end. This page says what each directory holds, which release
group it belongs to, and how {term}`galoshes` ends up carrying {term}`ex-ray`.

## What is where

A **release group** is a set of crates that share one version and are released together, as `releases/<group>/v<X.Y.Z>`
tags. A crate names its group in `[package.metadata.hole-release].group`, and `cargo xtask version` checks it. There are
four groups: `hole`, `garter`, `galoshes` and `ex-ray`. The ex-ray group has no `Cargo.toml`: its version is
{src}`crates/ex-ray/version.toml`.

A crate with `publish = false` is never pushed to crates.io. Of the Rust crates only `garter` is published. Licenses are
on the [licensing page](../reference/licensing.md).

| Directory                             | Group      | What it is                                                                                      |
| ------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------- |
| `crates/hole/`                        | `hole`     | The `hole` binary: Tauri app, command line, and the bridge entry point                          |
| `crates/bridge/`                      | `hole`     | The bridge as a library: TUN, routing, Shadowsocks, IPC, DNS                                    |
| `crates/common/`                      | `hole`     | Types shared by the app and the bridge: protocol, config, import, logging                       |
| `crates/tun-engine/`                  | `hole`     | The TUN device, OS routing and the packet loop                                                  |
| `crates/tun-engine-macros/`           | `hole`     | The `#[freeze]` macro `tun-engine` uses                                                         |
| `crates/dump/`, `crates/dump-macros/` | `hole`     | A YAML-shaped representation for logs, and its derive                                           |
| `crates/handle-holders/`              | `hole`     | Which processes hold a handle to a file                                                         |
| `crates/test-observability/`          | `hole`     | Dev-dependency: installs the test log subscriber and panic hook                                 |
| `crates/garter/`                      | `garter`   | Runs a chain of {term}`SIP003 plugin`s; on crates.io. Also holds the `mock-plugin` test fixture |
| `crates/garter-bin/`                  | `garter`   | The `garter` command-line binary                                                                |
| `crates/galoshes/`                    | `galoshes` | The galoshes plugin: a multiplexed transport with ex-ray embedded                               |
| `crates/ex-ray/`                      | `ex-ray`   | The first-party Go plugin, built on v2ray-core, with that code vendored under `third_party/`    |
| `crates/file-lock/`                   |            | `Exclusive`, a file lock that is safe in a directory another user can write                     |
| `crates/tombstone/`                   |            | Records a native crash so the next start can report it                                          |
| `crates/stepstool/`                   |            | Elevation: sudo priming and wrapping on macOS, elevation detection on Windows                   |
| `crates/util/`                        |            | Small shared pieces: port allocation, retry, directory handles                                  |
| `crates/payload-archive/`             |            | Packs and unpacks the update payload                                                            |
| `crates/plugin-e2e/`                  |            | Test harness: a real Shadowsocks server and the plugin round trips                              |
| `crates/dev-console/`                 |            | The dev-mode supervisor (see [Development](development.md))                                     |
| `xtask/`, `xtask-lib/`                |            | `cargo xtask`, and the helper crate it shares with build scripts                                |
| `build.yaml`                          |            | The build graph `cargo xtask build`, `run` and `list` read                                      |
| `msi-installer/`, `dmg-installer/`    |            | The Windows and macOS installers, in Python (see [The installers](installers.md))               |
| `ui/`, `scripts/`, `tests/`           |            | The front end (Vite), utility scripts, and the WebDriver end-to-end specs                       |

## How galoshes carries ex-ray

galoshes embeds the ex-ray executable at compile time, so the two must be built in that order:

1. `cargo xtask ex-ray` builds ex-ray from Go into `.cache/ex-ray/`.
1. {src}`crates/galoshes/build.rs` hashes that file and passes its path and SHA-256 to the compiler as `EX_RAY_PATH` and
   `EX_RAY_SHA256`. If the file is missing, galoshes still compiles, and the build prints a warning.
1. At run time {src}`galoshes <crates/galoshes/src/embedded.rs>` writes ex-ray to its runtime directory
   (`$XDG_RUNTIME_DIR/galoshes` when set, else a per-user cache directory) and verifies its hash. It replaces an existing
   file that does not match, and refuses to run if the embedded bytes do not match the compiled-in hash. It also
   refuses a directory mounted `noexec`.

`cargo xtask build` follows this order for you, because `galoshes` depends on `ex-ray` in {src}`build.yaml`.

## Client TLS in ex-ray must fail closed on ECH

When `ech=always` is set, ex-ray must not send a ClientHello that names the real server in clear text. The vendored
`third_party/v2ray-core` enforces this with two factories in `transport/internet/tls/config.go`:

- `GetTLSConfigForClient` for transports that can carry {term}`ECH`. It fails when `ech=always` is set and no ECH
  config could be obtained.
- `GetTLSConfigForUnsupportedClient` for engines that cannot (uTLS, hysteria2). It refuses `ech=always`, and warns on
  `ech=auto`.

Every client dial path takes its config from one of them. The bare `GetTLSConfig` belongs to server listeners. The one
client-side exception is the retry after the server rejects ECH and supplies a replacement config list: that path
builds the bare config and sets the non-empty list itself, so it cannot produce a clear-text name.

Two things keep this true. The `ech=always` round trips in {src}`crates/plugin-e2e/tests/roundtrip.rs` check that an
unreachable ECH resolver refuses the tunnel, and the `ex-ray-tests` target (`cargo xtask run ex-ray-tests`) runs ex-ray's Go
tests and those of the vendored `tls`, `quic`, `hysteria2` and `transportcommon` packages. Neither covers the case that a merge of upstream v2ray-core
brings back a bare `GetTLSConfig` on a client path, because the vendored tree is excluded from the linters. After every
such merge, search the client dial paths for it.
