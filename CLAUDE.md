# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin support.

## Architecture

Single-binary design:

- **`hole`** — the only binary, serves as both the Tauri GUI and the privileged bridge depending on CLI arguments.
- GUI mode (no args): system tray, settings window, config management. Unprivileged.
- Bridge mode (`hole bridge run`): privileged service running as root/SYSTEM. Manages TUN, routing, shadowsocks-service.

GUI and bridge communicate over IPC (Unix socket on macOS, named pipe on Windows) using HTTP/1.1 REST (JSON), defined by an OpenAPI spec at `crates/common/api/openapi.yaml`.

### Bridge test-isolation contract

All production I/O in the bridge — shadowsocks tunnel lifecycle, routing table mutations, OS gateway introspection — routes through the `Proxy` and `Routing` traits in `crates/bridge/src/`. Helper types whose `Drop` impls perform cleanup must route that cleanup through trait methods, not through raw free functions. Compile-time enforcement lives in `clippy.toml` via the `disallowed_methods` list. See `crates/bridge/src/proxy.rs` and `crates/bridge/src/routing.rs` for trait contracts, and bindreams/hole#165 for the incident that motivated the rule.

### CLI

```
hole [--show-dashboard]           → GUI (default)
hole version                      → print version information
hole bridge run [--socket-path P] [--log-dir DIR] [--state-dir DIR] → run bridge (foreground, needs elevation)
hole bridge run --service [--log-dir DIR] [--state-dir DIR]         → run as service (invoked by SCM/launchd)
hole bridge install               → register + start bridge service (needs elevation)
hole bridge uninstall             → stop + remove bridge service (needs elevation)
hole bridge status                → print install/running status
hole bridge log [--log-dir DIR]   → print bridge log to stdout
hole bridge log path [--log-dir DIR] → print log file path
hole bridge log watch [--tail N] [--log-dir DIR] → stream log output
hole bridge grant-access [--then-send B64 | --then-send-file PATH] → create hole group, add user, write SID file (needs elevation)
hole bridge ipc-send (--base64 B64 | --request-file PATH)          → proxy a single IPC command (needs elevation)
hole proxy start --config-file PATH [--local-port PORT]            → start the proxy from a ServerEntry JSON file
hole proxy stop                                                    → stop the proxy
hole proxy test-server --config-file PATH                          → run a one-shot connectivity test against a server config
hole upgrade                      → check for updates and install latest version (unattended)
hole path add                     → add hole to system PATH
hole path remove                  → remove hole from system PATH
```

### Crash recovery

While a proxy is active, the bridge persists two small state files for
crash recovery, both in `<state_dir>/`:

- **`bridge-routes.json`** — records the installed TUN name, server IP,
  and upstream interface. Cleared on clean shutdown. On next startup,
  `routing::recover_routes` tears down any routes leaked by a previous
  crashed run.
- **`bridge-plugins.json`** — records the PIDs and start times of plugin
  processes (v2ray-plugin, galoshes) spawned by the bridge. Cleared on
  clean shutdown. On next startup, `plugin_recovery::recover_plugins`
  kills any tracked processes that are still alive (with PID-reuse
  safety via start-time verification). The same file is also read by the
  test harness (`DistHarness::drop`) to reap leaked plugins after tests.

Both recovery functions run *after* the IPC socket is bound. If the
in-bridge recovery fails or the process can't restart,
`scripts/network-reset.py` reads the route state file and performs an
equivalent cleanup from outside (plugin reaping by name as a last resort).

## Workspace layout

```
crates/common/   → hole-common (shared types: protocol, config, import)
crates/bridge/   → hole-bridge (bridge library, no binary)
crates/hole/     → hole (Tauri app + CLI + bridge entry point, binary name: "hole")
xtask/           → workspace task runner (`cargo xtask <stage|deps|version|...>`)
xtask-lib/       → shared helper crate used by xtask AND crates/hole/build.rs
external/        → Third-party source (git subrepos)
msi-installer/   → WiX MSI installer (Python project: thin wrapper around xtask + WiX)
scripts/         → Utility scripts (dev.py, network-reset.py, sign-release.py, ...)
ui/              → Frontend HTML/CSS/TypeScript (Vite)
```

Build orchestration is owned by `xtask/`. The canonical list of files that
go into the runnable BINDIR (next to `hole.exe`) lives in
[xtask/src/bindir.rs](xtask/src/bindir.rs); both `scripts/dev.py` and
`msi-installer` call `cargo xtask stage` instead of duplicating composition.
Runtime asset acquisition (v2ray-plugin Go build, wintun.dll download) lives
in `cargo xtask deps`. `crates/hole/build.rs` is restricted to compile-time
metadata (icon generation, git version via `xtask-lib::version`).

`cargo xtask stage --with-tests --tests-out-dir <dir>` additionally stages
workspace test binaries at stable paths (`<dir>/{crate}.test.exe`) so Windows
Firewall can cache consent across rebuilds (bindreams/hole#210). Convention:
`<dir>` is the sibling of `--out-dir` (e.g. `target/debug/dist/tests`). When
two cargo targets share a name (e.g. the `hole` crate's lib and bin), the
staged name is disambiguated to `{crate}-{kind}.test.exe`
(`hole-lib.test.exe` + `hole-bin.test.exe`).

## Build

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow (hot-reload, foreground bridge mode).

Requires: Rust toolchain, Go toolchain (for v2ray-plugin), Node.js.

```sh
npm install                      # install frontend dependencies (first time only)
cargo xtask deps                 # build v2ray-plugin from Go + download wintun (one-time, cached)
cargo build --workspace          # all crates
uv run scripts/dev.py            # dev mode (see CONTRIBUTING.md)
cargo test --workspace           # all tests
```

### Windows installer

```sh
uv run --directory msi-installer build       # builds hole.msi in target\release\
msiexec /i target\release\hole.msi           # interactive install
msiexec /i target\release\hole.msi /quiet    # unattended install
```

### macOS DMG

```sh
npx tauri build                  # produces .dmg in target/release/bundle/
```

## Testing

Uses [skuld](https://github.com/bindreams/skuld) framework (`#[skuld::test]`), not `#[test]`.
Unit test files are siblings: `foo.rs` → `foo_tests.rs`.

### Windows installer

```sh
cd msi-installer && uv run --group dev pytest -v   # WiX source + MSI build validation
```

## Releases

Release assets follow GOOS/GOARCH naming, OS first:

- `hole-{version}-windows-amd64.msi`
- `hole-{version}-darwin-arm64.dmg`
- `hole-{version}-darwin-amd64.dmg`

Each release also includes `SHA256SUMS` (hash manifest) and `SHA256SUMS.minisig` (minisign signature). The auto-updater matches assets by these suffixes and verifies integrity via the signed manifest.

### Release workflow

1. Trigger the **Draft Release** workflow with the version (e.g. `1.0.0`)
1. CI builds all platforms, creates a draft release with `SHA256SUMS`
1. Sign: `uv run scripts/sign-release.py v1.0.0`
1. Trigger the **Publish Release** workflow — verifies the signature, publishes the release (creates the git tag)

## Icons

Source icons are `crates/hole/icons/icon.svg` (app icon) and `crates/hole/icons/tray-{enabled,disabled}.svg` (tray icons). The build script (`build.rs`) converts them automatically. Do not commit generated raster icons.
