# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin support.

## Architecture

Single-binary design:

- **`hole`** — the only binary, serves as both the Tauri GUI and the privileged bridge depending on CLI arguments.
- GUI mode (no args): system tray, settings window, config management. Unprivileged.
- Bridge mode (`hole bridge run`): privileged service running as root/SYSTEM. Manages TUN, routing, shadowsocks-service.

GUI and bridge communicate over IPC (Unix socket on macOS, named pipe on Windows) using HTTP/1.1 REST (JSON), defined by an OpenAPI spec at `crates/common/api/openapi.yaml`.

### CLI

```
hole                              → GUI (default)
hole version                      → print version information
hole bridge run [--socket-path P] [--foreground] [--no-tun] → run as service/bridge (invoked by SCM/launchd)
hole bridge install               → register + start bridge service (needs elevation)
hole bridge uninstall             → stop + remove bridge service (needs elevation)
hole bridge status                → print install/running status
hole bridge log                   → print bridge log to stdout
hole bridge log path              → print log file path
hole bridge log watch [--tail N]  → stream log output
hole bridge grant-access [--then-send B64 | --then-send-file PATH] → add current user to hole group (needs elevation)
hole bridge ipc-send (--base64 B64 | --request-file PATH)          → proxy a single IPC command (needs elevation)
hole upgrade                      → check for updates and install latest version (unattended)
hole path add                     → add hole to system PATH
hole path remove                  → remove hole from system PATH
```

## Workspace layout

```
crates/common/   → hole-common (shared types: protocol, config, import)
crates/bridge/   → hole-bridge (bridge library, no binary)
crates/gui/      → hole-gui (Tauri app + CLI, binary name: "hole")
external/        → Third-party source (git subrepos)
msi-installer/   → WiX MSI installer (Python project: source, build script, tests)
scripts/         → Utility scripts
ui/              → Frontend HTML/CSS/TypeScript (Vite)
```

## Build

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow (hot-reload, foreground bridge mode).

Requires: Rust toolchain, Go toolchain (for v2ray-plugin), Node.js.

```sh
npm install                      # install frontend dependencies (first time only)
cargo build --workspace          # all crates (build.rs builds v2ray-plugin + downloads wintun)
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

Source icons are `crates/gui/icons/icon.svg` (app icon) and `crates/gui/icons/tray-{enabled,disabled}.svg` (tray icons). The build script (`build.rs`) converts them automatically. Do not commit generated raster icons.
