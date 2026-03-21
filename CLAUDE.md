# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin support.

## Architecture

Single-binary design:
- **`hole`** — the only binary, serves as both the Tauri GUI and the privileged daemon depending on CLI arguments.
- GUI mode (no args): system tray, settings window, config management. Unprivileged.
- Daemon mode (`hole daemon run`): privileged service running as root/SYSTEM. Manages TUN, routing, shadowsocks-service.

GUI and daemon communicate over IPC (Unix socket on macOS, named pipe on Windows) using length-prefixed JSON.

### CLI

```
hole                              → GUI (default)
hole version                      → print version information
hole daemon run                   → run as service/daemon (invoked by SCM/launchd)
hole daemon install               → register + start daemon service (needs elevation)
hole daemon uninstall             → stop + remove daemon service (needs elevation)
hole daemon status                → print install/running status
hole daemon log                   → print daemon log to stdout
hole daemon log path              → print log file path
hole daemon log watch [--tail N]  → stream log output
hole daemon grant-access [--then-send B64] → add current user to hole group (needs elevation)
hole daemon ipc-send --base64 B64          → proxy a single IPC command (needs elevation)
hole upgrade                      → check for updates and install latest version (unattended)
hole path add                     → add hole to system PATH
hole path remove                  → remove hole from system PATH
```

## Workspace layout

```
crates/common/   → hole-common (shared types: protocol, config, import)
crates/daemon/   → hole-daemon (daemon library, no binary)
crates/gui/      → hole-gui (Tauri app + CLI, binary name: "hole")
external/        → Third-party source (git subrepos)
installer/       → WiX MSI installer source (Windows)
scripts/         → Build and utility scripts
ui/              → Frontend HTML/CSS/JS
```

## Build

Requires: Rust toolchain, Go toolchain (for v2ray-plugin).

```sh
cargo build --workspace          # all crates (build.rs builds v2ray-plugin + downloads wintun)
npx tauri dev                    # GUI dev mode (from repo root)
cargo test --workspace           # all tests
```

### Windows installer

```powershell
.\scripts\build-installer.ps1    # builds hole.msi in target\release\
msiexec /i target\release\hole.msi          # interactive install
msiexec /i target\release\hole.msi /quiet   # unattended install
```

### macOS DMG

```sh
npx tauri build                  # produces .dmg in target/release/bundle/
```

## Testing

Uses [skuld](https://github.com/bindreams/skuld) framework (`#[skuld::test]`), not `#[test]`.
Unit test files are siblings: `foo.rs` → `foo_tests.rs`.

## Releases

Release assets follow GOOS/GOARCH naming, OS first:
- `hole-{version}-windows-amd64.msi`
- `hole-{version}-darwin-arm64.dmg`
- `hole-{version}-darwin-amd64.dmg`

The auto-updater matches assets by these suffixes.

## Icons

Source icon is `crates/gui/icons/icon.svg`. The build script (`build.rs`) converts it to PNG/ICO/ICNS automatically. Do not commit generated raster icons.
