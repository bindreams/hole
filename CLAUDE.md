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
hole daemon run                   → run as service/daemon (invoked by SCM/launchd)
hole daemon install               → register + start daemon service (needs elevation)
hole daemon uninstall             → stop + remove daemon service (needs elevation)
hole daemon status                → print install/running status
hole daemon log                   → print daemon log to stdout
hole daemon log path              → print log file path
hole daemon log watch [--tail N]  → stream log output
hole path add                     → add hole to system PATH
hole path remove                  → remove hole from system PATH
```

## Workspace layout

```
crates/common/   → hole-common (shared types: protocol, config, import)
crates/daemon/   → hole-daemon (daemon library, no binary)
crates/gui/      → hole-gui (Tauri app + CLI, binary name: "hole")
installer/       → WiX MSI installer source (Windows)
scripts/         → Build and utility scripts
ui/              → Frontend HTML/CSS/JS
```

## Build

```sh
cargo build --workspace          # all crates
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

## Icons

Source icon is `crates/gui/icons/icon.svg`. The build script (`build.rs`) converts it to PNG/ICO/ICNS automatically. Do not commit generated raster icons.
