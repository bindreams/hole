# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin support.

## Architecture

Two-binary design:
- **`hole`** (Tauri GUI) — system tray, settings window, config management. Unprivileged.
- **`hole-daemon`** — privileged helper running as root/SYSTEM. Manages TUN, routing, shadowsocks-service.

They communicate over IPC (Unix socket on macOS, named pipe on Windows) using length-prefixed JSON.

## Workspace layout

```
crates/common/   → hole-common (shared types: protocol, config, import)
crates/daemon/   → hole-daemon (privileged daemon binary)
crates/gui/      → hole-gui (Tauri app, binary name: "hole")
ui/              → Frontend HTML/CSS/JS
```

## Build

```sh
cargo build --workspace          # all crates
npx tauri dev                    # GUI dev mode (from repo root)
cargo test --workspace           # all tests
```

## Testing

Uses [skuld](https://github.com/bindreams/skuld) framework (`#[skuld::test]`), not `#[test]`.
Unit test files are siblings: `foo.rs` → `foo_tests.rs`.

## Icons

Source icon is `crates/gui/icons/icon.svg`. The build script (`build.rs`) converts it to PNG/ICO/ICNS automatically. Do not commit generated raster icons.
