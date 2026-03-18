# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin support for macOS and Windows.

## Features

- **Transparent proxy** via TUN interface — zero config for all apps, including those that ignore system proxy settings
- **SOCKS5 proxy** on port 4073 for advanced users
- **DNS leak prevention** — all DNS traffic routed through the tunnel
- **System tray** — Enable/Disable, Start at Login, Settings, Exit
- **Server import** — import from shadowsocks client config files (single and multi-server)
- **v2ray-plugin** support (built from source)
- **Logging** with daily rotation

## Architecture

Single-binary design — `hole` serves as both the Tauri GUI and the privileged daemon depending on CLI arguments:

| Mode | Privilege | Role |
|---|---|---|
| `hole` (no args) | User | Tauri GUI — system tray, settings window, config management |
| `hole daemon run` | Root / SYSTEM | Privileged helper — TUN, routing, shadowsocks-service |

Communication happens over IPC (Unix socket on macOS, named pipe on Windows) using length-prefixed JSON.

## Build

Prerequisites: Rust toolchain, Go toolchain, Node.js (for Tauri CLI and E2E tests).

```sh
# Build all crates (build.rs automatically builds v2ray-plugin from source
# and downloads wintun.dll on Windows)
cargo build --workspace

# Run GUI in dev mode
npx tauri dev

# Run all tests
cargo test --workspace
```

## Project layout

```
crates/
  common/    hole-common — shared types (protocol, config, import)
  daemon/    hole-daemon — privileged daemon library
  gui/       hole-gui    — Tauri app + CLI (binary name: "hole")
external/
  v2ray-plugin/  v2ray-plugin source (git subrepo)
installer/   WiX MSI installer source (Windows)
ui/          Frontend HTML/CSS/JS
scripts/     Build and maintenance scripts
tests/       E2E test specs (WebDriverIO)
```

## Testing

Unit tests use the [skuld](https://github.com/bindreams/skuld) framework. Test files are siblings to their source files (`foo.rs` → `foo_tests.rs`).

```sh
cargo test --workspace           # all unit tests
npm run test:e2e                 # E2E tests (requires release build)
```

## Emergency network reset

If routing gets into a bad state during development:

```sh
# macOS
sudo python scripts/network-reset.py

# Windows (run as Administrator)
python scripts/network-reset.py
```

## License

TBD
