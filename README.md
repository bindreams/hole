# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin support for macOS and Windows.

## Features

- **Transparent proxy** via TUN interface — zero config for all apps, including those that ignore system proxy settings
- **SOCKS5 proxy** on port 4073 for advanced users
- **DNS leak prevention** — all DNS traffic routed through the tunnel
- **System tray** — Enable/Disable, Start at Login, Settings, Exit
- **Server import** — import from shadowsocks client config files (single and multi-server)
- **v2ray-plugin** support (bundled)
- **Logging** with daily rotation

## Architecture

Two-binary design for privilege separation:

| Binary | Privilege | Role |
|---|---|---|
| `hole` | User | Tauri GUI — system tray, settings window, config management |
| `hole-daemon` | Root / SYSTEM | Privileged helper — TUN, routing, shadowsocks-service |

Communication happens over IPC (Unix socket on macOS, named pipe on Windows) using length-prefixed JSON.

## Build

Prerequisites: Rust toolchain, Node.js (for Tauri CLI and E2E tests).

```sh
# Download v2ray-plugin and wintun binaries
python scripts/fetch-v2ray-plugin.py

# Build all crates
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
  daemon/    hole-daemon — privileged daemon binary
  gui/       hole-gui    — Tauri app (binary name: "hole")
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
