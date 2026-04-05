# Contributing to Hole

## Architecture overview

Hole is a single Rust binary (`hole`) that serves as both the GUI app and a privileged daemon:

- **GUI mode** (default, no args): Tauri desktop app with system tray and settings window. Unprivileged.
- **Daemon mode** (`hole daemon run`): Privileged service managing TUN device, routing, and shadowsocks. Runs as a Windows Service or macOS launchd daemon.

The GUI and daemon communicate over a local Unix domain socket using HTTP/1.1 REST (JSON), defined in `crates/common/api/openapi.yaml`.

### Build-time vs runtime tooling

The frontend (`ui/`) is HTML, CSS, and TypeScript. **Node.js is used only at build time** — it runs Vite (the bundler/dev server) and the TypeScript compiler. No Node.js process exists at runtime.

At runtime, Tauri embeds the OS's native webview (Edge WebView2 on Windows, WebKit on macOS) to render the frontend. The backend is pure Rust.

### Workspace layout

| Directory        | Crate/Purpose                                          |
| ---------------- | ------------------------------------------------------ |
| `crates/common/` | `hole-common` — shared types: protocol, config, import |
| `crates/daemon/` | `hole-daemon` — daemon library (no binary)             |
| `crates/gui/`    | `hole-gui` — Tauri app + CLI (binary name: `hole`)     |
| `external/`      | Third-party source (git subrepos)                      |
| `ui/`            | Frontend HTML/CSS/TypeScript (Vite)                    |

## Prerequisites

- Rust toolchain
- Go toolchain (for v2ray-plugin, built automatically by `build.rs`)
- Node.js (for frontend tooling)

## Development

### First-time setup

```sh
npm install
```

### Running in dev mode

```sh
uv run scripts/dev.py
```

This builds the workspace, then launches the daemon and GUI with multiplexed, color-coded logs. Frontend changes (`ui/`) hot-reload instantly via Vite HMR. Rust changes require Ctrl+C and re-run.

Alternatively, run them in separate terminals:

**Terminal 1 — Daemon:**

```sh
cargo build
cargo run -- daemon run --foreground --no-tun --socket-path $TEMP/hole-dev.sock
```

- `--foreground`: bypasses the Windows Service / launchd dispatcher, runs directly in terminal
- `--no-tun`: skips TUN device and routing setup (no elevation needed)
- The daemon logs to stderr at debug level in foreground mode

**Terminal 2 — GUI + Frontend** (Vite HMR):

```sh
HOLE_DAEMON_SOCKET=$TEMP/hole-dev.sock npx tauri dev --no-watch
```

- `HOLE_DAEMON_SOCKET` tells the GUI to connect to the dev daemon instead of the production one
- Vite serves the frontend with hot module replacement
- `--no-watch` skips Rust file watching (rebuild manually when needed)

### Notes

- `--foreground` without `--no-tun` still requires elevation (for TUN/routing). For most UI development, `--no-tun` is sufficient.
- Use absolute paths (like `$TEMP`) for `--socket-path` to avoid Windows AF_UNIX path length limits.
- The first build is slow (compiles v2ray-plugin from Go, downloads wintun on Windows, generates icons). Subsequent rebuilds are incremental.

## Testing

```sh
cargo test --workspace
```
