# Contributing to Hole

## Architecture overview

Hole is a single Rust binary (`hole`) that serves as both the GUI app and a privileged bridge:

- **GUI mode** (default, no args): Tauri desktop app with system tray and settings window. Unprivileged.
- **Bridge mode** (`hole bridge run`): Privileged service managing TUN device, routing, and shadowsocks. Runs as a Windows Service or macOS launchd bridge.

The GUI and bridge communicate over a local Unix domain socket using HTTP/1.1 REST (JSON), defined in `crates/common/api/openapi.yaml`.

### Build-time vs runtime tooling

The frontend (`ui/`) is HTML, CSS, and TypeScript. **Node.js is used only at build time** — it runs Vite (the bundler/dev server) and the TypeScript compiler. No Node.js process exists at runtime.

At runtime, Tauri embeds the OS's native webview (Edge WebView2 on Windows, WebKit on macOS) to render the frontend. The backend is pure Rust.

### Workspace layout

| Directory        | Crate/Purpose                                          |
| ---------------- | ------------------------------------------------------ |
| `crates/common/` | `hole-common` — shared types: protocol, config, import |
| `crates/bridge/` | `hole-bridge` — bridge library (no binary)             |
| `crates/gui/`    | `hole-gui` — Tauri app + CLI (binary name: `hole`)     |
| `external/`      | Third-party source (git subrepos)                      |
| `ui/`            | Frontend HTML/CSS/TypeScript (Vite)                    |

## Prerequisites

- Rust toolchain
- Go toolchain (for v2ray-plugin, built automatically by `build.rs`)
- Node.js (for frontend tooling)

## Development

### Running in dev mode

```sh
uv run scripts/dev.py
```

This builds the workspace, starts Vite, and launches the bridge + GUI with multiplexed, color-coded logs. Frontend changes (`ui/`) hot-reload instantly via Vite HMR. Rust changes require Ctrl+C and re-run.

### Manual workflow

If you prefer separate terminals or need more control:

**Terminal 1 — Bridge:**

```sh
cargo build
cp target/debug/hole $TEMP/hole-dev-bridge   # copy to avoid file lock (see below)
$TEMP/hole-dev-bridge bridge run --foreground --no-tun --socket-path $TEMP/hole-dev.sock
```

**Terminal 2 — Vite + GUI:**

```sh
npm run dev &                                          # Vite on port 1420
HOLE_BRIDGE_SOCKET=$TEMP/hole-dev.sock target/debug/hole
```

The bridge binary must be copied because it holds a file lock while running. Without the copy, `cargo build` would fail with "Access is denied" when you try to rebuild.

### Flags

- `--foreground`: bypasses the Windows Service / launchd dispatcher, runs directly in terminal with stderr logging at debug level
- `--no-tun`: skips TUN device and routing setup (no elevation needed, requires `--foreground`)
- `HOLE_BRIDGE_SOCKET`: tells the GUI to connect to a dev bridge at a custom socket path

### Notes

- `--foreground` without `--no-tun` still requires elevation (for TUN/routing). For most UI development, `--no-tun` is sufficient.
- Use absolute paths (like `$TEMP`) for `--socket-path` to avoid Windows AF_UNIX path length limits.
- The first build is slow (compiles v2ray-plugin from Go, downloads wintun on Windows, generates icons). Subsequent rebuilds are incremental.

## Testing

```sh
cargo test --workspace
```
