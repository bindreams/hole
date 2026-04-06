# Contributing to Hole

## Architecture overview

Hole is a single Rust binary (`hole`) that serves as both the GUI app and a bridge to a remote shadowsocks server:

- **GUI mode** (default, no args): Tauri desktop app with system tray and settings window. Unprivileged.
- **Bridge mode** (`hole bridge run`): Manages TUN device, routing, and the shadowsocks connection. Foreground by default; runs as a system service (Windows SCM or macOS launchd) when invoked with `--service`.

The GUI and bridge communicate over a local Unix domain socket using HTTP/1.1 REST (JSON), defined in `crates/common/api/openapi.yaml`.

### Build-time vs runtime tooling

The frontend (`ui/`) is HTML, CSS, and TypeScript. **Node.js is used only at build time** — it runs Vite (the bundler/dev server) and the TypeScript compiler. No Node.js process exists at runtime.

At runtime, Tauri embeds the OS's native webview (Edge WebView2 on Windows, WebKit on macOS) to render the frontend. The backend is pure Rust.

### Workspace layout

| Directory        | Crate/Purpose                                                |
| ---------------- | ------------------------------------------------------------ |
| `crates/common/` | `hole-common` — shared types: protocol, config, logging      |
| `crates/bridge/` | `hole-bridge` — bridge library (TUN/routing/shadowsocks/IPC) |
| `crates/gui/`    | `hole-gui` — Tauri app + CLI (binary name: `hole`)           |
| `external/`      | Third-party source (git subrepos)                            |
| `ui/`            | Frontend HTML/CSS/TypeScript (Vite)                          |

### Logging

Both the GUI and the bridge always write logs to stderr **and** a rolling daily file. The default log directory is `dirs::state_dir()/hole/logs` (user-local, no elevation needed):

- Windows: `%LOCALAPPDATA%\hole\logs\`
- macOS: `~/Library/Application Support/hole/logs/`

Log files are `gui.log` and `bridge.log` respectively. When running the bridge as a service (`hole bridge install`), the service installer passes `--log-dir` pointing to a system path:

- Windows: `C:\ProgramData\hole\logs\`
- macOS: `/var/log/hole/`

### State files (crash recovery)

While a proxy is active, the bridge writes `bridge-routes.json` to its state directory recording the installed TUN name, server IP, and upstream interface. On next startup the bridge reads this file (after a successful IPC bind) to clean up any routes leaked by a previous crashed run. The file is removed on clean shutdown.

Default state directory:

- Windows: `%LOCALAPPDATA%\hole\state\`
- macOS: `~/Library/Application Support/hole/state/`
- Service (Windows): `C:\ProgramData\hole\state\`
- Service (macOS): `/var/db/hole/state/`
- `scripts/dev.py` passes an explicit `--state-dir` pointing at `$TMPDIR/hole-dev/state` so the file is easy to find.

If the dev bridge is killed before clean shutdown and your internet breaks, run `scripts/network-reset.py` (it reads the same state file and performs the equivalent cleanup).

## Prerequisites

- Rust toolchain
- Go toolchain (for v2ray-plugin, built automatically by `build.rs`)
- Node.js (for frontend tooling)

## Development

### Running in dev mode

Dev mode creates a **real TUN interface** and modifies the routing table — it matches the production bridge code path. This requires elevation:

```sh
# Windows: from an elevated PowerShell
uv run scripts/dev.py

# macOS
sudo uv run scripts/dev.py
```

This builds the workspace, starts Vite, and launches the bridge + GUI with multiplexed, color-coded logs. Frontend changes (`ui/`) hot-reload instantly via Vite HMR. Rust changes require Ctrl+C and re-run.

On macOS, `dev.py` detects `SUDO_USER` and drops privileges for the GUI and Vite subprocesses (via POSIX `setuid`/`setgid` + `extra_groups`) so they read your real `~/Library` config while the bridge inherits root. On Windows, UAC elevation is token-based, so all subprocesses naturally share the same user identity — no drop is needed.

Before starting the bridge, `dev.py` invokes `hole bridge grant-access` to create the `hole` group, add your user to it, and (on Windows) write the installer-user-SID file. The bridge then uses the production `IpcServer::bind` + `apply_socket_permissions` path — the same DACL/group/SDDL code that runs in the installed service. Dev exercises this path on every run.

If the dev process crashes or is killed and your internet breaks, run `scripts/network-reset.py` — also requires elevation — to recover. It reads the same state file the bridge writes and targets the exact leaked routes.

Dev mode does **not** remove you from the `hole` group on exit (same as production: once granted access you keep it until `hole bridge uninstall`, which deletes the group). This means re-running `dev.py` after a crash is a no-op on the group-add step.

On macOS, `dseditgroup` membership changes are reflected in `getgrouplist` immediately for newly-spawned processes in the normal case. If DirectoryService has cached the old membership (rare; seen on heavily-loaded systems or across user sessions), the dropped GUI may report "permission denied" when connecting to the dev socket. Re-running `dev.py` refreshes the cache; logging out and back in forces it.

### Manual workflow

If you prefer separate terminals or need more control:

**Terminal 1 — Bridge (elevated):**

```sh
# From an elevated PowerShell (Windows) or under sudo (macOS)
cargo build
cp target/debug/hole $TEMP/hole-dev-bridge             # copy to avoid file lock (see below)
$TEMP/hole-dev-bridge bridge grant-access              # create hole group, add user
$TEMP/hole-dev-bridge bridge run \
    --socket-path $TEMP/hole-dev.sock \
    --state-dir $TEMP/hole-dev-state
```

**Terminal 2 — Vite + GUI (unelevated):**

```sh
npm run dev &                                          # Vite on port 1420
HOLE_BRIDGE_SOCKET=$TEMP/hole-dev.sock target/debug/hole
```

The bridge binary must be copied because it holds a file lock while running. Without the copy, `cargo build` would fail with "Access is denied" when you try to rebuild.

### Flags

- `hole bridge run` defaults to foreground mode, logging to stderr + file. **Requires elevation** for TUN/routing.
- `--service`: register with the Windows Service / macOS launchd dispatcher. The service installer passes this automatically.
- `--log-dir DIR`: override the default log directory.
- `--state-dir DIR`: override the default route-state directory (crash-recovery file).
- `--socket-path PATH`: override the default IPC socket location.
- `HOLE_BRIDGE_SOCKET` env var: tells the GUI to connect to a dev bridge at a custom socket path.

### Notes

- Running `hole bridge run` requires elevation (for TUN/routing). `scripts/dev.py` enforces this at startup.
- Use absolute paths (like `$TEMP`) for `--socket-path` to avoid Windows AF_UNIX path length limits.
- The first build is slow (compiles v2ray-plugin from Go, downloads wintun on Windows, generates icons). Subsequent rebuilds are incremental.

## Testing

```sh
cargo test --workspace
```
