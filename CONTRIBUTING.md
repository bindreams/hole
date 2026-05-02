# Contributing to Hole

## Architecture overview

Hole is a single Rust binary (`hole`) that serves as both the GUI app and a bridge to a remote shadowsocks server:

- **GUI mode** (default): Tauri desktop app with system tray and settings window. Unprivileged.
- **Bridge mode** (`hole bridge run`): Manages TUN device, routing, and the shadowsocks connection. Foreground by default; runs as a system service (Windows SCM or macOS launchd) when invoked with `--service`.

The GUI and bridge communicate over a local Unix domain socket using HTTP/1.1 REST (JSON), defined in `crates/common/api/openapi.yaml`.

### Build-time vs runtime tooling

The frontend (`ui/`) is HTML, CSS, and TypeScript. **Node.js is used only at build time** — it runs Vite (the bundler/dev server) and the TypeScript compiler. No Node.js process exists at runtime.

At runtime, Tauri embeds the OS's native webview (Edge WebView2 on Windows, WebKit on macOS) to render the frontend. The backend is pure Rust.

### Workspace layout

| Directory        | Crate/Purpose                                                                            |
| ---------------- | ---------------------------------------------------------------------------------------- |
| `crates/common/` | `hole-common` — shared types: protocol, config, logging                                  |
| `crates/bridge/` | `hole-bridge` — bridge library (TUN/routing/shadowsocks/IPC)                             |
| `crates/hole/`   | `hole` — Tauri app + CLI + bridge entry point (binary name: `hole`)                      |
| `xtask/`         | workspace task runner (`cargo xtask <build\|test\|list\|stage\|...>`) — see `build.yaml` |
| `xtask-lib/`     | shared helper crate used by xtask AND `crates/hole/build.rs`                             |
| `external/`      | Third-party source (git subrepos)                                                        |
| `ui/`            | Frontend HTML/CSS/TypeScript (Vite)                                                      |

### Logging

Both the GUI and the bridge always write logs to stderr **and** a 10 MiB rotating file (one rotated backup kept). The default log directory is `dirs::state_dir()/hole/logs` (user-local, no elevation needed):

- Windows: `%LOCALAPPDATA%\hole\logs\`
- macOS: `~/Library/Application Support/hole/logs/`

Log files are `gui.log` and `bridge.log` respectively. When running the bridge as a service (`hole bridge install`), the service installer passes `--log-dir` pointing to a system path:

- Windows: `C:\ProgramData\hole\logs\`
- macOS: `/var/log/hole/`

**WebView2 / Chromium logs.** Tauri's embedded WebView2 runtime on Windows carries its own Chromium logging facility that writes directly to the inherited stderr handle without going through our `tracing` subscriber. These lines arrive in Chromium's native `[MMDD/HHMMSS.mmm:LEVEL:file:line]` format instead of ours. The FD-level stdio safety net set up in [`crates/common/src/logging.rs`](crates/common/src/logging.rs) catches them: the reader thread tees each line to (a) a `tracing` event with target `hole::stderr_relay`, which the file layer records into `gui.log`, and (b) the saved-original stderr handle, which preserves dev-terminal visibility (`scripts/dev.py` reprints them with a `[client]` prefix). Chromium lines therefore *do* end up in `gui.log` and on the dev-mode terminal, just in Chromium's format rather than ours. If you see one, it is a real Chromium log record — investigate the underlying cause rather than reaching for a filter. See [#144](https://github.com/bindreams/hole/issues/144) for a worked example (the dashboard close lifecycle that triggered `Failed to unregister class Chrome_WidgetWin_0. Error = 1412`).

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
- Go toolchain (for v2ray-plugin, built by `cargo xtask deps`)
- Node.js ≥24 (constraint pinned via `engines.node` in [package.json](package.json); current Active LTS)

### npm dependency management

`scripts/dev.py` runs `npm install`, which updates `package-lock.json` to match `package.json` whenever the two have drifted. PR-time CI runs `npm ci` via the `frontend-build` xtask target, which is strict — it fails if `package-lock.json` and `package.json` are inconsistent. **If you modify `package.json` directly, commit the resulting `package-lock.json` change in the same commit, or CI will reject the PR.** Renovate handles routine npm updates automatically (see [.github/renovate.json](.github/renovate.json)).

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

Windows (elevated PowerShell):

```powershell
cargo xtask build hole                                                    # deps + cargo build (debug) + stage to target/debug/dist
cargo xtask stage --profile debug --out-dir "$env:TEMP\hole-dev-manual"   # per-session BINDIR (hole.exe + sidecars + wintun.dll)
& "$env:TEMP\hole-dev-manual\hole.exe" bridge grant-access                # create hole group, add user
& "$env:TEMP\hole-dev-manual\hole.exe" bridge run `
    --socket-path "$env:TEMP\hole-dev.sock" `
    --state-dir   "$env:TEMP\hole-dev-state"
```

macOS (under sudo):

```sh
cargo xtask build hole                                                    # deps + cargo build (debug) + stage to target/debug/dist
cargo xtask stage --profile debug --out-dir "$TMPDIR/hole-dev-manual"     # per-session BINDIR (hole + sidecars)
"$TMPDIR/hole-dev-manual/hole" bridge grant-access                        # create hole group, add user
"$TMPDIR/hole-dev-manual/hole" bridge run \
    --socket-path "$TMPDIR/hole-dev.sock" \
    --state-dir   "$TMPDIR/hole-dev-state"
```

`cargo xtask build hole` walks the `build.yaml` DAG: it builds v2ray-plugin
(Go), galoshes (workspace member), downloads wintun on Windows, then runs
`cargo build --workspace` (debug) and `cargo xtask stage --profile debug --out-dir target/debug/dist`. Use `cargo xtask list` to print the full target
table; `cargo xtask build|test --all` builds or runs every target applicable
to the host platform.

**Terminal 2 — Vite + GUI (unelevated):**

Windows (PowerShell):

```powershell
npm run dev                                            # Vite on port 1420 (run in its own terminal)
$env:HOLE_BRIDGE_SOCKET = "$env:TEMP\hole-dev.sock"
target\debug\hole.exe
```

macOS (bash):

```sh
npm run dev &                                          # Vite on port 1420
HOLE_BRIDGE_SOCKET=$TMPDIR/hole-dev.sock target/debug/hole
```

`cargo xtask stage` populates a directory with `hole.exe`, `v2ray-plugin.exe`, and (on Windows) `wintun.dll` — the same layout as the installed MSI in `Program Files\hole\bin\`. The canonical file list lives in [xtask/src/bindir.rs](xtask/src/bindir.rs); adding a new BINDIR file is a one-line change there and both `dev.py` and `msi-installer` pick it up automatically. The bridge binary must be staged out of the cargo target dir because the running bridge holds a file lock on its own exe — without staging, the next `cargo build` would fail with "Access is denied". The `v2ray-plugin` sidecar must be a sibling of the bridge so [resolve_plugin_path_inner](crates/bridge/src/proxy.rs) finds it.

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
- The first run of `cargo xtask deps` is slow (compiles v2ray-plugin from Go, downloads wintun on Windows). Subsequent runs are near-instant: Go's build cache short-circuits, and the wintun download is sha256-sentineled. Icons are generated by `crates/hole/build.rs` on every cargo build but cached in `.cache/icons/`.

## Testing

```sh
cargo test --workspace
```

### Avoiding Windows Firewall prompts on every rebuild

Bridge tests bind a TCP listener on all interfaces (for TUN routing), so Windows Firewall prompts for "allow access to local networks" when the test binary starts. Cargo names test binaries `target/debug/deps/hole_bridge-{hash}.exe` with a content-hash suffix that churns on every rebuild, so Firewall never caches consent. On a fullscreen-capable setup the prompt also closes fullscreen apps.

To approve once and never again:

```sh
cargo xtask stage --with-tests \
    --out-dir target/debug/dist/bin \
    --tests-out-dir target/debug/dist/tests
./target/debug/dist/tests/hole_bridge.test.exe   # approve the prompt once
```

Test execution may report failures on that first run — individual tests aren't the point here. The goal is simply for `hole_bridge.test.exe` to bind its socket so Windows Firewall shows the prompt against a path that won't churn.

Subsequent `cargo xtask stage --with-tests` runs reuse the same stable path, so Firewall consent persists. Re-run the staging command after each source change — the staged binary does not update automatically. When two cargo targets share a name (e.g. the `hole` crate's lib and bin), dest names get disambiguated to `hole-lib.test.exe` / `hole-bin.test.exe`. See bindreams/hole#210.

### Investigating Windows CI flakes

When Windows CI fails with a timeout in `server_test_tests` or loopback connects time out unexpectedly, work through these steps IN ORDER before proposing any timeout bump. bindreams/hole#165 was debugged for multiple hours because these steps were not documented — the bug was a unit test that shelled out to `netsh` via an RAII guard that bypassed the backend trait.

1. **If the failure is `PermissionDenied` / `WSAEACCES` / os error 10013 on a socket bind**, the retry in [`hole_common::port_alloc::free_port`](crates/common/src/port_alloc.rs) handles the common case. Also matched: `AddrInUse` / `AddrNotAvailable`. Terminal failure after the internal retry budget means the machine's TCP or UDP excluded-port range covers most of the dynamic range. Inspect with `netsh int ipv4 show excludedportrange tcp`, `netsh int ipv4 show excludedportrange udp`, `netsh int ipv6 show excludedportrange tcp`, `netsh int ipv6 show excludedportrange udp`, and `netsh int ipv4 show dynamicportrange tcp`. Hyper-V / WSL / Docker Desktop are the typical reservation sources. See bindreams/hole#253 and bindreams/galoshes#21 for the cross-protocol mechanism.

1. **If the failure is `Access is denied (os error 5)` on spawn**, grep the log for `file-lock holder`. `DistHarness::spawn` retries three times with 500 ms exponential backoff on file-contention errors, and on terminal failure calls `handle_holders::log_holders` to enumerate processes holding `hole.exe` (see bindreams/hole#208). Expect `MsMpEng.exe` (Windows Defender) as the typical culprit. If no holders appear but the spawn still fails, Defender is PPL-protected and our non-`SeDebugPrivilege` enumeration skipped it — the `info!` line "file-lock holder enumeration skipped PIDs we couldn't open" is the tell.

1. **Grep the failing test output for `routing subprocesses` or `netsh|route add|route delete`.** The #165 fix added a regression test (`proxy_manager_tests_never_spawn_routing_subprocess`) that prints `"proxy_manager start/stop cycles spawned N routing subprocesses"` and asserts `N == 0`. If that assertion fires, a new code path has bypassed the `Routing` trait — find the new `Drop` impl or helper that calls the free `routing::setup_routes`/`teardown_routes` functions and route it through the trait. Clippy's `disallowed_methods` lint should have caught this at build time; if it didn't, the lint needs tightening.

1. **Run `cargo clippy --workspace` locally against the failing branch.** The `disallowed_methods` lint rejects calls to `routing::setup_routes`, `routing::teardown_routes`, and `shadowsocks_service::local::Server::new` from anywhere except the trait implementations themselves. A new hit means the bridge contract is being violated.

1. **Check for new `std::process::Command::new` calls in recent diffs to `crates/bridge/src/`.** Not covered by the clippy lint (too broad a ban would break platform/group.rs). Each new usage is a potential test-time subprocess leak.

1. **Check the runner-level duration lines in skuld's stderr** — skuld prints `[skuld] <test>: pass (NN ms)` for every test. Any test whose duration is a significant outlier compared to main is the load driver.

1. **Compare with a recent main branch CI run on the same runner image.** If main passes and your branch doesn't, the delta is in your branch (necessary but not sufficient — #165 was a latent bug that a new branch tripped via timing).

1. **Only if all of the above rule out code-level issues**, consider that the CI runner image itself has changed. Open a tracking issue and reconstruct a packet-capture CI job from git history at branch `azhukova/165` — do not bump timeouts without completing the investigation.

**Do NOT, under any circumstances:**

- Bump timeouts in `server_test_tests.rs` without completing steps 1-5
- Mark failing tests with `#[cfg_attr(windows, ignore)]`
- Add `--test-threads=1` to the Windows CI invocation
- Serialize tests via bare `#[skuld::test(serial)]` except for structural invariant checks. Resource-contention serialization belongs on the fixture that models the resource (`#[skuld::fixture(serial = LABEL)]`) or on the test carrying the resource's label: `#[skuld::test(labels = [LABEL], serial = LABEL)]`. Labels live in `crates/bridge/src/test_support/skuld_fixtures.rs` (`DIST_BIN`, `PORT_ALLOC`, `TUN`, `IPV6`). Label names are cross-crate reserved via skuld's SQLite coordinator — adding the same label name in another crate will unintentionally serialize tests across crates.
- Add a per-test timeout. Job-level timeouts in `.github/workflows/ci.yaml` — `build` 30m, `test-hole` 20m, `test-garter`/`test-galoshes` 10m — are the sole global test timeouts. Developers wanting local per-test hang protection can set `NEXTEST_SLOW_TIMEOUT` in their shell.
