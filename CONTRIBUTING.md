# Contributing to Hole

Product overview and install live in [README.md](README.md); an agent-facing
architecture map lives in [CLAUDE.md](CLAUDE.md). This file is the contributor
reference: how the system is built, how to build/run/test it, and the
invariants you must not break.

## Architecture

Hole is a single Rust binary (`hole`) that is both the GUI app and a privileged
bridge, selected by CLI arguments:

- **GUI mode** (no args): Tauri desktop app — system tray, settings window,
  config management. Unprivileged.
- **Bridge mode** (`hole bridge run`): manages the TUN device, routing, and the
  shadowsocks connection. Foreground by default; runs as a system service
  (Windows SCM / macOS launchd) with `--service`. Needs elevation.

GUI ↔ bridge speak HTTP/1.1 REST (JSON) over a local Unix socket (macOS) or
named pipe (Windows), defined by `crates/common/api/openapi.yaml`.

### Build-time vs runtime tooling

The frontend (`ui/`) is HTML/CSS/TypeScript. **Node.js is used only at build
time** — Vite (bundler/dev server) and `tsc`. No Node process exists at runtime:
Tauri embeds the OS webview (Edge WebView2 on Windows, WebKit on macOS) and the
backend is pure Rust.

### Single-instance enforcement

GUI mode is single-instance via `tauri-plugin-single-instance`, keyed on the
`com.hole.app` identifier. A second `hole` invocation forwards its `argv` + `cwd`
to the running instance (which opens the dashboard) and exits. The lock is
per-session on Windows (`CreateMutexW` without a `Global\` prefix — concurrent
FUS/RDP users each get their own GUI) and machine-wide on macOS (AF_UNIX listener
under `/tmp`). The plugin is registered *inside* `launch_gui`, so every CLI
subcommand bypasses the lock; the callback dispatches UI work to the main thread
via `AppHandle::run_on_main_thread`.

**Upgrade-while-running caveat.** `hole upgrade`'s `/quiet` MSI does not relaunch
the GUI on in-place upgrade (`LaunchApp` is gated on `NOT WIX_UPGRADE_DETECTED`).
The old GUI keeps the lock, so launching the freshly-installed `hole.exe`
silently forwards args to the old instance and exits.

### UDP policy

Hole is a VPN. UDP flows whose filter decision resolves to `Proxy` are
**dropped, not bypassed**, when the configured plugin cannot carry UDP (plain
v2ray-plugin is TCP-only) — bypassing to the clear-text upstream would leak the
flow outside the tunnel. The invariant is structurally enforced by the cascade
in [`HoleRouter::resolve_endpoint`](crates/bridge/src/hole_router.rs):
`Proxy` + UDP + `!supports_udp()` resolves to `&self.block`, never
`&self.bypass`. UDP-capable plugins (galoshes, via YAMUX) tunnel UDP normally.
The three drop reasons (rule block, UDP-proxy-unavailable, IPv6-bypass-unreachable)
each log through dedicated [`BlockEndpoint`](crates/bridge/src/endpoint/block.rs)
methods.

**UDP/53 exception.** When DNS is enabled, UDP/53 is diverted to
[`LocalDnsEndpoint`](crates/bridge/src/endpoint/local_dns.rs) *before* the
cascade reads the filter decision, so DNS works even on a TCP-only plugin. See
[DNS forwarder](#dns-forwarder).

### DNS forwarder

On TCP-only plugins, full-tunnel DNS would have no path (UDP/53 is dropped for
privacy). The bridge carries DNS over the TCP tunnel:

- [`DnsForwarder`](crates/bridge/src/dns/forwarder.rs) — bytes-in/out forwarder;
  PlainUdp / PlainTcp / DoT / DoH; preserves the client's transaction ID.
- [`LocalDnsEndpoint`](crates/bridge/src/endpoint/local_dns.rs) — the in-TUN
  UDP/53 interceptor; the sole OS DNS path. OS adapter DNS is pointed at the
  configured resolver IPs (default `[1.1.1.1, 1.0.0.1]`), which route into
  `hole-tun` via the `0.0.0.0/1` split route and are diverted to this endpoint
  → `DnsForwarder` over the tunnel. OS TCP/53 to those IPs falls through the
  proxy cascade to the real resolver's `:53` over the tunnel.
- [`Socks5Connector`](crates/bridge/src/dns/socks5_connector.rs) — routes the
  forwarder's upstream through the SS SOCKS5 listener so user `Block` rules can't
  strand the resolver (TCP via `tokio-socks`; UDP via hand-rolled UDP ASSOCIATE,
  RFC 1928).
- [`SystemDnsConfig`](crates/bridge/src/dns/system.rs) — Windows `netsh`, macOS
  `networksetup`. Apply advertises the resolver IPs to the TUN **and** upstream
  adapters (on Windows both v4 and v6 families, each set from its own configured
  resolvers; a family with none is left untouched); capture runs on the upstream
  only (the TUN is freshly created). Prior config persists to `bridge-dns.json`;
  the post-apply cache flush is fire-and-forget.

`DnsConfig::default()` is `enabled: true`, `Https`, `[1.1.1.1, 1.0.0.1]` — and
`AppConfig` is `#[serde(default)]`, so the forwarder enables silently on
upgrade.

**Start-time gate (load-bearing).** A forwarder self-test runs inside
[`start_inner`](crates/bridge/src/proxy_manager.rs) **before**
`Dispatcher::new` / `routing.install` / `apply_dns_settings`; on failure it
returns `ProxyError::ForwarderSelfTestFailed` and the RAII guards unwind without
touching routes, system DNS, or the wintun adapter. Guarded by
`start_blocks_on_forwarder_self_test_failure`.

**Hard errors:** `dns.enabled = true` with `servers = []` is a config error.

### Listener selection invariants

[`ProxyConfig`](crates/common/src/protocol.rs) has two listener toggles
(`proxy_socks5`, `proxy_http`) plus `local_port_http` (SOCKS5 uses `local_port`).
[`build_ss_config`](crates/bridge/src/proxy/config.rs) pushes at most two
`LocalInstanceConfig`s and rejects three combinations up-front (surfaced as
`BridgeResponse::Error`):

1. `Full && !proxy_socks5 && proxy_http` → `TunnelRequiresSocks5` (the TUN
   data plane either rides the user-facing SOCKS5 listener, or — pure-VPN —
   an internal one on an ephemeral port; a mixed user-facing-HTTP +
   internal-SOCKS5 split is rejected so the fixed HTTP port never sits
   inside `bind_ephemeral`'s unbounded retry loop).
1. `SocksOnly && !proxy_socks5 && !proxy_http` → `NoListenersEnabled`.
1. `proxy_socks5 && proxy_http && local_port == local_port_http` →
   `DuplicateListenerPort`.

`Full && !proxy_socks5 && !proxy_http` is the **pure-VPN** configuration —
what the GUI sends when the "Local proxy server" master toggle is off
(`build_proxy_config` gates both flags on `proxy_server_enabled`, #459):
`build_ss_config` emits a single SOCKS5 instance on a caller-supplied
ephemeral loopback port (`proxy_manager::start_inner` allocates it via
`port_alloc::bind_ephemeral`), the TUN dispatcher and DNS forwarder dial
that port, and nothing is bound on `local_port` / `local_port_http`.

The HTTP listener's `Mode` is always `TcpOnly` (HTTP CONNECT is TCP-only,
RFC 7231 §4.3.6); the SOCKS5 listener's is always `TcpAndUdp`.

### Bridge test-isolation contract

All production OS-mutating I/O — shadowsocks lifecycle, routing-table mutations,
gateway introspection, DNS resolver config — routes through three traits so tests
can mock it: `Proxy` ([proxy.rs](crates/bridge/src/proxy.rs)), `Routing`
([routing.rs](crates/tun-engine/src/routing.rs)), and `Dns`
([dns/system.rs](crates/bridge/src/dns/system.rs)). **Helper types whose `Drop`
performs cleanup must route it through trait methods, not raw free functions.**
Compile-time enforcement is in the root [`clippy.toml`](clippy.toml)
`disallowed_methods` list (`routing::setup_routes`/`teardown_routes`; the Win32
DNS FFIs `SetInterfaceDnsSettings`/`GetInterfaceDnsSettings`). See #165 (the
incident) and #397 (the `Dns` extension).

`Dns` has a two-layer seam — outer (`MockDns` at `ProxyManager::new_with_dns`)
and inner per-platform backend (`MockBackend` at `SystemDns::new_with_backend`).
Both are necessary: an outer-only mock can pass while `SystemDns::apply` ignores
cancel internally.

### Bridge cancellation contract

Cooperative-cancellation propagation (Go `context.Context` style) is the **only**
cancellation mechanism. Future-drop cancellation is reserved for catastrophic /
panic teardown. The cancel scope is rooted at the IPC `handle_start` handler
([ipc.rs](crates/bridge/src/ipc.rs)); every phase of
[`ProxyManager::start_cancellable`](crates/bridge/src/proxy_manager.rs) receives
the token by reference. A fresh `CancellationToken::new()` inside
`crates/bridge/src/` would shadow the chain and is banned by `clippy.toml`
(sanctioned exceptions carry a per-site `#[allow]` + citation). See #397.

Three invariants:

1. **Cooperative observation between phases** —
   `tokio::select! { biased; _ = cancel.cancelled() => Err(Cancelled), r = work => r }`
   or a `cancel.is_cancelled()` check between loop iterations. The one exception:
   a future with no async cleanup obligation (e.g. `DnsForwarder::forward`, whose
   socket closes on `Drop`) may be future-dropped, documented inline.
1. **Async cleanup is explicit** — types with async cleanup expose
   `async fn shutdown(&mut self)` and use `drop_bomb::DebugDropBomb` to enforce
   that callers awaited it (panics in debug, `warn!` + sync fallback in release).
1. **`select!` arms must not drop work mid-cleanup** — restructure so cleanup is
   awaited after the select returns; see the apply loop in `SystemDns::apply`.

[`SystemDnsApplied`](crates/bridge/src/dns/system.rs) owns a `DebugDropBomb`
defused by `shutdown()` and is constructed only in the `Ok` branch of
`Dns::apply`. **Known follow-up:** `SystemRoutes::Drop` still tears down routing
synchronously (blocks the worker on `netsh`/`route`); converting it to the
`shutdown` + `DebugDropBomb` discipline is tracked.

### Spawn-retry & file-contention

Transient `Command::spawn` contention (Windows Defender scanning a fresh
`hole.exe`; macOS `ETXTBSY`) is handled by three layers:

- [`handle-holders`](crates/handle-holders/) — query API `find_holders` /
  `log_holders` (Windows `NtQuerySystemInformation`; macOS `lsof`). Best-effort.
- `util::retry::exp_backoff` and `util::retry::retry_if(op, predicate, attempts, base)`, shipping an `is_file_contention` predicate
  (`ERROR_ACCESS_DENIED`/`ERROR_SHARING_VIOLATION`; `ETXTBSY`/`EBUSY`).

`DistHarness::spawn` composes them (`retry_if(spawn, is_file_contention, 3, 500ms)`) and logs holders on terminal failure (#208).

### Port allocation

Ephemeral-port allocation goes through `util::port_alloc`
([crates/util/src/port_alloc.rs](crates/util/src/port_alloc.rs)) — an Apache-2.0
crate so both Hole's GPL crates and the Apache plugin world can depend on it.

- `bind_ephemeral(ip, protocols, op)` — **the canonical entry point.** Allocates
  a port, runs `op(port)`, and retries the whole cycle on `is_bind_race` errors.
  **Unbounded retry, no budget** — the only terminations are success or a
  non-bind-race error; it yields each iteration and logs at attempt milestones.
- `free_port` — primitive that returns a verified-free port divorced from a bound
  socket. **Direct callers are clippy-`disallowed_methods`** — use
  `bind_ephemeral`, or `#[allow]` + comment when the port must reach a subprocess
  before the bind (`test_support::port_alloc::allocate_ephemeral_port` is the
  sanctioned exception).
- `ensure_port_free` — pure probe without allocation.

The retry exists because Windows keeps **independent TCP/UDP excluded-port-range
tables** (Hyper-V/WSL/Docker reservations); an OS-picked port for one transport
may be reserved for the other. There is no "right" budget — a saturated runner
needs many retries, a healthy machine one. See #285, #300, #304.

### Crash recovery

While a proxy is active the bridge persists small state files in `<state_dir>/`,
cleared on clean shutdown and replayed on next startup (all *after* the IPC
socket binds; DNS recovery runs before route recovery so a mid-recovery crash
leaves working DNS + broken routes, not the inverse):

- **`bridge-routes.json`** — TUN name, server IP, upstream interface;
  `routing::recover_routes` tears down leaked routes.
- **`bridge-plugins.json`** — plugin PIDs + start times;
  `plugin_recovery::recover_plugins` kills survivors (PID-reuse-safe).
- **`bridge-dns.json`** — prior system DNS; `dns::recovery::recover_dns_config`
  restores it.
- **ETW sessions** (Windows) — `hole-bridge-etw-<pid>`;
  `diagnostics::etw::sweep_stale_sessions` (`QueryAllTracesW`) stops stale ones by
  name prefix.

Default `<state_dir>` is `dirs::state_dir()/hole/state` — Windows
`%LOCALAPPDATA%\hole\state\`, macOS `~/Library/Application Support/hole/state/`;
installed service `C:\ProgramData\hole\state\` / `/var/db/hole/state/`;
`dev-console` passes `$TMPDIR/hole-dev/state`.

If in-bridge recovery can't run, [`scripts/network-reset.py`](scripts/network-reset.py)
performs equivalent cleanup from outside.

### Config corruption recovery

`ConfigStore` ([crates/common/src/config_store.rs](crates/common/src/config_store.rs))
is the only door to `config.json` — `AppConfig::save` is clippy-disallowed
elsewhere, and there is no other loader. On load, a corrupt or unreadable file
is quarantined to a timestamped sibling (`config.json.<ts>Z.bak`) before
defaults are used, and the user gets a native dialog naming the backup. If
quarantine fails (e.g. unwritable directory), saving is blocked for the whole
session (`ConfigError::SaveBlocked`) so the corrupt file is never overwritten —
the original data-loss bug (#467) was a save clobbering a file that had failed
to parse. Saves are atomic (sibling temp file + rename) so a crash mid-save
cannot produce a corrupt config.

### Native-crash observability (tombstone)

Native faults (SIGSEGV/access-violation, stack overflow, SIGABRT/`abort()`,
SIGILL/FPE/BUS, heap corruption, Windows invalid-parameter/pure-virtual) bypass
Rust's unwinding panic hook. The first-party Apache-2.0
[`tombstone`](crates/tombstone/) crate (built on `crash-handler`) closes the gap.

`tombstone::attach(kind, log_dir)` is called at the logging chokepoint
([`init_multi`](crates/common/src/logging.rs), right after
`install_panic_hook()`), covering GUI/CLI/bridge; galoshes attaches in its own
`main`. On a fault, `on_crash` runs in a compromised context and does only
signal-safe work: write a fixed-format `crash-<kind>-<pid>.marker` via raw
syscalls (no heap/locks/`format!`), then return `Handled(false)` so the OS
default path (WER / `.ips` / core dump) still runs. All I/O errors are swallowed.
`tombstone::sweep(log_dir)` runs at the next start of the same kind, emits a
`tracing::error!(target: "crash", …)`, and deletes the marker. Markers land in
`log_dir` (not `state_dir`) so the elevated bridge's marker is readable by the
unprivileged GUI.

- **Platform coverage:** marker + sweep work on Windows, macOS, **and Linux**
  (galoshes ships a Linux release, so `tombstone` must compile and run there).
  Linux runtime crash tests are a known gap (compile-verified via the galoshes
  Linux build; runtime-exercised only on the Win/mac `hole-tests` lane).
- **Dev-only minidumps:** under the non-default `crash-dumps` feature, `on_crash`
  also writes a `.dmp` via `minidump-writer` — **Windows/macOS only** (no
  in-process Linux self-dump). `minidump-writer` never links into a shipped
  binary (process memory holds keys + traffic, and it has no Windows-aarch64
  support).
- **Plugins:** ex-ray is spawned with `GOTRACEBACK=crash`; `record_exit` logs a
  mid-run plugin death with `exit_code`/`killed`.
- **Known gap (accepted, untested):** Windows `__fastfail` / `int 29h` (incl.
  `/GS` stack-cookie failures and `std::process::abort()` on Windows) is
  uncatchable by design. On macOS `abort()` → SIGABRT is caught.

### Panic-dump dispatcher

`hole-test-observability` ships a workspace-shared panic-hook dispatcher
([panic_dump](crates/test-observability/src/panic_dump.rs)). On a test panic it
iterates registered `PanicDumpSource`s, then chains to the previous hook.
**Contract:** `dump()` MUST swallow all I/O errors — a double-panic would replace
the original message. Registration is RAII (`register` → guard). The dispatcher
is installed at ctor time, so consumers just `register()`. Current consumer:
`BridgeChildLogSource` dumps each live `DistHarness` child's `bridge.log` (#303).

### Tray menu rebuild contract

All tray menu commits go through `tray::rebuild_tray_menu`, which dispatches
the whole rebuild — state reads included — to the main thread
(`run_on_main_thread` executes inline when already there). A raw `set_menu`
from a worker thread reads state early and commits the menu later through the
event-loop queue, so a stale menu can overwrite a newer one (the #473 desync).
Enforcement is in [`clippy.toml`](clippy.toml) (`TrayIcon::set_menu` is
disallowed; the one commit point inside `rebuild_tray_menu` carries a per-site
`#[allow]`). Corollary: `sync_menu_state` is main-thread-only — menu-item
setters dispatch-and-block from any other thread, so calling it from a worker
while holding a lock deadlocks the app.

## Workspace layout

Each publishable member declares a release group in
`[package.metadata.hole-release].group` (enforced by `xtask-lib::version`).
`publish = false` means not pushed to crates.io.

| Directory / file                   | Crate · license · group                | Purpose                                                                         |
| ---------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------- |
| `crates/common/`                   | `hole-common` · GPL · hole             | Shared types: protocol, config, import, logging                                 |
| `crates/bridge/`                   | `hole-bridge` · GPL · hole             | Bridge library (TUN/routing/SS/IPC/DNS)                                         |
| `crates/hole/`                     | `hole` · GPL · hole                    | Tauri app + CLI + bridge entry (binary `hole`)                                  |
| `crates/tun-engine[-macros]/`      | GPL · hole                             | TUN + routing + packet-loop engine (+ `#[freeze]` macro)                        |
| `crates/dump[-macros]/`            | GPL · hole                             | YAML-shaped logging representation (+ derive)                                   |
| `crates/handle-holders/`           | GPL · hole                             | File-handle introspection (Win NtQuery / mac lsof)                              |
| `crates/test-observability/`       | `hole-test-observability` · GPL · hole | Dev-dep: pre-main ctor installs subscriber + panic hook                         |
| `crates/tombstone/`                | Apache · —                             | Native-crash handler (marker + optional minidump)                               |
| `crates/kill-group/`               | Apache · kill-group                    | Process-tree kill-groups (job object / process group); split from garter (#197) |
| `crates/stepstool/`                | Apache · —                             | Elevation primitives: sudo priming + wrapping (POSIX), elevation detection (Win) |
| `crates/garter[-bin]/`             | Apache · garter                        | SIP003u plugin-chain runner lib (**on crates.io**) + CLI + mock-plugin fixture  |
| `crates/galoshes/`                 | Apache · galoshes                      | Bundled+standalone SIP003u plugin (YAMUX + embedded ex-ray)                     |
| `crates/ex-ray/`                   | Apache · ex-ray                        | First-party Go SIP003u plugin on v2ray-core (wire-compatible with v2ray-plugin) |
| `crates/util/`                     | Apache · —                             | `port_alloc`, `retry` (Apache so plugins can depend)                            |
| `crates/plugin-e2e/`               | GPL · —                                | Shared ss-server/cert harness + ex-ray↔stock + galoshes roundtrips (#197)       |
| `crates/dev-console/`              | GPL · —                                | Dev-mode supervisor: bridge (elevated) + Vite + GUI, multiplexed logs (#454)    |
| `build.yaml`                       | —                                      | Declarative build-target DAG for `cargo xtask build\|run\|list`                 |
| `xtask/`, `xtask-lib/`             | —                                      | Task runner + helper crate shared with `crates/hole/build.rs`                   |
| `msi-installer/`, `dmg-installer/` | —                                      | Windows MSI (WiX) + macOS DMG signature checks (Python, #364)                   |
| `ui/`, `scripts/`, `tests/`        | —                                      | Frontend (Vite), utility scripts, E2E specs (WebDriverIO)                       |

The Apache crates are Apache-2.0 per-crate (see [NOTICES.md](NOTICES.md)); Hole's
own crates are GPL-3.0-or-later. Combined distributions (`hole.exe`, `hole.msi`,
bundled `galoshes.exe`) ship as a whole under GPL via Apache→GPL one-way
compatibility.

**ex-ray embedding.** `galoshes` embeds the ex-ray Go binary at compile time:
`cargo xtask ex-ray` builds it into `.cache/ex-ray/`;
[`galoshes/build.rs`](crates/galoshes/build.rs) emits `EX_RAY_PATH` +
`EX_RAY_SHA256`, and galoshes re-hashes the embedded bytes at runtime and refuses
to run on mismatch. At startup galoshes extracts ex-ray to
[`embedded::runtime_dir`](crates/galoshes/src/embedded.rs)
(`$XDG_RUNTIME_DIR/galoshes` else the platform cache dir; bails if neither is
set) and probes it for `noexec` (statvfs/statfs) — the Linux `/tmp` fallback was
removed because tmpfs is commonly `noexec` (#401).

## Prerequisites

- Rust toolchain
- Go toolchain (for ex-ray; built by `cargo xtask deps`)
- Node.js ≥24 (pinned via `engines.node` in [package.json](package.json))

### npm dependency management

Dev mode (`dev-console`) runs `npm install`, which updates `package-lock.json`
when it drifts from `package.json`. PR CI runs strict `npm ci` (via `frontend-build`),
which fails on inconsistency. **If you edit `package.json`, commit the resulting
`package-lock.json` in the same commit, or CI rejects the PR.** Renovate handles
routine updates ([renovate.json](.github/renovate.json)).

## Build

Requires the toolchains above. `build.yaml` is the single source of truth for the
build graph; `cargo xtask list` prints the target table.

```sh
npm install                  # frontend deps (first time only)
cargo xtask deps             # build ex-ray (Go) + download/verify wintun.dll (cached)
cargo xtask build hole       # deps + cargo build (debug) + stage to target/debug/dist
cargo xtask run hole         # dev mode (= build hole + dev-console)
cargo xtask run hole-tests   # canonical local nextest invocation
```

### Tauri dev/prod feature toggle

The `hole` crate defaults to `tauri/custom-protocol` (**production mode**:
`cfg(dev) = false`, webview loads bundled `tauri.localhost`, `tauri-codegen`
embeds `ui/dist/` and panics if it's missing). With `--no-default-features`
(**dev mode**) the webview loads Vite's `http://localhost:1420` and `ui/dist/` is
not required. The `hole` / `hole-tests` xtask targets pass
`--no-default-features`; `hole-msi` / `hole-dmg` use the default and depend on
`frontend-build`. **Running `cargo build -p hole` directly: add
`--no-default-features` for dev, or `cargo xtask build frontend-build` first.**
See #372.

### Windows installer

```sh
uv run --directory msi-installer build       # builds hole.msi in target\release\
msiexec /i target\release\hole.msi [/quiet]  # install (interactive / unattended)
cd msi-installer && uv run --group dev pytest -v   # WiX source + MSI build validation
```

### macOS DMG

```sh
cargo xtask build hole-dmg       # produces .dmg (npx tauri build under the hood)
cargo xtask run hole-dmg-tests   # mount + assert .app code signature is intact
```

## Development

### Running in dev mode

Dev mode creates a **real TUN interface** and edits the routing table (the
production bridge path), so the bridge needs elevation — but you run the command
unprivileged:

```sh
# macOS: NO sudo
cargo xtask run hole

# Windows: from an elevated PowerShell
cargo xtask run hole
```

> **Do NOT `sudo cargo xtask run hole`.** dev-console refuses to run as root,
> but the outer xtask build cascade runs first — so a sudo'd invocation leaves
> root-owned files in `target/` before dev-console can bail (bindreams/hole#452).
> Closing this sudo-invocation path structurally is tracked in #453.

`cargo xtask run hole` launches the [`dev-console`](crates/dev-console/)
supervisor, which builds the workspace, starts Vite, and launches bridge + GUI
with multiplexed color-coded logs. `cargo run -p dev-console` works standalone
too (it runs `cargo xtask build hole` itself). Frontend changes hot-reload via
Vite HMR; Rust changes need Ctrl+C and re-run.

- **dev-console runs unprivileged and elevates only the bridge.** On macOS it
  prompts for your sudo password once, then `sudo`s just `bridge grant-access` +
  `bridge run`. Vite and the GUI run as you, reading your real `~/Library`. On
  Windows everything inherits the already-elevated UAC token (token-based; no
  identity change).
- dev-console runs `hole bridge grant-access` (creates the `hole` group, adds
  your user) so the bridge exercises the production DACL/group path on every
  run. The group is **not** removed on exit (same as production). The GUI needs
  the `hole` group to open the IPC socket; the first run after `grant-access`
  creates the group, so a one-time log out / log back in (or reboot) may be
  required.
- **Bridge readiness is a rendezvous, not a poll.** dev-console pre-binds a
  localhost TCP listener and passes `--ready-notify ADDR/TOKEN` to `bridge run`;
  the bridge echoes the token only after the IPC socket is bound and its
  permissions are applied. (This replaces the old socket-file wait, which raced
  the DACL setup.)
- **Ctrl+C stops the bridge gracefully** so it restores routes/DNS before
  exiting: SIGTERM (relayed by sudo) on macOS, CTRL_BREAK on Windows. Children
  that ignore the graceful signal for 10s are force-killed with their process
  trees — except the macOS bridge, which sudo cannot force-kill; dev-console
  prints a `network-reset.py` recovery pointer instead.

### Manual workflow

Separate terminals, more control. **Terminal 1 — bridge:** build and stage as
your normal user; only `bridge grant-access` + `bridge run` need elevation.

```powershell
# Windows (elevated PowerShell — UAC token-based, everything inherits it)
cargo xtask build hole
cargo xtask stage --profile debug --out-dir "$env:TEMP\hole-dev-manual"
& "$env:TEMP\hole-dev-manual\hole.exe" bridge grant-access
& "$env:TEMP\hole-dev-manual\hole.exe" bridge run `
    --socket-path "$env:TEMP\hole-dev.sock" --state-dir "$env:TEMP\hole-dev-state"
```

```sh
# macOS — run as yourself; sudo only the two bridge commands
cargo xtask build hole
cargo xtask stage --profile debug --out-dir "$TMPDIR/hole-dev-manual"
sudo "$TMPDIR/hole-dev-manual/hole" bridge grant-access
sudo "$TMPDIR/hole-dev-manual/hole" bridge run \
    --socket-path "$TMPDIR/hole-dev.sock" --state-dir "$TMPDIR/hole-dev-state"
```

**Terminal 2 — Vite + GUI (unelevated):**

```powershell
# Windows
npm run dev                                       # Vite on port 1420
$env:HOLE_BRIDGE_SOCKET = "$env:TEMP\hole-dev.sock"; target\debug\hole.exe
```

```sh
# macOS
npm run dev &                                     # Vite on port 1420
HOLE_BRIDGE_SOCKET=$TMPDIR/hole-dev.sock target/debug/hole
```

`cargo xtask stage` populates a BINDIR (`hole` + `ex-ray` sidecar + `wintun.dll`
on Windows) matching the installed `Program Files\hole\bin\`. The bridge must be
staged out of the cargo target dir because the running bridge file-locks its own
exe; the `ex-ray` sidecar must be a sibling so `resolve_plugin_path_inner` finds
it. The canonical file list is [xtask/src/bindir.rs](xtask/src/bindir.rs).

### Flags

- `hole bridge run` — foreground, logs to stderr + file. **Needs elevation.**
- `--service` — register with Windows SCM / macOS launchd (the service installer
  passes this).
- `--log-dir` / `--state-dir` / `--socket-path` — override defaults.
- `HOLE_BRIDGE_SOCKET` env var — tells the GUI to connect to a dev bridge socket.

### Notes

- The unelevated GUI needs the `hole` group to open the IPC socket; `bridge grant-access` creates it and adds your user, so on a fresh machine a one-time
  log out / log back in (or reboot) may be required before the GUI can connect.
- Use absolute paths (e.g. `$TEMP`) for `--socket-path` to avoid Windows AF_UNIX
  path-length limits.
- The dev binary shares `com.hole.app` with the installed build, so if an
  installed `hole.exe` is running, dev launches forward to it and the dev GUI
  won't appear — quit the installed Hole first.
- If a dev crash breaks routing, run `scripts/network-reset.py` (elevated).
- First `cargo xtask deps` is slow (compiles ex-ray, downloads wintun);
  subsequent runs are near-instant (Go build cache + sha256-sentineled download).

## Testing

Unit tests use the [skuld](https://github.com/bindreams/skuld) framework
(`#[skuld::test]`, not `#[test]`); test files are siblings (`foo.rs` →
`foo_tests.rs`).

```sh
cargo xtask run hole-tests                       # canonical local invocation
cargo test --workspace --no-default-features     # plain cargo equivalent
npm run test:e2e                                 # E2E (requires a release build)
```

### Avoiding Windows Firewall prompts

Bridge tests bind a TCP listener on all interfaces, so Windows Firewall prompts
on each rebuild (cargo's content-hash test-binary names churn, defeating cached
consent). Stage tests at a stable path once:

```sh
cargo xtask stage --with-tests \
    --out-dir target/debug/dist/bin --tests-out-dir target/debug/dist/tests
./target/debug/dist/tests/hole_bridge.test.exe   # approve the prompt once
```

Re-run the staging command after each source change (the staged binary doesn't
auto-update). Co-named lib/bin targets disambiguate to `hole-lib.test.exe` /
`hole-bin.test.exe` (#210).

### Investigating Windows CI flakes

When Windows CI times out in `server_test_tests` or loopback connects hang, work
through these IN ORDER before proposing any timeout bump:

1. **`PermissionDenied`/`WSAEACCES`/os error 10013 on bind** — handled by
   [`bind_ephemeral`](#port-allocation)'s unbounded `is_bind_race` retry. A loop
   that never converges means the machine's excluded-port range covers most of
   the dynamic range; inspect `netsh int ipv4 show excludedportrange tcp` (and
   `udp`/`ipv6`). Hyper-V/WSL/Docker are typical sources.
1. **`Access is denied (os error 5)` on spawn** — grep for `file-lock holder`;
   `DistHarness::spawn` retries + enumerates holders (#208). `MsMpEng.exe`
   (Defender) is the usual culprit (PPL-protected → may be unenumerable).
1. **Grep for `routing subprocesses` / `netsh|route add|route delete`** — the
   `proxy_manager_tests_never_spawn_routing_subprocess` test asserts `N == 0`. A
   hit means a code path bypassed the `Routing` trait.
1. **Run `cargo clippy --workspace --no-default-features`** — `disallowed_methods`
   rejects raw `routing::setup_routes`/`teardown_routes` and
   `shadowsocks_service::local::Server::new` outside trait impls.
1. **Check for new `std::process::Command::new` in `crates/bridge/src/`** — not
   clippy-covered; each is a potential test-time subprocess leak.
1. **Check skuld's per-test `pass (NN ms)` lines** for a duration outlier.
1. **Compare with a recent main CI run** on the same runner image.
1. **Only if all the above rule out code issues**, consider the runner image
   changed — open a tracking issue and reconstruct a packet-capture job.

**Do NOT:** bump timeouts in `server_test_tests.rs` before steps 1–5; mark tests
`#[cfg_attr(windows, ignore)]`; add `--test-threads=1`; serialize via bare
`#[skuld::test(serial)]` (use a fixture/resource label); or add per-test
timeouts. Job-level timeouts (`build` 30m, `test-hole` 20m, `test-garter`/
`test-galoshes` 10m) are the only global timeouts.

### Test invariants

- **Test observability** — every test-bearing crate dev-deps
  `hole-test-observability` and calls `hole_test_observability::register!()` once
  per binary. A pre-main ctor installs a process-global `tracing_subscriber`
  (stderr), `RUST_BACKTRACE=full`, and Hole's tracing panic hook. Override via
  `HOLE_TEST_LOG`. Third-party `log::trace!` is level-rejected before allocation
  (the #147 perf guard). (#301)
- **No raw subscriber init** — `clippy.toml` disallows
  `tracing_subscriber::fmt().init()` / `try_init()` workspace-wide (one
  `#[allow]`-suppressed production caller in `crates/common/src/logging.rs`).
- **Per-test subscribers** — install via
  [`garter::tracing_test::set_default_in_current_thread`](crates/garter/src/tracing_test.rs),
  not raw `tracing::subscriber::set_default` (clippy-disallowed): the guard is
  thread-local, so on a multi-thread runtime `tokio::spawn`'d tasks lose it.
  `#[skuld::test] async fn` builds a current-thread runtime automatically (#302).
- **No sleeps for synchronization** — `thread::sleep`, `tokio::time::sleep`,
  `browser.pause()`, and any timeout-bounded poll (`waitUntil({ timeout })`,
  `tokio::time::timeout(d, wait_for_x)`) are forbidden for sync. Two exception
  classes, each with a one-line comment naming it: (1) **test-of-timing** (the
  delay IS the behavior under test) and (2) **external event with graceful
  failure bound** (a remote/out-of-process op that might never succeed; the
  framework/job timeout is the failure-to-human signal). Use the codebase's
  rendezvous primitives (oneshot, `watch`, `WaitableWriter`, `CancellationToken`,
  `JoinHandle.await`, `tokio::time::pause/advance`) for intra-process sync (#383).

## Logging & diagnostics

### Log destinations

Both GUI and bridge write to stderr **and** a 10 MiB rotating file (one backup).
Default dir is `dirs::state_dir()/hole/logs` (`gui.log`, `bridge.log`):

- Windows `%LOCALAPPDATA%\hole\logs\`, macOS `~/Library/Application Support/hole/logs/`
- Installed service: Windows `C:\ProgramData\hole\logs\`, macOS `/var/log/hole/`

### WebView2 and Chromium logs

Windows WebView2 writes Chromium-format lines (`[MMDD/HHMMSS.mmm:LEVEL:file:line]`)
straight to the inherited stderr, bypassing our `tracing` subscriber. The
FD-level stdio safety net in
[`crates/common/src/logging.rs`](crates/common/src/logging.rs) tees each line to
a `tracing` event (target `hole::stderr_relay`, recorded into `gui.log`) and to
the original stderr (dev terminal). **A Chromium line is a real log record —
investigate the underlying cause rather than reaching for a filter** (#144).

### Console relay and toasts

`console.error`/`console.warn` in `ui/` are intercepted by `installConsoleRelay()`
in [`ui/main.ts`](ui/main.ts) (the first thing `init()` runs) and forwarded to Rust via
`@tauri-apps/plugin-log`, landing in `gui.log`. The relay is **log-only — it does
not show toasts** (toasts are per-call-site so a tight loop can't flood the UI).
(Not to be confused with `attachConsole()`, which mirrors Rust→JS.) Surface
user-visible failures with `showToast(message, kind)` from
[`ui/toast.ts`](ui/toast.ts) (caps at 5 visible). **Errors containing filesystem
paths or other PII must be redacted before reaching a toast** — the detail still
lands in `gui.log`. Two mechanisms are sanctioned. **(1) A PII/content-free error
type + `warn!` with the path to `gui.log`:** `ConfigError`
([`config.rs`](crates/common/src/config.rs)) carries the failing operation and the
OS error, never the path, and its `Parse` variant surfaces only a category plus
line/column — never the raw `serde_json` message (which can echo a password).
`save_config` ([`commands.rs`](crates/hole/src/commands.rs)) logs the path via
`warn!` and shows the path-free message in the toast. **(2) A detail-free
structured wire variant + `warn!`** when the detail itself could carry
content/PII: `import_servers_from_file` returns `ImportFailure::SaveFailed` /
`CorruptedJson` (no fields) and logs the full error.

### Logging directives (HOLE_BRIDGE_LOG)

`HOLE_BRIDGE_LOG` takes a comma-separated list of `tracing` directives (default
`hole_bridge=info`); `RUST_LOG` is also honored and both compose. Example:
`hole_bridge=debug,shadowsocks_service=trace` adds shadowsocks-service per-relay
byte counts (`L2R N bytes, R2L M bytes`) — a load-bearing #248-class diagnostic,
but expensive (≥1 TRACE line per TCP connection); use for debugging only.

### Plugin diagnostics

The out-of-process plugin (`ex-ray`, `galoshes`) is otherwise invisible:

- **Plugin tap** — enabled by `AppConfig.diagnostic_plugin_tap` (persists to
  service-mode bridges) or `HOLE_BRIDGE_PLUGIN_TAP=1` (dev shell only).
  [`garter::TapPlugin`](crates/garter/src/tap.rs) logs per-connection
  `bytes_to/from_plugin`, `ttfb_ms` (`None` = closed without an upstream byte —
  the #248 diagnostic), `close_kind`, and `tap_conn_id`. On self-test failure the
  bridge emits a breadcrumb to the tap lines (#388). Costs a loopback round-trip
  per byte + a line per connection — not for default operation under load.
- **Plugin debug logging (always on)** — `inject_plugin_debug_logging` appends
  `loglevel=debug` to `SS_PLUGIN_OPTIONS` for `v2ray-plugin`/`ex-ray`; stderr is
  captured via `garter::binary` and filtered by `HOLE_BRIDGE_LOG`.

## CLI (dev/admin commands)

User-facing commands are in [README.md](README.md#commands). The rest:

```
hole bridge run [--socket-path P] [--log-dir DIR] [--state-dir DIR]   run bridge (foreground, needs elevation)
hole bridge run --service [--log-dir DIR] [--state-dir DIR]           run as service (invoked by SCM/launchd)
hole bridge install | uninstall | status                             register/start | stop/remove | status (elevation)
hole bridge log [path | watch [--tail N]] [--log-dir DIR]            print | locate | stream the bridge log
hole bridge grant-access [--then-send B64 | --then-send-file PATH]    create hole group, add user, write SID file
hole bridge ipc-send (--base64 B64 | --request-file PATH)            proxy a single IPC command (elevation)
hole proxy start --config-file PATH [--local-port PORT] [--local-port-http PORT] [--no-socks5] [--http] [--tunnel-mode MODE]
hole proxy stop                                                       stop the proxy
hole proxy test-server --config-file PATH                            one-shot connectivity test
```

## Commit messages — Conventional Commits

The repo squash-merges every PR, so the PR title becomes the `main` commit
subject. PR titles MUST follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>)?: <description>
```

`type` ∈ `feat fix docs style refactor perf test build ci chore revert`; `scope`
is optional; a trailing `!` flags a breaking change. A CI check
([semantic-pr.yaml](.github/workflows/semantic-pr.yaml)) validates the title;
rename via `gh pr edit <N> --title "…"`. The type prefix drives per-track release
notes (`scripts/generate-release-notes.py` groups squash-commits by type;
unrecognized → "Other").

## Releases

Five independent tracks, each tagged `releases/<product>/v<X.Y.Z>`. All but
`kill-group` have a draft+publish workflow pair: the **draft** workflow does all
reversible prep (build, test, hash, upload to a draft release); the **publish**
workflow does the irreversible public actions (tag, `cargo publish`,
latest-flip). The split exists to keep one sanity gate before irreversible work.
`kill-group` has no binary artifacts, so it is published manually — see
[docs/RELEASE-OPS.md](docs/RELEASE-OPS.md#kill-group-manual-publish).

| Product      | Artifacts                                     | Signed   | crates.io    |
| ------------ | --------------------------------------------- | -------- | ------------ |
| `hole`       | MSI + DMG (amd64+arm64) + `SHA256SUMS`        | minisign | No           |
| `galoshes`   | 6-platform binaries + `SHA256SUMS`            | No       | No           |
| `garter`     | crates.io lib + 6-platform CLI + `SHA256SUMS` | No       | `garter`     |
| `kill-group` | crates.io lib                                 | No       | `kill-group` |
| `ex-ray`     | 6-platform binaries + `SHA256SUMS`            | No       | No           |

Asset naming is `<product>-<version>-<os>-<arch>[.ext]`.

- **Only `hole` is signed** — it auto-updates, so supply-chain integrity matters.
  The others are embedded into hole (covered by its signature) or built from
  source by consumers who pin SHA256 against `SHA256SUMS`.
- **`/releases/latest` pinning** — each draft pins `--latest` at
  `gh release create` (`hole=true`, others `false`); without it GitHub's legacy
  semver+date heuristic can promote the wrong track (#308).
- **garter publish is idempotent** — it queries crates.io and skips `cargo publish` if the version exists; a `dry_run` input runs `--dry-run` only.
- **garter depends on kill-group** — publish kill-group to crates.io before (or
  with) any garter release that bumps the dependency.
- **Versions** live in each crate's `[package.metadata.hole-release].group`
  (ex-ray in `crates/ex-ray/version.toml`); validate with `cargo xtask version [--check --group <name> [--exact]]` (release CI uses `--exact`). The legacy
  `v0.1.0` tag predates the scheme and is ignored.

Rollback, minisign key rotation, and the crates.io dry-run TOCTOU note are in
[docs/RELEASE-OPS.md](docs/RELEASE-OPS.md).

## Icons

Source icons under `crates/hole/icons/` are per-platform SVGs
(`icon-{windows,macos}.svg`, `tray-windows-{light,dark}.svg`, `tray-macos.svg`),
converted to raster by `build.rs` (cached in `.cache/icons/`) — **do not commit
generated raster icons**. `TrayState::Disabled` currently aliases `Enabled` (the
enum is preserved for a future variant). `.cache/icons/icon.ico` is bound by the
MSI as `ARPPRODUCTICON` so Add/Remove Programs matches the app icon (#359).

The macOS tray icon is a [template image]: alpha-only shape, RGB=0, inverted by
the OS to match the menu bar. Runtime icon updates must use
`set_icon_with_as_template(icon, true)` — `TrayIcon::set_icon` hardcodes
`icon_is_template=false` (tray-icon 0.23.1) and turns the icon solid black on
the first state change; `set_icon`/`set_icon_as_template` (tauri and inner
`tray_icon` layers) are clippy-banned (#469).

## Emergency network reset

If routing gets into a bad state during development:

```sh
sudo python scripts/network-reset.py    # macOS
python scripts/network-reset.py         # Windows (run as Administrator)
```

It reads the bridge's route-state file and tears down the exact leaked routes
(reaping plugins by name and stopping ETW sessions as a last resort).

[template image]: https://developer.apple.com/documentation/appkit/nsimage/1520017-template
