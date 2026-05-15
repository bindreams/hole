# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin support.

## Architecture

Single-binary design:

- **`hole`** — the only binary, serves as both the Tauri GUI and the privileged bridge depending on CLI arguments.
- GUI mode (no args): system tray, settings window, config management. Unprivileged.
- Bridge mode (`hole bridge run`): privileged service running as root/SYSTEM. Manages TUN, routing, shadowsocks-service.

GUI and bridge communicate over IPC (Unix socket on macOS, named pipe on Windows) using HTTP/1.1 REST (JSON), defined by an OpenAPI spec at `crates/common/api/openapi.yaml`.

### UDP policy

Hole is a VPN. UDP flows whose filter decision resolves to `Proxy` are **dropped**, not bypassed, when the configured plugin cannot carry UDP (e.g. plain v2ray-plugin is TCP-only). Falling back to the clear-text upstream interface would leak the flow outside the encrypted tunnel, violating the user's VPN expectation.

The invariant is structurally enforced by the cascade in [`HoleRouter::resolve_endpoint`](crates/bridge/src/hole_router.rs) — `FilterAction::Proxy` + UDP + `!Socks5Endpoint::supports_udp()` resolves to `&self.block`, never `&self.bypass`. Users who need tunneled UDP should configure a UDP-capable plugin (galoshes uses YAMUX multiplexing).

The three drop reasons — explicit rule block, UDP-proxy-unavailable, IPv6-bypass-unreachable — each log through dedicated [`BlockEndpoint`](crates/bridge/src/endpoint/block.rs) methods so a future reader can distinguish them in the bridge log.

**UDP/53 exception — the DNS forwarder.** When `DnsConfig.intercept_udp53` is enabled (default), UDP destined to port 53 is diverted to [`LocalDnsEndpoint`](crates/bridge/src/endpoint/local_dns.rs) *before* the cascade looks at the filter decision. The endpoint forwards the query through the [`DnsForwarder`](crates/bridge/src/dns/forwarder.rs), which upstreams via the local shadowsocks SOCKS5 listener over the encrypted tunnel. This lets apps that hardcode DNS destinations (Chrome DoH to 8.8.8.8, systemd-resolved stub) resolve even when paired with a TCP-only plugin. Non-DNS UDP still follows the drop invariant above.

### Listener selection invariants

[`ProxyConfig`](crates/common/src/protocol.rs) exposes two independent
local-listener toggles — `proxy_socks5` and `proxy_http` — plus the HTTP
listener's own port `local_port_http` (SOCKS5 uses the long-standing
`local_port`). [`build_ss_config`](crates/bridge/src/proxy/config.rs)
pushes at most two `LocalInstanceConfig`s, one per enabled listener, and
rejects three combinations up-front (returning `ProxyError` variants
surfaced as `BridgeResponse::Error`):

1. `tunnel_mode == Full && !proxy_socks5` → `TunnelRequiresSocks5`. The
   TUN [`Dispatcher`](crates/bridge/src/dispatcher.rs) hands captured
   traffic to the SOCKS5 listener on `local_port`; a Full-mode proxy
   without that listener would silently lose all intercepted flows.
1. `!proxy_socks5 && !proxy_http` → `NoListenersEnabled`.
1. `proxy_socks5 && proxy_http && local_port == local_port_http` →
   `DuplicateListenerPort`. SOCKS5 and HTTP CONNECT use different
   handshake protocols and cannot share a port.

The HTTP listener's `Mode` is always `TcpOnly` regardless of
`tunnel_mode` — HTTP CONNECT is TCP-only (RFC 7231 §4.3.6). The SOCKS5
listener's `Mode` is always `TcpAndUdp`: in Full mode the dispatcher
relays UDP through SOCKS5 UDP ASSOCIATE, and in SocksOnly mode the
listener exposes UDP ASSOCIATE to local SOCKS5 clients. Pre-#250 the
SocksOnly path was forced to `TcpOnly` under #189's mis-attributed
"select_all" hypothesis; the real fix for the original symptom is PR
#207's two-pass test ordering (#200).

### DNS forwarder

Clients on TCP-only plugins (v2ray-plugin, anything without UDP multiplexing) would otherwise have no working DNS in full-tunnel mode — the OS sends UDP/53 into the TUN, the cascade drops it for privacy. The bridge ships a built-in DNS forwarder that carries DNS over the TCP tunnel.

- [`DnsForwarder`](crates/bridge/src/dns/forwarder.rs) — pure bytes-in/bytes-out forwarder. Supports PlainUdp / PlainTcp / DoT / DoH. Preserves the client's transaction ID so it can drop in as a forwarder for both [`LocalDnsServer`](crates/bridge/src/dns/server.rs) (OS-facing loopback:53) and [`LocalDnsEndpoint`](crates/bridge/src/endpoint/local_dns.rs) (in-tunnel UDP/53 intercept).
- [`LocalDnsServer`](crates/bridge/src/dns/server.rs) — binds loopback `<ip>:53` UDP+TCP via a fallback ladder (`127.0.0.1:53` → `127.53.0.1..254:53` → fail). The bridge runs elevated, so port 53 binding never hits the privilege gate.
- [`Socks5Connector`](crates/bridge/src/dns/socks5_connector.rs) — routes the forwarder's upstream connections through the SS SOCKS5 listener on `127.0.0.1:<ss-port>` so user filter rules that `Block` the resolver IP cannot strand the forwarder's own queries. TCP uses `tokio-socks`; UDP uses a hand-rolled SOCKS5 UDP ASSOCIATE per RFC 1928.
- [`SystemDnsConfig`](crates/bridge/src/dns/system.rs) — platform-specific capture/apply/restore. Windows uses `netsh`, macOS uses `networksetup`. **Apply runs on both the TUN adapter and the upstream physical adapter; capture runs on the upstream only** (Phase 4 of #247: the TUN is freshly created by `routing.install`, its prior DNS is definitionally "defaults", and `netsh show dnsservers` against it was one of the slow paths in the 11.3s stall; on teardown the TUN is destroyed with the routes, so there's nothing to restore). Captured prior (v4 + v6, three shapes: static list / DHCP / none) is persisted to `bridge-dns.json` for crash recovery. Post-apply flush (`ipconfig /flushdns` / `dscacheutil -flushcache`) runs fire-and-forget on a detached `std::thread::spawn` — callers (setup and teardown alike) never block on it; the OS-wide DNS cache stays stale for up to its TTL (60-300s typical) after connect/disconnect, which trades a brief stale-answer window for not stalling the UI spinner 1-5s per flush.

**Upgrade migration**: `AppConfig` already carries `#[serde(default)]`, so existing configs without a `dns` key deserialize with `DnsConfig::default()` — which has `enabled: true`, `protocol: Https`, `servers: [1.1.1.1, 1.0.0.1]`, `intercept_udp53: true`. This enables the forwarder silently on upgrade (per user spec: "enabled on upgrade, no notification").

### Bridge test-isolation contract

All production I/O in the bridge — shadowsocks tunnel lifecycle, routing table mutations, OS gateway introspection — routes through the `Proxy` trait in `crates/bridge/src/proxy.rs` and the `Routing` trait in `crates/tun-engine/src/routing.rs`. Helper types whose `Drop` impls perform cleanup must route that cleanup through trait methods, not through raw free functions. Compile-time enforcement lives in the workspace root `clippy.toml` via the `disallowed_methods` list (`tun_engine::routing::setup_routes` / `teardown_routes`). See bindreams/hole#165 for the incident that motivated the rule.

### Spawn-retry architecture (file-contention diagnostics)

Three independent layers compose to handle transient file-contention on `Command::spawn` — typically Windows Defender scanning a freshly-built `hole.exe`, or macOS holding a writer while something tries to exec:

1. **`handle-holders` workspace crate** — pure query API: `find_holders(&Path)` returns every process currently holding the file, `log_holders(&Path)` logs them at `tracing::error!`. Windows uses `NtQuerySystemInformation(SystemExtendedHandleInformation)` with a non-blocking `GetFileType == FILE_TYPE_DISK` pre-filter to avoid pipe/device hangs, then `DuplicateHandle` + `GetFileInformationByHandle` for file-id comparison. macOS shells out to `lsof -F pc`. Best-effort — never introduces a new failure mode.
1. **`hole_common::retry::exp_backoff(attempt, base)`** — pure `base * 2^attempt` with saturation.
1. **`hole_common::retry::retry_if(op, predicate, max_attempts, base_delay)`** — generic predicate-based retry with exponential backoff. Ships with an `is_file_contention(&io::Error)` predicate that matches `ERROR_ACCESS_DENIED` (5) / `ERROR_SHARING_VIOLATION` (32) on Windows and `ETXTBSY` / `EBUSY` on macOS.

`DistHarness::spawn` composes them: `retry_if(|| cmd.spawn(), is_file_contention, 3, 500ms)`, and on terminal failure calls `handle_holders::log_holders(&hole_exe)` before propagating. See bindreams/hole#208 for the incident that motivated this.

### Port allocation

Getting a free port for local binding or SIP003 subprocess handoff goes through `hole_common::port_alloc` ([crates/common/src/port_alloc.rs](crates/common/src/port_alloc.rs)):

- `Protocols` — bitflag set of `TCP | UDP`. `hole_common::plugin::plugin_protocols(name)` maps a plugin's `udp_supported` bit to the right set.
- `bind_with_retry(ip, protocols, attempts, op) -> io::Result<(u16, T)>` — **the canonical entry point.** Allocates a port, calls `op(port)`, and retries the whole (allocate, bind) cycle on `is_bind_race` errors. Three production sites use it: `LocalDnsServer::bind`, `start_plugin_chain`, and `test_support::ssserver::start_real_ss_server*`.
- `free_port(ip, protocols) -> io::Result<u16>` — primitive: finds a port free for every transport in `protocols`. Multi-transport is implemented as "pick via one transport, verify the rest via `ensure_port_free`, retry on mismatch." Retries internally on `ErrorKind::AddrInUse | PermissionDenied | AddrNotAvailable` (the [`is_bind_race`](crates/common/src/retry.rs) predicate). Terminal `WARN` log on exhaustion. **Direct callers are rejected by clippy `disallowed_methods`** — use `bind_with_retry` instead, or suppress with `#[allow]` + comment when the port must be returned to the caller before the bind happens (`test_support::port_alloc::allocate_ephemeral_port` is the sanctioned exception). See bindreams/hole#285.
- `ensure_port_free(addr, protocols)` — pure probe without allocation; binds one socket per transport and drops.

`LocalDnsServer::bind` ([crates/bridge/src/dns/server.rs](crates/bridge/src/dns/server.rs)) routes port-0 callers through `bind_with_retry` to absorb the TOCTOU between `free_port`'s probe-drop and the real UDP+TCP pair bind. Fixed-port callers (`bind_ladder` on port 53) skip the wrapper — retry in place is futile, the ladder is the correct escape.

The retry exists because Windows maintains **independent TCP/UDP excluded-port-range tables** (Hyper-V / WSL / Docker Desktop reservations, visible via `netsh int ipv4 show excludedportrange`); an OS-picked ephemeral port for one transport may be reserved for the other and the paired bind transiently fails. Galoshes's `garter::chain::allocate_one_port` hits the same class of bug — see bindreams/galoshes#21 for the deterministic `SO_EXCLUSIVEADDRUSE`-wildcard reproducer.

**Scope of `bind_with_retry`.** The retry catches `is_bind_race` errors that surface from `op` as `io::Error`. Out-of-process binders (plugin subprocesses) report bind failures through other channels and are *not* retried by the wrapper. The retry-asymmetry per consumer:

- **`LocalDnsServer::bind`** (no plugin) — load-bearing. UDP+TCP bind synchronously inside `op`; bind races propagate as `io::Error` and are retried.
- **`start_real_ss_server`** (no plugin) — load-bearing. `SsServerBuilder::build` binds TCP+UDP synchronously; bind races propagate as `io::Error` (this is what fixed #285).
- **`start_real_ss_server_with_plugin_*`** — structural-consistency only. The public_port is bound by the plugin subprocess after `build()` returns Ok; a public-port WSAEACCES surfaces as a `wait_for_port` timeout / connection refused, never as `io::Error`. The wrapper here only catches races on the SS-side rendezvous loopback port. Per-protocol correctness comes from the right `Protocols` argument.
- **`start_plugin_chain`** — structural-consistency only. Plugin subprocess binds out-of-process; failures arrive as `ProxyError::Plugin(...)` via oneshot timeout / exit-before-ready and are converted to non-bind-race `io::Error::other` so they propagate immediately.

The actual race-mitigation for the structural-consistency sites comes from `free_port`'s internal probe-side retries.

### Logging directives

`HOLE_BRIDGE_LOG` accepts a comma-separated list of `tracing` filter
directives, all of which are honored
([`crates/bridge/src/logging.rs`](crates/bridge/src/logging.rs)). The
default is `hole_bridge=info`. Examples:

- `HOLE_BRIDGE_LOG=hole_bridge=debug` — bridge-only debug.
- `HOLE_BRIDGE_LOG=hole_bridge=debug,shadowsocks_service=trace` —
  bridge debug + shadowsocks-service per-relay byte counts. The TRACE
  line shape from
  [`shadowsocks-service local/utils.rs`](https://docs.rs/shadowsocks-service/1.24.0/src/shadowsocks_service/local/utils.rs.html)
  is `tcp tunnel <peer> <-> <target> (proxied) closed, L2R N bytes, R2L M bytes`. Load-bearing diagnostic for #248-class tunnel issues
  ("did the plugin chain receive any bytes back?"). `LogTracer` is
  installed automatically via `tracing-subscriber 0.3`'s default
  features so `log::*!` events from third-party crates surface as
  tracing events.

`RUST_LOG` is also honored (read by
`EnvFilter::from_env_lossy()` upstream of `add_directive`); both
compose. Setting `shadowsocks_service=trace` in production is
expensive — Full-tunnel mode + heavy browsing produces roughly one
TRACE line per TCP connection (≥100/sec under Chrome). Use for
debugging sessions only; `bridge.log` rotates via
`MAX_LOG_BYTES`/`MAX_ROTATED_LOGS` so the cap is bounded.

### Plugin tap (HOLE_BRIDGE_PLUGIN_TAP)

When the bridge's local SOCKS5 listener relays a connection to the
plugin chain, the boundary in between is normally invisible — the
plugin process (`v2ray-plugin`, `galoshes`) runs out-of-process and
its network I/O is not captured by the bridge's ETW consumer. Setting
`HOLE_BRIDGE_PLUGIN_TAP=1` interposes
[`garter::TapPlugin`](crates/garter/src/tap.rs) between
shadowsocks-service and the inner plugin. Per-TCP-connection it logs:

- `bytes_to_plugin` / `bytes_from_plugin` — raw byte counts in each
  direction, observed by [`garter::CountingStream`](crates/garter/src/counting.rs).
- `ttfb_ms` — milliseconds from `accept` to the first non-zero
  upstream read. `None` means the connection closed without ever
  receiving a byte from the plugin chain — the load-bearing diagnostic
  for #248-class "tunnel returns nothing" cases.
- `close_kind` — taxonomy of how the connection ended (`graceful`,
  `rst`, `abort`, `eof`, `timeout`, `broken_pipe`, `other`),
  cross-platform via Win32+POSIX errno mapping.
- `close_dir` is implicit in the byte-count asymmetry: if
  `bytes_inbound_read != bytes_inbound_written` an inflight cancel hit.

**Dev-mode only.** Service-mode bridges (Windows SCM / launchd) do not
inherit user shell env, so the gate is meant for `scripts/dev.py` and
hand-run `hole bridge run`. Cost: an extra loopback round-trip per
byte, fine for a debugging session, inappropriate as default.

### Plugin debug logging (always-on)

`crates/bridge/src/proxy/plugin.rs::inject_plugin_debug_logging` always
appends a debug-level log directive to the plugin's `SS_PLUGIN_OPTIONS`
when the plugin's syntax is known:

- `v2ray-plugin` → appends `;loglevel=debug`. v2ray-plugin honors the
  last occurrence of any duplicate key, so this overrides a user's
  earlier `loglevel=warning`.

The cost is paid in `bridge.log` volume; the bridge captures plugin
stderr via `garter::binary` and routes it through the tracing
subscriber, so users still filter normally via `HOLE_BRIDGE_LOG`. The
diagnostic value (catching plugin-side handshake / dial / WebSocket
failures) is high — plugin-process invisibility was the recurring
blocker on #248-class tunnel issues. Future binary plugins can extend
the match arm in `inject_plugin_debug_logging`.

### CLI

```
hole [--show-dashboard]           → GUI (default)
hole version                      → print version information
hole bridge run [--socket-path P] [--log-dir DIR] [--state-dir DIR] → run bridge (foreground, needs elevation)
hole bridge run --service [--log-dir DIR] [--state-dir DIR]         → run as service (invoked by SCM/launchd)
hole bridge install               → register + start bridge service (needs elevation)
hole bridge uninstall             → stop + remove bridge service (needs elevation)
hole bridge status                → print install/running status
hole bridge log [--log-dir DIR]   → print bridge log to stdout
hole bridge log path [--log-dir DIR] → print log file path
hole bridge log watch [--tail N] [--log-dir DIR] → stream log output
hole bridge grant-access [--then-send B64 | --then-send-file PATH] → create hole group, add user, write SID file (needs elevation)
hole bridge ipc-send (--base64 B64 | --request-file PATH)          → proxy a single IPC command (needs elevation)
hole proxy start --config-file PATH [--local-port PORT] [--local-port-http PORT] [--no-socks5] [--http] [--tunnel-mode MODE] → start the proxy from a ServerEntry JSON file
hole proxy stop                                                    → stop the proxy
hole proxy test-server --config-file PATH                          → run a one-shot connectivity test against a server config
hole upgrade                      → check for updates and install latest version (unattended)
hole path add                     → add hole to system PATH
hole path remove                  → remove hole from system PATH
```

### Crash recovery

While a proxy is active, the bridge persists two small state files for
crash recovery, both in `<state_dir>/`:

- **`bridge-routes.json`** — records the installed TUN name, server IP,
  and upstream interface. Cleared on clean shutdown. On next startup,
  `routing::recover_routes` tears down any routes leaked by a previous
  crashed run.
- **`bridge-plugins.json`** — records the PIDs and start times of plugin
  processes (v2ray-plugin, galoshes) spawned by the bridge. Cleared on
  clean shutdown. On next startup, `plugin_recovery::recover_plugins`
  kills any tracked processes that are still alive (with PID-reuse
  safety via start-time verification). The same file is also read by the
  test harness (`DistHarness::drop`) to reap leaked plugins after tests.
- **`bridge-dns.json`** — records the DNS loopback bind address and the
  prior system-DNS configuration (per adapter, per v4/v6 family: static
  list / DHCP / none). Written after `LocalDnsServer::bind_ladder` and
  before `SystemDnsConfig::apply`; cleared on clean shutdown. On next
  startup, `dns::recovery::recover_dns_config` restores prior settings
  and deletes the file. The recovery runs *before* `routing::recover_routes`
  so a mid-recovery crash leaves the user with functional DNS + broken
  routes rather than the harder-to-debug inverse.
- **ETW sessions** (Windows only) — the bridge opens a named ETW trace
  session `hole-bridge-etw-<pid>` for in-process network diagnostics
  (see `crates/bridge/src/diagnostics/etw.rs`). A crashed bridge leaves
  this session alive until the machine reboots. On next startup,
  `diagnostics::etw::sweep_stale_sessions` enumerates live sessions via
  `QueryAllTracesW` and stops any whose name starts with
  `hole-bridge-etw-`. Sweep is keyed on the name prefix only, safe
  against PID reuse.

All three recovery paths run *after* the IPC socket is bound. If the
in-bridge recovery fails or the process can't restart,
`scripts/network-reset.py` reads the route state file and performs an
equivalent cleanup from outside (plugin reaping by name as a last
resort; ETW sessions are best-effort via `logman stop` from the shell).

## Workspace layout

Each publishable workspace member declares a release group in
`[package.metadata.hole-release].group` (see "Releases" above) — column 3
of this layout. `publish = false` means the crate is not pushed to
crates.io; the group still controls its version lock.

```
crates/common/            → hole-common.  GPL-3.0, hole group, publish=false.
                            Shared types: protocol, config, import.
crates/bridge/            → hole-bridge.  GPL-3.0, hole group, publish=false.
                            Bridge library, no binary.
crates/hole/              → hole.         GPL-3.0, hole group, publish=false.
                            Tauri app + CLI + bridge entry point, binary name: "hole".
crates/tun-engine/        → tun-engine.   GPL-3.0, hole group, publish=false.
                            General-purpose TUN + routing + packet-loop engine.
crates/tun-engine-macros/ → tun-engine-macros. GPL-3.0, hole group, publish=false.
                            Proc-macro support crate for tun-engine (`#[freeze]`).
crates/dump/              → dump.         GPL-3.0, hole group, publish=false.
                            YAML-shaped representation for logging (dump trichotomy).
crates/dump-macros/       → dump-macros.  GPL-3.0, hole group, publish=false.
                            Proc-macro support for `dump` (#[derive(Dump)]).
crates/handle-holders/    → handle-holders. GPL-3.0, hole group, publish=false.
                            File-handle introspection (Windows NtQuery / macOS lsof).
crates/garter/            → garter.       Apache-2.0, garter group, **published to crates.io**.
                            SIP003u plugin-chain runner library (ChainPlugin, ChainRunner).
crates/garter-bin/        → garter-bin.   Apache-2.0, garter group, publish=false.
                            `garter` binary (YAML-config-driven plugin chainer for
                            plugin developers; NOT shipped in Hole's MSI).
crates/galoshes/          → galoshes.     Apache-2.0, galoshes group, publish=false.
                            Bundled SIP003u plugin: YAMUX-multiplexed TCP+UDP relay
                            with embedded v2ray-plugin (SHA256-verified at compile time).
                            Shipped alongside hole.exe AND released standalone for servers.
crates/mock-plugin/       → mock-plugin.  Apache-2.0, no group, publish=false.
                            Minimal SIP003u TCP echo plugin for garter integration tests.
build.yaml                → declarative build-target manifest (the DAG of `hole`,
                            `hole-msi`, `hole-dmg`, `galoshes`, `*-tests`, `clippy-*`,
                            `prek`, `frontend-check`, etc.) consumed by
                            `cargo xtask build|run|list`. Schema in
                            xtask/src/manifest.rs; orchestration in xtask/src/orchestrate.rs.
xtask/                    → workspace task runner. Top-level commands:
                            - `cargo xtask build <name> | --all`  — run a target's `build:` steps
                            - `cargo xtask run <name>`            — run a target's `run:` steps
                                                                    (tests, linters, dev mode);
                                                                    invokes the build cascade first
                            - `cargo xtask list`                  — print the target table
                            Primitive subcommands stay available for one-off use:
                            `cargo xtask <stage|deps|v2ray-plugin|galoshes|wintun|version|...>`
xtask-lib/                → shared helper crate used by xtask AND crates/hole/build.rs
external/                 → Third-party source (git-subrepos via ingydotnet/git-subrepo,
                            not git submodules): `v2ray-plugin` (Go). v2ray-plugin
                            release-group version lives at
                            external/v2ray-plugin/version.toml.
msi-installer/            → WiX MSI installer (Python project: thin wrapper around xtask + WiX)
scripts/                  → Utility scripts (dev.py, network-reset.py, sign-release.py, ...)
ui/                       → Frontend HTML/CSS/TypeScript (Vite)
```

The ex-Galoshes crates (`garter`, `garter-bin`, `galoshes`, `mock-plugin`)
are Apache-2.0 per-crate — see [NOTICES.md](NOTICES.md) for the
attribution. Hole's own crates are GPL-3.0-or-later; combined binary
distributions produced by this workspace (`hole.exe`, `hole.msi`,
bundled `galoshes.exe`) ship as a whole under GPL-3.0 per Apache→GPL
one-way compatibility.

### v2ray-plugin embedding

The `galoshes` crate embeds the v2ray-plugin Go binary into its own
executable at compile time:

1. Go source lives at [external/v2ray-plugin/](external/v2ray-plugin/),
   managed as a `git-subrepo` of `shadowsocks/v2ray-plugin` (the ingydotnet
   tool, not `git submodule`). Pull upstream changes with
   `git subrepo pull external/v2ray-plugin`. Hole-local security/feature
   patches land as ordinary commits on top. `git subrepo push` is not
   used — we do not contribute back automatically.
1. `cargo xtask v2ray-plugin` (or `cargo xtask deps`, which calls it
   first) builds the Go source into
   `.cache/v2ray-plugin/v2ray-plugin-<host-target-triple>[.exe]`.
1. [`crates/galoshes/build.rs`](crates/galoshes/build.rs) reads that
   cache file, computes its SHA-256, and emits `V2RAY_PLUGIN_PATH` +
   `V2RAY_SHA256` as env vars the crate `include_bytes!`s. At runtime,
   `galoshes` re-hashes the embedded bytes and refuses to run on
   mismatch — compile-time binary integrity.
1. `output_name()` in `xtask/src/v2ray_plugin.rs` maps the host target
   triple to the expected cache filename; it covers all six target
   triples in the CI matrix (Hole's Windows/macOS set plus ex-Galoshes
   Linux x64/arm64 and Windows-arm64).

Build orchestration is owned by `xtask/`. The canonical list of files that
go into the runnable BINDIR (next to `hole.exe`) lives in
[xtask/src/bindir.rs](xtask/src/bindir.rs); both `scripts/dev.py` and
`msi-installer` call `cargo xtask stage` instead of duplicating composition.
Runtime asset acquisition (v2ray-plugin Go build, wintun.dll download) lives
in `cargo xtask deps`. `crates/hole/build.rs` is restricted to compile-time
metadata (icon generation, git version via `xtask-lib::version`).

`cargo xtask stage --with-tests --tests-out-dir <dir>` additionally stages
workspace test binaries at stable paths (`<dir>/{crate}.test.exe`) so Windows
Firewall can cache consent across rebuilds (bindreams/hole#210). Convention:
`<dir>` is the sibling of `--out-dir` (e.g. `target/debug/dist/tests`). When
two cargo targets share a name (e.g. the `hole` crate's lib and bin), the
staged name is disambiguated to `{crate}-{kind}.test.exe`
(`hole-lib.test.exe` + `hole-bin.test.exe`).

## Build

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow (hot-reload, foreground bridge mode).

Requires: Rust toolchain, Go toolchain (for v2ray-plugin), Node.js.

```sh
npm install                      # install frontend dependencies (first time only)
cargo xtask build hole           # deps + cargo build (debug) + stage — single command
cargo xtask run hole             # dev mode (= build hole + uv run scripts/dev.py)
cargo xtask run hole-tests       # canonical local nextest invocation for hole crates
```

`build.yaml` at the repo root is the single source of truth for the build
graph. `cargo xtask list` prints the full target table.

### Windows installer

```sh
uv run --directory msi-installer build       # builds hole.msi in target\release\
msiexec /i target\release\hole.msi           # interactive install
msiexec /i target\release\hole.msi /quiet    # unattended install
```

### macOS DMG

```sh
npx tauri build                  # produces .dmg in target/release/bundle/
```

## Testing

Uses [skuld](https://github.com/bindreams/skuld) framework (`#[skuld::test]`), not `#[test]`.
Unit test files are siblings: `foo.rs` → `foo_tests.rs`.

### Windows installer

```sh
cd msi-installer && uv run --group dev pytest -v   # WiX source + MSI build validation
```

## Releases

Four independent release tracks, one per product. Each tags as
`releases/<product>/v<X.Y.Z>` and has its own draft+publish workflow pair.
Version per group is declared in each crate's
`[package.metadata.hole-release].group` and enforced workspace-wide by
`xtask-lib::version` (publishable-but-ungrouped crates are rejected;
within-group versions must match).

| Product        | Group members                                                                                       | Artifacts                                                                | Signed         | crates.io     |
| -------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | -------------- | ------------- |
| `hole`         | `hole, hole-common, hole-bridge, tun-engine, tun-engine-macros, dump, dump-macros, handle-holders`  | MSI + DMG (amd64+arm64) + `SHA256SUMS`                                   | Yes (minisign) | No            |
| `galoshes`     | `galoshes`                                                                                          | 6-platform server binaries + `SHA256SUMS`                                | No             | No            |
| `garter`       | `garter, garter-bin`                                                                                | crates.io `garter` lib + 6-platform `garter` CLI binaries + `SHA256SUMS` | No             | `garter` only |
| `v2ray-plugin` | (not a Rust crate — version in `external/v2ray-plugin/version.toml`, lineage form `X.Y.Z[-hole.N]`) | 6-platform tar.gz set (upstream parity + windows-arm64) + `SHA256SUMS`   | No             | n/a           |

Asset naming:

- hole: `hole-{version}-{os}-{arch}.{msi,dmg}` (unchanged)
- galoshes: `galoshes-{version}-{os}-{arch}[.exe]`
- garter: `garter-{version}-{os}-{arch}[.exe]` (binary from `garter-bin`)
- v2ray-plugin: `v2ray-plugin-{os}-{arch}-v{version}.tar.gz` (matches upstream's exact shape)

### Why only hole is signed

`hole` is auto-updated end-user software — supply-chain integrity matters.
The other products are either embedded into hole (so their bytes are
covered by hole's signature) or built-from-source by their consumers
(server operators, plugin developers) who can pin SHA256 against
`SHA256SUMS` directly.

### Why draft/publish split for every track

Draft does all reversible preparation (build, test, hash, upload to
draft release) — the "engineer" workflow. Publish does irreversible
public actions (tag creation, `cargo publish` for garter, latest-flip)
— the "boss" workflow. The split exists for every product to keep one
sanity-check gate before irreversible work, not just for hole's signing
step.

### Per-product release workflows

- **hole**: `draft-release-hole.yaml` → `scripts/sign-release.py <version>` → `publish-release-hole.yaml`. Tag created at publish.

- **galoshes**: `draft-release-galoshes.yaml` → `publish-release-galoshes.yaml`. No signing.

- **garter**: `draft-release-garter.yaml` (also runs `cargo publish --dry-run -p garter` for early failure) → `publish-release-garter.yaml`. Publish workflow is idempotent: it queries crates.io's API to see whether the version already exists (200) and skips the `cargo publish` step if so, so a re-run after a partial-failure resumes cleanly. A `dry_run: true` input runs `cargo publish --dry-run` and exits without touching crates.io or the tag.

- **v2ray-plugin**: `draft-release-v2ray-plugin.yaml` → `publish-release-v2ray-plugin.yaml`. The matrix is upstream's release platform set — darwin amd64/arm64, linux amd64/arm64, windows amd64 — **plus windows-arm64**, which upstream doesn't ship but we already build and transitively test via galoshes-on-windows-arm64 (galoshes embeds v2ray-plugin). 6 platforms total. When upstream changes its set, edit the matrix and the SHA256SUMS line count in the draft workflow. Hole-local v2ray-plugin patches land via `git subrepo pull external/v2ray-plugin` followed by ordinary commits.

  **Lineage versioning.** v2ray-plugin's version (`external/v2ray-plugin/version.toml`) follows the convention `X.Y.Z` (we vendor upstream's `vX.Y.Z` release exactly) or `X.Y.Z-hole.N` (we vendor upstream-master between two upstream tags, with `N` counting our successive Hole-side release iterations against the same `X.Y.Z` base). Per semver, `X.Y.Z-hole.N` orders strictly above `X.Y.Z-1`'s artifacts and strictly below upstream's eventual `vX.Y.Z` — capturing exactly the "between releases" semantic. Precedent: Go modules' pseudo-versions use the same `X.Y.(Z+1)-pre` shape.

  Worked example: our current vendored commit `e9af1cd` is 5 upstream-master commits past `v1.3.2` (including a v2ray-core v4→v5 migration). Bump base = `1.3.3` (next patch after upstream's last tag), iteration = `1` (first Hole release of this base) → `version = "1.3.3-hole.1"`.

  **Maintainer rules** (xtask-lib/src/v2ray_plugin_version.rs enforces shape + sequence; bases are your call):

  - When pulling upstream-master between two upstream tags: set `X.Y.Z` to upstream's next-patch-after-last-tag and `N` to 1 (or increment if you've cut a prior Hole release against the same base).
  - When pulling at an upstream tag exactly: set version to that tag's bare `X.Y.Z` (no `-hole.N` suffix).
  - On each successive Hole release with the same `X.Y.Z` base, increment `N` by exactly 1 (no gaps). The validator rejects skips.
  - The validator does NOT cross-check against upstream's tag history (we don't have upstream's git data locally); the maintainer is responsible for picking the right `X.Y.Z` base.

  **Display-version note.** Dev builds downstream of `releases/v2ray-plugin/v1.3.3-hole.1` produce `1.3.3-hole.1-snapshot+git.<hash>`. This is valid semver — the `-snapshot` extends the pre-release identifier — and intentional. Two dashes before `+git.` is not a bug.

### Version model (`cargo xtask version`)

```
cargo xtask version                                     # table of every group's resolved version
cargo xtask version --group <hole|garter|galoshes|v2ray-plugin>            # one group's display version
cargo xtask version --check --group <name>              # validate Cargo.toml vs nearest tag (one-bump-ahead OK)
cargo xtask version --check --group <name> --exact      # validate exact match (release CI uses this)
```

When a group has no `releases/<group>/v...` tag yet (bootstrap state),
the non-`--exact` check accepts any version; `--exact` errors loudly.

The legacy `v0.1.0` tag predates this scheme; per-group tag-glob lookups
ignore it.

## Icons

Source icons under `crates/hole/icons/` are split per platform:

- `icon-windows.svg` / `icon-macos.svg` — app icons; `build.rs` selects by `CARGO_CFG_TARGET_OS`.
- `tray-windows-{light,dark}.svg` — tray icons for light/dark Windows taskbars (selected at runtime via the `SystemUsesLightTheme` registry value).
- `tray-macos.svg` — macOS tray template; luminance-to-alpha by `build.rs`, then `icon_as_template(true)` at the Tauri layer.

`TrayState::Disabled` currently aliases to `Enabled` — both resolve to the same bytes in [crates/hole/src/tray_icons.rs](crates/hole/src/tray_icons.rs). The enum is preserved so a designer-supplied disabled variant can drop in without API churn at call sites.

The build script (`build.rs`) converts them automatically. Do not commit generated raster icons.
