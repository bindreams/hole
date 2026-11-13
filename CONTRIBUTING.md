# Contributing to Hole

Product overview and install live in [README.md](README.md); an agent-facing
architecture map lives in [CLAUDE.md](CLAUDE.md). This file is the contributor
reference: how the system is built and the invariants you must not break.
How to set up, build, run and test it is in
[docs/contributing/](docs/contributing/index.md).

## Architecture

How Hole is put together (its two modes, its layers and the kill switch) is in
the contributor docs, starting at
[the architecture overview](docs/contributing/architecture/overview.md). The
subsections below are the subsystems not yet moved there.

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

**A start's token does not outlive the start.** It stays registered in
`handle_start` until the session has committed and persisted, so a Cancel can
still reach it after the proxy is running. State that lives as long as the
session therefore must not descend from it: the plugin chain owns its own
shutdown token (`spawn_plugin_runner_at`) and honours the start token explicitly
while the start is in progress. The chain's task and token live in one
`ChainTask` whose `Drop` ends the chain, so a start future being dropped tears the
plugin down. Every failure inside the start awaits `ChainTask::end` before it is
reported: the token is signalled and the task aborted and awaited, so the runner starts no
further plugin before the teardown's reap (see the limit below), and a Cancel never waits for
garter's drain. The
plugins get no graceful stop: the abort drops garter's `kill_on_drop`, contained plugin child, which
hard-kills the plugin's process tree, and the reap is the backstop that kills by recorded identity. Afterwards the chain
ends only through `PluginChain::end` or when a plugin exits, which `check_health` reads as a
death. garter's `ChainRunner` given a `cancel_token`
registers no signal handler of its own (one without a token keeps it), so a
SIGTERM or Ctrl+C reaches the chain only through the bridge's own shutdown, never
as an apparent plugin death.

**Every exit of a start ends in one teardown.** `start_inner` builds a
[`Session`](crates/bridge/src/session.rs) that owns each resource from the moment it is
acquired. A failed start, a stop and a health-check give-up all run `Session::teardown`: DNS
restore, engine, the plugin chain ended (`PluginChain::end`: cancelled, aborted, its runner awaited) and then its
plugins reaped, `proxy.stop().await`, routes, and the standing cover handed back for the caller to
settle (a stop) or release under the cover lock (a failed start). The reap runs whenever a
plugin is configured, by the recorded identities in the state directory, so a chain that
spawned and then failed to become ready is reaped too; it runs on a blocking thread (inline if
the runtime cancelled that task before it ran). No phase of the teardown observes a cancel
token.

The chain's end waits for garter's runner, not for the per-plugin tasks it spawned: a plugin being
started at that instant may still spawn and record itself after `end` returns. Its own drop kills
the process tree, and its record stays in the state file for the next reap to remove by identity.
This happens only to a start cancelled, or failing readiness, mid-spawn. Joining those tasks is
tracked in [#1244](https://github.com/bindreams/hole/issues/1244).

`Drop` is only the net for a panic or a dropped future, and it is not the teardown run
implicitly. `Session` declares its fields in the teardown's release order (DNS, dispatcher,
plugins, proxy, routes, standing cover) and a drop releases them in that order, awaiting
nothing: a DNS guard or dispatcher dropped without its awaited `shutdown()` is a drop bomb in
debug builds and falls back to a synchronous release in release builds, the plugin chain is
aborted without a join (its plugin child's drop kills the tree, but nothing waits for that and no
reap runs, so a plugin it recorded may outlive it) and
`proxy.stop()` is not awaited (the running proxy's own `Drop` closes its sockets).

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

**The engine driver's join carries no bound.** Every await in
[`Driver::run`](crates/tun-engine/src/engine/driver.rs) is raced against the
driver's cancellation token, including the DNS interceptor call
(`tun_engine::engine::dns::intercept`) and the TUN write
(`tun_engine::engine::egress::flush`) — the loop's only await a unix `AsyncFd`
can hold `Pending` on indefinitely. Because of that,
[`Dispatcher::shutdown`](crates/bridge/src/dispatcher.rs) joins the driver task
with no bound, awaiting through `&mut JoinHandle` so a cancelled caller cannot
detach it, and returns a `DriverExit`. What it actually waits for on Windows is
the synchronous `WintunCloseAdapter` call (plus a registry subtree delete),
which runs in the future's `Drop` once `Driver::run` returns — finite and
uninterruptible (tokio **1.52.3**: a task's future is dropped before its join
waker fires, `runtime/task/harness.rs:549` via `runtime/task/core.rs:403-408`),
which is why a bound at the join would leak the adapter rather than merely
being unnecessary. Consequence: on the bridge's multi-thread runtime,
`Dispatcher::drop` blocks unboundedly the same way, so **dropping a future
that owns a `Dispatcher` does not cancel that wait — it converts it into a
synchronous block on the dropping thread.** No caller may drop such a future
as a way to bound anything — this is what rules out a `TimeoutLayer` on the
IPC router. See #905.

[`SystemDnsApplied`](crates/bridge/src/dns/system.rs) owns a `DebugDropBomb`
defused by `shutdown()` and is constructed only in the `Ok` branch of
`Dns::apply`. **Known follow-up:** `SystemRoutes::Drop` still tears down routing
synchronously (blocks the worker on `netsh`/`route`); converting it to the
`shutdown` + `DebugDropBomb` discipline is tracked.

### Proxy shutdown contract

`ShadowsocksRunning::stop()` / `Drop` (`crates/bridge/src/proxy/shadowsocks.rs`)
must close every socket the shadowsocks local server bound before returning —
otherwise an immediate rebind of the same fixed port fails with
`AddrInUse` (#876).

**Three abort layers, not one.** Upstream (`shadowsocks-service` 1.24.0) tears
`local::Server::run()` down through nested `Drop` → `abort()`, none of which
Hole can join because the handles are private:

| Layer | Who aborts                                                | What the aborted task still owns                                                             |
| ----- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| 1     | `ShadowsocksRunning::stop` aborts the `server.run()` task | nothing directly; its drop triggers layer 2                                                  |
| 2     | `utils::ServerHandle::drop` → `abort()`                   | the `Socks`/`Http` accept loops — the TCP listener and the bound UDP socket                  |
| 3     | `UdpAssociation::drop` → `abort()`                        | an `Arc` clone of the inbound SOCKS5 UDP listener, held by every live UDP association's task |

Holding the layer-2 sub-handles ourselves (the obvious fix) still leaves layer
3 open: `UdpAssociationManager` never surfaces its handles, so a live UDP
association keeps the port bound until its task is dropped. `Server::run(self)`
consumes the server and exposes no shutdown signal either — the fix is a
runtime-level join, a strict superset of anything an upstream API could offer.

**The fix: each proxy gets its own tokio runtime** (`SsRuntime`), and
`stop()`/`Drop` shut it down and block until every task on it has dropped —
that join is what closes the descriptors.

**Where `drop(Runtime)` is legal.** `Runtime::drop` panics unless
`try_enter_blocking_region()` returns `Some`, which holds **iff the calling
thread is not inside any runtime** — flavour is irrelevant to the predicate,
it only decides whether `block_in_place` is available. Three ways to satisfy
it: outside any runtime, inside a `spawn_blocking` closure, or inside
`block_in_place` on a multi-thread worker (which temporarily exits the
runtime for the closure's duration). A fresh `std::thread` is unconditionally
outside any runtime, so hopping to one always works.

`spawn_blocking` is tempting but unsound as the hop: when the target pool is
shutting down, `Spawner::spawn_task` drops the closure **inline on the
calling thread** instead of running it — if that thread is an entered
worker, dropping the captured `Runtime` there panics, and the runtime is left
half torn down with nothing left to join it. `join_runtime` therefore always
hops via `std::thread::spawn(..).join()`, and uses `block_in_place` only to
release a multi-thread worker's core first (mirroring `Dispatcher::drop`) —
never as the hop itself. This mechanism has no failure path with respect to
the `drop(Runtime)` legality predicate above, so `stop()`'s port-release
guarantee is unqualified against *that*: no `Err` arm, no flavour-specific
fallback, no shutdown-race carve-out. It carries exactly one accepted,
orthogonal exception: `std::thread::spawn` itself panics if the OS refuses to
create a new thread (resource exhaustion) — a whole-process condition no
`Result` plumbing in `join_runtime` would meaningfully recover from, and
distinct from the legality predicate this function exists to satisfy.

**No error arm, deliberately.** Recovering from that OS-thread-creation
failure would need `std::thread::Builder::spawn` plus a channel to hand `rt`
to the scratch thread only *after* confirming it spawned — the closure
passed to `spawn` cannot simply own `rt` and fall back to `mem::forget` on
`Err`, because a failed spawn has already dropped the closure (and therefore
`rt`, inline, on the calling thread) by the time `Err` is observed, which is
the exact hazard this function exists to avoid. That channel-based version is
possible but is not worth the added surface for a condition this rare, right
after `SsRuntime::new` just created four more OS threads via the same
allocator. Accepting the panic is the chosen resolution.

**`stop()`'s ordering is load-bearing.** It classifies the task's own exit
(await the aborted `JoinHandle`, distinguishing panic from cancellation)
*before* joining the runtime — joining first would make every outcome look
like a plain cancellation.

**`worker_threads(4)`** on `SsRuntime` is a reduction from the ambient
runtime's `available_parallelism()` (what the proxy used to run on).
Unmeasured — falsified by a sustained single-tunnel throughput measurement on
a >4-core box that saturates all four workers, or a CPU profile showing the
`hole-ss` threads pinned during a large transfer. The local server is
expected to be I/O-bound (loopback accept, SOCKS5 framing, a copy loop), with
the remote server and plugin chain as the practical ceiling — but this has
not been measured.

**Tracing hand-off, test-only.** `garter::tracing_test::set_default_in_current_thread`
asserts the *ambient* runtime is current-thread; it cannot see that a task
now runs on `SsRuntime`'s own workers instead, so without help their tracing
events land with no subscriber and are silently dropped in tests. Production
installs a subscriber globally (`crates/common/src/logging.rs`) and needs no
hand-off, so `SsRuntime::new` gates the whole mechanism behind `#[cfg(test)]`:
it captures the constructing thread's dispatcher and re-installs it on every
worker via `Builder::on_thread_start`, and — this is the part that is easy to
get wrong — **clears it in a matching `on_thread_stop`, never `mem::forget`s
it**. `tracing-core`'s `DefaultGuard::drop` is the only site that decrements
the process-global scoped-dispatcher counter; forgetting the guard leaks that
counter permanently non-zero after the first proxy session, silently forcing
*every* thread in the process onto tracing's slower thread-local-lookup path
(and, past thread teardown, silently dropping events) for the rest of the
process's life — for the remainder of the test binary, since this is
test-only, but the failure mode is exactly the kind of silent event loss the
hand-off exists to prevent, so the guard discipline matters as much as the
hand-off itself.

**The no-hang property depends on a pinned dependency version.** `drop(Runtime)`
waits for currently-*running* blocking-pool tasks. Nothing reachable on
Hole's local-server path has one today:

- `shadowsocks` 1.24.0: Windows' `DnsResolver::System` branch calls a
  blocking `lookup_host`, but Hole's config never selects it — no ACL, all
  `ServerAddr::SocketAddr`.
- `hickory-resolver` / `hickory-proto` (pulled in transitively —
  `shadowsocks-service`'s default `hickory-dns` feature is on, and
  `crates/bridge/Cargo.toml` never disables default features): on unix,
  `local::Server::new` unconditionally constructs a hickory system resolver
  (`DnsConfig::System` is the default and Hole never overrides it), so this
  code *does* run on `SsRuntime` on Linux/macOS even though Hole never asks
  it to resolve anything. Neither crate has a `spawn_blocking` call today.

A dependency bump could reintroduce one with no other test going red —
`upstream_has_no_blocking_calls_on_the_shutdown_path`
(`crates/bridge/src/proxy/shadowsocks_tests.rs`) walks all four dependencies'
source trees and fails the build if it does. It is a textual, not semantic,
scan (exact-substring match on the literal identifiers, not scoped to
call-graph reachability) — a best-effort tripwire against an accidental
upstream reintroduction, not a proof against a determined rename/alias.


### Tray menu rebuild contract

All tray menu commits go through `tray::rebuild_tray_menu`, which dispatches
the whole rebuild — state reads included — to the main thread
(`run_on_main_thread` executes inline when already there). A raw `set_menu`
from a worker thread reads state early and commits the menu later through the
event-loop queue, so a stale menu can overwrite a newer one (the #473 desync).
The tray **icon** is committed inside the same ordered closure for the same
reason (the #492 stale-icon class). Enforcement is in
[`clippy.toml`](clippy.toml) (`TrayIcon::set_menu` is disallowed; the one
commit point inside `rebuild_tray_menu` carries a per-site `#[allow]`).
Corollary: `sync_autostart_state` is main-thread-only — menu-item setters
dispatch-and-block from any other thread, so calling it from a worker while
holding a lock deadlocks the app.

The rebuild renders from the runtime truth, never from persisted config
(#462): proxy state comes from `AppState`'s `ProxyStateCell` (fed by every
bridge exchange, inside the client lock) plus the in-flight `TransitionSlot`
target; status/connect text is baked into the menu at build time. Persisted
`config.enabled` records the last honored intent, with
`tray::persist_intended_enabled` as its sole writer; it is read at launch by
`tray::startup_should_connect` for `StartupBehavior::RestoreLastState` (#458).
The tray never renders from it — display and direction come from the
`ProxyStateCell`.

### Version lockstep

The GUI and bridge must never *operate* as a mismatched-version pair — the
single-exe design assumes it and the IPC contract has no version negotiation.
The bridge stamps its build version on **every** IPC response
(`X-Hole-Bridge-Version`, in [`build_router`](crates/bridge/src/ipc.rs)) and
serves it at `GET /v1/version`; the value is injected into `IpcServer::bind`
from the `hole` crate (the bridge crate can't read `HOLE_VERSION`). The GUI
client compares that header to its own `HOLE_VERSION` on every exchange and
returns `ClientError::VersionMismatch`; [`BridgeLink`](crates/hole/src/state.rs)
fires an injected self-heal hook ([selfheal.rs](crates/hole/src/selfheal.rs))
which, by `same_file` file-identity (startup image vs. the file at that path
now), either relaunches the updated image — via the cross-platform exit-wait
primitive [relaunch.rs](crates/hole/src/relaunch.rs), which watches the
predecessor through `cosca::Process::wait` — or, if it *is* the installed image,
shows a path-free reinstall dialog. The successor still has to read the
predecessor's identity while the `READY` handshake holds it alive: `wait` takes
an identity as input and re-verifies it, so the ordering plus the start token is
what closes the pid-reuse window. `relaunch.rs` carries no `#[cfg]` at all;
`decide` and the wiring are platform-agnostic and table-tested. Inert until an update produces a mismatch, and gated off for
dev/snapshot builds.

**One-time caveat:** a GUI built *before* this feature has no self-heal logic,
so the *first* upgrade-to-this-version can run a stale GUI against the new
bridge until the user restarts it — benign because the change is purely
additive (the IPC contract is preserved). The leak-free bridge swap that
*produces* the mismatch is the [update cutover](docs/contributing/architecture/update-cutover.md).

## Logging & diagnostics

### Log destinations

Both GUI and bridge write to stderr **and** a 10 MiB rotating file (one backup; a second file, `<name>.1.fallback`, only
while the first backup's name cannot take the rotation).
Default dir is `dirs::state_dir()/hole/logs` (`gui.log`, `bridge.log`):

- Windows `%LOCALAPPDATA%\hole\logs\`, macOS `~/Library/Application Support/hole/logs/`
- Installed service: Windows `C:\ProgramData\hole\logs\`, macOS `/var/log/hole/`

`hole bridge log` defaults to the installed-service dir; override with `--log-dir`
or `HOLE_LOG_DIR` to read a foreground/dev bridge's log.

The log directory sits in the user's profile when the bridge runs elevated on
their behalf, so `init_dual` opens it once as a
[`util::dir::Dir`](crates/util/src/dir.rs) (no symlink followed, created if
missing, handed to the user) and the log file is a
[`DirRotate`](crates/common/src/logging/dir_rotate.rs) inside that handle: the
open, the rotation rename, the legacy-file cleanup and the `chown` of each fresh
active file are all by a single name in it. A log directory the walk refuses (a
symlink a user could have planted) disables the file sink with one line on the
real stderr, which carries no path; the bridge keeps running.

A name the rotation cannot be renamed over (a directory at `bridge.log.1`, a handle without delete sharing on it)
sends the full file to `bridge.log.1.fallback` instead, replacing the one before it, so at most one such file exists;
a rotation that reaches `bridge.log.1` again removes the fallback, which holds older lines. When neither name can take
the file (the active file itself is held without delete sharing, or both names are directories) no line is lost: the
file keeps being appended past the limit while the holder keeps it, and the next rotation that succeeds restores the
limit. Only a file that cannot be opened loses lines, and says so once on the real stderr.

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
`CorruptedJson` (no fields) and logs the full error. **(3) The redaction
registry** ([below](#server-address-redaction)) for the configured server
address, which no per-site rule can cover.

### Server-address redaction

The configured server address — hostname, DoH-resolved IP, and every textual
form of either — is replaced by an opaque token before it reaches a log file,
the dev console, a toast, or the support bundle. For a censorship-circumvention
VPN it is the most sensitive value on the machine, and the default log filter is
a **global `info`** (`build_filter` seeds `info` and *then* adds
`hole_bridge=info`), so every crate in the process — third-party ones included —
can write one. That set is not enumerable in advance, which is why the sink
layer carries the weight.

**What is covered.** [`util::redact`](crates/util/src/redact.rs) holds a
process-global registry of armed literals behind an `ArcSwap` (lock-free reads,
so no logging call can block behind a concurrent arm) and an `aho-corasick`
automaton (`LeftmostLongest`, ASCII-case-insensitive). `RedactingWriter` wraps
four non-blocking writers in `init_dual`, and **exactly one of them is a log
file**: the `DirRotate` appender. Wrapping that one closes the file leak;
the other three (the stderr layer's writer and the two stdio-relay tees) are the
developer's terminal and cannot reopen it either way.

**What is armed.** `arm_server` derives, from `entry.server`: the value as
configured, its trailing-dot-stripped form, its `idna::domain_to_ascii` A-label,
and — when it parses as an IP — that address's canonical text. `arm_resolved_ip`
derives the bare and bracketed `[…]` forms (`handoff_host`'s IPv6 shape). **Each
candidate is then filtered individually**, not the input string:
`server = "127.0.0.1."` does not parse as an `IpAddr`, so a value-level carve-out
passes it through and the trailing-dot strip arms the bare loopback address —
turning every loopback mention in the process into a token. A candidate is armed
unless it is empty, matches `localhost` case-insensitively, or (after stripping
one `[`/`]` pair) parses to a loopback or unspecified address.

**Tokens.** `<server:XXXXXXXX>` — the first 8 hex characters of the entry's
random v4 UUID, never derived from the address — plus `<server:recovered>`, the
one token minted without an entry in hand (crash recovery replays a prior run's
routes before any config exists). Arming is keyed by literal, **last wins**: a
re-arm re-points the literal in place and emits one `info!` naming both tokens
and neither address, which is what joins the recovery lines to the session lines
in a collected bundle. Replaced in place, never appended, so the automaton stays
bounded however many times a long-running service arms.

**Collisions.** Nothing validates a configured host, so `server: "hole"` is
reachable, and arming it would rewrite `hole-tun`, `hole_bridge::proxy_manager`
and the log-directory path throughout the file. There is no non-arbitrary
threshold separating "too short" from "fine", so `arm` does not guess: it tests
the candidate against `COLLISION_CORPUS`, **arms it anyway** — privacy does not
yield — and emits one `warn!` naming the token and the collision, so the mangled
log explains itself. The corpus's only job is that warning, so its
incompleteness can weaken a diagnostic message and can never weaken redaction.

**Prevention.** `ServerAddress` ([`config.rs`](crates/common/src/config.rs))
implements neither `Display` nor `Deref`, so `server_host = %config.server.server`
is a compile error and `format!("{}", *addr)` cannot reopen it. `expose()` is
the single named exit, so grepping for it enumerates every real read site.
`Password` is the same shape beside it, and both carry a redacting `Debug` so
a derived `Debug` on a container is not a hole. The *absence* of those two
impls is pinned by compile-fail probes
([`crates/common/tests/secret_shape/`](crates/common/tests/secret_shape/),
driven by `trybuild` from `the_secret_newtypes_have_no_second_exit`): adding
either compiles cleanly and fails no other test, so the shape needs a test of
its own and not only its consequence.

**The password's asymmetry.** For the password, prevention is the *whole*
mechanism: nothing arms it into the registry above, so there is no sink-level
cure if a secret escapes through a formatter Hole does not own. That is
deliberate — a short or dictionary-word password armed into the global
automaton would rewrite unrelated log text, the `COLLISION_CORPUS` hazard
without the bounded corpus that makes it diagnosable. So the type is what has
to hold, and the two type-level rules below are load-bearing for the password
in a way they are merely belt-and-braces for the address.

**Where a secret enters.** `UiServerEntry`
([`ui_settings.rs`](crates/hole/src/ui_settings.rs)) is the one place a
password comes in from outside — the webview's `save_config` payload. It
carries both newtypes from the deserializer inward rather than wrapping at the
far end of `apply`, because it derives `Debug` and every field between those
two points would otherwise be renderable. Both newtypes are
`#[serde(transparent)]`, so the payload shape is unchanged.

**Key material can leak through an error, not just a log field.** The
2022-blake3 ciphers take the password as base64 key material, so
`ServerConfig::new` can reject it — and `shadowsocks::config::ServerConfigError`'s
`Display` names the offending byte and its offset, which is one character of
the user's key plus where to find it. All three `ServerConfig::new` sites
(`proxy::config::build_ss_config`, `server_test::build_server_config`, and the
plugin-path rebuild in `server_test::maybe_start_plugin`) route it through
`classify_key_material` — the one exhaustive match on that type — into
`KeyMaterialFault`, a closed set of causes carrying no decode detail. Its
`ProxyError` variant is `InvalidKeyMaterial`, not `InvalidMethod`: a cipher
name Hole does not know and a good cipher with a bad key are different faults
in different fields.

**And through a parse error.** `serde_json::Error`'s `Display` quotes its input
back — the offending value for a data error, an arbitrary caller-supplied
*string* for an unknown variant or field — and every JSON this workspace parses
can hold a protected value: the user's `config.json`, an imported profile, the
elevation payload (a whole `BridgeRequest`, in transit), and four bridge state
files (`bridge-target.json` and `bridge-startup.json` hold a password;
`bridge-routes.json` holds `server_ip`; `bridge-lockdown-pf.json`'s
`main_snapshot` holds one whenever the `pfctl -sr` ruleset it captured was
Hole's own cover). [`util::parse_error::describe_parse_error`](crates/util/src/parse_error.rs)
is the one door: category plus line and column, never a fragment. It lives in
`util` rather than `hole-common` because `tun-engine` parses two of those files
and does not depend on `hole-common`; `hole_common::config` re-exports it so
Hole-side callers keep one name. `ConfigError::Parse` and `ImportError::Parse`
go further and drop the `serde_json::Error` outright, carrying the same scalars
as *fields*, so neither their `Display` nor their derived `Debug` can echo.

The state-file and elevation sites are the sharp ones, for the same reason:
nothing is armed when they run. The elevation arms only after a successful
parse, and the crash-recovery sweep runs before any session exists — so on
those paths the address has no sink-level backstop either, and the password
never has one anywhere.

**What replaces the address in a Hole-authored line.** `server` (the token),
`server_kind` (`domain`/`ipv4`/`ipv6`), `server_family`, `server_scope`
(`global`/`private`/`loopback`/`link_local`), and the unchanged `server_port`.
Checked against the diagnoses this repo has actually needed (#248, #541, #655,
#770, #694): none required the address. The joined `route`/`netsh` argv
(`routing.rs`'s `log_route_command`), the ETW `remote` field, `netsh` stdout and
garter's plugin relay deliberately get **no** per-site edit — the sink covers
them, and hand-redaction there would rot.

**Three limits, so this is not read as a total guarantee.** First, `dump!`'s
ladder resolves per top-level expression, not per field: any `Serialize` type
transitively holding a `ServerAddress` **or a `Password`** needs its own `Dump`
impl, or the serde tree renders the inner string and the newtype's `dump` is
never reached. The rungs are `ServerEntry`, `AppConfig`, `ProxyConfig`,
`TestServerRequest`, `BridgeRequest`, and the bridge's on-disk `TargetFile` /
`PersistedTarget` / `StartupPreferenceFile`. `BridgeRequest` is the top — the
type the elevation flow serializes whole — and its impl is exhaustive with no
`_` arm, so a new variant has to state whether it carries a secret;
`AppConfig`'s destructures exhaustively for the same reason. The one type the
rule reads as covering and deliberately does not is `ImportOutcome`:
`crates/hole` has no `dump` dependency, so nothing there can call `dump!` and
adding the impl would mean adding the capability. All of this is convention
backed by per-container tests, not a compiler guarantee, with the sink as the
backstop for the address and nothing behind it for the password. Second, an
address written in a form no armed literal is a byte-substring of —
a percent- or punycode-escaped form from a third-party process, a non-canonical
IPv6 text form from a peer that is not `std` — is not redacted.

**Third, and the one to know about: `shadowsocks_service=trace` writes the
password to `bridge.log` in clear.** `shadowsocks::ServerConfig` derives
`Debug` over a cleartext `password: String`, and `shadowsocks_service` renders
it — `local/mod.rs`'s `trace!("{:?}", config)` at local-server construction,
and two `trace!`s in `local/dns/server.rs`. `expose()` hands upstream a
`String` it is entitled to keep; no newtype on Hole's side can reach that, and
the password has no sink-level cure to catch it the way the address does. The
directive is not obscure — [`init_multi`](crates/common/src/logging.rs)'s own
worked example is `HOLE_BRIDGE_LOG=hole_bridge=debug,shadowsocks_service=trace`
— and `bridge.log` is collected into the support bundle. **Do not turn that
directive on against a real server, and do not ship a bundle collected while
it was on.** Flooring the third-party directive in `build_filter` would close
it at the cost of the diagnostic; that trade has not been made.

**Existing artifacts.** Files already on disk are not rewritten: a SYSTEM bridge
rewriting files in a user-writable directory is an attack surface. The support
bundle is scrubbed on collection instead, and its `REDACTION.txt` states the
three residuals plainly.

### Logging an error

An error reaches a log as a value, in one form:

```rust
tracing::warn!(error = &e as &dyn std::error::Error, "what failed");
```

- **Boxed and borrowed.** A boxed error (`Box<dyn Error>`, with or without `+ Send + Sync`) and an `anyhow::Error` pass
  as `error = &*b`, and a reference to one as `error = &**b`. When `e` is a reference to a concrete error, cast it
  without the extra `&` (`error = e as &dyn std::error::Error`): `&&T` is not `'static`.
- **The message never interpolates the error** (`{e}`, `%e`, `?e`): the field carries it, and the message would print
  its first link a second time. The message names what failed.
- **The renderer.** `YamlFormat` renders an error field as a YAML list of its `source()` chain, outermost first, each
  link's `Display` as one item (a multi-line `Display` stays one item). The stock formatter that `galoshes` and
  `garter-bin` install prints the same field as `error=<Display> error.sources=[..]`, so the call site is the same there.
- **The type rule.** A variant's `Display` names what this layer failed to do and never formats its `source()`; a cause
  is `#[source]` or `#[from]`. A `Display` that includes its cause prints it twice. A wrapper variant exposes its
  inner error as its `source()` and is never `#[error(transparent)]`, which forwards `source()` past the inner value so
  `find` and `raw_os_error` cannot reach it. A new wrapper is `#[error("<what failed>")] V(#[source] Inner)` (or
  `#[from]`); the existing `#[error("{0}")]` wrappers are the transitional exception, and a logged chain shows their
  inner text twice until they get text of their own.
- **Reading a chain in code.** Use [`util::error`](crates/util/src/error.rs) (`chain`, `links`, `find`, `raw_os_error`);
  do not write a `source()` loop by hand. What the walks reach is stated in the module doc.
- **A value that is not an error stays as it is.** Third-party types with no `std::error::Error` impl and a `String`
  made from an error are logged as they are; text a user reads (a dialog, a toast) is written from `user_message()` or
  the type's `Display`, never from the log field.

### Logging directives (HOLE_BRIDGE_LOG)

`HOLE_BRIDGE_LOG` takes a comma-separated list of `tracing` directives (default
`hole_bridge=info`); `RUST_LOG` is also honored and both compose. Example:
`hole_bridge=debug,shadowsocks_service=trace` adds shadowsocks-service per-relay
byte counts (`L2R N bytes, R2L M bytes`) — a load-bearing #248-class diagnostic,
but expensive (≥1 TRACE line per TCP connection); use for debugging only.

The file and stderr sinks filter independently. `HOLE_LOG` sets the file-sink
directives; `HOLE_LOG_STDERR` sets the stderr-sink directives (defaults to
mirroring the file sink when unset); `HOLE_LOG_DIR` overrides the log directory.
`HOLE_BRIDGE_LOG` stays the bridge's file-sink override and takes precedence over
`HOLE_LOG`.

### Dev-run capture

`cargo xtask run hole` writes `<repo>/.tmp/dev-run/<datetime>/` per run:
`bridge.log` and `gui.log` at trace (Hole crates trace, deps debug), plus
`dev-console.log` (the supervisor transcript and the runtime mux at info). No
retention — old run dirs are kept until you delete them.

### Plugin diagnostics

The out-of-process plugin (`ex-ray`, `galoshes`) is otherwise invisible:

- **Plugin tap** — enabled by `AppConfig.diagnostic_plugin_tap` (persists to
  service-mode bridges) or `HOLE_BRIDGE_PLUGIN_TAP=1` (dev shell only).
  [`garter::TapPlugin`](crates/garter/src/tap.rs) logs per-connection
  `bytes_to/from_plugin`, `ttfb_ms` (`None` = closed without an upstream byte —
  the #248 diagnostic), `close_kind`, and `tap_conn_id`. On self-test failure the
  bridge emits a breadcrumb to the tap lines (#388). Costs a loopback round-trip
  per byte + a line per connection — not for default operation under load.
- **Plugin directive injection** — for a plugin whose
  `PluginDescriptor::takes_hole_directives` is set, `inject_plugin_directives`
  appends `loglevel=debug` and `ech-doh=<resolver-DoH-url>` (when a resolver is
  configured) to `SS_PLUGIN_OPTIONS`; any other plugin gets its options
  validated and passed through untouched. An operator's own `loglevel` is always
  replaced; their `ech-doh` is replaced only when Hole's URL displaces it
  (`hole_ech_doh_outranks`), otherwise it stands and Hole's appended copy loses
  to it (ex-ray is first-wins). The derivation of the `ech-doh` URL
  (`derive_ech_doh`) and the cover's resolver permit read the same field.
  Stderr is captured via `garter::binary` and filtered by `HOLE_BRIDGE_LOG`.
  The bridge never injects `ech=<mode>` — ex-ray owns the mode (default `auto`).

## Releases

Four independent tracks, each tagged `releases/<product>/v<X.Y.Z>`. Each has a
draft+publish workflow pair: the **draft** workflow does all reversible prep
(build, test, hash, upload to a draft release); the **publish** workflow does the
irreversible public actions (tag, `cargo publish`, latest-flip). The split exists
to keep one sanity gate before irreversible work.

| Product    | Artifacts                                     | Signed   | crates.io |
| ---------- | --------------------------------------------- | -------- | --------- |
| `hole`     | MSI + DMG (amd64+arm64) + `SHA256SUMS`        | minisign | No        |
| `galoshes` | 6-platform binaries + `SHA256SUMS`            | No       | No        |
| `garter`   | crates.io lib + 6-platform CLI + `SHA256SUMS` | No       | `garter`  |
| `ex-ray`   | 6-platform binaries + `SHA256SUMS`            | No       | No        |

Asset naming is `<product>-<version>-<os>-<arch>[.ext]`.

- **Only `hole` is signed** — it auto-updates, so supply-chain integrity matters.
  The others are embedded into hole (covered by its signature) or built from
  source by consumers who pin SHA256 against `SHA256SUMS`.
- **`/releases/latest` pinning** — each draft pins `--latest` at
  `gh release create` (`hole=true`, others `false`); without it GitHub's legacy
  semver+date heuristic can promote the wrong track (#308).
- **garter publish is idempotent** — it queries crates.io and skips `cargo publish` if the version exists; a `dry_run` input runs `--dry-run` only.
- **garter publishes by trusted publishing** — no stored token. crates.io's
  trusted publisher for `garter` names repository `bindreams/hole` and workflow
  `publish-release-garter.yaml` (the caller, not the reusable workflow). crates.io
  matches the top-level workflow, so a call through `workflow_call` from another
  workflow is refused unless that one is registered too.
- **garter publishes against crates.io's `cosca`** — the workspace pins a registry
  version, so `cargo package` accepts the dependency.
- **Versions** live in each crate's `[package.metadata.hole-release].group`
  (ex-ray in `crates/ex-ray/version.toml`); validate with `cargo xtask version [--check --group <name> [--exact]]` (release CI uses `--exact`). The legacy
  `v0.1.0` tag predates the scheme and is ignored.
- **A draft ships what CI tested.** Every draft workflow checks that its commit is
  an ancestor of `main` (`.github/actions/verify-release-commit-on-main`), then calls
  `ci.yaml` on it with `release-tag` set (the call has its own concurrency group, so
  two drafts never cancel each other). Each leg creates the tag locally before
  building, so the binaries carry the release version, and stages what the tag's
  product ships right after the tests of those files (the DMG after the
  install-and-connect test as well)
  (`cargo xtask stage-release --lane msi|dmg|plugins`, steps `release-stage-*`; see
  `xtask/src/stage_release.rs`). Only a passing leg uploads
  `release-<track>-<os>-<arch>`; the draft job needs the whole of CI to have passed, checks
  (`.github/actions/check-release-assets`) that the downloaded files are exactly what
  `cargo xtask release-assets --tag <tag>` lists, builds the release notes'
  Downloads table from the same list, then hashes and uploads the files; it builds
  nothing.
- **What staging requires.** The Windows update zip is packed from
  `target/release/installer-stage` (the MSI's payload directory), not from
  `target/release`. `hole.exe version` and `garter --version` must print the tag's
  version, so a build of a dirty tree (`X.Y.Z.dirty`) fails; `garter --help` must
  exit 0. The galoshes and ex-ray versions are not checked.
- **Installer under test.** The DMG tests take the DMG from `DMG_UNDER_TEST`
  (default: the release build's single `.dmg`), the MSI lifecycle tests the MSI from
  `MSI_UNDER_TEST` (default: `target/release/hole.msi`). A relative path in either
  variable is from the repo root, in the Python harnesses and in xtask alike.
  `stage-release` stages only this checkout's own build (the update archive and the
  `hole.exe` probe come from it), so it refuses a variable that names any other
  file.

Rollback, minisign key rotation, and the crates.io dry-run TOCTOU note are in
[RELEASE-OPS.md](RELEASE-OPS.md).

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
