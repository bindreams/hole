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

GUI ↔ bridge speak HTTP/1.1 REST (JSON) over an AF_UNIX socket on both platforms
(macOS via `tokio::net::UnixListener`, Windows via `socket2` — see
`crates/bridge/src/socket.rs`), defined by `crates/common/api/openapi.yaml`.

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
`Proxy` + UDP + `!supports_udp()` resolves to a drop, never to
`&self.bypass`. UDP-capable plugins (galoshes, via YAMUX) tunnel UDP normally.
A drop is not a dispatch — nothing serves the flow. The three drop reasons
(rule block, UDP-proxy-unavailable, IPv6-bypass-unreachable) each get their own
method on [`DropSink`](crates/bridge/src/drop_sink.rs), whose production impl
logs them; tests substitute a recording sink, which is what makes this invariant
assertable.

**UDP/53 exception.** When DNS is enabled, UDP/53 is diverted to
[`LocalDnsEndpoint`](crates/bridge/src/endpoint/local_dns.rs) *before* the
cascade reads the filter decision, so DNS works even on a TCP-only plugin. See
[DNS forwarder](#dns-forwarder).

### IPv6 in the tunnel

IPv6 traverses the tunnel. The `::/1` + `8000::/1` split pair captures it,
[`Socks5Endpoint`](crates/bridge/src/endpoint/socks5.rs) carries any v6
destination, and `Ipv6BypassUnreachable` is a **bypass**-only drop — a `Proxy`
decision on a v6 flow goes to the proxy unconditionally.

`hole-tun` holds `TUN_SUBNET6` twice: on the OS interface **and** in smoltcp's
address list. Without the OS half a host with no global IPv6 anywhere has no
source address for the `/1` routes, and every IPv6 flow fails instead of
tunnelling. (A dual-stack host sources from the upstream adapter, which is why
the gap is invisible there.)

The ULA's 40-bit global ID is pseudo-randomly generated per RFC 4193 §3.2.2,
not `fd00::`. That prefix is what WireGuard examples, Docker, Proxmox and NAS
defaults hand out, and Hole's becomes a real on-link route on `hole-tun` — a
collision would let the tunnel swallow the user's own ULA network.

**The interface's IPv6 half does not exist when the device is created.** The
`tun` crate waits for the IPv4 half and deliberately not the IPv6 one, so
[`device::ipv6_addr`](crates/tun-engine/src/device/ipv6_addr.rs) waits itself:
register the `NotifyIpInterfaceChange` callback, **then** check existence with
`GetIpInterfaceEntry`, then block. Registering first is load-bearing —
`MibInitialNotification` only confirms registration and carries a NULL row, so
an interface the kernel published during the `tun` crate's own AF_INET wait
emits no later `MibAddInstance`, and a register-and-block would burn the whole
budget and report a live IPv6 half as absent. The budget bounds "it never
appears", which is what IPv6 being unbound on the host looks like; it is a
failure bound on an external event, not a synchronisation delay.

The address row carries `DadState = IpDadStatePreferred`, so it is never
tentative and no interface-wide state is touched — the same field the `tun`
crate sets for the IPv4 address on every Full-mode start.

**Assignment is fatal on Windows and warn-only on macOS.** A missing route is a
leak; a missing address is a blackhole, and Windows is where the path is
tested. The macOS path cannot run in production until the TUN naming issue is
fixed and its only test is an argv-shape test, so a fatal failure there would
first execute in a user's hands; it becomes fatal once it has run green on the
darwin TUN lane. The tolerate predicate is **not** `ipv6_available`, which
measures upstream reachability — an independent question. Route-install
fatality follows the same rule: **the IPv6 route adds are non-fatal exactly
when the TUN has no IPv6 half**, measured by `gateway::tun_ipv6_available` at
install time. Upstream reachability is not an operand — a host whose EDR
unbinds IPv6 from new adapters has a reachable upstream and an unusable
tunnel, and reading upstream there refuses a connection that would work.

Phase 5 of `start_inner` is cooperative because of this wait: `Dispatcher::new`
runs `Device::build` on `spawn_blocking` raced against the start's cancel token
in a `biased` `select!`. The phase is no longer millisecond-scale, and on a
covered start a Cancel it could not observe would extend the window during
which the whole host is fail-closed.

The Windows path uses IP Helper FFI rather than `netsh` because `netsh interface ipv6 add address` defaults to `store=persistent`: such an address is
written to the registry keyed by the adapter GUID, which wintun derives from
the adapter name, so a crash would leave it waiting to be re-applied to the
next `hole-tun`. A `CreateUnicastIpAddressEntry` address is runtime-only and
dies with the adapter — nothing for `recover_routes` to sweep.

### TCP accept refusal

The accept verdict is reached while the listener socket is still in
`SynReceived` with its SYN-ACK paused (smoltcp's `socket-tcp-pause-synack`), so
a declined connection is refused with a pre-handshake RST and never with a reset
of a connection the client believes it opened. The verdict itself is
[`decide_admission`](crates/tun-engine/src/engine/admission.rs) — a pure
function over the handshake plus a permit-acquiring closure — and the driver arm
is a mechanical dispatch over its three outcomes. A socket with a packet still to
emit is *retired* rather than removed:
[`SocketStack::poll`](crates/tun-engine/src/engine/socket_stack.rs) reaps it
once `remote_endpoint()` goes `None`, smoltcp's signal that it has emitted the
socket's last packet. `decide_disposal` picks the path per state — `Closed` and
`Listen` retire, while `TimeWait` is dropped at once, since retiring it would
hold the socket and both its buffers for smoltcp's 10 s `CLOSE_DELAY`. The drop
is safe because every socket the stack creates has its delayed ACK disabled
(`set_ack_delay(None)`), so smoltcp emits any ACK it owes on the poll that
ingests the segment and a socket removed at `TimeWait` is never holding one —
without that, the peer's last data-plus-FIN would go unacknowledged and its
retransmission would be answered with a reset. A connection socket that reverts
to `Listen` — the client answered the SYN-ACK with an RST — is retired through
that same list, so it cannot shadow the live listener on its port.

Retiring a socket only marks it; reaping — the `SocketSet::remove` that actually
frees its slot — happens inside the next `poll`. A socket marked but not yet
reaped is still live and still bound to its port, so a SYN that arrives before
that `poll` can be handed to it instead of to the real listener, and no accept
path is watching it (bindreams/hole#911).
[`Driver::settle_packet`](crates/tun-engine/src/engine/driver.rs) is the one
production entry point for a TUN packet and closes that gap structurally rather
than by convention: enqueue, both polls, admission dispatch and retirement all
happen inside one call, so two packets' verdicts can never straddle a `poll` no
matter how `run()`'s TUN-read cadence changes.

Ownership of a 4-tuple is exclusive, and `take_handshakes` enforces it. Re-arming
a port hands the listener whichever socket slot is lowest and free, which can put
it *below* the connection it was just re-armed for; smoltcp gives a packet to the
first socket that accepts it, and a `Listen` socket accepts a bare SYN on the
local port alone. A SYN can therefore land on the replacement listener rather
than on its own connection — and tuple equality alone does not say whether it is
that connection's retransmit or a new connection reusing the tuple (a client
that lost its own TCP state while the datapath's persists: reboot, sleep-resume,
a recycled ephemeral port). `take_handshakes` tells them apart by ISN, read off
the wire since smoltcp exposes none: the same ISN as the tuple's owner is
`Duplicate` and its socket is dropped without a segment — no second permit, no
second router task, and no RST, since one would acknowledge the client's SYN,
which it must accept while in SYN-SENT, and so would kill the very connection it
is retransmitting for. A different ISN reports `Pending` with `supersedes` set
to the stale owner (RFC 9293 §3.10.7.4); the driver tears that owner down —
closing its channels, removing its socket — before admitting or refusing the new
SYN in its place.

An admitted connection also gets a keep-alive interval and a timeout
(`tcp_keep_alive_interval`, `tcp_peer_timeout`). They bound an external event —
a client process that may never speak again — not anything inside the engine.
Without them a connection stalled in `SynReceived`, `FinWait2` or `CloseWait`
never reaches a state `decide_disposal` has a verdict for, and holds its entry,
both buffers and its connection slot for the life of the process;
`max_connections` of those wedge the tunnel for all new TCP. The probe is what
keeps the bound off a client that is merely quiet: only silence in reply to it
resets the socket to `Closed`, where the disposal path already runs.

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
returns whichever `ProxyError` the run's evidence supports — `NoTunnelConnection`
(every connect failed outright), `TunnelSetupIncomplete` (one was still
outstanding when its budget fired), `TunnelSilent`, or the generic
`ForwarderSelfTestFailed` — and the RAII guards unwind without touching routes,
system DNS, or the wintun adapter. `classify_failure` picks between them from
counted evidence, never from a cause code. Guarded by
`start_blocks_on_forwarder_self_test_failure`.

**Hard errors:** `dns.enabled = true` with `servers = []` is a config error.

**Failure reporting.** `DnsForwarder::forward` is infallible by design — it
synthesizes SERVFAIL when every upstream fails, because the in-TUN endpoint must
always have bytes to write back. `try_forward` is the same walk without that
erasure: it returns the highest-ranked `UpstreamCause` observed
(`UpstreamCause::rank`) — see `is_trust_chain_rejection` for how a rejected
certificate is distinguished from other TLS failures. It also takes the per-upstream budget as a
parameter (see `try_forward`'s doc for why callers must pass it rather than wrap
the call). The DoH bootstrap resolver uses `try_forward` so `BootstrapError` can tell a
user that something is intercepting TLS, distinct from a resolver that simply
did not answer; see `BootstrapError`'s doc for its PII-free,
existential `Display` contract.

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
  before the bind. Two sanctioned exceptions:
  `test_support::port_alloc::allocate_ephemeral_port` and `plugin_e2e::ports`.
- `ensure_port_free` — pure probe without allocation.

The retry exists because Windows keeps **independent TCP/UDP excluded-port-range
tables** (Hyper-V/WSL/Docker reservations); an OS-picked port for one transport
may be reserved for the other. There is no "right" budget — a saturated runner
needs many retries, a healthy machine one. See #285, #300, #304.

**Reserve for the protocols the consumer will bind.** Where the consumer is
known at reservation time, name it exactly —
`hole_common::plugin::plugin_alloc_protocols` keys SS_LOCAL by binary (galoshes
TCP+UDP, everything else TCP). Where the reservation happens before the
consumer is known, reserve the union over the possible consumers:
`plugin_e2e::ports::reserve_ss_local` is generic over which client plugin will
run, and that set includes galoshes, so it always reserves TCP+UDP —
over-reserving UDP for a TCP-only plugin costs a retry, under-reserving it for
galoshes costs a race. `garter::chain::allocate_ports` verifies TCP only and is
clippy-banned outside garter's own chain-internal use, which carries a per-site
allow.

### Route-command failure policy

`netsh`/`route` subprocesses run through one of two phase runners in
[routing.rs](crates/tun-engine/src/routing.rs), and which one a phase gets is a
security decision, not a style one:

- **Fatal — install only** (`run_setup_commands`, via `setup_routes`). The first
  fatal command that does not exit zero aborts the phase and is returned as a
  `RouteCommandError`. `SystemRouting::install` then rolls back and returns
  `Err`, so no `SystemRoutes` guard exists. Reporting split routes that were
  never installed is a **leak**: traffic egresses outside the tunnel while the UI
  says "protected" (#901).
- **Best-effort — teardown and crash recovery** (`run_cleanup_commands`, via
  `teardown_routes` / `recover_routes`). Every command is issued; a failure
  neither short-circuits the rest nor is returned. Stopping at the first failure
  would strand routes and leave the user worse off than if Hole had never run.

No future edit can turn stranded-route cleanup into an early return: a
`CleanupReport` is counts, not a `Result`, so there is nothing to `?` out of.

**The pairing is a compile error, not a convention.** A phase is a value of
`FatalPhase` or `BestEffortPhase` (sealed `Phase` trait, `BEST_EFFORT` const per
type — it also picks the log level), and each runner accepts only its own type;
the command types differ too (`SetupCommand` vs `Vec<String>`). Wiring a
teardown phase into the fatal runner does not compile. This replaces a
`debug_assert` pairing check, which compiled out in release — the same
silently-absorbed-failure class this policy exists to close.

**Fatality is per command, not per phase** (`SetupCommand::fatal`). The two IPv6
split routes are non-fatal when `gateway::tun_ipv6_available(tun_name)` is false:
on a host whose IPv6 stack is unbound from the TUN adapter itself
(`DisabledComponents`, or an EDR policy that unbinds IPv6 from new adapters)
`netsh interface ipv6 add route ::/1 <tun>` cannot succeed, and such a host emits
no IPv6 traffic to leak — aborting there would lose the whole tunnel and avoid
nothing. Everything else, and every command when the TUN's IPv6 IS bound, stays
fatal. The probe targets the TUN, not the upstream interface
`GatewayInfo::ipv6_available` measures: it is the TUN's name the `::/1`/`8000::/1`
commands carry, and `setup_routes` runs after `Dispatcher::new` has created it, so
the adapter already exists to probe. The two commands are still *issued*, only
their failure tolerated — the TUN is a virtual device, so a bound-but-otherwise-
unreachable adapter still accepts the route; only a genuinely unbound TUN can
make the add itself fail.

**Accepted trade: a false start-failure is preferred to a silent leak.** No test
exercises `setup_routes` against a real elevated `netsh`/`route` under an
already-installed route, so it is not measured whether a healthy install can
legitimately exit non-zero. One path could produce it: `SystemRoutes::drop`
clears the state file even when teardown failed, and `recover_routes` only
deletes split routes under that file's guard, so a stale route can outlive its
record. If that ever bites, the fix is upstream — make the pre-install split
sweep unconditional — never tolerating an "already exists" exit code here, which
is the exists-tolerance heuristic #899/#910 forbids. Until then a hard start
failure surfaces the stranded route instead of routing around it.

`RouteCommandError`'s `Display` is PII-free by construction (program name,
position in the phase, exit code): it reaches a GUI toast verbatim through
`StartError::Failed`. The argv and the child's stdout/stderr go to `bridge.log`.

A failed install's rollback does exactly four things — see
`SystemRouting::install_with`'s doc comment, which is the source of truth.

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

### Crash recovery

While a proxy is active the bridge persists small state files in `<state_dir>/`,
cleared on clean shutdown and replayed on next startup (all *after* the IPC
socket binds; DNS recovery runs before route recovery so a mid-recovery crash
leaves working DNS + broken routes, not the inverse):

- **`bridge-routes.json`** — TUN name, server IP, upstream interface;
  `routing::recover_routes` tears down leaked routes. The same call also sweeps a
  stale [fail-closed cover](#fail-closed-cover) (Windows by fixed WFP GUID,
  macOS via `bridge-failclosed.json`).
- **`bridge-failclosed.json`** (macOS only) — the `pfctl -E` enable token of an
  engaged fail-closed cover; `routing::failclosed::recover_cover` restores
  `/etc/pf.conf` and drops the refcount. Windows keys its cover by fixed WFP
  GUIDs and needs no file. See [Fail-closed cover](#fail-closed-cover).
- **`bridge-plugins.json`** — persisted cosca process identities;
  `plugin_recovery::reap_recorded_plugins` kills survivors by exact identity —
  no tolerance window — and deletes the file only after accounting for every
  record it named. The same reap runs at bridge start, at chain stop, and in the
  test harness's teardown.
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

### Yamux transport self-heal

The galoshes yamux client ([`crates/galoshes/src/yamux.rs`](crates/galoshes/src/yamux.rs))
reconnects after a transport reset instead of wedging the tunnel:

- **Death detection.** The driver task owns the yamux `Connection` and drops its
  inbound-stream sender when the connection ends; `run_client_session` seeing
  `inbound_rx.recv() == None` is the transport-death signal — no separate
  liveness poll is needed.
- **Reconnect backoff.** Every reconnect waits at least `REMOTE_BACKOFF_BASE`
  (a floor bounding a peer flapping right after one byte) and escalates
  exponentially to `REMOTE_BACKOFF_MAX` on repeated failures.
  "Productive" is **transport-level**, not application-level: `TransportLivenessTap`
  sits below yamux framing and counts every inbound read — relayed data or a bare
  ping/flow-control frame alike — as liveness, which resets the backoff to the
  floor. A session whose count never moved counts as a failure and escalates.
- **Teardown tradeoff.** On session end the driver is `abort()`-ed rather than
  drained, so any relay stream still in flight is truncated. This trades a
  handful of interrupted flows for a bounded, deterministic teardown instead of
  hanging on a chain drain-timeout.
- **Local errors don't tear down the tunnel.** A local `accept`/`recv` error on
  the client's loopback listener, or the server's inbound listener, is logged
  and the accept loop continues — reconnecting the transport wouldn't fix a
  local socket error, and a broken listener is not what these errors indicate
  (they're transient: a stray `ECONNABORTED`, momentary `EMFILE`).
- **Proactive keepalive**
  ([`yamux/keepalive.rs`](crates/galoshes/src/yamux/keepalive.rs)). A visible
  death (FIN/RST, yamux protocol error) is caught by the inbound-channel signal
  above. A peer that goes silent without resetting — a black-holed link — is
  caught instead by a client keepalive. Every `KEEPALIVE_INTERVAL` in which
  `TransportLivenessTap` counted nothing, the client opens a
  `StreamTag::Keepalive` substream and writes an 8-byte nonce, purely to give an
  idle transport a reason to speak; a transport that delivered anything is not
  probed at all, so a busy tunnel carries no keepalive traffic. The verdict is
  not "did the echo come back" — the client reads the substream exactly once and
  never inspects what it got — but "did the tap count *any* inbound read before
  `KEEPALIVE_TIMEOUT` was up". That is what makes the wire addition safe against
  version skew: an un-upgraded server resets the unknown tag, and the reset is
  inbound traffic that is necessarily read *before* the probe's read can end, so
  the tunnel behaves exactly as it did before. The whole cycle including the
  substream open sits inside the deadline, because opening parks indefinitely
  once enough substreams await an ACK. Detection is bounded by
  `2 × KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT` from the last inbound byte, which
  holds only while the deadline is no longer than the interval; the interval may
  also not drop below yamux's own 10 s ping cadence, which is what keeps a
  healthy-but-slow server off the fatal path. `const` assertions pin both
  relations at the constants.

### galoshes mux default

galoshes appends `mux=0` to the `SS_PLUGIN_OPTIONS` it hands its embedded
ex-ray ([`crates/galoshes/src/exray_options.rs`](crates/galoshes/src/exray_options.rs)).
Its yamux layer has already collapsed every logical stream onto one connection,
so v2ray-core's Mux.Cool has nothing left to multiplex — it only adds framing
and a second connection lifecycle that can fail on its own.

ex-ray is **first-wins** on duplicate SIP003 keys
([`crates/ex-ray/args.go`](crates/ex-ray/args.go)), so the appended pair is a
*default*: an operator's own earlier `mux=` overrides it.

`mux` also selects the server's dokodemo destination (`v1.mux.cool` when
enabled), so **a `mux=0` client cannot talk to a `mux=1` server**. Both ends
must run a galoshes that agrees; during a version-skew window, pinning `mux=1`
in the plugin options on both ends restores the old wire format.

A skewed pair **stalls before it breaks**: the `mux=1` server's worker cannot
unmarshal the client's first frame, so it poisons its inbound pipe and stops
reading — but nothing is reset, because no further byte is due. The
[yamux keepalive](#yamux-transport-self-heal) is what converts the stall into a
teardown: its next probe hits the poisoned pipe, the server closes, and the
client sees the transport die. Skew therefore surfaces as a connection that
lasts one keepalive interval, not as an immediate refusal.

The append goes through `garter::{split_plugin_options, join_plugin_options}`
so the escaping cannot drift from the parser's: a naive strip-then-append turns
`path=/a\;` into `path=/a\;mux=0`, which ex-ray reads as one pair with no `mux`
key at all. Two shapes have no correct output and are refused at startup — a
dangling final escape, and a segment with an empty key — because ex-ray rejects
either string wholesale and silently falls back to every flag default.

### Fail-closed cover

Two egress-block covers share the platform `Cover` guard (kind-aware `Drop`):
the **transient cutover cover** below and the **standing lockdown cover**
([next section](#lockdown-mode)). Both are RAII guards permitting a curated
egress set and blocking everything else; they differ in lifetime and which set
they permit.

#### Transient cutover cover

`Routing::install_failclosed_cover(server_ip, resolver_ip)` engages a leak-free
egress block — permit loopback and the SS server IP, **block everything else** —
as an RAII guard whose `Drop` disengages it. It is a bounded-window kill switch;
a crash while it is held leaves traffic **blocked, not leaked**.
`ProxyManager::start_cancellable` is its production caller: every covered
(auto-connect) start whose **lockdown intent is OFF** engages it before
`start_inner`, retaining it (host stays blocked, not leaked) if the start
fails, and releasing it on success, cancel, or a user stop. When the standing
lockdown intent is ON, a covered start does NOT engage this cover at all — that
cohort's cover is installed once at `routing.install` instead
([Lockdown mode](#lockdown-mode)) — and a HELD transient cover from a prior
start is released outright, a brief, disclosed open window until the lockdown
cover takes over. It does *not* cover an indefinite outage (a bridge that
stays down) — without lockdown, default-off Hole fails *open* there; lockdown
closes that broader gap.

`resolver_ip` optionally permits ONE more address, scoped to **TCP port 443**
(not the server permit's unrestricted shape — `doh_url_for_ip` in
`crate::dns::ech` never constructs a URL with any other port, so 443 is
structurally the only value this fetch can need, not a heuristic threshold):
`EchDoh::resolver`, the exact address Hole's own `ech-doh` URL names, gated on
`crate::proxy::plugin::effective_ech_doh` returning `Holes` — the value ex-ray
will actually dial, not merely a plugin being configured (no plugin is one way
to get `None`; a non-ECH-capable plugin, a fatal ex-ray config, `ech=never`,
no TLS-enabled domain SNI, or an operator's own `ech-doh` outranking Hole's
are the others — see `ech_fetch_is_reachable`'s and `classify_ech_doh`'s docs).
Without it, ex-ray's later lazy ECH-config fetch — which fires
on the plugin chain's first dial, i.e. *under* this same cover — would be
blocked and stall to ex-ray's client timeout. **Permitting it grants no new
trust regardless of `PinSource`:** Hole *authored* the address — `ech_doh_url`
either uses the bootstrap-verified IP or falls back to one in the user's own
configured `dns.servers` — so config-authorship trust alone is judged
sufficient. This is NOT a claim that this attempt personally dialed the
address: `resolve_via_doh` does dial every configured resolver even on total
failure (so `Answered` and `SecureBootstrapFailed` both had it dialed this
session), but `NoQueryNeeded` (a literal-IP server) dials nothing at all, and
`ResolverDeselected` (a covered retry whose `dns.servers` changed) may name an
address only a prior resolve dialed, or never dialed by this bridge process
at all — see `EchDoh`'s doc for the exact breakdown. An OPERATOR-supplied
address is different: an operator's own `ech-doh` in `plugin_opts` can win
first-wins over Hole's (`crate::proxy::plugin::effective_ech_doh`, not
`ech_doh.is_some()` alone, decides which value actually reaches ex-ray), and
that address is never permitted — Hole did not author it, so config-authorship
trust does not extend to it. `effective_ech_doh` also means a non-ECH-capable
plugin never widens the cover for a fetch that provably does not use it. A
covered retry against the same server reuses the held cover as-is UNLESS this
attempt's freshly-derived permit now differs from what the cover was actually
engaged with (e.g. `dns.servers` changed the fallback address, a plugin was
added or removed between attempts, or an operator's own `ech-doh` started or
stopped outranking Hole's) — that drift, including a NARROWING to nothing
needed, makes the held cover stale, and it is released and re-engaged fresh
with the corrected permit, the same repair pattern already used for a
different-server retry: the resolver permit carries no App-ID/process scoping
on either platform, so leaving a wider-than-needed permit live for the rest
of the blocked state is a real widening, not a correction with no benefit.
If the corrected engage itself fails, the repair falls back to restoring the
PREVIOUS permit rather than leaving the host uncovered; an unchanged retry
(still wanting the same permit) repairs again rather than staying wedged —
the failure could have been transient, and each attempt's release-to-reengage
window is bounded to
that one (user-paced) retry regardless.

**Disclosed residual:** an operator's OWN `ech-doh` outranking Hole's
(`EffectiveEchDoh::Operators`, never permitted per above) is therefore
*always* a stall risk under a covered start;
`ProxyManager::start_cancellable` logs a dedicated `warn!`
naming the operator's URL. A repair's compensating restore can also leave the
LIVE held cover's permit mismatched from what THIS attempt actually needs
(the corrected engage failed) — a separate `warn!` fires for that case too,
comparing against the live permit rather than re-trusting that the repair
always converges, in EITHER direction: too narrow (`Holes`, an ECH-fetch stall
risk) or too wide (`None`, the kill switch permits a resolver address nothing
needs). A THIRD case is untouched by this mechanism entirely (not merely a
residual within it): the [standing lockdown cover](#lockdown-mode)'s own
ruleset never carries a resolver permit at all, on EITHER platform, whether
the cover was just engaged fresh (`routing.install_lockdown`, called from
`start_cancellable`'s `lockdown_on` branch on every covered start) or adopted
across a restart — `build_lockdown_main_ruleset` (macOS) and
`lockdown_app_ids` (Windows) take no `resolver_ip`/`EchDoh` input at all. On
macOS this blocks the fetch outright, silently, on every lockdown-on covered
start with an ECH-effective config — not only a restart-adopt, which merely
compounds it by also removing the in-process signal a fresh engage still has
(`effective_ech_doh`, computed before `install_lockdown` runs) but has no API
to consume. On Windows the App-ID floor (`resolve_plugin_path(plugin)` — the
plugin's OWN resolved binary) is sufficient for a direct `ex-ray`/
`v2ray-plugin` config, but NOT for a chained plugin like `galoshes`: it
`include_bytes!`s ex-ray and spawns it as a separate process from its own
extracted runtime path (`crates/galoshes/src/embedded.rs`), which
`lockdown_app_ids` never adds to the permit set — WFP's App-ID condition
matches the RUNNING process's own image path, so ex-ray (the process that
actually dials the DoH resolver) is unpermitted there too. Tracked
separately: [#753](https://github.com/bindreams/hole/issues/753) (filed
narrower than this; scope correction pending). Finally, the
release-then-reengage repair itself has a brief window with NO cover at all
between the release and the corrected (or restored) re-engage — disclosed in
the repair's own `warn!` lines, not silent, but not eliminated either: both
platforms' engage primitives are delete-then-add / flush-then-reload, not an
atomic in-place update. Tracked separately:
[#758](https://github.com/bindreams/hole/issues/758). If BOTH the corrected
engage AND the compensating restore fail — two independent OS-level
failures back to back — the attempt proceeds fully uncovered: the same
fail-open outcome as an ordinary single-engage failure, just requiring two
failures instead of one to reach. The next retry finds the held cover is
`None` and re-engages fresh from scratch. Also disclosed via its own
`warn!`. **Windows only:** the two new resolver-permit filters grew
`FILTER_GUIDS` from ten entries to twelve, so a crash-then-downgrade (a build
that knows all twelve GUIDs engages, crashes, and an older build's recovery
sweep only knows the first ten) leaves those two permits un-swept; they are
*permits*, never blocks,
so this is bounded and self-healing (a later upgrade's sweep cleans them up),
not a leak of blocked traffic. Disclosed as a source comment on
`FILTER_GUIDS` itself. Tracked separately:
[#754](https://github.com/bindreams/hole/issues/754). **Windows only, also
pre-existing:** the repair's release step deletes the held cover's filters by
fixed GUID and discards the result; if a delete genuinely fails, the
subsequent re-engage's add for that same GUID reports success
(`FWP_E_ALREADY_EXISTS` is treated as OK, by design, for the crash-recovery
idempotency case) while the LIVE filter still carries the OLD value — a
stale permit surviving, not a leaked block. Disclosed as a source comment on
`ok_or_exists`. Tracked separately:
[#761](https://github.com/bindreams/hole/issues/761).

It is **name-agnostic** — it does *not* permit the TUN interface. The new
bridge's start-time DNS-forwarder self-test runs over loopback to the SS client
and out to the server IP, so loopback + server-IP permits suffice; app traffic
into the (briefly absent) tunnel being blocked for the cover window is the
accepted fail-closed cost. That window is no longer sub-second: the gate's own
bound is `TUNNEL_QUERY_TIMEOUT` per configured resolver (see "DNS forwarder"
above), so a slow-but-live tunnel can hold the cover for seconds, not
milliseconds.

- **Windows** ([`routing/failclosed/windows.rs`](crates/tun-engine/src/routing/failclosed/windows.rs)):
  a persistent provider + sublayer + filter set installed in one FWPM
  transaction. Loopback is permitted on `ALE_AUTH_CONNECT_V4`/`_V6` *and*
  `ALE_AUTH_RECV_ACCEPT_V4`/`_V6` (a loopback connect authorizes on both ALE
  directions, so a CONNECT-only permit would deny the accept side and break the
  loopback data plane). The deterministic matcher on *all four* layers is the
  `FWPM_CONDITION_IP_REMOTE_ADDRESS` range (`127.0.0.0/8` V4, `::1/128` V6) — at
  CONNECT the remote is the destination, at RECV_ACCEPT the peer, both `127.x`/`::1`
  for a loopback flow. The `FWP_CONDITION_FLAG_IS_LOOPBACK` flag is **not reliably
  set at either ALE layer** under CI's elevated token (flag-only left the loopback
  connect blocked by block-all *and* the accept side dropped), so it is no longer
  load-bearing; it is kept at CONNECT only as belt-and-suspenders. The server IP
  is permitted on CONNECT, all else blocked on CONNECT (egress kill switch).
  **One sublayer, weight-based arbitration**: permits sit at weight 15, block-all
  at weight 0, and the higher-weight permit wins within the sublayer. **No filter
  sets `CLEAR_ACTION_RIGHT`** — that flag makes a filter's own action *soft*
  (cross-sublayer overridable); omitting it makes the action *hard*, and hardness
  governs only cross-sublayer arbitration, never within one. A `FWP_ACTION_BLOCK`
  with the flag omitted is therefore a *default hard* block; setting the flag only
  on the permits (soft) left block-all (hard) vetoing every permit, so the cover
  blocked everything. This weight-ordered layout matches wireguard-windows (its
  loopback/TUN/DHCP permits and block-all are weight-ordered with the flag off; it
  sets `CLEAR_ACTION_RIGHT` only on its own service permit, none of ours). A
  higher-weight third-party sublayer could in principle override us (accepted), and
  a two-sublayer hard-permit/soft-block layout is a possible future hardening.
  **Non-dynamic session** — a dynamic
  session would auto-delete the filters when the engaging process exits, reopening
  the leak mid-gap. Recovery deletes the fixed compiled-in GUIDs (idempotent), so
  no state file is needed. The FWPM FFIs are clippy-disallowed outside this module.
- **macOS** ([`routing/failclosed/macos.rs`](crates/tun-engine/src/routing/failclosed/macos.rs)):
  `pfctl -E` (refcounted) + a self-contained ruleset loaded over stdin (`pfctl -Fa -f -`). Disengage restores `/etc/pf.conf` and drops the refcount (`pfctl -X <token>`). The token is persisted to `bridge-failclosed.json` *before* the
  blocking ruleset loads, so recovery can `-X` it cleanly. Caveat: restore reloads
  the on-disk `/etc/pf.conf`, not a snapshot of a live ruleset (matches wg-quick).

Each platform splits a pure, unit-tested rule/spec builder (transient:
`build_cover_spec` / `build_pf_ruleset`; lockdown: `build_lockdown_spec` /
`build_lockdown_main_ruleset`) from the thin engage layer — mirroring
`build_setup_commands` vs the phase runners. Under the
[#165](#bridge-test-isolation-contract) isolation contract the builders are the
only thing unit-tested; the kernel-level engage is exercised in production and,
for the lockdown cover, by the privileged-lane real-engage tests (#527) — both
on the `tun` lane (Windows under the elevated CI token; macOS under root for
`pfctl`) — proving the WFP/pf cover actually blocks a non-permitted egress while
loopback stays permitted. On Windows the no-leak is additionally proven **at the
wire** by an in-box `pktmon` capture keyed on a per-marker UDP-payload nonce
([`cutover_nic_capture_privileged.rs`](crates/bridge/tests/cutover_nic_capture_privileged.rs),
with a load-bearing positive control); macOS keeps the connect()-probe there
because its BPF tap sits upstream of pf, so an en0 capture would record packets pf
later drops (unsound). The recovery sweep runs on every bridge start via
`recover_routes`.

#### ECH-config-fetch reachability gate

The resolver permit above must not widen for a fetch that provably cannot
happen. `crate::proxy::plugin::ech_fetch_is_reachable` and its helper
`ex_ray_fatal_config_error` model ex-ray's own decision of whether it will
even attempt an ECH-config fetch, reading `plugin_opts` the way ex-ray's own
SIP003 parser does (`ex_ray_flag_value`: a bare key is ex-ray's `"1"`, not
`garter`'s `""`) and mirroring every `plugin_opts`-reachable config-build
error ex-ray's `main.go`/`options.go`/`config.go` treats as `os.Exit(23)` —
closed enums (`ech`, `mode`), numeric ranges (`mux`, `fwmark`,
`tcp-keepalive`), port/address validity (`localPort`, `localAddr`,
`remotePort`, `remoteAddr`), presence-only flags requiring an exact `"1"`
(`tls`, `server`, `fastOpen`, `__android_vpn`), non-empty-required strings
(`host`, `path`), a well-formed `https://` `ech-doh`, `ech=always`'s TLS and
resolved-`ech-doh` requirements, and `cert`/`certRaw`/`key` requiring TLS.
`ex_ray_fatal_config_error`'s own doc comment is the single source of truth
for the full per-key rule set and ex-ray's real evaluation order (checked
there, not duplicated here) — each numeric/enum literal it hardcodes is
pinned by an `include_str!`-based test against the vendored source
(`ech_and_mode_enums_match_vendored_config_go`), on the COMPARISON itself
(e.g. `uint32Opt`'s `v <= math.MaxUint32`) where possible, not the error
message text — a message is free to change for reasons unrelated to the
bound it protects, and a message-text pin has already gone stale that way
once.

`loglevel` is deliberately NOT modeled as a fatal class, and `cert`/
`certRaw`/`key`'s CONTENT and ex-ray's `server` plugin option's
cross-assignment are disclosed, deliberately unmodeled residuals — see
`ex_ray_fatal_config_error`'s own doc comment (the single source of truth
per the paragraph above) for the full reasoning behind each.

An explicit empty `host=` is fatal at parse time
(`parseStringOption(..., emptyOK: false)`), so `*host` can never be `""`
this way — but the reachable SNI check ALSO strips a literal
`experiment:8357` prefix before testing domain-ness, mirroring v2ray-core's
own `Config.parseServerName` (`ApplyECH` reads the STRIPPED `ServerName`,
not the raw `host` value), and `*host` EXACTLY equal to that bare prefix
strips to `""` without being fatal. v2ray-core's own `Config.ServerName`
empty-`ServerName` fallback to the dial destination (`tls.WithDestination`,
filling it from `remoteAddr`, applied BEFORE the `parseServerName`
assignment and only when `ServerName` is still `""` at that point) IS
reachable this way, and `ech_fetch_is_reachable` models it: the fetch's
reachability then depends on `remoteAddr` instead.

### Lockdown mode

The **standing lockdown cover** (`Routing::install_lockdown`, #527) is an
opt-in, **default-off**, bridge-owned kill switch. When enabled it engages a
persistent OS-level egress block permitting **only** loopback, the `hole-tun`
interface, the onward server connection, and (Windows) the plugin + bridge
binaries by App-ID — so normal traffic flows while connected and the block holds
across a bridge restart for free. When disabled, behavior is byte-identical to a
Hole without it.

It contrasts with the [transient cutover cover](#transient-cutover-cover) on
three axes:

- **Permit set.** Lockdown adds a TUN-interface permit (Windows: by `NET_LUID`;
  macOS: `pass out quick on <tun>`) so app traffic flows; the transient cover
  deliberately omits it (permit loopback + server + the resolver Hole's own
  `ech-doh` names, when a plugin needs it) because holding it while connected
  would block all browsing.
- **Lifetime.** Lockdown is authoritative and standing — it persists across a
  crash or restart and is reconciled on the next start via
  `decide_cover_recovery` (Adopt never disengages the cover, and on Windows
  additionally reclaims the volatile TUN permit if `hole-tun` no longer
  resolves — see "Disclosed residuals" below; the server permit stays
  deferred to the next connect's own `engage_lockdown`; Sweep disengages, and
  only on an explicit recorded off). The transient cover is a non-standing,
  bounded-window RAII guard engaged only for the duration of one covered
  (auto-connect) start attempt, and swept by `recover_routes` like every other
  cover state on the next start.
- **Failure mode.** A failed lockdown engage during a lockdown-on start is
  **fail-FATAL** — it aborts the start and tears everything down; the transient
  cover fails *open* on its own engage error so a half-loaded ruleset never
  strands the host. Lockdown is **last-writer-wins**: an absolute set via
  `POST /v1/lockdown`, system-wide.

Intent persists to `bridge-lockdown.json`; macOS additionally records the
pre-lockdown pf snapshot in `bridge-lockdown-pf.json` so Sweep restores the host
without `-Fa`. The LUID is **never persisted** (a teardown mints a new one) —
re-resolved every engage via `LuidResolver`.

The TUN-interface permit is proven against two real, live TUN devices
(`crates/tun-engine/src/routing/failclosed/live_tun_permit_privileged_tests.rs`,
both platforms): it passes traffic on the interface it names and is blocked
when re-engaged naming a different live interface. On Windows, a session-level
composition guard additionally proves an armed kill switch does not block its
own session's tunnel traffic while blocking an off-tunnel probe
(`crates/bridge/src/proxy_manager_live_tun_permit_e2e_tests.rs`); it is not a
falsification test — the dispatcher's TUN name and the one passed to
`install_lockdown` share one constant, so they cannot disagree — and its macOS
counterpart, where the name is runtime-discovered, does not exist yet.
No test carries a packet to the internet through the tunnel: the in-process
test server dials the client's own route table, so a tunnel-routed destination
loops back and pf has no per-process matching to exempt the local server's own
egress from the block.

`hole bridge unlock` is the elevated escape hatch to disengage a standing cover
when no bridge is alive (`cutover::unlock`). Unlike the best-effort startup
Sweep, it is **fail-loud**: it disengages via `failclosed::disengage_lockdown`
FIRST and flips the intent off only on confirmed success, returning a non-zero
exit otherwise (e.g. run unprivileged). A swallowed failure would leave the
cover engaged — egress still blocked — while the intent read "off".

#### The unconditional escape from a stranded cover

An unclean exit with the kill switch on can leave the host fail-closed with no
bridge running to release it. `failclosed::release_all` is the unconditional
clear: it clears both cover kinds (the standing lockdown cover and the
transient block-until-connected cover) without ever asking whether either is
present, never short-circuits (every clear is attempted before any failure is
examined), never reports success over a host it left closed, and never erases
a cover's state file after a restore that did not confirm — a corrupt or
version-skewed file is treated as a cover to clear, not as absence.
`ProxyManager::turn_lockdown_off` wraps it with the feature's only condition —
whether a session is running — and is called by both the tray's Unblock item
and the Lockdown-off toggle, so turning the kill switch off now releases
immediately rather than waiting for the next bridge start.

`POST /v1/unblock` and `hole bridge unlock` are two doors with deliberately
different scopes. The transient cover's authority inside a live bridge is the
in-process `ProxyManager` posture's `PendingStart` state ([Cover
ownership](#cover-ownership)): `start_cancellable` reads it as proof the host
is covered, skipping re-engagement on a covered retry and suppressing the
censorship self-test on that basis. An
out-of-process command that deleted the transient filters would leave that
guard claiming a cover that no longer exists, and the next retry would run
uncovered while believing itself protected — so `cutover::unlock` keeps
clearing only the standing cover. The transient cover therefore has exactly
two escapes, both in-process: the tray's Go Offline action while the bridge
holds it, and `recover_routes`' unconditional sweep at the next bridge start
when it does not.

Disclosed residuals:

1. The `Lockdown: On (warning: not engaged)` tray label can still be wrong in
   this window — it derives from the running session, not an OS probe of the
   cover.

1. On macOS a state file that cannot be read costs the host its captured
   pre-cover pf rules (the release falls back to the default ruleset) and
   leaks a pf enable refcount until reboot.

1. An unreadable `bridge-lockdown.json` is read through two named folds of
   `lockdown_state::Intent`, not one bool, because the consumers want
   different answers. `reads_armed` (`On | Unreadable`) drives the status
   reply and the tray, so a corrupt record reads **armed** and keeps the
   Unblock item on the menu — losing the record is not consent to disarm.
   `installs_standing_cover` (`On` only) drives the connect path and the
   update-consent gate, so the same corrupt record reads **not standing**: a
   covered start keeps engaging the transient block-until-connected cover
   (block early, do not leak) instead of skipping it for a standing cover
   that only arrives after `routing.install`, and `consent_gate` still asks
   for informed consent because no standing cover holds the update gap. The
   tray can therefore read `Lockdown: On (warning: not engaged)` there, which
   is the honest rendering.

1. Startup reconciliation is a **20-cell table** over two measured axes, not
   two bools — `decide_cover_recovery(Intent, CoverPresence)` in
   `crates/tun-engine/src/routing.rs`. Intent is
   `On | Off | Unset | Unreadable`; presence is
   `Live | Recorded | Absent | Indeterminate | Unreachable`, measured by
   `failclosed::lockdown_cover_presence` (Windows: `FwpmFilterGetByKey0` over
   every lockdown GUID; macOS: our own `hole-lockdown` rule label read back
   from `pfctl -s labels`, falling back to `bridge-lockdown-pf.json`). Four
   rules: `Absent`/`Unreachable` are always `Noop`; `Sweep` requires
   `Intent::Off` **and** an actionable presence; `Adopt` requires an
   actionable presence with an intent of `On`/`Unreadable`/`Unset`, and
   `Unset` additionally requires positive evidence; the intent file is
   repaired to `enabled: true` only on `Presence::Live` with an `Unset` or
   `Unreadable` intent, never inferred.

   `Live` means **any residue**, not the whole cover: the Windows sweeps loop
   delete-by-key with every return code discarded over persistent filters, so
   a sweep interrupted mid-loop survives a reboot as a partial cover that a
   single-GUID probe would call `Absent` forever.

   `Adopt` never disengages the cover, on either platform. The server-permit
   volatile-refresh it used to perform moved into `engage_lockdown`, which
   deletes the TUN and server permits inside its own transaction before the
   adds. Keeping that delete at recovery time meant a second bridge with a
   fresh state dir (`Unset` x `Live` -> Adopt) would delete a *running* first
   bridge's server-IP permit while block-all stayed in force. The disclosed
   cost: an adopted cover keeps its stale server-IP permit until the next
   connect re-engages — a permit on an idle cover, and the App-ID permit
   already grants the bridge and plugin binaries unrestricted egress in that
   window.

   The TUN-LUID permit is the one exception: `Adopt` additionally calls
   `failclosed::reclaim_stale_tun_permit` (Windows only), which deletes it
   when `hole-tun` no longer resolves. Unlike the server IP, a resolving
   `hole-tun` is itself proof some bridge may be relying on the permit, so
   this can never touch a running bridge's cover — it only fires once the
   name is provably gone (e.g. after a crash). Without it, a `NET_LUID`
   (`IfType<<48 | NetLuidIndex<<24`) whose freed index NDIS later reassigns to
   an unrelated wintun-based adapter would inherit unconditional egress from
   the stale permit, armed but silently open, until the next connect. The
   reclaim is keyed on THIS bridge's own last-known TUN name (from its own
   `bridge-routes.json`, not a global constant): a different install's cover
   leaves no such record, so the reclaim does not run for it — the same
   per-install identity gap #878 tracks.

1. On macOS, `release_all` still treats a MISSING (not merely unreadable)
   state file as "no cover of this kind" — `StateFile::Absent`,
   indistinguishable from "never engaged" — and still returns `Ok` over a
   labelled-but-unrecorded cover, because it has no snapshot to restore.
   Presence is no longer file-only, though: the pf rule label makes a live
   cover with no state file detectable at **startup recovery**, which adopts
   it, and the self-capture guard stops the next connect from recording that
   cover as the host baseline (`main_snapshot_captured: false`, whose restore
   target is `/etc/pf.conf`).

1. A second bridge with an **explicit off intent** still sweeps machine-wide.
   The Windows lockdown GUIDs are compile-time constants identical in every
   build and install, and `lockdown_cover_presence` ignores `state_dir`, so
   the probe answers "is a Hole lockdown cover present", never "is it mine".
   `hole bridge run` takes independent `--socket-path`/`--state-dir`, so a
   second bridge whose own `bridge-lockdown.json` says `enabled: false` still
   sweeps a first bridge's live cover while that GUI reports Running. What
   #881 closed is the three routes where the second state dir has *no
   readable intent* — a wipe, a reinstall, a fresh `--state-dir` — which now
   Adopt instead of Sweep AT RECOVERY TIME. The remaining route needs
   per-install cover identity or the machine-wide lock, and is
   [#878](https://github.com/bindreams/hole/issues/878)'s.

   **The `Unset` x `Live` -> Adopt route is not fully closed — it is
   deferred, not removed.** Recovery no longer clobbers a running first
   bridge directly, but an adopted second bridge's OWN NEXT CONNECT still
   can: `decide_cover_recovery(Unset, Live)` sets `record_intent_on = true`,
   which persists `enabled: true` into the second bridge's own state dir and
   sets its adopted claim, so `standing_cover_expected()` reads true on its
   very next start. That start's `install_lockdown` -> `engage_lockdown`
   deletes the TUN-LUID and server-IP permits by the SAME compile-time-constant
   GUIDs (`LOCKDOWN_FILTER_GUIDS`, shared across every install) and re-adds
   them keyed to the second bridge's own LUID and server IP, inside the same
   transaction as its own block-all — while the first bridge is still
   running. On Windows this breaks the first bridge's tunnel the moment the
   second bridge connects; on macOS `engage_lockdown`'s `FreshEnable` reloads
   the ENTIRE main pf ruleset via `pfctl -f -`, so the second bridge's connect
   wholly overwrites the first bridge's lockdown ruleset. The fix needs the
   same per-install cover identity as the bullet above — [#878](https://github.com/bindreams/hole/issues/878).

1. `Unset` intent with `Unreachable` presence over a live cover leaves the
   Unblock item hidden. The routes in are the Base Filtering Engine not
   running or an RPC failure — both transient, and both states in which
   `hole bridge unlock` would also fail, so the honest escape is the next
   start once BFE answers, which adopts the cover and restores the menu item.

1. An adopted cover records **two** facts, kept in two places. The
   adopted-cover claim (`ProxyManager::set_standing_cover_adopted`, recorded
   by `route_recovery::recover_and_record`) says only "a standing cover is
   live right now and this process has not released it" — and is set only on
   a MEASURED `CoverPresence::Live`, not merely `action == Adopt`: `Adopt` also
   covers `Recorded` and `Indeterminate`, whose own docs say the OS did NOT
   confirm one, so asserting liveness there would tell the connect path and
   the update-consent gate no cover holds the update gap when none was
   confirmed. The armed kill switch is `bridge-lockdown.json`, written by
   `promote_adopted_claim` the moment a start honours the claim with a real
   `install_lockdown`. Holding both in the claim is what let an ordinary
   config edit disarm the switch: `reload`'s slow path is `stop()` then
   `start()`, the `UserStop` teardown cleared the claim along with the cover,
   and the next start re-derived `false`. Re-deriving on a later start is not
   a fallback — once the cover is torn down the measurement reads `Absent` and
   the decision is `Noop`. A failed repair write at `Unset`/`Live` therefore
   costs the preference only until the next connect retries it, and never the
   escape: within the run the claim is what keeps `lockdown_enabled` reporting
   armed.

   The claim is **not a latch** — it clears at four sites, three of which
   release the cover and clear only on a CONFIRMED `release_all_covers()`
   result, never on the guard's own silent `Drop`: `turn_lockdown_off`'s idle
   arm, a `UserStop` teardown, and `check_health` tearing down a dead session.
   An unconfirmed release at any of the three leaves the claim — and the
   Unblock item — in place, on the theory that a false "released" is worse
   than a stale "still armed". The fourth site, `turn_lockdown_off`'s
   mid-session arm, releases nothing (the session's own cover is `stop_with`'s
   to decide) and clears only because the user's newly-persisted explicit off
   must not keep being overridden by a stale claim from before this session, or
   from this session's own now-superseded adoption. Only `turn_lockdown_off`
   clears the persisted arm, so the escape still disarms the switch for good.

1. Startup still mutates global WFP state **unconditionally** via the
   transient cover sweep, which runs outside every presence branch and
   deletes the twelve transient GUIDs plus the shared sublayer and provider.
   The standing kill switch is what #881 made conditional; the narrow true
   claim is that it is never touched at startup without an explicit recorded
   "off".

#### Cover ownership

`ProxyManager` answers "who, inside this process, holds a fail-closed cover"
in exactly one place: one field (`posture: Posture<P, R, D>`, replacing what
were two independently mutable `Option` fields), three states (`Idle` / a
pending covered start / a live session), one derivation
(`Posture::cover_holder`, producing a `CoverHolder`) that every other site
asks rather than recomputes. `CoverHolder::Nobody` is a claim about *this
process* and never about the host — a cover stranded by an unclean exit, or
adopted at startup, is `Nobody` here and can still block every packet.
Answering "is the host held closed right now" needs an OS probe this model
does not have; that probe is later work, and this model is the vocabulary it
composes into, not a substitute for it.

"That every other site asks rather than recomputes" is enforced by a
structural test (`the_standing_cover_field_has_exactly_one_reader`,
`proxy_manager/cover_tests.rs`), not proven by the type system — it counts
`.field`-access reads of the session's standing-cover field and asserts
there is exactly one, in `Posture::cover_holder`. It is blind to an added
accessor under a different name and to a pattern-destructuring read (the
shape `stop_with` itself already uses, to consume rather than derive
ownership from, this same field); see the guard's own doc for the full
disclosed gap.

### Update cutover

`POST /v1/update-apply` ([`cutover/apply.rs`](crates/bridge/src/cutover/apply.rs))
swaps the bridge's own running binary and restarts the service in place. The GUI
already minisign-verified the MSI/DMG on download; the handler claims the marker
(the atomic single-occupancy guard) **first**, copies the payload into a
bridge-private dir, **re-verifies that copy offline** (minisign + SHA), extracts
the bare binaries from it, and dispatches the OS actor — so the verified bytes are
the extracted bytes and only the marker-winner ever stages (no concurrent-stage
clobber). On macOS the `.app` swap target is validated to a genuine
`com.hole.app` bundle *before* the marker (a destination precondition, 400). A
lockdown-off update **requires `consent: true`** (the enforcement seam — a brief
leak is accepted only with informed consent); under lockdown-on the standing cover
holds the gap, so consent is moot.

Leak-correctness rides the **standing lockdown cover**, not a transient one. The
bridge's marker-conditional shutdown sees the marker and `disarm`s the cover
(persist-without-disengage via `std::mem::forget`) instead of dropping it, so the
WFP/pf filters survive the restart and the new bridge re-adopts them
(`decide_cover_recovery == Adopt`). The `cutover::os::CutoverOs` effects trait
exposes no cover-mutating method, so a cutover structurally cannot engage a
transient cover (the Mullvad-#8470 brick); a lockdown-off cutover is a plain
restart that fails *open*.

The **swap is rename-away-then-move-in** and **all-or-nothing**: the live binary
is renamed aside (`std::fs::rename` uses POSIX semantics, renaming a running exe
held `FILE_SHARE_DELETE`; macOS `.app` via `renamex_np(RENAME_SWAP)`) and the
staged new bytes move onto the freed canonical path, flipping `same_file::Handle`
identity so the GUI self-heal returns Relaunch. The swap covers the **full BINDIR
set** (every bundled binary, not just `hole.exe`); a mid-set failure rolls the
committed swaps back to the prior consistent set before erroring, so the service
never boots a mixed old/new mix (the destructive delete of swapped-out images is
deferred until the whole set commits, which is what makes the rollback possible).

The restart is **OS-asymmetric**. Windows spawns a detached LocalSystem
`hole bridge cutover` child (a service cannot SCM-restart itself) that
stops → swaps → starts via `NotifyServiceStatusChange` (a real kernel rendezvous,
gated on a RUNNING callback, never a sleep or loopback probe). macOS runs inline:
swap first, then `launchctl kill SIGTERM` rides the graceful shutdown
(`pm.stop()` → the marker-conditional disarm fires), and `KeepAlive=true`
respawns the now-swapped binary.

The **marker** (`update-in-progress.json` in the service log dir, world-readable
0o644 cross-privilege) does triple duty: the GUI holds its last snapshot instead
of flashing Disconnected while it is set, the bridge shutdown disarms the cover
while it is set, and it is the PR3 banner source. It is cleared unconditionally
(remove-by-path) on the next bridge's post-bind sweep.

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
*produces* the mismatch is the [update cutover](#update-cutover).

## Workspace layout

Each publishable member declares a release group in
`[package.metadata.hole-release].group` (enforced by `xtask-lib::version`).
`publish = false` means not pushed to crates.io.

| Directory / file                   | Crate · license · group                | Purpose                                                                          |
| ---------------------------------- | -------------------------------------- | -------------------------------------------------------------------------------- |
| `crates/common/`                   | `hole-common` · GPL · hole             | Shared types: protocol, config, import, logging                                  |
| `crates/bridge/`                   | `hole-bridge` · GPL · hole             | Bridge library (TUN/routing/SS/IPC/DNS)                                          |
| `crates/hole/`                     | `hole` · GPL · hole                    | Tauri app + CLI + bridge entry (binary `hole`)                                   |
| `crates/tun-engine[-macros]/`      | GPL · hole                             | TUN + routing + packet-loop engine (+ `#[freeze]` macro)                         |
| `crates/dump[-macros]/`            | GPL · hole                             | YAML-shaped logging representation (+ derive)                                    |
| `crates/handle-holders/`           | GPL · hole                             | File-handle introspection (Win NtQuery / mac lsof)                               |
| `crates/test-observability/`       | `hole-test-observability` · GPL · hole | Dev-dep: pre-main ctor installs subscriber + panic hook                          |
| `crates/tombstone/`                | Apache · —                             | Native-crash handler (marker + optional minidump)                                |
| `crates/stepstool/`                | Apache · —                             | Elevation primitives: sudo priming + wrapping (POSIX), elevation detection (Win) |
| `crates/garter[-bin]/`             | Apache · garter                        | SIP003u plugin-chain runner lib (**on crates.io**) + CLI + mock-plugin fixture   |
| `crates/galoshes/`                 | Apache · galoshes                      | Bundled+standalone SIP003u plugin (YAMUX + embedded ex-ray)                      |
| `crates/ex-ray/`                   | Apache · ex-ray                        | First-party Go SIP003u plugin on v2ray-core (wire-compatible with v2ray-plugin)  |
| `crates/util/`                     | Apache · —                             | `port_alloc`, `retry` (Apache so plugins can depend)                             |
| `crates/plugin-e2e/`               | GPL · —                                | Shared ss-server/cert harness + ex-ray↔stock + galoshes roundtrips (#197)        |
| `crates/dev-console/`              | GPL · —                                | Dev-mode supervisor: bridge (elevated) + Vite + GUI, multiplexed logs (#454)     |
| `build.yaml`                       | —                                      | Declarative build-target DAG for `cargo xtask build\|run\|list`                  |
| `xtask/`, `xtask-lib/`             | —                                      | Task runner + helper crate shared with `crates/hole/build.rs`                    |
| `msi-installer/`, `dmg-installer/` | —                                      | Windows MSI (WiX) + macOS DMG signature checks (Python, #364)                    |
| `ui/`, `scripts/`, `tests/`        | —                                      | Frontend (Vite), utility scripts, E2E specs (WebDriverIO)                        |

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

**Client TLS dial paths must fail closed on ECH.** Every client TLS dial path in
the vendored `ex-ray/third_party/v2ray-core` must build its config via a factory:
`GetTLSConfigForClient` (ECH-capable transports) or `GetTLSConfigForUnsupportedClient`
(ECH-incapable engines: uTLS, hysteria2); only server listeners call the bare
`GetTLSConfig`. A bare `GetTLSConfig` on a client path leaks the real SNI in
cleartext under `ech=always`. The factory split is the load-bearing guarantee:
once a client path goes through a factory, the require-ECH gate cannot be
bypassed. CI enforces it two ways — the `ech=always` + unreachable-`ech-doh` ⟹
tunnel-refused roundtrip tests in `crates/plugin-e2e/tests/roundtrip.rs` (ex-ray's
real ws-tls + QUIC paths), and the `ex-ray-tests` job (`cargo xtask run ex-ray-tests`), whose Go unit tests exercise the per-engine fail-closed/refuse
behavior in the vendored `transport/internet/{tls,quic,hysteria2}` packages. The
residual is an upstream v2ray-core re-merge re-introducing a bare `GetTLSConfig`
on a client path (the vendored tree is lint-excluded): re-verify on every re-merge.

## Prerequisites

- Rust toolchain (pinned via [rust-toolchain.toml](rust-toolchain.toml); rustup
  installs it on the first `cargo` call in the repo)
- Go toolchain (for ex-ray; built by `cargo xtask deps`) — pinned by the
  `toolchain` directive in [crates/ex-ray/go.mod](crates/ex-ray/go.mod), which
  `go` enforces on a bare `go build` and CI feeds to `actions/setup-go`
- Node.js ≥24 — a *range* (`engines.node` in [package.json](package.json)),
  resolved at job time

Rust and Go are exact pins, so a release of either cannot turn `main` red on its
own. Bump them deliberately: clippy gains lints between releases, and
golangci-lint must be new enough to typecheck the Go standard library it is
pointed at. Renovate tracks both compilers but never automerges either — a
compiler bump always arrives as its own reviewable pull request
([renovate.json](.github/renovate.json)). `actions/setup-go` prefers
`toolchain` over `go` when both are present, so `toolchain` is what CI
installs. The `go` directive keeps Renovate's default range strategy, a no-op
while its range already covers the latest release, so routine Go releases only
move `toolchain`; both directives share one never-automerged rule so a Go
major (which would move `go`) can't slip through either.

| Pin                                                | Renovate manager                            |
| -------------------------------------------------- | ------------------------------------------- |
| `rust-toolchain.toml` `channel`                    | `rust-toolchain` (depName `rust`)           |
| `go.mod` `toolchain` directive                     | `gomod` (depName `go`, depType `toolchain`) |
| `go.mod` `go` directive (rarely moves — see above) | `gomod` (depName `go`, depType `golang`)    |

Nothing else is pinned, and the claim stops there. Node floats within `24.x`,
and `prek`, `nextest`, Python and `uv` are all installed unversioned in jobs
that gate `main`. `prek` and `nextest` are the sharpest of those — a linter and
a test runner, the same class of tool that gains behaviour between releases. If
the same commit passes one day and fails the next, check those before assuming
the code moved.

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
cargo xtask run hole         # dev mode (build cascade, then dev-console supervises)
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
cargo xtask run hole-dmg-tests   # mount + assert payload + code signature are intact
```

The DMG does not use `cargo xtask stage`; Tauri bundles the canonical BINDIR via
`crates/hole/tauri.conf.json` — `externalBin` (plugin sidecars → `Contents/MacOS/`),
`resources` (`NOTICES.md` → `Contents/Resources/`), and `macOS.files` (`hole.dSYM`
→ `Contents/MacOS/hole.dSYM`). The dSYM ships **next to the binary** because std's
backtrace symbolizer locates a `*.dSYM` by scanning the running binary's directory
and matching its Mach-O UUID — so production panic backtraces resolve frame names +
line numbers (the Windows `hole.pdb` analog; see #393). `bundle.macOS.files` is
bundle-time-only (not validated by `tauri_build::build()` like `resources`), so the
dSYM — the build's own output — needs no `build.rs` stub. cargo's `split-debuginfo = "packed"` emits `target/release/hole.dSYM` as a *symlink* into `deps/`, which the
bundler would ship dangling; the `hole-dmg` build dereferences it into `.cache/`
(the source `macOS.files` points at) before bundling. The `hole-dmg-tests` pytest
derives its expected payload from `cargo xtask bindir-names --os darwin`, so the
Tauri config can't silently drift.

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
supervisor, which starts Vite and launches bridge + GUI with multiplexed
color-coded logs. dev-console builds nothing — the xtask cascade builds first
(#564); `cargo run -p dev-console` works standalone against an already-built
tree. Frontend changes hot-reload via Vite HMR; Rust changes need Ctrl+C and
re-run.

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
- **Multiplexed logs (`mux`).** Steady state streams each child's entries in
  arrival order, deferring an EntryBuffered stream's most-recent entry until its
  next anchor or pipe EOF (atomic multi-line framing). At shutdown the printer
  switches to collect-and-sort, emitting the trailing burst ordered by ISO
  timestamp instead of pump-EOF order (bindreams/hole#568).

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

`cargo xtask stage` populates a BINDIR (`hole` + the `ex-ray` and `galoshes`
plugin sidecars + `NOTICES.md` + per-platform debug symbols + `wintun.dll` on
Windows) matching the installed `Program Files\hole\bin\`. The bridge must be
staged out of the cargo target dir because the running bridge file-locks its own
exe; the plugin sidecars must be siblings so `resolve_plugin_path_inner` finds
them. The canonical file list (the single source of truth, per-OS) is
[`bindir_dest_names`](xtask-lib/src/bindir.rs); the installer manifests are
checked against it by conformance tests (`cargo xtask bindir-names`).

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

### Known coverage gap: macOS reopen

`RunEvent::Reopen` — the Spotlight/Finder/Launchpad activation that reveals the
dashboard — has no automated coverage on any platform. `RunEvent` is
`#[non_exhaustive]` and constructed by the wry runtime, and there is no macOS GUI
driver lane (the WebdriverIO E2E is Windows-only; `tauri-driver` has no macOS
backend). Verify by hand on macOS when touching `handle_run_event` or
`tray::open_settings_window`: with Hole running and the dashboard closed,
Spotlight "Hole" must reveal it.

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
- **Every crate runs in CI** — the `every_workspace_crate_runs_in_ci` conformance
  test ([`xtask/src/ci_coverage.rs`](xtask/src/ci_coverage.rs)) fails if a
  workspace crate's tests are run by no CI job (the recurring orphaned-test
  class). A new crate must join some CI test job's package filter, or — if it has
  no runnable tests — get an `UNTESTED_IN_CI` entry with a reason. (#526) A
  general per-crate-per-platform version of this guard (asserting non-zero test
  *counts*, not just presence) was found to be undetectable at package
  granularity — every `test-hole` package already has ungated tests on every
  platform it runs on — and was not built (#894). In its place,
  `skuld_label_coverage::verify` asserts the `tun` skuld label's live listing
  for `test-hole` is non-empty on the platform running it, catching the one
  demonstrated regression class (a platform's whole privileged/TUN lane
  silently going empty).
- **`global_net_state` label conformance** — `.config/nextest.toml`'s
  `global_net_state` test-group serializes cross-binary tests that mutate
  global OS network state via a hand-maintained name-substring filter (see that
  file's own comment). `cargo xtask verify-global-net-state-labels`
  (`xtask/src/global_net_state_conformance.rs`) binds that filter to the
  `global_net_state` skuld label attached at each test's own definition site,
  checking live that both select the exact same tests and that the group's
  `max-threads` is still `1` (#894). It does not catch a higher-precedence
  `[[profile.default.overrides]]` entry stealing these tests into a different
  group, and its universe is `test-hole`'s package set even though the
  nextest.toml filter applies workspace-wide.

## Logging & diagnostics

### Log destinations

Both GUI and bridge write to stderr **and** a 10 MiB rotating file (one backup).
Default dir is `dirs::state_dir()/hole/logs` (`gui.log`, `bridge.log`):

- Windows `%LOCALAPPDATA%\hole\logs\`, macOS `~/Library/Application Support/hole/logs/`
- Installed service: Windows `C:\ProgramData\hole\logs\`, macOS `/var/log/hole/`

`hole bridge log` defaults to the installed-service dir; override with `--log-dir`
or `HOLE_LOG_DIR` to read a foreground/dev bridge's log.

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
file**: the `UserOwnedRotate` appender. Wrapping that one closes the file leak;
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

**What replaces the address in a Hole-authored line.** `server` (the token),
`server_kind` (`domain`/`ipv4`/`ipv6`), `server_family`, `server_scope`
(`global`/`private`/`loopback`/`link_local`), and the unchanged `server_port`.
Checked against the diagnoses this repo has actually needed (#248, #541, #655,
#770, #694): none required the address. The joined `route`/`netsh` argv
(`routing.rs`'s `log_route_command`), the ETW `remote` field, `netsh` stdout and
garter's plugin relay deliberately get **no** per-site edit — the sink covers
them, and hand-redaction there would rot.

**Two limits, so this is not read as a total guarantee.** First, `dump!`'s
ladder resolves per top-level expression, not per field: any `Serialize` type
transitively holding a `ServerAddress` needs its own `Dump` impl, or the serde
tree renders the inner string and `ServerAddress::dump` is never reached.
`ServerEntry` and `ProxyConfig` have one; that is convention backed by
per-container tests, not a compiler guarantee, with the sink as the backstop.
Second, an address written in a form no armed literal is a byte-substring of —
a percent- or punycode-escaped form from a third-party process, a non-canonical
IPv6 text form from a peer that is not `std` — is not redacted.

**Existing artifacts.** Files already on disk are not rewritten: a SYSTEM bridge
rewriting files in a user-writable directory is an attack surface. The support
bundle is scrubbed on collection instead, and its `REDACTION.txt` states the
three residuals plainly.

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
- **Plugin directive injection** — `inject_plugin_directives` appends
  `loglevel=debug` (always) and `ech-doh=<resolver-DoH-url>` (when a resolver is
  configured) to `SS_PLUGIN_OPTIONS` for `v2ray-plugin`/`ex-ray`/`galoshes`;
  stderr is captured via `garter::binary` and filtered by `HOLE_BRIDGE_LOG`. The
  bridge never injects `ech=<mode>` — ex-ray owns the mode (default `auto`).

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
- **garter publish is blocked** — garter takes `cosca` as a git rev with no
  version key, which `cargo package` refuses. It unblocks when the workspace pin
  names a registry version, the final gate of #816.
- **Versions** live in each crate's `[package.metadata.hole-release].group`
  (ex-ray in `crates/ex-ray/version.toml`); validate with `cargo xtask version [--check --group <name> [--exact]]` (release CI uses `--exact`). The legacy
  `v0.1.0` tag predates the scheme and is ignored.

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
