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
  `routing::recover_routes` tears down leaked routes. The same call also sweeps a
  stale [fail-closed cover](#fail-closed-cover) (Windows by fixed WFP GUID,
  macOS via `bridge-failclosed.json`).
- **`bridge-failclosed.json`** (macOS only) — the `pfctl -E` enable token of an
  engaged fail-closed cover; `routing::failclosed::recover_cover` restores
  `/etc/pf.conf` and drops the refcount. Windows keys its cover by fixed WFP
  GUIDs and needs no file. See [Fail-closed cover](#fail-closed-cover).
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
needs). The [standing lockdown cover](#lockdown-mode) carries the identical
permit — see that section. Finally, the release-then-reengage repair itself
has a brief window with NO cover at all
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
`FILTER_GUIDS` itself. The standing lockdown cover's `LOCKDOWN_FILTER_GUIDS`
grew the same way for the same reason, disclosed as a source comment there
too; both arrays share the one tracking issue:
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
into the (briefly absent) tunnel being blocked for the sub-second cover window is
the accepted fail-closed cost.

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
`build_setup_commands` vs `run_commands`. Under the
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

The **standing lockdown cover** (`Routing::install_lockdown_permits`, #527) is an
opt-in, **default-off**, bridge-owned kill switch. When enabled it engages a
persistent OS-level egress block permitting **only** loopback, the `hole-tun`
interface, the onward server connection, the resolver Hole's own `ech-doh`
names when a plugin needs it (same gate, same TCP/443 scope, same
config-authorship trust as the [transient cover's resolver
permit](#transient-cutover-cover); an address permit, not an App-ID one,
because a chained plugin like `galoshes` spawns its inner ex-ray as a
separate process no App-ID set names), and (Windows) the plugin + bridge
binaries by App-ID — so normal traffic flows while connected and the block holds
across a bridge restart for free. When disabled, behavior is byte-identical to a
Hole without it.

It contrasts with the [transient cutover cover](#transient-cutover-cover) on
three axes:

- **Permit set.** Lockdown adds a TUN-interface permit (Windows: by `NET_LUID`;
  macOS: `pass out quick on <tun>`) so app traffic flows; the transient cover
  deliberately omits it because holding it while connected would block all
  browsing. Both covers otherwise permit the identical resolver address under
  the identical gate — see the paragraph above.
- **Lifetime.** Lockdown is authoritative and standing — it persists across a
  crash or restart and is reconciled on the next start via
  `decide_cover_recovery` (Adopt keeps the host fail-closed; on Windows it
  drops the volatile TUN + server + resolver GUIDs so the next connect
  re-adds them fresh, on macOS it removes nothing at all — the whole pf
  ruleset, resolver permit included, stays live from before the
  crash/restart until the next connect's `engage_lockdown` reloads it; Sweep
  disengages when intent is off). The transient cover is a non-standing,
  bounded-window RAII guard engaged only for the duration of one covered
  (auto-connect) start attempt, and swept by `recover_routes` like
  every other cover state on the next start.
- **Failure mode.** A failed lockdown engage during a lockdown-on start is
  **fail-FATAL** — it aborts the start and tears everything down; the transient
  cover fails *open* on its own engage error so a half-loaded ruleset never
  strands the host. Lockdown is **last-writer-wins**: an absolute set via
  `POST /v1/lockdown`, system-wide.

Intent persists to `bridge-lockdown.json`; macOS additionally records the
pre-lockdown pf snapshot in `bridge-lockdown-pf.json` so Sweep restores the host
without `-Fa`. The LUID is **never persisted** (a teardown mints a new one) —
re-resolved every engage via `LuidResolver`.

**Engage is two-phase.** `Routing::install_lockdown_permits` engages every
permit except the TUN one — loopback, server, (when `Some`) resolver, App-IDs
— and RETURNS the RAII `Cover` the running session eventually holds.
`ProxyManager::start_cancellable` calls it BEFORE `start_inner` even runs,
mirroring exactly when the transient cover engages, holding the guard in a
plain LOCAL variable scoped to `start_cancellable` itself — NOT inside
`start_inner`, so a later phase's failure can't accidentally tear it down via
`start_inner`'s own RAII unwind (that would also delete a pre-existing
adopted cover's floor, since both share the same fixed identity).
`Routing::engage_lockdown_tun` then adds ONLY the TUN permit to that SAME
guard at Phase 6, once `routing.install` has resolved the adapter — it returns
no guard of its own: on Windows it opens its own FWPM engine, adds the two TUN
filters (a tolerant add — `FWP_E_ALREADY_EXISTS` treated as success — is
correct here because the guard never persists across attempts; there is no
cross-attempt retry needing a strict add to distinguish from a genuine
first-engage/Adopt-continuation, which can legitimately see already-present
floor filters), and closes the engine immediately. On macOS it reloads the
full pf ruleset (`pfctl -f -` has no incremental update), reusing the
token/snapshot Phase 0 persisted — and, unlike Phase 0's own load-failure
handling, a failed reload here does NOT restore the pre-lockdown snapshot:
`pfctl -f -` is atomic, so a rejected ruleset leaves the PREVIOUSLY loaded
one (Phase 0's, still fully enforced, just missing the TUN line) unchanged —
destroying it anyway would take down a cover that is still live and correct.
Either way the ONE guard Phase 0 returned still owns the whole cover's
disengage, TUN permit included once Phase 6 adds it.

Without the Phase-0 step, a plugin's Phase-4 forwarder self-test — where
ex-ray's lazy ECH-config fetch actually fires, on the chain's first real dial
— runs *before* Phase 6 ever installs the resolver permit; on an
already-armed machine (a prior run's cover, live or adopted) that dial is
blocked by the standing block-all with nothing yet permitting it, so the
start fails identically on every retry. Both engage calls are fail-FATAL.

**The guard's lifetime is bounded to one attempt.** `start_cancellable` holds
the `Option<R::Cover>` Phase 0 returns as a plain local and passes it into
`start_inner` for Phase 6 to add the TUN permit to. On success it is marked
fully owned (`CoverGuard::mark_owned`, next paragraph) and moved into
`RunningState.lockdown`, where it disengages on an ordinary `stop()` and
disarms (persist-without-disengage) on a cutover, exactly like every other
cover this manager holds. On EVERY early return — an ordinary `Err` from any
later phase, or a `Cancelled` from mid-flight cancellation — the local simply
goes out of scope and drops via Rust's own RAII, the same way `start_inner`'s
own `routes` guard unwinds on a Phase 1-5 failure: no special-cased
retention, no separate "pending" bucket for `stop_with` to reconcile, and no
distinction between an ordinary failure and a cancel (the transient cover
already treats those identically — "same trust as a user disconnect" — and
the standing cover now does too) — **except one: ownership.**

**Ownership: a guard must not destroy a cover it did not create.** Phase 0's
engage can find a standing cover already live — adopted from a prior bridge
process that crashed or cutover-restarted (`CoverRecovery::Adopt`), not
created by this attempt at all. If a *later* phase then fails, the local's
ordinary-RAII drop described above would, unqualified, tear that adopted
cover down: on Windows every lockdown GUID deleted, on macOS the
pre-lockdown snapshot restored and the state file cleared — regressing the
crash-recovery guarantee for exactly the failure (a blocked self-test) the
kill switch exists to survive. Each platform's `engage_lockdown` records
which case it was in an `Ownership` enum on the returned `Cover` (Windows:
was the floor filter already present before this call touched anything;
macOS: was there already a persisted state file) and `Drop for Cover`
branches on it: `Fresh` (this call created the cover from nothing)
disengages as before; `Adopted` (this call found one already live) does
nothing, leaving pf/WFP exactly as this attempt's own re-engage left them —
either the adopted values unchanged (this attempt's engage never reached its
own mutate) or this attempt's own rewritten ruleset (the engage succeeded,
loading THIS attempt's server/resolver/App-IDs, and a later phase then
failed). Either state is still a complete, self-consistent, fully
fail-closed floor for this attempt's config — never less restrictive than
before this attempt started, just possibly missing whatever this attempt
itself never reached (e.g. the TUN permit, if Phase 6 never ran). There is
no separate "restore to before this attempt" snapshot to fall back to — that
would be exactly the identity-tracking machinery the simplification above
dropped, applied one layer further out.

Ownership is consulted ONLY by `Drop`, and is otherwise inert: no identity
comparison (host/server/resolver/App-IDs), no staleness check, no repair
path, no cross-attempt state. It answers exactly one question, asked once,
at Phase 0: did this attempt create the cover, or find one already there?
Once a connect attempt actually SUCCEEDS, the running session is what the
user sees as "connected" and explicitly disconnects from — an explicit stop
from that point on must always be able to open the host, independent of the
cover's provenance before this attempt started. `CoverGuard::mark_owned`
flips an `Adopted` guard to `Fresh` for exactly this reason, called once, in
`start_cancellable`, immediately before the guard moves into
`RunningState.lockdown` — without it, `stop_with`'s ordinary `drop(lk)` on
UserStop would silently no-op for a session that started from an adopted
cover, which is never correct: a user-initiated disconnect must open the
host regardless of how the standing cover came to exist.

This accepts a retry-window gap, now narrower than it first appears: a
`Fresh`-owned attempt's guard disengages immediately on failure or
cancellation, opening the host briefly until the NEXT retry's own Phase 0
re-engages fresh — the identical gap an ordinary `main` connect already has
on every failed or cancelled attempt, so retaining state only for the
two-phase split would have spent real complexity protecting a window that
predates this fix and was never in its scope. An `Adopted` attempt's guard
has no such gap at all: it never disengages on failure, by design. Tracked
as [#768](https://github.com/bindreams/hole/issues/768).

On macOS, `reconcile_pf_enabled` runs before `engage_lockdown_tun`'s (Phase
6\) reload, which assumes an already-persisted token: `pfctl -f -` into a
DISABLED pf exits 0 while enforcing nothing, so skipping this check reports a
connected, armed session as covered while pf enforces nothing at all. Phase
0 and Phase 6 can
still be separated by several seconds within a SINGLE attempt (the plugin
chain start, self-test, and route install all run in between), so this check
stays load-bearing even though the guard no longer persists across attempts.

Full mode completes both phases: Phase 0 here, Phase 6 (the TUN permit) in
`start_inner`. SocksOnly's `start_inner` returns before Phase 6 ever runs —
no TUN, no LUID — but Phase 0 needs neither, and guard ownership doesn't
depend on Phase 6 either (`RunningState.lockdown` is filled from the
caller's local guard on the `Ok` path regardless of mode), so a COVERED
SocksOnly start under lockdown intent also applies Phase 0:
`lockdown_applies = intent && (tunnel_mode == Full || covered)`. The
transient cover is not a viable substitute here — its engage/disengage
replace pf's entire main ruleset, and it has no way to tell a clean host
apart from one where a standing cover (this process's own prior attempt, or
one adopted from before a crash) is already live, so using it for SocksOnly
would risk destroying that live cover instead of complementing it. A MANUAL
(uncovered) SocksOnly start still never applies lockdown, matching every
other manual connect's fail-open-by-design convention — there is no
fully-uncovered gap to close on a connect the user drove directly.
`lockdown_applies` is computed once in `start_cancellable` and passed into
`start_inner` as a parameter, the same pattern `ech_resolver_permit` already
uses — `start_inner` does not independently re-read the persisted intent
file, which has out-of-process writers (`hole bridge unlock`) that could
otherwise flip it mid-attempt and desync the two phases.

`hole bridge unlock` is the elevated escape hatch to disengage a standing cover
when no bridge is alive (`cutover::unlock`). Unlike the best-effort startup
Sweep, it is **fail-loud**: it disengages via `failclosed::disengage_lockdown`
FIRST and flips the intent off only on confirmed success, returning a non-zero
exit otherwise (e.g. run unprivileged). A swallowed failure would leave the
cover engaged — egress still blocked — while the intent read "off".

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
primitive [relaunch.rs](crates/hole/src/relaunch.rs) (Windows
`WaitForSingleObject`, macOS `kqueue`/`NOTE_EXIT`) — or, if it *is* the
installed image, shows a path-free reinstall dialog. The only `#[cfg]` live in
the `ArmedWait`/identity seams; `decide` and the wiring are platform-agnostic
and table-tested. Inert until an update produces a mismatch, and gated off for
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
| `crates/kill-group/`               | Apache · kill-group                    | Process-tree kill-groups (job object / process group); split from garter (#197)  |
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
  no runnable tests — get an `UNTESTED_IN_CI` entry with a reason. (#526)

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
`CorruptedJson` (no fields) and logs the full error.

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
