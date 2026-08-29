# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin
support (served by the bundled first-party `ex-ray` binary). A single Rust binary
is both the unprivileged Tauri GUI (no args) and the privileged bridge
(`hole bridge run`, root/SYSTEM).

This file is the agent-facing architecture map. Product and install live in
[README.md](README.md); the full contributor reference — build, dev, test, and
every rule below in detail — lives in [CONTRIBUTING.md](CONTRIBUTING.md). Read it
before editing; the sections linked below are the authoritative source.

**IMPORTANT:** NEVER PIPE TESTS TO `tail`! ALWAYS SET A TIMEOUT FOR THE SHELL COMMAND! Tests are known to hang, you WILL get stuck and WILL not have information to debug why if you tail.

## Architecture map

- **Single binary, two modes.** GUI (system tray, settings, config) and bridge
  (TUN, routing, shadowsocks-service) selected by CLI args; they speak HTTP/1.1
  REST (JSON) over an AF_UNIX socket on both platforms (Windows via `socket2`). →
  [CONTRIBUTING.md#architecture](CONTRIBUTING.md#architecture)
- **Single-instance GUI.** Single-instance via `tauri-plugin-single-instance`
  (`com.hole.app`); CLI subcommands bypass the lock. →
  [CONTRIBUTING.md#single-instance-enforcement](CONTRIBUTING.md#single-instance-enforcement)
- **UDP-drop policy.** Hole is a VPN: UDP flows that resolve to `Proxy` on a
  TCP-only plugin are **dropped, not bypassed** (bypassing would leak outside the
  tunnel); enforced structurally in `HoleRouter::resolve_endpoint`. UDP/53 is
  diverted to the DNS forwarder before the cascade. →
  [CONTRIBUTING.md#udp-policy](CONTRIBUTING.md#udp-policy)
- **IPv6 in the tunnel.** IPv6 is meant to traverse the tunnel: the `::/1` +
  `8000::/1` split pair captures it, and `hole-tun` holds `TUN_SUBNET6` on the
  **OS interface** as well as in smoltcp, so a host with no global IPv6 still
  has a source address for those routes. The ULA's global ID is generated per
  RFC 4193, not `fd00::`. Windows waits for the interface's IPv6 half itself
  (`tun` waits only for the IPv4 one) and creates the address
  `IpDadStatePreferred`; assignment is fatal on Windows, warn-only on macOS,
  and `Dispatcher::ipv6_assigned()` is what route-install fatality must read. →
  [CONTRIBUTING.md#ipv6-in-the-tunnel](CONTRIBUTING.md#ipv6-in-the-tunnel)
- **TCP accept refusal.** The accept verdict lands while the listener is still
  in `SynReceived` with its SYN-ACK paused, so a declined connection is refused
  with a pre-handshake RST instead of black-holing behind a SYN-ACK; the verdict
  is the pure `decide_admission`. A socket with a packet still to emit is
  *retired* rather than removed, and reaped once smoltcp clears its 4-tuple —
  including one that reverted to `Listen`, which would otherwise hijack its
  port. No socket in the stack defers an ACK, so `TimeWait` strands nothing on
  immediate removal. A 4-tuple has one owner: a same-tuple SYN's ISN, read off
  the wire, tells a retransmit from a new connection reusing it (RFC 9293
  §3.10.7.4), and a re-armed listener that outranks its own connection in slot
  order and steals that client's retransmitted SYN is caught the same way — such
  a handshake is `Duplicate` and its socket is dropped without a segment.
  `Driver::settle_packet` bundles admission and retirement into one call per
  packet so a socket mid-teardown can never intercept the next SYN. An admitted
  connection carries a keep-alive plus a timeout, the sanctioned bound on a
  client that may never speak again — without it a stall in
  `SynReceived`/`FinWait2`/`CloseWait` holds its slot forever. →
  [CONTRIBUTING.md#tcp-accept-refusal](CONTRIBUTING.md#tcp-accept-refusal)
- **DNS forwarder.** Carries DNS over the TCP tunnel for TCP-only plugins; OS
  adapter DNS is advertised the configured resolver IPs, which route into
  `hole-tun` and are intercepted by the in-TUN `LocalDnsEndpoint`; a start-time
  forwarder self-test gates the whole connection. →
  [CONTRIBUTING.md#dns-forwarder](CONTRIBUTING.md#dns-forwarder)
- **Listener selection invariants.** `build_ss_config` rejects
  `TunnelRequiresSocks5` (full + HTTP-only) / `NoListenersEnabled`
  (socks-only + none) / `DuplicateListenerPort` up-front; full mode with
  no listeners is the pure-VPN start (internal SOCKS5 data plane on an
  ephemeral port). →
  [CONTRIBUTING.md#listener-selection-invariants](CONTRIBUTING.md#listener-selection-invariants)
- **Bridge trait seam.** All OS-mutating bridge I/O routes through the `Proxy`,
  `Routing`, and `Dns` traits so tests can mock it. →
  [CONTRIBUTING.md#bridge-test-isolation-contract](CONTRIBUTING.md#bridge-test-isolation-contract)
- **Proxy shutdown contract.** `stop()` returns only once the listener sockets
  are closed; the proxy owns its own runtime because upstream's teardown is
  three layers of bare `abort()`. →
  [CONTRIBUTING.md#proxy-shutdown-contract](CONTRIBUTING.md#proxy-shutdown-contract)
- **Cooperative-cancel model.** Cancellation propagates via tokens from the IPC
  `handle_start` handler; no future-drop cancellation. The engine driver
  observes the token at every await, so the dispatcher's join of it carries no
  bound. →
  [CONTRIBUTING.md#bridge-cancellation-contract](CONTRIBUTING.md#bridge-cancellation-contract)
- **Native-crash observability.** The `tombstone` crate writes a signal-safe
  crash marker; the next start of the same kind sweeps it. →
  [CONTRIBUTING.md#native-crash-observability-tombstone](CONTRIBUTING.md#native-crash-observability-tombstone)
- **Route-command failure policy.** Install is fatal, teardown/crash recovery
  are best-effort — the type system (`FatalPhase`/`BestEffortPhase`) enforces
  which runner a phase gets, and per-command fatality tolerates the IPv6
  splits failing on a TUN with no IPv6 binding. →
  [CONTRIBUTING.md#route-command-failure-policy](CONTRIBUTING.md#route-command-failure-policy)
- **Crash-recovery sweep.** `bridge-{routes,plugins,dns}.json` + ETW sessions are
  replayed/cleaned on next startup after the IPC socket binds. →
  [CONTRIBUTING.md#crash-recovery](CONTRIBUTING.md#crash-recovery)
- **Yamux transport self-heal.** The galoshes yamux client reconnects after a
  transport reset instead of wedging; death is detected via the driver's
  inbound channel closing, and reconnect backoff is floored and resets on
  transport-level liveness (any inbound yamux frame). `driver.abort()`
  teardown deliberately truncates in-flight relays. A silent (no-RST) black
  hole is caught by an idle-gated client keepalive on a `Keepalive` substream:
  a cycle is fatal only when the transport tap counted no inbound read across a
  whole interval and deadline, so an un-upgraded peer's tag rejection reads as
  liveness and a busy tunnel is never probed at all. →
  [CONTRIBUTING.md#yamux-transport-self-heal](CONTRIBUTING.md#yamux-transport-self-heal)
- **galoshes mux default.** galoshes appends `mux=0` for its embedded ex-ray —
  its yamux already collapsed every stream onto one connection, so Mux.Cool is
  pure overhead. ex-ray is first-wins on duplicate SIP003 keys, so an operator's
  earlier `mux=` overrides it. `mux` also picks the server's dokodemo
  destination, so a `mux=0` client cannot reach a `mux=1` server. →
  [CONTRIBUTING.md#galoshes-mux-default](CONTRIBUTING.md#galoshes-mux-default)
- **Fail-closed covers.** The **standing lockdown** cover
  (`Routing::install_lockdown`, opt-in kill switch) holds the update-cutover gap:
  the bridge **disarms-not-drops** it across the restart and the new bridge
  re-adopts it (`decide_cover_recovery == Adopt`). The **transient**
  `install_failclosed_cover` (permit loopback + server, plus the resolver
  Hole's own `ech-doh` URL names when it's the value ex-ray will actually dial
  — `effective_ech_doh == Holes`, not merely a plugin being configured —
  scoped to TCP/443) is a bounded-window RAII guard engaged by every covered
  (auto-connect) start whose lockdown intent is OFF; a lockdown-on covered
  start uses the standing cover instead and releases any held transient one.
  Both are persistent WFP filters (Win) / self-contained pf ruleset (mac); the
  transient one is swept unconditionally on next start, the standing one only
  on an explicit recorded off — full reconciliation table (`decide_cover_recovery`)
  and disclosed residuals in CONTRIBUTING.md. An adopted cover's ARMED half
  is promoted into `bridge-lockdown.json` at the first real engage, so a
  disconnect (`reload`'s slow path is stop + start) cannot disarm the switch;
  only `turn_lockdown_off` clears it. The escape from a stranded
  cover (`failclosed::release_all`) is unconditional and knows nothing about cover
  state; its only condition is whether a session is running, and turning the
  kill switch off takes the same path. Who holds a cover has exactly one
  answer, derived once from `ProxyManager`'s single `posture` field
  (`Posture::cover_holder`); no site recomputes it from session state. →
  [CONTRIBUTING.md#fail-closed-cover](CONTRIBUTING.md#fail-closed-cover)
- **Server-address redaction.** The configured address — hostname, resolved IP,
  every textual form — is replaced by a `<server:XXXXXXXX>` token before it
  reaches a log, the dev console, a toast, or the support bundle. A byte-level
  `RedactingWriter` under the **one** log-file writer (plus the three console
  writers) provides coverage, because the default filter is a global `info` and
  the set of crates that can write an address is not enumerable; a `Display`-less
  `ServerAddress` newtype provides prevention. Arming is last-wins, so the
  crash-recovery `<server:recovered>` token joins to the session token on the
  next connect. →
  [CONTRIBUTING.md#server-address-redaction](CONTRIBUTING.md#server-address-redaction)
- **Logging & plugin diagnostics.** Log destinations, the WebView2/console-relay
  tee, `HOLE_BRIDGE_LOG` directives, and the plugin tap. →
  [CONTRIBUTING.md#logging--diagnostics](CONTRIBUTING.md#logging--diagnostics)

## Invariants you must not break

- **UDP-proxy flows DROP, never bypass** — bypassing leaks the flow outside the
  encrypted tunnel.
  [→](CONTRIBUTING.md#udp-policy)
- **Bridge OS I/O goes through the `Proxy`/`Routing`/`Dns` traits**, including
  `Drop` cleanup — never the raw free functions (clippy-enforced).
  [→](CONTRIBUTING.md#bridge-test-isolation-contract)
- **Cooperative cancel tokens only** — no fresh `CancellationToken::new()` in
  `crates/bridge/src/` (clippy-enforced).
  [→](CONTRIBUTING.md#bridge-cancellation-contract)
- **Ephemeral ports via `bind_ephemeral`, never raw `free_port`** — the retry is
  unbounded by design, no budget (clippy-enforced).
  [→](CONTRIBUTING.md#port-allocation)
- **No sleeps / timeout-polls for synchronization** — use the codebase's
  rendezvous primitives; two narrow exception classes only.
  [→](CONTRIBUTING.md#test-invariants)
- **Tests use `#[skuld::test]`** with `register!()` per binary; install per-test
  subscribers via `set_default_in_current_thread` and never
  `tracing_subscriber::fmt().init()` (clippy-enforced).
  [→](CONTRIBUTING.md#test-invariants)
- **PII redaction** — errors carrying filesystem paths or other PII must be
  redacted before reaching any log, toast, or bundle; a path's detail still
  lands in `gui.log`, but the server address never does.
  [→](CONTRIBUTING.md#logging--diagnostics)
- **The server address is never logged** — no `Display` on `ServerAddress`
  (compiler-enforced), `.expose()` is its only exit, and every `Serialize` type
  transitively holding one needs its own `Dump` impl.
  [→](CONTRIBUTING.md#server-address-redaction)

## macOS CI is the scarce resource

~9 darwin jobs per PR against a small shared pool; the Windows and Linux legs finish long
before them. Queue depth scales with the number of concurrent branches, not their size. Land
what is open before starting more.

## Pointers

- Product, install, user-facing CLI, distributions → [README.md](README.md)
- Build, dev, test, coding rules, dev/admin CLI →
  [CONTRIBUTING.md](CONTRIBUTING.md)
  ([build](CONTRIBUTING.md#build) ·
  [development](CONTRIBUTING.md#development) ·
  [testing](CONTRIBUTING.md#testing) ·
  [releases](CONTRIBUTING.md#releases))
- Release ops (rollback, minisign key rotation) →
  [RELEASE-OPS.md](RELEASE-OPS.md)
