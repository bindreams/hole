# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin
support (served by the bundled first-party `ex-ray` binary). A single Rust binary
is both the unprivileged Tauri GUI (no args) and the privileged bridge
(`hole bridge run`, root/SYSTEM).

This file is the agent-facing architecture map. Product and install live in
[README.md](README.md); the full contributor reference — build, dev, test, and
every rule below in detail — lives in [CONTRIBUTING.md](CONTRIBUTING.md) and, for
build, development and testing, [docs/contributing/](docs/contributing/index.md). Read
them before editing; the sections linked below are the authoritative source.

**IMPORTANT:** NEVER PIPE TESTS TO `tail`! ALWAYS SET A TIMEOUT FOR THE SHELL COMMAND! Tests are known to hang, you WILL get stuck and WILL not have information to debug why if you tail.

## Architecture map

- **Single binary, two modes.** GUI (system tray, settings, config) and bridge
  (TUN, routing, shadowsocks-service) selected by CLI args; they speak HTTP/1.1
  REST (JSON) over an AF_UNIX socket on both platforms (Windows via `socket2`). →
  [docs/contributing/architecture/overview.md](docs/contributing/architecture/overview.md)
- **Single-instance GUI.** Single-instance via `tauri-plugin-single-instance`
  (`com.hole.app`); CLI subcommands bypass the lock. →
  [CONTRIBUTING.md#single-instance-enforcement](CONTRIBUTING.md#single-instance-enforcement)
- **UDP-drop policy.** Hole is a VPN: UDP flows that resolve to `Proxy` on a
  TCP-only plugin are **dropped, not bypassed** (bypassing would leak outside the
  tunnel); enforced structurally in `HoleRouter::resolve_endpoint`. UDP/53 is
  diverted to the DNS forwarder before the cascade. →
  [docs/contributing/architecture/datapath.md#udp-is-dropped-never-bypassed](docs/contributing/architecture/datapath.md#udp-is-dropped-never-bypassed)
- **TUN naming.** The running TUN device's name has exactly one source of
  truth at runtime, `tun_engine::device::TunIdentity`: Windows names it the
  fixed constant `WINDOWS_TUN_ALIAS` (`"hole-tun"`), macOS's kernel assigns
  it (`TunName::KernelAssigned`, a `utunN`) and every macOS consumer —
  DNS apply, the lockdown TUN permit — reads it back rather than assuming
  a literal. →
  [docs/contributing/architecture/tun-device.md#the-device-name-has-one-source](docs/contributing/architecture/tun-device.md#the-device-name-has-one-source)
- **IPv6 in the tunnel.** IPv6 is meant to traverse the tunnel: the `::/1` +
  `8000::/1` split pair captures it, and the TUN interface holds
  `TUN_SUBNET6` on the **OS interface** as well as in smoltcp, so a host with
  no global IPv6 still has a source address for those routes. The ULA's
  global ID is generated per RFC 4193, not `fd00::`. Windows waits for the
  interface's IPv6 half itself (`tun` waits only for the IPv4 one) and
  creates the address `IpDadStatePreferred`; assignment is fatal on Windows,
  warn-only on macOS, and `Dispatcher::ipv6_assigned()` is what route-install
  fatality must read. →
  [docs/contributing/architecture/tun-device.md#ipv6-in-the-tunnel](docs/contributing/architecture/tun-device.md#ipv6-in-the-tunnel)
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
  [docs/contributing/architecture/tcp-admission.md](docs/contributing/architecture/tcp-admission.md)
- **DNS forwarder.** Carries DNS over the TCP tunnel for TCP-only plugins; OS
  resolution is diverted to the configured resolver IPs on the TUN interface
  only, which route into it and are intercepted by the in-TUN
  `LocalDnsEndpoint`; a start-time forwarder self-test gates the whole
  connection. The apply mechanism itself is platform-specific — Windows sets
  the adapter's resolvers directly; macOS's `networksetup` has no interface
  identifier, so it instead publishes a synthetic, session-scoped
  `SCDynamicStore` supplemental-resolver key (`tun_engine::dns_steer`) — both
  fail-fatal, enforced by the sealed `DnsPhase`/`LeakBearing`/`Cosmetic`
  split. →
  [docs/contributing/architecture/dns-forwarder.md](docs/contributing/architecture/dns-forwarder.md)
- **DNS-egress confinement (Windows).** Hole never writes DNS settings to an
  adapter it doesn't own; on Windows, egress on UDP+TCP port 53 is also
  confined to `hole-tun` by a WFP filter set in a **process-scoped dynamic**
  FWPM session — the opposite lifetime from the fail-closed covers below, and
  deliberately so: it needs no crash-recovery state because it dies with the
  bridge. →
  [docs/contributing/architecture/dns-forwarder.md#how-the-operating-system-reaches-it](docs/contributing/architecture/dns-forwarder.md#how-the-operating-system-reaches-it)
- **Listener selection invariants.** `build_ss_config` rejects
  `TunnelRequiresSocks5` (full + HTTP-only) / `NoListenersEnabled`
  (socks-only + none) / `DuplicateListenerPort` up-front; full mode with
  no listeners is the pure-VPN start (internal SOCKS5 data plane on an
  ephemeral port). →
  [docs/contributing/architecture/datapath.md#the-listener-the-datapath-dials](docs/contributing/architecture/datapath.md#the-listener-the-datapath-dials)
- **Bridge trait seam.** All OS-mutating bridge I/O routes through the `Proxy`,
  `Routing`, and `Dns` traits so tests can mock it. →
  [CONTRIBUTING.md#bridge-test-isolation-contract](CONTRIBUTING.md#bridge-test-isolation-contract)
- **Datapath test seams.** The router seam splits the drop path off `Endpoint`
  so the cascade's consequence is assertable without an engine; the datapath
  seam generifies `Engine`/`Driver` over their packet I/O so the TUN loop is
  drivable from memory. →
  [docs/contributing/testing.md#which-lane-proves-what](docs/contributing/testing.md#which-lane-proves-what)
- **Plugin binaries.** The bridge runs only the plugins Hole ships, found in the one folder its
  `PluginSource` names, never `PATH`. On macOS `hole` carries both plugins and the service makes a root-owned
  folder (`/Library/Application Support/Hole`) hold exactly those at every start, before it serves; the app
  bundle ships none. A layout stamp this release cannot read is never repaired over; plugins are run from that
  folder only once the start's repair left it holding what `hole` carries. →
  [docs/contributing/architecture/plugin-binaries.md](docs/contributing/architecture/plugin-binaries.md)
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
  crash marker; the next start of the same kind sweeps it. On macOS
  `on_crash` terminates the process instead of returning — see crash.rs's
  module doc before touching either half. →
  [CONTRIBUTING.md#native-crash-observability-tombstone](CONTRIBUTING.md#native-crash-observability-tombstone)
- **Route ownership.** Teardown and recovery delete only the `RouteId`s
  `bridge-routes.json` records as installed. On macOS no delete-side qualifier
  can substitute: `RTM_DELETE` matches on destination + netmask only, and the
  one key discriminator (`-ifscope`) would hide the splits from unbound
  traffic. Windows' bypass delete can additionally be scoped by the
  install-time gateway, carried in `original_gateway`. Leftovers a sweep
  can't confirm gone are carried forward in `stale`, never dropped. →
  [CONTRIBUTING.md#route-ownership](CONTRIBUTING.md#route-ownership)
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
  [docs/contributing/architecture/galoshes-transport.md#telling-that-the-transport-is-dead](docs/contributing/architecture/galoshes-transport.md#telling-that-the-transport-is-dead)
- **galoshes mux default.** galoshes appends `mux=0` for its embedded ex-ray —
  its yamux already collapsed every stream onto one connection, so Mux.Cool is
  pure overhead. ex-ray is first-wins on duplicate SIP003 keys, so an operator's
  earlier `mux=` overrides it. `mux` also picks the server's dokodemo
  destination, so a `mux=0` client cannot reach a `mux=1` server. →
  [docs/contributing/architecture/galoshes-transport.md#the-mux-default](docs/contributing/architecture/galoshes-transport.md#the-mux-default)
- **Fail-closed covers.** The standing lockdown cover (the opt-in kill switch) outlives
  the bridge: the bridge **disarms-not-drops** it and the new bridge adopts it. Release
  decisions come from the persisted `Target` and the measured `CoverPresence`;
  `Routing::release_all_covers` is unconditional; mutators take `&CoverLock`. →
  [docs/contributing/architecture/kill-switch.md](docs/contributing/architecture/kill-switch.md)
- **Server-address redaction.** The configured address — hostname, resolved IP,
  every textual form — is replaced by a `<server:XXXXXXXX>` token before it
  reaches a log, the dev console, a toast, or the support bundle. A byte-level
  `RedactingWriter` under the **one** log-file writer (plus the three console
  writers) provides coverage, because the default filter is a global `info` and
  the set of crates that can write an address is not enumerable; a `Display`-less
  `ServerAddress` newtype provides prevention. Arming is last-wins, so the
  crash-recovery `<server:recovered>` token joins to the session token on the
  next connect. The password has a matching `Display`-less `Password` newtype
  and its own asymmetric limits. →
  [CONTRIBUTING.md#server-address-redaction](CONTRIBUTING.md#server-address-redaction)
- **File lock.** Cross-process file locks use `file_lock::Exclusive`, which
  never re-permissions a file it did not create or the expected owner does not
  already own (it replaces a leftover, refuses a symlink or other non-regular
  file), because the state directory may belong to the interactive user. For the
  same reason the directory is opened once through handles, a link followed only
  under the ownership-transition rule (`util::dir::Dir`), and the lock and the
  state-file writers listed in the section below go through that handle, never
  back through the path. →
  [CONTRIBUTING.md#file-lock](CONTRIBUTING.md#file-lock)
- **Logging & plugin diagnostics.** Log destinations, the WebView2/console-relay
  tee, `HOLE_BRIDGE_LOG` directives, and the plugin tap. →
  [CONTRIBUTING.md#logging--diagnostics](CONTRIBUTING.md#logging--diagnostics)

## Invariants you must not break

- **UDP-proxy flows DROP, never bypass** — bypassing leaks the flow outside the
  encrypted tunnel.
  [→](docs/contributing/architecture/datapath.md#udp-is-dropped-never-bypassed)
- **Bridge OS I/O goes through the `Proxy`/`Routing`/`Dns` traits**, including
  `Drop` cleanup — never the raw free functions (clippy-enforced).
  [→](CONTRIBUTING.md#bridge-test-isolation-contract)
- **Cooperative cancel tokens only** — no fresh `CancellationToken::new()` in
  `crates/bridge/src/` (clippy-enforced).
  [→](CONTRIBUTING.md#bridge-cancellation-contract)
- **Delete only recorded routes** — a route whose install failed belongs to
  whoever holds it now; deleting it takes down another VPN's tunnel.
  [→](CONTRIBUTING.md#route-ownership)
- **Ephemeral ports via `bind_ephemeral`, never raw `free_port`** — the retry is
  unbounded by design, no budget (clippy-enforced).
  [→](CONTRIBUTING.md#port-allocation)
- **No sleeps / timeout-polls for synchronization** — use the codebase's
  rendezvous primitives; three narrow exception classes only.
  [→](docs/contributing/testing.md#no-synchronization-by-elapsed-time)
- **Tests use `#[skuld::test]`** with `register!()` per binary; install per-test
  subscribers via `set_default_in_current_thread` and never
  `tracing_subscriber::fmt().init()` (clippy-enforced).
  [→](docs/contributing/testing.md#rules-every-test-follows)
- **PII redaction** — errors carrying filesystem paths or other PII must be
  redacted before reaching any log, toast, or bundle; a path's detail still
  lands in `gui.log`, but the server address never does.
  [→](CONTRIBUTING.md#logging--diagnostics)
- **Per-variant policy lives on the type, never at a call site** — a decision
  keyed to an enum variant belongs in ONE exhaustive match on that type
  (`SessionEvent::preserves_death_reason`, `CoverPresence::is_present`,
  `StaleKeyPolicy::refuses_a_stale_key`, `Coverage::plan`), and
  two variants are never grouped because they happen to share a consequence.
  Grouping by consequence is what let `ProcessExiting` inherit an answer chosen
  for a cutover; re-deriving the rule at each site is what let `== Live` drop
  the two uncertain probe results. This exact shape produced four separate bugs
  in one change — each a contract stated in prose at the definition site and
  violated at a call site far away — so it is test-enforced
  (`session_event_policy_lives_on_the_type_not_at_call_sites`,
  `cover_presence_is_never_compared_against_a_variant`,
  `stale_key_policy_lives_on_the_type_not_at_call_sites`,
  `coverage_policy_lives_on_the_type_not_at_call_sites`). Prefer removing the
  hazard outright over guarding it: `CoverGuard::disarm` had a "call only
  before process exit" precondition that no test could enforce, and closing the
  handle it leaked deleted the rule instead of policing it.
  [→](docs/contributing/architecture/kill-switch.md#the-decisions)
- **Privileged code in a folder a user may own walks through handles** —
  `util::dir::Dir` (or `ReadDir`, for code that only reads), never a path call.
  The walk gets the path as given: never `canonicalize` it first, which follows
  every link with no rule. A link is followed only if the walk never
  moves from a folder an unprivileged user owns into one somebody else owns (a
  system-owned link stays trusted, a user's link to their own folder is followed,
  a user's link into the system's or another account's is refused); the final name
  is never followed; mode and owner are set through the open file; nothing touches
  a path after a rename.
  [→](CONTRIBUTING.md#privileged-code-in-folders-a-user-may-own)
- **Hole never writes the server address or the password** — no `Display` on
  `ServerAddress` or `Password` (compiler-enforced), `.expose()` is the only
  exit from either, and every `Serialize` type transitively holding one needs
  its own `Dump` impl.
  [→](CONTRIBUTING.md#server-address-redaction)

## macOS CI is the scarce resource

2 darwin jobs per PR (one per arch) against a small shared pool; the Windows and Linux legs finish long
before them. Queue depth scales with the number of concurrent branches, not their size. Land
what is open before starting more.

## Pointers

- Product, install → [README.md](README.md)
- User-facing CLI, distributions → [docs/reference/cli.md](docs/reference/cli.md),
  [docs/reference/distributions.md](docs/reference/distributions.md)
- Setup, build, development, testing, CI, commit messages, dev/admin CLI →
  [docs/contributing/](docs/contributing/index.md)
  ([setup](docs/contributing/setup.md) ·
  [build](docs/contributing/build.md) ·
  [development](docs/contributing/development.md) ·
  [testing](docs/contributing/testing.md) ·
  [CI](docs/contributing/ci.md) ·
  [commit messages](docs/contributing/commit-messages.md) ·
  [dev/admin CLI](docs/contributing/bridge-cli.md))
- Architecture, releases → [CONTRIBUTING.md](CONTRIBUTING.md)
  ([releases](CONTRIBUTING.md#releases))
- Release ops (rollback, minisign key rotation) →
  [RELEASE-OPS.md](RELEASE-OPS.md)
