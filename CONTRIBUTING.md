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

### TUN naming

The running TUN device's name has exactly one source of truth at runtime:
`tun_engine::device::TunIdentity`, read back from the device
`Dispatcher::new` just opened. No other site may assume or hardcode a value —

- **Windows**: `TunName::Requested(WINDOWS_TUN_ALIAS)` —
  `WINDOWS_TUN_ALIAS` is the fixed constant `"hole-tun"`
  (`crates/bridge/src/proxy/config.rs`), so wintun creates an adapter under
  that literal name every session. `TunIdentity` still exists on this
  platform; reading it back is just redundant with the constant every other
  caller already has.
- **macOS**: `TunName::KernelAssigned` — the `tun` crate opens the first free
  `/dev/tunN` and the kernel assigns the interface name (`utunN`); the
  specific `N` is neither chosen nor predictable. `identity().alias()` is the
  only way to learn which interface a given `Dispatcher::new` call opened,
  and every macOS consumer that used to assume a fixed name — DNS apply
  (`SystemDns::apply`, see [DNS forwarder](#dns-forwarder)) and the lockdown
  TUN-interface permit (see [the kill switch](docs/contributing/architecture/kill-switch.md)) — now takes a
  `TunIdentity` instead of a string literal.

### IPv6 in the tunnel

IPv6 traverses the tunnel. The `::/1` + `8000::/1` split pair captures it,
[`Socks5Endpoint`](crates/bridge/src/endpoint/socks5.rs) carries any v6
destination, and `Ipv6BypassUnreachable` is a **bypass**-only drop — a `Proxy`
decision on a v6 flow goes to the proxy unconditionally.

The TUN interface (see [TUN naming](#tun-naming)) holds `TUN_SUBNET6` twice:
on the OS interface **and** in smoltcp's address list. Without the OS half a
host with no global IPv6 anywhere has no source address for the `/1` routes,
and every IPv6 flow fails instead of tunnelling. (A dual-stack host sources
from the upstream adapter, which is why the gap is invisible there.)

The ULA's 40-bit global ID is pseudo-randomly generated per RFC 4193 §3.2.2,
not `fd00::`. That prefix is what WireGuard examples, Docker, Proxmox and NAS
defaults hand out, and Hole's becomes a real on-link route on the TUN
interface — a collision would let the tunnel swallow the user's own ULA
network.

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
tested. The macOS TUN-naming defect that used to block Full mode from
starting at all is fixed, and real tests now exercise
this path there (`crates/tun-engine/src/dns_steer/privileged_tests.rs`,
`crates/bridge/src/proxy_manager_macos_full_tunnel_privileged_tests.rs`) —
but neither asserts anything about IPv6 assignment specifically, so the
macOS IPv6 path's first real execution is still this PR's own darwin TUN CI
lane. Whether a failure there should become fatal, matching Windows, is a
decision still pending that run's result. The tolerate predicate is **not**
`ipv6_available`, which
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
  the TUN interface (see [TUN naming](#tun-naming)) via the `0.0.0.0/1` split
  route and are diverted to this endpoint → `DnsForwarder` over the tunnel.
  OS TCP/53 to those IPs falls through the proxy cascade to the real
  resolver's `:53` over the tunnel.

- [`Socks5Connector`](crates/bridge/src/dns/socks5_connector.rs) — routes the
  forwarder's upstream through the SS SOCKS5 listener so user `Block` rules can't
  strand the resolver (TCP via `tokio-socks`; UDP via hand-rolled UDP ASSOCIATE,
  RFC 1928).

- [`SystemDns`](crates/bridge/src/dns/system.rs) — Hole writes DNS to no
  adapter or service but the one belonging to the tunnel it created, and the
  mechanism diverges by platform (bindreams/hole#868):

  - **Windows**: DNS is set directly on the TUN adapter (`hole-tun`); v4 and
    v6 families are set separately, each from its own configured resolvers,
    and a family with none is left untouched. Egress on UDP+TCP port 53 is
    additionally confined to that adapter by a WFP filter set
    ([`tun_engine::dns_confine`](crates/tun-engine/src/dns_confine.rs)) — a
    process-scoped dynamic FWPM session, not a persistent one, so it dies
    with the bridge and needs no crash-recovery state.
  - **macOS**: `networksetup`'s DNS subcommands take a network-*service*
    name (e.g. "Wi-Fi"), never an interface name — passing the TUN
    interface's name here was a guaranteed no-op,
    since there is no service by that name to configure. Instead,
    `apply_macos` publishes the (routed-family-filtered, see below)
    resolvers as a supplemental resolver at a synthetic, session-scoped
    `SCDynamicStore` key
    ([`tun_engine::dns_steer`](crates/tun-engine/src/dns_steer.rs)): a
    dictionary naming a
    nonexistent service (`{ ServerAddresses, SupplementalMatchDomains: [""], SearchOrder: 100000 }`) that configd merges as a resolver for
    every query, ranked above its own default. The store session opens with
    `session_keys(true)`, so the key is scoped to the bridge's own
    dynamic-store session and configd discards it on session close —
    including on `SIGKILL` — the macOS analogue of the Windows WFP
    session's process-scoped lifetime. Nothing of the user's own DNS
    configuration is ever read or captured, so there is nothing to restore
    beyond removing that one key. `advertise_ips` is filtered to the
    address families the tunnel is actually carrying (`RoutedFamilies`,
    read once from the routes `Routing::install` just landed — never from
    the TUN's own IPv6 read-back or the upstream gateway's IPv6
    availability, which answer a different question;
    plan, decision D4); an empty filtered list is refused rather than
    silently advertising nothing.
  - **Both platforms are fail-fatal**: a failure to confine/steer aborts the whole start rather than leaving a session the UI reports as connected with a silent DNS leak. `crate::dns::system::phase`'s sealed
    `DnsPhase`/`LeakBearing`/`Cosmetic` split enforces this in the type
    system — mirroring `tun_engine::routing`'s `FatalPhase`/`BestEffortPhase`
    — so a backend call is generic over which phase runs it, and
    warn-and-continue for a leak-bearing call requires choosing `Cosmetic`
    at the call site: a visible, reviewable act, not an available idiom.
    Only the post-apply resolver-cache flush is `Cosmetic`.

  There is nothing to capture and nothing to restore on either platform's
  fresh-apply path; see [Crash recovery](#crash-recovery) for the one
  remaining, read-only use of `bridge-dns.json` (undoing an older build's
  own upstream-adapter DNS rewrite after a crash). Residuals, disclosed
  rather than silently accepted: DNS-over-HTTPS to an on-link resolver is
  indistinguishable from ordinary HTTPS to that host on either platform, and
  on Windows DNS-over-TLS (port 853) is not confined — only port 53 is
  (macOS's steering key has no per-port egress filter to evade in the first
  place; it only supplies an additional resolver).

`DnsConfig::default()` is `enabled: true`, `Https`, `[1.1.1.1, 1.0.0.1]` — and
`AppConfig` is `#[serde(default)]`, so the forwarder enables silently on
upgrade.

**Start-time gate (load-bearing).** A forwarder self-test runs inside
[`start_inner`](crates/bridge/src/proxy_manager.rs) **before**
`Dispatcher::new` / `routing.install` / `apply_dns_settings`; on failure it
returns whichever `ProxyError` the run's evidence supports — `NoTunnelConnection`
(every connect failed outright), `TunnelSetupIncomplete` (one was still
outstanding when its budget fired), `TunnelSilent`, or the generic
`ForwarderSelfTestFailed` — and the session's teardown runs without touching routes,
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

### System tools (absolute paths)

The bridge runs as root/SYSTEM, so it never spawns an OS tool by bare name: a bare
name is resolved through `PATH` (macOS) or, on Windows, through the application
directory and the *current directory* before System32
([`CreateProcess`, "lpApplicationName"](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)),
and a lower-privileged user can influence all of those. Every OS tool is a
[`util::system_tool::SystemTool`](crates/util/src/system_tool.rs) variant
(`route`, `ifconfig`, `pfctl`, `networksetup`, `launchctl`, `dseditgroup`, … on
macOS; `route`, `netsh`, `net`, `pnputil` on Windows), and
`SystemTool::command()` is the only way to build its `Command`: the program is an
absolute path, on Windows under the directory `GetSystemDirectoryW` reports. A
root PowerShell is deliberately not a `SystemTool` variant:
`util::system_tool::SystemPowershell::command(script)` is its only constructor, so
a PowerShell without the module pin below cannot be written. If
that call fails, `path()`/`command()` return the error and the caller carries it
as its spawn error (`CommandFailure::Spawn`, or the `io::Error` it already
returns), so a best-effort teardown logs it and goes on. The root PowerShell
child gets `PSModulePath` set to the system module directory alone, both in its
environment and by an assignment `SystemPowershell::command` prepends to every script
(PowerShell rebuilds an inherited value equal to the machine's, so the
environment alone does not hold): its default begins with the invoking user's
writable `Documents\WindowsPowerShell\Modules`, and cmdlet autoload would run a
planted module as SYSTEM/admin.
On Windows both constructors also set `CREATE_NO_WINDOW`: the release GUI and its
elevated children have no console, so a console tool started without it would open
a visible console window.
`RouteCommand`/`SetupCommand` carry a `SystemTool` plus the arguments, not an argv
whose first element is a program name. Compile-time enforcement is
[`clippy.toml`](clippy.toml): `std::process::Command::new`,
`tokio::process::Command::new` and every `cosca` command constructor
(`Command::new`, `run`, `run_line`, sync and `tokio`) are disallowed, and so are
the `cosca::Command` methods that name its program (`executable`, `raw_executable`,
`arg`, `args`, `commandline`), because `Command: Default` is a constructor no path can ban. A
spawn that is not an OS tool (Hole's own executable, the unprivileged GUI's
`osascript`, the developer's `sudo`, `xtask`/`dev-console` tooling, test
harnesses) takes an `#[allow]` with its reason; test files and tooling files take
a module-level one. Bridge production code never does: an inner
`#![allow(clippy::disallowed_methods)]` switches the process ban off for the whole
module, so a spawn there takes an item-level allow. A library the privileged
binary must not call (`handle-holders`' `lsof`) is a `[dev-dependencies]` entry
of the bridge, not a `[dependencies]` one. Test and tooling code that runs under `sudo`/an admin shell
in CI (the privileged lanes) is attended and keeps bare names.

The plugin spawn follows the same rule by a different mechanism: the privileged
bridge runs only the plugins Hole ships (`hole_common::plugin::KNOWN_PLUGINS`),
found in the one folder its `PluginSource` names
([where each platform gets them](#plugin-binaries-where-each-platform-gets-them)).
`PluginSource::resolve` is the only production producer of a `BundledPlugin`
(a shipped plugin's descriptor bound to the absolute path of its binary),
and `start_plugin_chain` takes only that, so a bare name for
`garter::BinaryPlugin` to look up on `PATH` cannot be written on the bridge's path.
A test stages an install with `PluginSource::build_dir(Some(exe))`. It is the one gate for "may this plugin run", asked first in
`start_cancellable` and `run_server_test`, before any DoH bootstrap, cover or
dial: an unbundled name or a missing binary is refused with nothing touched and
reaches the user as the usual start error. Import already rejects such plugins, so
only a hand-edited or old config, or a direct IPC call, gets here. Third-party
SIP003 plugins are not supported.

`Dns` has a two-layer seam — outer (`MockDns` at `ProxyManager::new_with_dns`)
and inner per-platform backend (`MockBackend` at `SystemDns::new_with_backend`).
Both are necessary: an outer-only mock can pass while `SystemDns::apply` ignores
cancel internally.

### Plugin binaries: where each platform gets them

The privileged bridge runs only the plugins Hole ships (`hole_common::plugin::KNOWN_PLUGINS`), found in one
folder its [`PluginSource`](crates/bridge/src/proxy/plugin_source.rs) names. `PluginSource` is the one owner of
"where are the plugins" for every platform and mode; a caller asks it to `resolve` a name and gets a `BundledPlugin`
(a shipped plugin's descriptor bound to the absolute path of its binary) or a typed error. Per-variant behaviour is a
method of the type, one exhaustive match each; no other file names a variant except the per-platform constructors
(`plugin_source_policy_lives_on_the_type_not_at_call_sites`).

| Platform and mode                       | `PluginSource`    | Where the plugins are                                                                     | Who writes them                                    | How they are verified                                                                                                                     | How they are repaired                    |
| --------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| macOS service                           | `Managed`         | `/Library/Application Support/Hole` (root-owned, 0755), never derived from the executable | the service, from the bytes embedded in `hole`     | SHA-256 of each file, owner, mode and link count, read through the open handle, against the hashes compiled into `hole`; the layout stamp | at every service start, before it serves |
| Windows service                         | `InstallDir`      | beside the installed bridge executable                                                    | the installer                                      | the installer's (Program Files is not user-writable)                                                                                      | by reinstalling                          |
| foreground, any platform                | `BuildDir`        | beside the bridge executable (a staged build directory)                                   | `cargo xtask stage`                                | none                                                                                                                                      | `cargo xtask stage`                      |
| foreground `--plugin-dir DIR` (Windows) | `Explicit`        | `DIR`, read, never written                                                                | the admin                                          | none                                                                                                                                      | the admin                                |
| foreground `--plugin-dir DIR` (macOS)   | `ExplicitStamped` | `DIR`, read, never written; its layout stamp must be current                              | the admin (the service wrote the installed folder) | the layout stamp                                                                                                                          | none                                     |

On macOS `hole` carries both plugin binaries (`crates/hole/build/embed_plugins.rs` reads
`.cache/<name>/<name>-<triple>`, copies those bytes to `$OUT_DIR/<name>` and hashes the same read, and writes
`$OUT_DIR/embedded_plugins.rs`; `src/embedded_plugins.rs` is in the binary, not the bridge library) and the app bundle ships none of them (`crates/hole/tauri.macos.conf.json` removes
`externalBin`). A dev or test build with stub sidecars embeds empty payloads, which repair never converges toward and never
removes anything for; a release build with an empty payload fails in `embed_plugins.rs`, and the DMG test
`test_hole_carries_the_plugin_bytes` still compares the bytes with `.cache`. The name sets are in [`bindir.rs`](xtask-lib/src/bindir.rs): `embedded_plugin_names` and `bundle_payload_names`
state the platform difference once.

Repair (`crates/bridge/src/plugin_repair.rs`) is a pure `decide_repair(Survey, carried) -> RepairPlan` and a thin
unix `apply`. A repair converges after a crash at any step: each file is a staged temp renamed over its name
(`util::dir::Dir`), and the stamp is stored last, and only when every step before it succeeded. A folder that is not sound (a link or file at its name, another
owner or group, a mode that group or others can write) is not trusted, and the stamp inside it is never read: it is rebuilt. A sound
folder with another mode is set to 0755. Unexpected names are removed, folders with everything below them
(`Dir::remove_tree`); a name that differs from a carried name or the stamp only in case is the same entry when the volume
says it is the same file (case-insensitive APFS), and a stray otherwise. A repair whose steps all succeeded is judged by
surveying the folder again, so a step the volume did not carry out as asked leaves the repair `Degraded`. The repair runs in `platform::macos::run` after the IPC bind and the liveness lock and before DNS and
route recovery, because repairs come first (the Windows `registration::run_startup_steps` does the same); its
duration is logged at `info`. It never stops the start, and the one bridge that holds the liveness lock is the only
repairer. How the start prepared is recorded as a `Prepared` (the repair's `RepairOutcome` and whether the runtime folder
was made) in a `RepairVerdict` that the `Managed` source holds: a plugin resolves only when the repair of this start
`Converged` or `Repaired` the folder and the runtime folder exists. A start whose repair ended `Degraded` (a failed write,
an unreadable folder, a build with no payload), whose runtime folder could not be made, or that has not prepared yet
refuses every plugin start and server test, naming the cause (the runtime folder's failure has its own error, naming
`/var/run/hole`), and the stamp of a folder no repair vouched for is never read. Both failures are logged even when the
folder's outcome is the one the error names.

The layout stamp is `layout.json` (`{"version": 1}`), a `util::versioned_file` OS record. A stamp this release cannot
read (newer, corrupt, or unreadable) is never replaced or removed: repair changes nothing, and every plugin start and
server test refuses with an error naming the stamp. The remedy has no in-app escape: stop Hole and move the named
file aside. The connect gate that would refuse before anything is mutated is not built yet (1096-b); until then the
refusal happens when the plugin is resolved.

`hole bridge run --plugin-dir DIR` runs a foreground bridge from `DIR`, which must be a directory (made absolute,
never canonicalized). The bridge runs, with its own privileges, the plugin binaries in the named folder. On macOS it
checks only that `DIR` is a Hole plugin folder (a current layout stamp, which tells a wrong folder from a right one), not
who can write it: name only a folder only root can write, such as `/Library/Application Support/Hole`. The stamp is read
under the bridge's vouched-read rules (`util::dir::ReadDir`), so name the real folder, not a user's link to a folder
somebody else owns, and a stamp another user owns is refused too: the error says the stamp was refused, and why. A
folder that is gone after the bridge started is reported as not found. A plugin that
unpacks itself (galoshes) uses the environment the bridge was started with, not `/var/run/hole`. `--service` does not
take it. The foreground default (`BuildDir`) likewise runs whatever sits beside the executable.

A plugin that extracts itself at run time (galoshes unpacks its embedded ex-ray) is given a root-only folder:
`PluginSource::runtime_dir` is `/var/run/hole` for `Managed` and none elsewhere, and the plugin spawn sets
`XDG_RUNTIME_DIR` to it, whether or not launchd supplies a `HOME`. Uninstall removes it with the plugin folder and the registration, attempting
every removal and naming each that failed, so a folder that cannot be removed never keeps the registration from going.
`bridge uninstall` is gated on `os::has_anything_to_uninstall` (the plist, the helper or either folder is still there),
not on the registration alone, so a retry reaches the leftovers of an uninstall whose folder removal failed after the plist
went; `is_installed` (the status readout) stays the plist.

Not yet measured, and measurable only on CI: that the linker-signed plugin bytes run as root under launchd on both
architectures (the `dmg-installer` install-and-connect e2e, which has to pass on this change before the claim holds);
`/Library/Application Support`'s owner and mode on a stock macOS; the duration of a repair on the first start after an
install.

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

### Windows service stop reporting

`run_service` reports `SERVICE_STOP_PENDING` with one checkpoint per teardown
phase ([`StopPhase`](crates/bridge/src/service_stop.rs)), and `Stopped` only
after the last. The proxy-side phases are entered by
`ProxyManager::stop_with_progress`, each just before the work it names and only
when that work exists in the session. The first report is made by the control
handler the moment Stop/Shutdown arrives, before the main task is signalled, so
a stop that lands during a startup await does not read as `Running`. A later
phase is reported when the previous one finishes and nothing reports on a timer,
so a wedged phase freezes the checkpoint where `sc queryex` and the
cutover/uninstall `NotifyServiceStatusChange` waiters can see it.

Each phase entered is logged at info (`service stop phase`, with its
checkpoint) to `bridge.log`, never by the control handler: it does no log I/O of
its own (a panic still passes through the process-wide panic hook; see the
`service_stop.rs` module doc) and catches a panicking report, since an unwinding
panic aborts the service. The shutdown forwarder task logs the first phase's
hand-off the moment it wakes from the shutdown signal, so a stop wedged before
its first entry still leaves a line. On an msiexec timeout the CI
diagnostics print `sc queryex HoleBridge` and those lines. A path that fails
before teardown (bind failure) skips the proxy and ETW phases. Only Windows CI
exercises the SCM side.

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
`PluginDescriptor::alloc_protocols` sizes SS_LOCAL per plugin (galoshes
TCP+UDP, everything else TCP). Where the reservation happens before the
consumer is known, reserve the union over the possible consumers:
`plugin_e2e::ports::reserve_ss_local` is generic over which client plugin will
run, and that set includes galoshes, so it always reserves TCP+UDP —
over-reserving UDP for a TCP-only plugin costs a retry, under-reserving it for
galoshes costs a race. `garter::ChainRunner` picks each intermediate port
itself, uncapped, one hop at a time just before that hop starts, and verifies
TCP only: every in-repo hop that is not the public one binds TCP alone. A hop that loses that port to another process reports a typed
`BindConflict` and is run again alone on a fresh pick, uncapped; a hop that does
not speak sitrep (`ReadinessMode::Probe`) cannot, so its lost port is a failed
start and is not restarted ([`ReadinessMode::Probe`](crates/garter/src/binary.rs)).

### File lock

A cross-process lock on a file goes through
[`file_lock::Exclusive`](crates/file-lock/src/exclusive.rs) (`flock` /
`LockFileEx`), not a second implementation. The bridge's liveness lock uses it. A
state file takes no lock file: `VersionedFile` serializes in-process callers on a
per-path lock and `BridgeLiveness` excludes other processes.

The lock file sits in a state directory the interactive user may own, so
whatever is at its name is attacker-chosen and the name can change between any
two calls that take it. `Exclusive` therefore decides on what an attacker cannot
change once the file is open: it creates with `O_EXCL` first (a file it creates is
its own), reopens an existing name without `O_CREAT`, and on unix with an `owner`
keeps only a file that `owner` already owns. A file owned by this process
instead (a leftover from a run that died before its `fchown`, or an unrelated
file linked at the name) is locked, has its *name* unlinked and is replaced by a
fresh file, so it is never modified and the owner is never locked out. `fchmod`
and `fchown` touch only a file the call created or one with a single name that
the owner owns; the owner's file with another name is locked as it is. The full
protocol and what it guarantees are in the
[module doc](crates/file-lock/src/exclusive.rs); Windows opens without
`FILE_SHARE_DELETE` so the name stays bound to the vetted file while the lock is
held.

The directory above the lock is as attacker-writable as the name (every
component under the user's profile is theirs to replace), so `Exclusive` opens it
first as a [`util::dir::Dir`](crates/util/src/dir.rs): one component at a
time, relative to the handle already held (`openat` with `O_NOFOLLOW` and
`mkdirat` on unix; `NtCreateFile` relative to the parent handle on Windows, which
opens a reparse point as itself so it can be judged). Every later step on the lock
file (the open, the name check, the unlink of a leftover) goes through that
handle. A path call would resolve the whole path again and follow whatever the
user swapped in.

- **Which links are followed.** Under the ownership-transition rule of
  [Privileged code in folders a user may own](#privileged-code-in-folders-a-user-may-own):
  a link the system owns (macOS's `/var`, `/tmp` and `/etc`, hence `temp_dir()`;
  Windows's `C:\Documents and Settings`) is followed, and so is a user's link to a
  folder that user owns (a `~/Library` moved to another disk); a user's link into
  a folder the system or another account owns is refused. Windows follows symlinks,
  junctions and mount points under the same rule and refuses any other reparse
  point. The refusal is a `Refused` that names the lock path and carries a
  `util::dir::Refusal`.
- **Ownership.** With an `owner`, the final directory must be owned by it or by
  this process (the second covers a directory a previous run created and died
  before handing over); any other owner is refused. Windows has no unix ids and
  does not check.
- **Search-only walk (unix).** Every component is opened for lookup only (Linux
  `O_PATH`, macOS `O_SEARCH`), which asks for search permission and not read, so a
  directory the caller can pass through but not list (`0o311`) is still on a usable
  path; only the final directory is reopened readable, through the handle in hand,
  for `fchown`, `fchmod` and `fsync`.
- **OS floor.** `openat`, `mkdirat`, `fstatat`, `unlinkat`, `renameat` (Linux
  2.6.39 for `O_PATH`, macOS 10.10) and `NtCreateFile` / `NtSetInformationFile` with a root
  directory (every NT version). Neither `openat2(RESOLVE_NO_SYMLINKS)` (Linux 5.6)
  nor `O_NOFOLLOW_ANY` (macOS 10.15) is used, so one code path serves every
  version and there is no fallback to path resolution. The Windows replace uses
  `FileRenameInformationEx` with POSIX semantics (Windows 10 1607, NTFS) and the
  plain replace where the volume rejects it.
- **Missing directories** above the file are created the same way, relative to
  their parent's handle, never by `create_dir_all` on a path.

A symlink (on Windows any reparse point), directory, socket or other non-regular
file at the name, a file owned by a third party, or a directory in the path that
`Dir` refuses, is **refused**: an `InvalidData` error holding a
`file_lock::Refused`. A second name for the lock file is not: the count can change
after it is read.

State-file writers use the same handle. Every state file is a
`util::versioned_file::VersionedFile` (`bridge-routes.json`, `bridge-target.json`,
`bridge-startup.json`, `bridge-plugins.json`, `bridge-dns.json`, the update marker
and the fail-closed files `bridge-failclosed.json`, `bridge-lockdown.json`,
`bridge-lockdown-pf.json`, `bridge-boottime.json`), and its three calls
(`observe`, `update`, `create_new`) open the directory as a `Dir` and do every
step inside that handle: the read, the staged temp file (sealed through its own
handle: owner, mode and ACL are set before the rename), the backup hard link, the
no-clobber rename, the replace and the directory flush. Nothing touches the final
name after the rename, so a name swapped for a hard link or symlink after it
changes nothing. A symlink at the file's own name is never read through: it is a
file this release cannot read, and the file's role decides what happens to it.
`the_state_file_writers_never_chown_chmod_or_rename_by_path` keeps the writers on
it. The log directory (`hole_common::logging::init_dual`, with `DirRotate`) is
written through the same `Dir`.

A write that reached the rename is complete: a failure of the directory flush after it is logged at warn and the call
is `Ok`, because the caller acts on what is on disk. A refusal (`StoreError::Unreadable`, `ReadFailed`) names the file,
never its directory. Every state file reader ignores a field it does not know (the owner's rule, "readers ignore unknown
fields"): the version is the only compatibility signal. For the lockdown intent, the boot-time witness,
`bridge-failclosed.json` and `bridge-lockdown-pf.json` that changed with `VersionedFile`, which replaced
`deny_unknown_fields`: `{"version":1,"enabled":false,"stray":1}` now reads as the intent Off, where it was
`Unreadable` (which keeps a standing cover at boot).

`Refused` follows the `ConfigError` precedent ([PII](#logging--diagnostics)): the
lock sits in a user's profile, so neither its `Display` nor its `Debug` carries
the path. `Refused` has no `source()`, and the `InvalidData` `io::Error` that holds it
delegates to it, so logging that error as `error = &e as &dyn std::error::Error`
([Logging an error](#logging-an-error)) renders one link, `refusing to lock: <reason>`.
The reason is a fixed sentence or a uid, never a name or a path: the directory's
refusal is folded into that `Display`, not a link of its own. That cannot put a username in
`bridge.log` (which the support bundle collects), also when a caller's error holds it as
a `#[source]`. `Refused::path()` is the one way out; a caller that wants it chooses a sink
that may hold a path (`gui.log`), never the bridge log or the bundle.

### Privileged code in folders a user may own

The bridge runs as root or SYSTEM, and some of what it reads and writes sits under the interactive user's
profile: the state directory, the log directory, the update marker. Every component of such a path is the
user's to replace between any two calls, so a path call (`create_dir_all`, `chown`, `rename`, `remove_file`,
`File::create`) resolves the whole path again and can be sent anywhere. Code that acts in such a folder
follows these rules, which [`util::dir::Dir`](crates/util/src/dir.rs) implements once; use it, do not
re-derive them.

1. **Walk through handles.** Open the directory once, one component at a time, each relative to the handle
   already held (`openat` on unix, `NtCreateFile` relative to the parent handle on Windows). Every later step
   names a file by one name *inside that handle*.

1. **Hand the walk the path as it was given.** A state or log directory is never resolved first (`canonicalize`,
   `realpath`): resolving follows every link with no rule, so the user's link to a folder of root's is the folder's
   own name by the time the walk judges it, and the walk accepts it. `std::path::absolute` makes a path absolute
   without following anything.

1. **The ownership-transition rule.** A link is followed only if the walk never moves from a folder an
   unprivileged user owns into one somebody else owns. This is systemd's `chase()` with `CHASE_SAFE`
   (`safe_transition`), tightened in two places:

   - A link is judged by its own owner as well as by the folder it sits in. A link the system owns (unix: root;
     Windows: SYSTEM, Administrators, TrustedInstaller) is followed in a folder the system owns (macOS's `/var`,
     Windows's `C:\Documents and Settings`), and refused in a user's folder, where it can only be a hard link the
     user planted.
   - A link an unprivileged user owns binds the walk to that user. The walk may pass through anyone's folders
     (an absolute target restarts at the root), but it creates only in folders that user owns and ends only in
     one. A user's link to their own relocated profile is followed; their link to `/etc` is refused, and so
     is a link whose target is another user's.

   Without the second tightening a link a user plants in a folder the system owns (`/tmp`) leads anywhere:
   `safe_transition` lets any step away from a system-owned folder pass and never sees who owns the link; that
   check is the cautionary case. The rule is one decision in one place (`dir/trail.rs`, `Owner::may_enter` and `Trail`), decided on
   each link, never at a call site.

   Two more things belong to the walk. It follows at most as many links as the OS itself follows in one path
   (`MAXSYMLINKS` 40 on Linux, 32 on macOS; 63 reparse points on Windows), which also ends a loop: a user plants
   the links and each can name the next several times, so without the bound a chain of forty costs exponential
   time in a process that runs as root. And a folder the walk makes below a user's link is given to that user at
   once, because a folder the bridge made is the bridge's on disk and the next walk through the link would refuse
   it. The user owns the parent, so the name can be swapped between making the folder and giving it; the hand-over
   therefore opens the name once (unix: `O_DIRECTORY | O_NOFOLLOW`), requires the handle to be a directory the
   bridge itself owns (a swapped-in folder is the user's, a hard link is not a directory), and gives that handle
   (`fchown`). On Windows the owner is set through a handle re-opened for the purpose and compared with the made
   one (it takes the restore privilege an elevated token holds). A folder made on a path with no user's link is
   left as its maker's, on Windows too: a folder SYSTEM made there is Administrators-owned, and if a user later
   puts a link they own above it, the walk refuses it on every start after (unix hands the final folder over in
   `Dir::secure`; Windows has no counterpart).

1. **Never follow the final name.** A file operation opens its name with `O_NOFOLLOW` / `FILE_OPEN_REPARSE_POINT`
   and creates with `O_EXCL`. A link there is renamed, linked or unlinked as itself and never read or written
   through. A FIFO there is not waited for (`O_NONBLOCK`), and reading anything that is not a regular file is
   refused.

1. **Write only to a file you made or the owner already owns.** A file kept at a name across runs (the log) is
   opened with `Dir::append_own_file`: created with `O_EXCL`, or an existing file taken only if it is the expected
   owner's with no other name (unix: its uid and a link count of 1; Windows: no other name). Anything else at the
   name (another name of a file, a link, a FIFO) is unlinked and replaced, never written through, and an existing
   file's owner and mode are left alone.

1. **Read through the handle too.** A privileged read of a fixed name in such a folder is `ReadDir::read` after the
   same walk (`VersionedFile::observe` for a state file, `ReadDir::read_vouched` for any other). `std::fs::read` opens by path without `O_NONBLOCK`: a
   FIFO the user plants at the name hangs the bridge (at start, before it serves; at shutdown, before it tears
   down), a link to `/dev/zero` is read without end, and a link is read as any path the user names. A read by
   path stays only where the reader is the unprivileged GUI. Code that only reads holds a `ReadDir`, not a `Dir`:
   it has no method that writes, renames or removes, so writing through a directory opened for reading cannot be
   written, on any platform. Windows is not asked for the right to add to a `ReadDir`'s directory, so a folder
   whose ACL a machine tightened to read-only for the reader (the GUI reads the update marker as the user) is
   still read. Code that also writes opens a `Dir` and takes a `ReadDir` view of it with `Dir::reader`
   (`VersionedFile::update` reads the current file that way; `observe` opens a `ReadDir`).

   `ReadDir::read_vouched`, which `VersionedFile::observe` reads with, also refuses a file the folder's owner cannot vouch for (`Refusal::ForeignFile`, decided by
   `trail::may_read` on both platforms): the file must be owned by the folder's own user, or by the system (root,
   SYSTEM, Administrators) with at most one link (none when a rename has just replaced the open file, which has no name
   left for a user to have planted). A user can hard-link any file the system can read at a state name
   (macOS has no `protected_hardlinks`), and the planted name has two links. The rule stops that and nothing else
   about ownership: a file the system owns that the user moved into the folder keeps its owner and its one link
   (a rename moves the inode), so it is read. What the user could learn from it is limited by the readers, below.
   This holds for the files read with
   `read_vouched`, which are published by rename (the update marker's claim by a rename that refuses to replace) and
   so have one name; `ReadDir::read` does not have it, and is for a file that has a second name by design. One
   exception: a write that fails to publish makes a backup link first, and when taking that backup back also
   fails the original has two names, so it reads as `ForeignFile` until the backup is removed
   (`crates/util/src/versioned_file/store.rs`, `take_back_backup`). A
   filesystem with no such rename fails the claim, and the move-aside of an unreadable record, with an `Unsupported`
   error naming the file; neither falls back to a hard link, which would leave the file under two names.

1. **Remove and move aside through the handle too.** A state file is removed by `VersionedFile::update` with `Change::Remove` and
   moved aside by `Change::MoveAside` or `Dir::rename_noreplace` (`dns_state::supersede`), never `std::fs::remove_file` or `rename` on a
   path: a component the user swapped for a link redirects the call, and a probe followed by a rename replaces a name
   that appeared in between. The same holds for the stale socket (`socket::remove`, `util::dir::make_dir_and_free_name`)
   and the installer's SID file (`Dir::write_atomic`, `ReadDir::read_vouched`, `socket::remove_name`) in the `hole` folder of `%ProgramData%`, to which a standard user can add names (it
   inherits `BUILTIN\Users:(CI)(WD,AD,WEA,WA)`; the installer does not narrow it). The socket's bind and the mode or
   DACL set on it afterwards still name it by path: no platform binds relative to a directory handle. A folder named by
   `--socket-path` is walked like the default one, so a link is followed only under the ownership-transition rule (one
   that leads out of a user's own folders is refused), and no further: Hole does not require the bridge to own it, and
   the caller vouches for it.

1. **Set mode and owner through the open file.** `fchown`, `fchmod` and the Windows ACL go to the handle of a
   temp file, before it is renamed into place (`Dir::write_atomic`, `Dir::stage`).

1. **Never touch a path after a rename.** Once the temp file has its final name the writer does nothing to that
   name: a name swapped for a hard link or a symlink after the rename changes nothing.

`the_state_file_writers_never_chown_chmod_or_rename_by_path` keeps the state-file writers on the handle.
`crates/bridge/src/dir_writers_tests.rs` holds every writer into a state directory to two properties: a hard link, a
symlink or a FIFO planted at a name it acts on changes nothing it leads to, and the writer either takes the name over
(or removes it) or refuses it with a typed refusal, and a second run in the same layout, with or without a user's link
on the path, succeeds. A source file that opens a `Dir`, calls `make_dir_and_free_name` or `append_own_file`, or
writes a `VersionedFile`, and has no row in its table fails
`every_file_that_opens_a_dir_has_a_row`, so a new writer cannot skip them. The readers have the same kind
of table (`no_reader_reads_through_a_symlink_planted_at_its_name`, `no_reader_waits_on_a_fifo_planted_at_its_name`,
and `state_symlink_tests.rs` in `tun-engine`): each writes a valid file, plants the name, and the reader must not
report the file the name leads to. A hard link is the file's own inode, so only `read_vouched`'s ownership and link-count rule tells it from the
file (`no_reader_reads_a_hard_link_the_system_would_not_have_made` and its `tun-engine` twin: a test cannot make a
file the system owns without being the system, so the planted name is refused when the runner is root or an elevated
token and read when it is a user). What a reader takes from a folder the user owns is parsed as that state's schema
and never echoed: every reader turns its `serde_json::Error` into a `util::parse_error::ParseFailure` (category and
position) where the parse happens, since the error's own text quotes the file, and the log goes to `bridge.log`, which
the user can read (`no_state_reader_logs_a_fragment_of_a_file_it_cannot_parse`, here and in `state_symlink_tests.rs`).
The installer-SID reader (`take_installer_user_sid`) reads plain text and parses nothing as JSON; it logs a fixed
warning for text that is not a SID and never the text (`text_that_is_not_a_sid_is_refused_and_never_logged`). Only text that passes
`is_valid_sid_string` reaches the DACL builder, which logs no rejected text either.
Five source scans close the class. They read every use of a function through the file's own `use` and `type` declarations
(`dir_writers_tests/scan.rs`): a name imported, aliased, globbed or reached through a `type` alias is seen as the function it
stands for, whether it is called or only named as a value (`.map(fs::read)`, `let f = fs::read;`, `(fs::read)(p)`). A `use`
declaration itself, a definition, a macro, and a field or parameter that has the name are not uses; a method counts when it
is called. A name that several `use` or `type` declarations bind (the arms of a `cfg` split) stands for every path they
give it. The scans are lexical tripwires over the explicit lists in `dir_writers_tests.rs`, not a proof about every
spelling: the resolver does not see a function bound by anything but `use` and `type` (a macro that expands to a
path, a `let` that renames a function and is then called by the new name), a path through a module of the same file that
re-exports it (`mod sys { pub use std::fs::remove_file; }`, then `sys::remove_file(p)`), or a call with a qualified self
(`<std::fs::File>::create(p)`). A call the lists do not name is not seen either: a new spelling of a by-path call needs a
new row in the list.
`no_privileged_code_acts_on_a_file_by_name`
(no privileged crate calls any of the `BY_NAME` list: `fchownat`, `fchmodat`, `libc::{chown, lchown, chmod, lchmod}`,
`fs::{chown, lchown, set_permissions}`, `SetNamedSecurityInfo*`, `SetFileSecurity*`, `SetFileAttributes*`,
`fs::{remove_file, remove_dir, remove_dir_all, rename, create_dir, create_dir_all, write, copy, hard_link, soft_link, symlink, symlink_file, symlink_dir}`, `File::{create, create_new, options}`, `OpenOptions::new`,
`libc::{unlink, rmdir, rename, mkdir, link, symlink}`, `DeleteFile*`, `MoveFile*`, `CreateDirectory*`,
`RemoveDirectory*`, `CreateHardLink*`, `CreateSymbolicLink*`; `OpenOptions::new` is on it so that a create by path is
judged here even in a file that `BY_PATH_ALLOWED` exempts for reads), except the sites listed in `BY_NAME_ALLOWED`, each
with its count and reason: a folder no user can add names to, the acting user's own, a test's, or an "open owner question" that
waits for a decision), `no_privileged_state_code_reads_a_file_by_path` (the privileged crates, `hole` among them, open no
file by path, except the files listed in `BY_PATH_ALLOWED`, each with its reason),
`no_privileged_code_resolves_a_link_before_the_walk` (the same crates call neither `canonicalize` nor `realpath`,
except the lines listed in `RESOLVING_ALLOWED`, each with its reason), `no_state_module_logs_a_path` (the
state modules log the file's name: no `.display()` or `.to_string_lossy()`, and no formatting or tracing macro takes a
binding the file declares as a path, as an argument, a `?`/`%` field or a `{name:?}` placeholder) and `no_privileged_json_parse_keeps_the_raw_error` (every non-test `serde_json` parse in `bridge`,
`tun-engine`, `util` and `common`, spelled `serde_json::from_*`, `Deserializer::from_*` or a `from_*` imported by name,
converts its error before the next parse or `fn`; the parses listed in `JSON_PARSE_ALLOWED` do not, each with its reason). A test of
a walk plants links with `util::dir::testing` (`plant_link`, `user_dir`, `SystemScratch`), which hand what they
make to an unprivileged owner whoever runs the test: a link to a folder the system owns must be refused, a link
to a folder its own owner owns must be followed, and the same through each writer.

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
- **Best-effort — teardown and crash recovery** (`run_teardown_commands`, via
  `teardown_routes` / `recover_routes`). Every command is issued; a failure
  neither short-circuits the rest nor is returned. Stopping at the first failure
  would strand routes and leave the user worse off than if Hole had never run.

No future edit can turn stranded-route cleanup into an early return: a
best-effort runner narrows a `Vec<RouteId>` accumulator, not a `Result`, so
there is nothing to `?` out of — see
[Route ownership](#route-ownership) for what that accumulator is and how it's
checkpointed.

**The pairing is a compile error, not a convention.** A phase is a value of
`FatalPhase` or `BestEffortPhase` (sealed `Phase` trait, `BEST_EFFORT` const per
type — it also picks the log level, and for `exec_one` which success oracle
applies — see [Route ownership](#route-ownership)), and each runner accepts
only its own type; the command types differ too (`SetupCommand` vs
`RouteCommand`). Wiring a teardown phase into the fatal runner does not
compile. This replaces a `debug_assert` pairing check, which compiled out in
release — the same silently-absorbed-failure class this policy exists to
close.

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

### Route ownership

Teardown and crash recovery delete **only** the routes the run recorded in
`bridge-routes.json`'s `installed` list.

**On macOS, nothing about the delete command itself can express "only if it is
ours"**:

- macOS `route delete` resolves its victim from the destination key and netmask
  alone. xnu's `rtrequest_common_locked` reaches `RTM_DELETE` via
  `rnh_deladdr(dst, netmask)` (`in_deleteroute` → `rn_delete`) and never reads
  the gateway, so `-interface <name>` — which `route(8)` turns into an
  `AF_LINK` gateway, `case K_IFACE` in `network_cmds/route.tproj/route.c` —
  scopes nothing. Worse, with that flag set and a name that no longer resolves,
  `getaddr` exits before `rtmsg()` writes to the routing socket, so the delete
  never happens at all.
- `-ifscope` is the real scoping flag and is equally unusable: a route carrying
  `RTF_IFSCOPE` is skipped by unscoped lookups (xnu `rt_lookup_common` searches
  the unscoped table first and retries only under the *primary* interface's
  scope), so scoping the install would leave the tunnel capturing nothing.
- Reading the table back first — `route get` then `route delete` — is
  check-then-act: it only narrows the window in which the other route is
  destroyed.

**On Windows, the delete command CAN express it, via the gateway.**
`ROUTE DELETE destination [MASK netmask] [gateway] ...` — `route.exe`'s own
help confirms the gateway argument is optional but accepted for DELETE, and
unlike macOS it scopes which entry is deleted. `install` already knows the
gateway (`platform_setup_commands` passes it to the matching `route add`), so
the server-bypass teardown carries it forward as `RouteState.original_gateway`
and emits `route delete <server_ip> mask 255.255.255.255 <gateway>` instead of
the unscoped form. This is `None` — falling back to the old unscoped delete, a
disclosed residual — only for a record migrated from schema 1/2/3, which
never persisted a gateway. The split-route deletes stay unscoped on both
platforms (`RouteId` provenance is their only handle); only the
single-destination bypass delete can carry a gateway at all.

**On-link is a route form, not a fallback.** When the upstream route to the
server has no gateway (`NextHop::OnLink`), Windows has no address to scope
the bypass by — `netsh interface ip add/delete route <server>/32 <interface>`
names the interface instead, symmetric with the IPv6 bypass, which has always
been interface-scoped for the same reason (no reliable IPv6 gateway
detection). Which form a record used is persisted as `RouteState.route_form`,
a field distinct from `original_gateway` — an on-link install and a migrated
pre-schema-4 record both leave `original_gateway`-shaped ambiguity, but only
`route_form` says which delete argv to reconstruct. macOS has no
interface-scoped IPv4 bypass form; an on-link default route is refused there
before `install` is ever reached (`gateway::reject_macos_on_link`).

Provenance is the one handle that outlives the interface, which matters because
the utun is always already gone by teardown: `Session::teardown` closes the TUN at
step 1 and drops the routes guard at step 4, and a crashed run's utun died with
its control-socket fd.

**Determining "ours" needs more than an exit code.** `route(8)` on macOS exits
0 unconditionally for `add`/`delete`/`change` once it dispatches at all
(`network_cmds/route.tproj/route.c`'s `K_ADD`/`K_DELETE`/`K_CHANGE` case runs
`newroute(); exit(0)`); the only signal a real routing-socket failure (EEXIST,
etc.) ever produces is the literal text `rtmsg()` prints to stderr via
`warnx("writing to routing socket: %s", ...)`. `routing::macos_route_command_succeeded`
parses that text for installs, and `routing::macos_route_confirmed_absent` for
deletes (distinguishing `ESRCH`/"not in table", meaning already gone, from
every other errno, meaning still installed). Windows' `route.exe`/`netsh`
exit non-zero on a genuine `add` failure, so no parsing is needed for
installs — but for *deletes*, a non-zero exit does NOT unambiguously mean
"already gone" (verified empirically: an absent route and one requiring
elevation both exit 1, no distinguishing text), so `route_confirmed_absent`
only trusts exit 0; a Windows delete that fails for any reason stays
recorded rather than risk silently dropping a route that is still there — a
disclosed residual on top of the one below. Parsing a CLI's diagnostic text
is a narrower and more fragile answer than a routing socket would be — see
the Residual paragraph below.

**A route command that ran but didn't confirm going in is a fail-closed
condition, not a degraded connect.** If any planned route's command spawns
but the oracle above says it did not go in (macOS: a real `rtmsg()` failure;
either platform: the runner itself reporting `false`), `install` rolls back
whatever did go in and returns `Err` rather than a partial tunnel — a user
who believes traffic is captured when some of it is not is worse off than
one who is told Hole failed to connect (Rule #0).

The consequence a co-resident VPN cares about: if another VPN already holds
`0.0.0.0/1` when Hole starts, Hole's `route add` fails, the route is never
recorded, and Hole's Stop leaves it alone.

**Persistence is checkpointed per command, not per phase.** `bridge-routes.json`
is rewritten before AND after every single route command — not once before the
whole install, not once after — so at any instant, including mid-crash, its
`installed` list names at most one route beyond what is actually confirmed in
the table (the one command in flight). Teardown and recovery apply the same
per-command checkpointing on the way out: a command that spawns is dropped from
the record only once its outcome is confirmed (deleted, or already absent);
one that fails to spawn stays recorded so the next start retries it, and nothing
downstream of it in the same run is skipped — teardown has no error channel to
abort through. "Next start" means the next `install`, not only the next
process start: `recover_routes` runs once per bridge process, but a
long-lived process can `install` multiple times (reconnect, server switch),
so `install` itself sweeps any record left retained by a prior `install` in
the same process before starting a new one. A record is only ever retained
because its own teardown could not confirm the route gone, so the sweep
commonly fails the identical way again — whatever it still cannot confirm
gone is carried forward into `RouteState.stale` (a list of
`{tun_name, server_ip, interface_name, original_gateway, route_form, installed}` groups,
each with its own provenance since a later sweep or `recover_routes` may run
under a different `tun_name`/`server_ip`/gateway than the new session's own).
The new session's own checkpoints only ever touch `installed`, never `stale`,
so a leak from an earlier session survives being overwritten by a later one;
`recover_routes` attempts every `stale` group in addition to the primary
record, and the state file is cleared only once both are empty.

**Groups are reduced to canonical form before anything runs.**
`routing::state::coalesce` is the one place that folds a group into `stale`:
groups sharing an identity (`tun_name`, `server_ip`, `interface_name`,
`original_gateway`, `route_form` — the tuple that determines the argv a
group's commands emit) merge into one whose `installed` is the union, each survivor is
sanitized against `planned_routes(server_ip)` (an id with no possible
teardown command — e.g. a `ServerBypass` against a loopback `server_ip` —
can never drain, so it would pin `stale` non-empty forever), and an empty
survivor is dropped. Without this, a reconnect to the same server — which
shares `tun_name` (a fixed constant) and often `server_ip` with an
already-carried-forward group — would re-emit a byte-identical delete: on
Windows the second occurrence is never confirmed, permanently stranding the
group; on macOS the split-route deletes are fully unscoped, so the second
occurrence removes whatever a third party claimed after the first freed the
prefix — the exact harm this section exists to prevent. `recover_groups`
additionally runs every group's split deletes before any group's bypass
delete, deduping by argv across groups (not just within one): a split
delete's argv depends on `tun_name` alone, so two groups with different
`server_ip` but the same `tun_name` would otherwise still collide.

**Residual (macOS only):** a VPN that takes the prefix over *mid-session* —
necessarily by deleting Hole's entry first — is still torn down by Hole's
Stop. macOS exposes no compare-and-delete, so closing that needs a different
mechanism (a routing socket that acts and then repairs from `RTM_DELETE`'s
reply), not a different flag. The same routing-socket mechanism would also
replace the stderr-text parsing above with a structured `rtm_errno` — tracked
separately, since it cannot be verified without a macOS dev box. Windows has
no equivalent residual here: a takeover VPN's route to the same destination
has a different gateway, so Hole's gateway-scoped delete simply fails to
match it (a safe no-op) rather than deleting the wrong entry — the failure
mode a check-then-act race would otherwise produce.

`scripts/network-reset.py` deliberately does not honour the record: it is the
unconditional escape hatch, in the same spirit as `failclosed::release_all`.

### Crash recovery

While a proxy is active the bridge persists small state files in `<state_dir>/`,
cleared on clean shutdown and replayed on next startup (all *after* the IPC
socket binds; DNS recovery runs before route recovery so a mid-recovery crash
leaves working DNS + broken routes, not the inverse):

- **`bridge-routes.json`** — TUN name, server IP, upstream interface, and the
  `installed` list of [`RouteId`](crates/tun-engine/src/routing.rs)s;
  `routing::recover_routes` tears down leaked routes. Teardown and recovery
  delete **only** the routes in `installed` — see
  [Route ownership](#route-ownership). The same call also sweeps a stale
  [fail-closed cover](docs/contributing/architecture/kill-switch.md) (Windows by fixed WFP GUID, macOS via
  `bridge-failclosed.json`).
- **`HoleDisabledByHole`** (Windows; a registry value under the service's
  own key, not a file in `<state_dir>`) — present while an uninstall's Disabled
  start type is in force; `repair_interrupted_change` (the cutover child,
  `bridge install`) and the next retirement reset what it names and sweep a
  stale one. It goes with the service's key. See
  [The Disabled service and its record](docs/contributing/architecture/kill-switch-uninstall.md#the-disabled-service-and-its-record).
- **`bridge-failclosed.json`** (macOS only) — the `pfctl -E` enable token of an
  engaged fail-closed cover; `routing::failclosed::recover_cover` restores
  `/etc/pf.conf` and drops the refcount. Windows keys its cover by fixed WFP
  GUIDs and needs no file. See [the kill switch](docs/contributing/architecture/kill-switch.md).
- **`bridge-plugins.json`** — persisted cosca process identities;
  `plugin_recovery::reap_recorded_plugins` kills survivors by exact identity —
  no tolerance window — and deletes the file only after accounting for every
  record it named. The same reap runs at bridge start, at chain stop, and in the
  test harness's teardown. At bridge start it runs before the boot reconcile
  (`boot::recover_then_reconcile`: route recovery, reap, reconcile): the reap
  kills every recorded plugin, so running it after would kill the auto-connect's
  own. IPC is not served until the boot returns.
- **`bridge-dns.json`** — read-only now. The bridge stopped writing this file
  (DNS confinement is process-scoped WFP state, not a file — see
  [DNS forwarder](#dns-forwarder)); what's left is the evidence-gated upgrade
  sweep that undoes a *pre-#846* build's own crashed-run rewrite:
  `dns::recovery::recover_dns_config` restores each recorded adapter/family
  only when its LIVE setting still equals what that old build advertised, and
  evaluates any given file at most once — on full success it deletes the
  file, otherwise it renames it to `bridge-dns.superseded.json` and never
  reads that name again. `scripts/network-reset.py` reads both names, so the
  escape survives the rename. A DNS confinement held by a **live but
  unreachable** bridge (a #936 symptom, since the IPC socket bind does not
  fully guarantee single-instance today) has no file-based release path —
  the confinement dies only with its owning process, and `network-reset.py`
  killing that process is the escape.
- **ETW sessions** (Windows) — `hole-bridge-etw-<pid>`;
  `diagnostics::etw::sweep_stale_sessions` (`QueryAllTracesW`) stops stale ones by
  name prefix. The bridge's own session is stopped in `EtwGuard::drop`, which
  re-issues STOP by name as a backstop when `UserTrace::stop` did not report
  success; if even that fails, `Drop` abandons the processing thread rather
  than risk an unbounded join (mechanism: `etw.rs` module doc, "Drain on
  Drop"; `Drop` is otherwise unbounded, bindreams/hole#1016).

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
(persist-without-disengage: the guard is consumed and emptied, so its `Drop`
disengages nothing) instead of dropping it, so the
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
stops → swaps → repairs the start type → starts via `NotifyServiceStatusChange`
(a real kernel rendezvous, gated on a RUNNING callback, never a sleep or
loopback probe). A service an administrator disabled is not started, and that is
a successful cutover: see
[the Disabled service and its record](docs/contributing/architecture/kill-switch-uninstall.md#the-disabled-service-and-its-record). macOS runs inline:
swap first, then `launchctl kill SIGTERM` rides the graceful shutdown
(`pm.stop()` → the marker-conditional disarm fires), and `KeepAlive=true`
respawns the now-swapped binary.

`service_scm::SystemScmActor` **deliberately leaks** the notify record of a
`NotifyServiceStatusChangeW` call whose callback has not run (mechanics:
`service_scm::registration`): one 88-byte record (64-bit Windows; `size_of` of the
record, asserted at compile time) per call that did not settle, including each
`ERROR_SERVICE_NOTIFY_CLIENT_LAGGING` return. Nothing caps how many such calls
are made (the LAGGING retry has no cap), so nothing caps the leak. Do not "fix" the leak without a
Win32 measurement showing that closing the service handle recalls a queued APC
and that a failed call queues none.

The **marker** (`update-in-progress.json` in the service log dir, world-readable
0o644 cross-privilege) does triple duty: the GUI holds its last snapshot instead
of flashing Disconnected while it is set, the bridge shutdown disarms the cover
while it is set, and it is the PR3 banner source. It is cleared unconditionally
(remove-by-name, never parse-then-clear) on the next bridge's post-bind sweep.
Every write, the clear and the read go through the log directory's no-follow `Dir`
handle (a temp file staged and sealed through its own handle, then renamed; the
single-occupancy claim renames without replacing, and fails with `Unsupported`, naming
the file, where the filesystem has no such rename). The read is the same for the GUI as the
user and for the bridge as root: the bridge reads it in a log directory a user may
own, where a FIFO planted at the name must not be waited for. A link or a FIFO at
the name reads as `Marker::Indeterminate`, a claim of no cutover.

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
syscalls (no heap/locks/`format!`). All I/O errors are swallowed.

The log directory is the interactive user's while the bridge writes in it as
root, so [`attach`](crates/tombstone/src/crash.rs) opens it once through
`util::dir::Dir` (see
[Privileged code in folders a user may own](#privileged-code-in-folders-a-user-may-own))
and holds it for the process lifetime. The handler creates the marker, and the
Windows dev-only `.dmp`, by a name pre-encoded at `attach` and relative to that
handle: `openat(O_CREAT | O_EXCL | O_NOFOLLOW)` on unix,
`NtCreateFile(FILE_CREATE)` on Windows. An entry already at the name is never
written through, truncated or replaced; `attach` picks a name that is free then
(`-1`, `-2` after the pid when an earlier process's marker or dump with the same
pid is unswept), so a name planted afterwards costs that one crash its marker
and the entry nothing. A directory that cannot be opened leaves the handler
attached (on macOS it still ends the process) and writing no marker.

On Windows and Linux it then returns `Handled(false)` so the OS default path
(WER / core dump) still runs. **On macOS it never returns** — it `_exit(70)`s,
for every fault class, every attach kind and every build, so a macOS crash
produces the marker and **neither an `.ips` nor a minidump**. That cost was
accepted on #842: no part of Hole should hang the process, even sometimes. Do
not restore either half without reading `crates/tombstone/src/crash.rs`'s
module doc, which is the canonical record. Two source-scanning guards in
`crash_tests.rs` hold that callback's shape, because the deadlock needs
CI-like allocation pressure and the runtime `crash_marker_*` tests stay green
without it: `macos_on_crash_terminates_unconditionally`, and
`macos_on_crash_calls_nothing_that_can_allocate`, which scans the whole
handler path transitively — `on_crash`, the marker write and every helper
below it — since an allocation one frame down deadlocks exactly as one in the
callback does.

`tombstone::sweep(log_dir)` runs at the next start of the same kind, emits a
`tracing::error!(target: "crash", …)`, and deletes the marker. Markers land in
`log_dir` (not `state_dir`) so the elevated bridge's marker is readable by the
unprivileged GUI. The sweep opens `log_dir` through `Dir` and reads each marker
through a `ReadDir` by its name inside that handle: a symlink at a marker name
is reported unreadable and unlinked as itself, a FIFO is never waited for, and a
marker the directory's owner cannot vouch for (`ReadDir::read_vouched`) is reported
unreadable too.
The listing of names is by path (names only; each read and removal is by name
in the handle, as `cleanup_legacy_daily_logs` does).

- **Platform coverage:** marker + sweep work on Windows, macOS, **and Linux**
  (galoshes ships a Linux release, so `tombstone` must compile and run there).
  Linux runtime crash tests are a known gap (compile-verified via the galoshes
  Linux build; runtime-exercised only on the Win/mac `hole-tests` lane).
- **Dev-only minidumps:** under the non-default `crash-dumps` feature, `on_crash`
  also writes a `.dmp` via `minidump-writer` — **Windows only**, despite the
  feature name reading cross-platform. Linux never had an in-process self-dump;
  macOS gave its up in #842 (above). `minidump-writer` is declared under
  `cfg(windows)`, so the feature links nothing on any other target (process
  memory holds keys + traffic, and it has no Windows-aarch64 support).
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
