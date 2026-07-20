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
- **Cooperative-cancel model.** Cancellation propagates via tokens from the IPC
  `handle_start` handler; no future-drop cancellation. →
  [CONTRIBUTING.md#bridge-cancellation-contract](CONTRIBUTING.md#bridge-cancellation-contract)
- **Native-crash observability.** The `tombstone` crate writes a signal-safe
  crash marker; the next start of the same kind sweeps it. →
  [CONTRIBUTING.md#native-crash-observability-tombstone](CONTRIBUTING.md#native-crash-observability-tombstone)
- **Crash-recovery sweep.** `bridge-{routes,plugins,dns}.json` + ETW sessions are
  replayed/cleaned on next startup after the IPC socket binds. →
  [CONTRIBUTING.md#crash-recovery](CONTRIBUTING.md#crash-recovery)
- **Yamux transport self-heal.** The galoshes yamux client reconnects after a
  transport reset instead of wedging; death is detected via the driver's
  inbound channel closing, and reconnect backoff is floored and resets on
  transport-level liveness (any inbound yamux frame). `driver.abort()`
  teardown deliberately truncates in-flight relays; a silent (no-RST)
  black-hole is out of scope (→ #660). →
  [CONTRIBUTING.md#yamux-transport-self-heal](CONTRIBUTING.md#yamux-transport-self-heal)
- **Fail-closed covers.** The **standing lockdown** cover
  (`Routing::install_lockdown`, opt-in kill switch) holds the update-cutover gap:
  the bridge **disarms-not-drops** it across the restart and the new bridge
  re-adopts it (`decide_cover_recovery == Adopt`). The **transient**
  `install_failclosed_cover` (permit loopback + server only) is a bounded-window
  RAII guard with **no production caller today** (test seam + recovery target).
  Both are persistent WFP filters (Win) / self-contained pf ruleset (mac), swept
  by `recover_routes` on next start. →
  [CONTRIBUTING.md#fail-closed-cover](CONTRIBUTING.md#fail-closed-cover)
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
  redacted before reaching a toast; the detail still lands in `gui.log`.
  [→](CONTRIBUTING.md#logging--diagnostics)

## Pointers

- Product, install, user-facing CLI, distributions → [README.md](README.md)
- Build, dev, test, coding rules, dev/admin CLI →
  [CONTRIBUTING.md](CONTRIBUTING.md)
  ([build](CONTRIBUTING.md#build) ·
  [development](CONTRIBUTING.md#development) ·
  [testing](CONTRIBUTING.md#testing) ·
  [releases](CONTRIBUTING.md#releases))
- Release ops (rollback, minisign key rotation) →
  [docs/RELEASE-OPS.md](docs/RELEASE-OPS.md)
