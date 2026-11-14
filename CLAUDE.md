# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin
support (served by the bundled first-party `ex-ray` binary). A single Rust binary
is both the unprivileged Tauri GUI (no args) and the privileged bridge
(`hole bridge run`, root/SYSTEM).

This file is the agent-facing map: one line per area, each linking the docs page that
holds it. Product and install: [README.md](README.md). Everything else: [docs/index.md](docs/index.md).

**IMPORTANT:** NEVER PIPE TESTS TO `tail`! ALWAYS SET A TIMEOUT FOR THE SHELL COMMAND! Tests are known to hang, you WILL get stuck and WILL not have information to debug why if you tail.

## Architecture map

- **Single binary, two modes.** The app and the bridge, chosen by CLI args, talking HTTP/1.1 REST over an AF_UNIX socket. →
  [overview](docs/contributing/architecture/overview.md#two-modes-one-binary)
- **Single-instance app.** One app instance per `com.hole.app` lock; the lock's scope differs by platform. →
  [app process](docs/contributing/architecture/app-process.md#one-instance-per-session)
- **UDP drop policy.** A UDP flow that resolves to `Proxy` on a TCP-only plugin is dropped, never bypassed:
  bypassing leaks it outside the encrypted tunnel. →
  [datapath](docs/contributing/architecture/datapath.md#udp-is-dropped-never-bypassed)
- **TUN naming.** The running device's name has one runtime source, `TunIdentity`. →
  [TUN device](docs/contributing/architecture/tun-device.md#the-device-name-has-one-source)
- **IPv6 in the tunnel.** The split routes capture it and the interface holds a ULA address, set per platform. →
  [TUN device](docs/contributing/architecture/tun-device.md#ipv6-in-the-tunnel)
- **TCP accept refusal.** A declined connection is refused with a pre-handshake RST, by the pure `decide_admission`. →
  [TCP admission](docs/contributing/architecture/tcp-admission.md)
- **DNS forwarder.** DNS rides the TCP tunnel for TCP-only plugins; the OS is pointed at it per platform. →
  [DNS forwarder](docs/contributing/architecture/dns-forwarder.md)
- **DNS-egress confinement (Windows).** Port-53 egress is confined to the TUN by a process-scoped WFP session. →
  [DNS forwarder](docs/contributing/architecture/dns-forwarder.md#how-the-operating-system-reaches-it)
- **Listener selection.** `build_ss_config` rejects invalid listener combinations up front. →
  [datapath](docs/contributing/architecture/datapath.md#the-listener-the-datapath-dials)
- **Bridge trait seam.** OS-mutating bridge I/O, `Drop` cleanup included, goes through the `Proxy`, `Routing` and
  `Dns` traits, never the raw free functions (clippy-enforced). →
  [test isolation](docs/contributing/architecture/test-isolation.md)
- **Datapath test seams.** Router and datapath seams make the drop path and the TUN loop testable without the OS. →
  [testing](docs/contributing/testing.md#which-lane-proves-what)
- **Plugin binaries.** The bridge runs only the plugins Hole ships, from one folder, never from `PATH`. →
  [plugin binaries](docs/contributing/architecture/plugin-binaries.md)
- **Proxy shutdown contract.** `stop()` returns only once the listener sockets are closed. →
  [proxy shutdown](docs/contributing/architecture/proxy-shutdown.md)
- **Cooperative cancellation.** A cancel travels by token, not by dropping a future; no fresh
  `CancellationToken::new()` in `crates/bridge/src/` (clippy-enforced). →
  [cancellation](docs/contributing/architecture/cancellation.md#one-cancel-mechanism-tokens)
- **Native-crash observability.** The `tombstone` crate writes a crash marker that the next start sweeps. →
  [native crashes](docs/contributing/architecture/native-crashes.md)
- **Route ownership.** Teardown and recovery delete only the routes `bridge-routes.json` records as installed; a
  route whose install failed belongs to whoever holds it now. →
  [route ownership](docs/contributing/architecture/route-ownership.md)
- **Route-command failure policy.** Install is fatal and teardown is best-effort, enforced by types. →
  [route failure policy](docs/contributing/architecture/route-failure-policy.md)
- **Crash-recovery sweep.** The next start replays and cleans the state files and ETW sessions. →
  [crash recovery](docs/contributing/architecture/crash-recovery.md)
- **Yamux transport self-heal.** The galoshes client reconnects after a transport reset and probes a silent black hole. →
  [galoshes transport](docs/contributing/architecture/galoshes-transport.md#telling-that-the-transport-is-dead)
- **galoshes mux default.** galoshes appends `mux=0` for its embedded ex-ray; an earlier operator `mux=` wins. →
  [galoshes transport](docs/contributing/architecture/galoshes-transport.md#the-mux-default)
- **Fail-closed covers.** The kill switch's standing cover outlives the bridge; the transient cover is dormant, and only its leftovers are swept. →
  [kill switch](docs/contributing/architecture/kill-switch.md)
- **Server-address redaction.** The configured address is replaced by a token before any log, toast or bundle.
  Hole never writes the address or the password: no `Display` on `ServerAddress` or `Password`
  (compiler-enforced), `.expose()` is the only exit, and a `Serialize` type holding one needs its own `Dump`. →
  [redaction](docs/contributing/architecture/redaction.md)
- **File lock and state files.** Cross-process locks and state-file writers go through `util::dir::Dir` handles. →
  [file lock](docs/contributing/architecture/file-lock.md)
- **Logging and plugin diagnostics.** Log destinations, `HOLE_BRIDGE_LOG` directives and the plugin tap. →
  [logging](docs/contributing/architecture/logging.md)
- **Releases, rollback, signing key, icons, uninstall refusal.** →
  [maintainers](docs/contributing/maintainers/index.md)

## Invariants you must not break

- **Ephemeral ports via `bind_ephemeral`, never raw `free_port`** — the retry is
  unbounded by design, no budget (clippy-enforced).
  [→](docs/contributing/architecture/contention-and-ports.md#port-allocation)
- **No sleeps / timeout-polls for synchronization** — use the codebase's
  rendezvous primitives; three narrow exception classes only.
  [→](docs/contributing/testing.md#no-synchronization-by-elapsed-time)
- **Tests use `#[skuld::test]`** (a stray `#[test]` fails a hook) with `register!()` per
  binary; install per-test subscribers via `set_default_in_current_thread` and never
  `tracing_subscriber::fmt().init()` (clippy-enforced).
  [→](docs/contributing/testing.md#rules-every-test-follows)
- **PII redaction** — errors carrying filesystem paths or other PII must be
  redacted before reaching any log, toast, or bundle; a path's detail still
  lands in `gui.log`, but the server address never does.
  [→](docs/contributing/architecture/logging.md#what-reaches-a-toast)
- **Per-variant policy lives on the type, never at a call site** — a decision
  keyed to an enum variant belongs in ONE exhaustive match on that type, and two
  variants are never grouped because they share a consequence; test-enforced.
  [→](docs/contributing/architecture/kill-switch.md#the-decisions)
  Prefer removing a hazard outright over guarding it:
  [coding rules](docs/contributing/development.md#coding-rules).
- **Privileged code in a folder a user may own walks through handles** —
  `util::dir::Dir` (or `ReadDir`, for code that only reads), never a path call,
  and never `canonicalize` the path first.
  [→](docs/contributing/architecture/privileged-folders.md)

## Pointers

- macOS CI is a small shared pool; land what is open before starting more →
  [CI](docs/contributing/ci.md#the-macos-runners-are-a-shared-pool)
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
- Emergency network reset (`scripts/network-reset.py`) →
  [development](docs/contributing/development.md)
