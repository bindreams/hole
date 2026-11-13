# The kill switch

The {term}`kill switch` is an operating-system firewall rule that the {term}`bridge` installs and that outlives the
bridge process. This page describes what the code does: what the rule permits, what puts it up and takes it down, which
decisions are made where, and the behaviours that are under question today. The user's view of the same feature is
[The kill switch](../../how-it-works/kill-switch.md).

## Summary

- A {term}`cover` is the installed rule: it permits a short list of outgoing connections and blocks every other one. The
  user-facing kill switch is the **standing** cover, installed by `Routing::install_lockdown`.
- It is installed at connect, right after the routes and before DNS is pointed at the tunnel, and only while the
  preference **Lockdown** is on and the connect builds a tunnel (SOCKS-only mode installs none).
- It is deliberately persistent. A crash, a restart or an update of the bridge leaves it in force, and the next bridge
  either adopts it or removes it according to what the user last asked for.
- Three facts drive every decision: the **intent** (the Lockdown preference, a persisted file), the **target** (what the
  user last asked to be connected to, a persisted file) and the **presence** of a cover (measured from the operating
  system, never remembered). Each is a closed type, and each decision is one exhaustive `match` with no wildcard arm.
- A fourth input acts at every bridge start, before anything is decided: the **startup preference** (**On system
  startup**). It is folded into the target, and **Do not connect** makes the target `Off`, which releases any cover the
  start finds, whatever the intent ([#1294](https://github.com/bindreams/hole/issues/1294)).
- Every mutation of a cover runs under one lock. See [Recovery, adoption and the cover lock](kill-switch-recovery.md).

## Vocabulary

| Term               | Meaning                                                                                                                                                          | Code                                                                                                                    |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Cover              | The installed rule, held in the bridge by an RAII guard. Dropping the guard removes the rule; `disarm` lets go and leaves it in force.                           | `Routing::Cover`, `CoverGuard` in {src}`crates/tun-engine/src/routing.rs`                                               |
| Standing cover     | The kill switch. Persistent, adopted across a restart, removed by an escape or when the target or the intent says so.                                            | `Routing::install_lockdown`                                                                                             |
| Transient cover    | A bounded block for a connect attempt. No start engages it today ([below](#the-transient-cover)).                                                                | `Routing::install_failclosed_cover`                                                                                     |
| Intent             | The Lockdown preference: `On`, `Off`, `Unset` (no record) or `Unreadable` (a record that cannot be read). Stored in the state directory.                         | `Intent` in {src}`crates/tun-engine/src/routing/failclosed/lockdown_state.rs`                                           |
| Target             | What the user last asked for: `Off`, `Connected { config }` or `Unreadable`.                                                                                     | `Target` in {src}`crates/bridge/src/target.rs`                                                                          |
| Startup preference | **On system startup**: `DoNotConnect`, `RestoreLastState` or `AlwaysConnect`. The app sends it with every connect; the bridge keeps it in `bridge-startup.json`. | `StartupBehavior` in {src}`crates/common/src/config.rs`, `resolve_startup_target` in {src}`crates/bridge/src/target.rs` |
| Presence           | What the operating system says about the standing cover: `Live`, `Recorded`, `Absent`, `Indeterminate`, `Unreachable`.                                           | `CoverPresence` in {src}`crates/tun-engine/src/routing.rs`                                                              |
| Session event      | Why a session ended: `UserStopped`, `GaveUp`, `CutoverRestart`, `Blipped`, `ProcessExiting`.                                                                     | `SessionEvent` in {src}`crates/bridge/src/target.rs`                                                                    |

The intent is `bridge-lockdown.json` and the target is `bridge-target.json`, both in the bridge's state directory. The
two are separate on purpose. The intent is a preference that survives a disconnect; the target says whether a connection
is wanted *now*. The target holds the whole connection config because the bridge must be able to reconnect at boot,
before any app exists and without reading the user's own config file, so the file lives in the bridge's state directory
and depends on no other process. For the `--service` bridge that directory is a system location; a bridge started by hand
keeps it in the invoking user's profile ([overview](overview.md)). An unreadable intent counts as armed for the Lockdown
checkbox and label, and installs no cover at connect (below); an unreadable target authorises neither connecting nor
disarming. The tray's **Unblock Network** item follows the measured presence of a cover, not the intent.

Only `Absent` means nothing is blocking. `Indeterminate` and `Unreachable` mean the probe could not answer, and every
site that offers an escape resolves them toward "still blocked". `CoverPresence::is_present` is that rule written once;
comparing against a single variant at a call site is what dropped the two uncertain answers before, and a test now
forbids it.

## What the cover permits

````{tab-set}
---
sync-group: os
---
```{tab-item} Windows
:sync: windows

The cover is a set of persistent filters in the Windows Filtering Platform, installed in one transaction by
{src}`crates/tun-engine/src/routing/failclosed/windows.rs` under Hole's own provider and sublayer (fixed GUIDs). The
session is not dynamic, because a dynamic session deletes its filters when the process exits.

Outgoing connections (`ALE_AUTH_CONNECT`, IPv4 and IPv6) are permitted when they are:

- to loopback, matched by the loopback flag and by the address range;
- on the TUN interface, matched by its interface LUID, which is looked up on every engage and never stored;
- from the plugin binary or from the bridge's own executable, matched by file path (App-ID);
- to the server's address, with any protocol and from any program.

A block-all filter at the lowest weight catches the rest, and the permits sit at a higher weight in the same sublayer
(`PERMIT_WEIGHT` over `BLOCK_WEIGHT`). Incoming connections are never blocked: the only filters at `RECV_ACCEPT` are
loopback permits, because a loopback connection is authorised on both directions. The block-all pair also has two
boot-time twins for the window before the Base Filtering Engine starts; see [Windows: filters and the boot
window](kill-switch-windows.md).
```
```{tab-item} macOS
:sync: macos

The cover is one self-contained pf ruleset, loaded with `pfctl -f -`, built by `build_lockdown_main_ruleset` in
{src}`crates/tun-engine/src/routing/failclosed/macos.rs`. In order, it:

- sets `block-policy drop`, so a blocked packet is silently dropped;
- exempts loopback twice, with `set skip on lo0` and with explicit `pass` rules;
- carries the host's own `nat` rules forward;
- permits **TCP** to the server's address;
- permits everything on the TUN interface, by its kernel-assigned `utunN` name;
- blocks all IPv6 that no earlier rule permitted;
- blocks everything else going out, under the label `hole-lockdown`.

pf has no per-process match, so there is no App-ID permit. Every permit is `no state`. Only outgoing traffic is
blocked. See [macOS: the pf ruleset](kill-switch-macos.md).
```
````

Under both, local network devices are blocked, because nothing permits them. DNS is not a separate permit: the resolvers
Hole advertises are reached through the TUN device, and the TUN permit passes them.

```{dropdown} Behaviours that follow from the permit lists
- **Bypass rules.** A {term}`filter` that sends a destination around the tunnel makes the bridge open a socket on the
  real interface. On Windows that socket is the bridge's own executable, so the App-ID permit lets it out. On macOS it
  meets the block. The same rule behaves differently per platform ([#1283](https://github.com/bindreams/hole/issues/1283)).
- **The App-ID is `hole.exe`.** The path comes from `current_exe()` in `lockdown_app_ids`
  ({src}`crates/bridge/src/proxy_manager.rs`). The app and every `hole` command run from the same file, so they pass the
  block too ([#1287](https://github.com/bindreams/hole/issues/1287)).
- **UDP to the server on macOS.** The server permit is `proto tcp`. With no plugin the Shadowsocks client sends UDP
  straight to the server, and the block drops it while the dashboard still shows UDP as available
  ([#1284](https://github.com/bindreams/hole/issues/1284)).
- **ECH config fetch.** Neither platform's rule set has an entry for the resolver that {term}`ex-ray` queries for the
  ECH config (`ech-doh`); the permit list above is complete. The plugin process makes that fetch. On Windows, when the
  plugin is ex-ray, its own file is permitted by App-ID, so the file permit and not the route decides. A plugin that
  runs ex-ray from another path, such as galoshes' embedded copy, is not covered by that permit, and nothing was checked
  for it. On macOS no per-program permit exists, so whether the fetch is blocked depends on its route, which has not
  been measured. The older issue ([#753](https://github.com/bindreams/hole/issues/753)) was closed as deferred.
```

## When a cover goes up

Both the app's Connect and the bridge's boot-time auto-connect call `ProxyManager::start_cancellable`. The standing
cover is engaged inside `acquire`, in this order: the proxy and plugin chain, the TUN device, **the routes**, **the
cover**, then DNS. The routes come first, so between the route install and the cover install traffic already flows into the
TUN device and nothing else is blocked yet. SOCKS-only mode returns from `acquire` before any routing step: it installs
no cover and does not refresh an adopted one.

```{mermaid}
sequenceDiagram
    participant PM as ProxyManager
    participant R as Routing
    participant OS as Firewall (WFP or pf)
    PM->>PM: standing_cover_expected()
    PM->>R: install(routes)
    Note over PM,R: traffic now flows into the TUN device
    PM->>PM: re-read the intent under the cover lock
    PM->>R: install_lockdown(server, tun, app_ids)
    R->>OS: pre-delete runtime-valued filters, add the set, commit
    PM->>PM: Session holds the cover
    PM->>R: Dns apply, when the DNS forwarder is on
```

- `standing_cover_expected()` is true when the intent is `On`, or when this run adopted a cover, and false when the
  intent is `Off`. An `Unreadable` intent with no adopted cover answers no: the start installs nothing, and the tray
  reads `Lockdown: On (warning: not engaged)`.
- The intent is read again under the cover lock right before the install. An `Off` that an Unblock recorded in the
  meantime wins over the earlier answer.
- The install is **fatal**. A failed engage aborts the start, and the session's teardown releases the routes.
- A start that fails *after* the install releases the cover it installed (`release_failed_start_cover`). A start that
  fails *before* it leaves any cover that already exists untouched.
- Ticking Lockdown while connected only records the intent. `turn_lockdown_on` installs nothing, so the block arrives at
  the next connect ([#1271](https://github.com/bindreams/hole/issues/1271)).
- Engaging over an adopted cover is safe. The engage deletes every filter whose condition holds a runtime value (the TUN
  LUID, the server address, the App-ID paths) inside its own transaction and adds them again, so a stale value from the
  previous run cannot survive the engage; the persistent block-all stays in force throughout.

## When a cover comes down

```{mermaid}
stateDiagram-v2
    [*] --> Absent
    Absent --> Live: connect with intent On
    Live --> Live: settings restart, update or clean shutdown, with intent On
    Live --> Absent: Disconnect or Exit, with a session running (a reconnect passes through here)
    Live --> Absent: the app polls and finds the proxy or plugin dead
    Live --> Absent: untick Lockdown
    Live --> Absent: Unblock Network
    Live --> Absent: hole bridge unlock, bridge service stopped
    Live --> Absent: a start that installed it fails
    Live --> Live: bridge exits or crashes, filters stay
    Live --> Absent: next bridge starts, intent Off
    Live --> Absent: next bridge starts, startup preference Do not connect
    Live --> Recorded: macOS reboot, pf is off and the record stays
    Recorded --> Live: macOS, a connect re-engages from the record
```

A session's teardown settles its cover with `teardown_cover_disposition` in {src}`crates/bridge/src/reconciler.rs`,
over the session event, the intent, the presence and the target. The target is moved first (`target_after`), so the
decision reads the state *after* the event.

| Event            | Raised by                                                        | Target after | The cover                                                                                                                                                                       |
| ---------------- | ---------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `UserStopped`    | Disconnect, or Exit (the app sends a Stop)                       | `Off`        | Released, whatever the intent and the presence say, when a session is running; with none, nothing is settled ([#1295](https://github.com/bindreams/hole/issues/1295))           |
| `GaveUp`         | `check_health` finds the proxy task or plugin chain dead         | `Off`        | `cover_step` against `Off`: released when presence is `Live`, `Recorded` or `Indeterminate`, left when `Absent` or `Unreachable`                                                |
| `CutoverRestart` | The update cutover stops the bridge                              | unchanged    | `cover_step` against `Connected`: kept with intent `On` or `Unreadable`; with `Off` or `Unset`, released when presence is `Live`, `Recorded` or `Indeterminate`, otherwise left |
| `Blipped`        | A settings change that cannot be applied live (`reload`)         | unchanged    | As `CutoverRestart`                                                                                                                                                             |
| `ProcessExiting` | The bridge is stopped with no update pending (SCM Stop, SIGTERM) | unchanged    | As `CutoverRestart`                                                                                                                                                             |

The `cover_step` rows read the target as the event left it. An `Unreadable` target holds the cover whatever the intent
says, because `cover_step` answers `Hold` for it before it looks at anything else. The intent the teardown uses is
`effective_lockdown_intent` ({src}`crates/bridge/src/proxy_manager.rs`), not the file alone: while this run holds an
adopted cover it has not released, the claim turns an `Unset` or `Unreadable` intent into `On`, and a recorded `Off` still
wins.

*Kept* means `disarm`: the guard is consumed and the process lets go of its handle, but the filters stay. The next bridge
finds them (presence `Live`) and adopts them, and then decides again at its own start, which can release them (see the
boot reconcile below). A network drop with the processes still alive is not an event at all: no teardown runs.

`UserStopped` settles a cover only when a session is running. `stop_with` on an idle manager records the target `Off` and
returns, so a cover this run adopted, or one left unguarded by the Windows read-back failure (above), stays in force when
Disconnect or Exit finds no session; Unblock Network or the next bridge start clears it
([#1295](https://github.com/bindreams/hole/issues/1295)).

Two details about `GaveUp`. `check_health` is called only by the status and metrics handlers in
{src}`crates/bridge/src/ipc.rs`, so a dead proxy or plugin is noticed when the app next polls, and with no app running
(a boot-time connect, the tray gone) the session record and the block stay until something polls
([#1285](https://github.com/bindreams/hole/issues/1285)). And the event sets the target to `Off`, which makes `cover_step`
release a present cover even though the intent is still `On`: the block does not trap a machine whose connection Hole has
abandoned. Whether one plugin crash should count as giving up is not decided.

Releases that are not session events:

- **A start that fails** after it installed the cover, as above.
- **Unticking Lockdown, Unblock Network and `hole bridge unlock`**, in the next section.
- **The boot reconcile**, in [Recovery](kill-switch-recovery.md). It releases a cover that the startup-resolved target
  does not authorise. With the startup preference **Do not connect** the target is `Off` at every start, so that is every
  cover it finds: an update's new bridge or a reboot adopts the cover and then releases it, with the intent still `On`
  ([#1294](https://github.com/bindreams/hole/issues/1294)).

## The decisions

`cover_step(intent, presence, target)` is the steady-state decision. `tunnel_step(session_live, target)` is its
counterpart for the session. Neither does I/O.

| Target       | Intent             | Presence                              | `cover_step` |
| ------------ | ------------------ | ------------------------------------- | ------------ |
| `Unreadable` | any                | any                                   | `Hold`       |
| `Off`        | any                | `Live`, `Recorded`, `Indeterminate`   | `Release`    |
| `Off`        | any                | `Absent`, `Unreachable`               | `Hold`       |
| `Connected`  | `On`, `Unreadable` | `Recorded`, `Indeterminate`, `Absent` | `Engage`     |
| `Connected`  | `On`, `Unreadable` | `Live`, `Unreachable`                 | `Hold`       |
| `Connected`  | `Off`, `Unset`     | `Live`, `Recorded`, `Indeterminate`   | `Release`    |
| `Connected`  | `Off`, `Unset`     | `Absent`, `Unreachable`               | `Hold`       |

`Engage` is acted on only at connect, inside `start_cancellable`; at boot and in a teardown it is treated as `Hold`,
because the TUN device and routes it needs do not exist there. An unset intent is not evidence to arm, so it behaves
like `Off` here; turning an unset intent into `On` over a live cover is recovery's job, not this function's.

Policy keyed to a variant lives on the type, in one exhaustive match, and never at a call site: grouping two variants
because they share a consequence is what once let `ProcessExiting` inherit an answer chosen for a cutover, and comparing
against `== Live` is what dropped the two uncertain presences. The sites are `SessionEvent::preserves_death_reason`,
`CoverPresence::is_present`, `StaleKeyPolicy::refuses_a_stale_key` and `Coverage::plan`, and a test for each fails on a
call site that re-derives the rule (`session_event_policy_lives_on_the_type_not_at_call_sites`,
`cover_presence_is_never_compared_against_a_variant`, `stale_key_policy_lives_on_the_type_not_at_call_sites`,
`coverage_policy_lives_on_the_type_not_at_call_sites`).

When a release and a tunnel step happen together, `step_order` puts the tunnel first: egress is never opened while the
tunnel is half-standing. For an engage and a tunnel start it lists the cover first, but the boot driver does nothing for
that step (`Phase::Cover(Engage)` in `reconcile_once`): the real engage runs inside `start_cancellable`, after the routes
(above). A boot connect therefore does not have the cover ahead of the tunnel.

## The escapes

Four doors release a cover on demand. They differ in whether a presence probe sits in front of the release, and in
whether the records move before or after it.

| Door                 | Entry                                                    | Runs while a bridge is up?   | What it does                                                                                                                                                                                                           |
| -------------------- | -------------------------------------------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Untick **Lockdown**  | `handle_lockdown` and `ProxyManager::turn_lockdown_off`  | Yes, under the proxy lock    | Releases every cover, then records the intent `Off`. The target is untouched; a running session stays up, unblocked.                                                                                                   |
| **Unblock Network**  | `handle_unblock` in {src}`crates/bridge/src/ipc.rs`      | Yes, and takes no proxy lock | Releases every cover, then records the target `Off`, the intent `Off`, and clears the auto-connect candidate. It reads no session state and stops no session ([#1282](https://github.com/bindreams/hole/issues/1282)). |
| `hole bridge unlock` | `cutover::unlock` in {src}`crates/bridge/src/cutover.rs` | No: refuses                  | Takes the liveness lock, records the target `Off`, disengages the standing cover only, clears the candidate, then records the intent `Off`. Prints what it could not prove.                                            |
| Startup sweep        | `recover_routes`, then `reconcile_once`                  | At boot                      | `recover_routes` removes a standing cover when the intent is recorded `Off`. `reconcile_once` then releases one that the startup-resolved target does not authorise. See [Recovery](kill-switch-recovery.md).          |

- **Presence probe.** Unblock and untick have none: they call `release_all_covers`, which is documented idempotent, and a
  stale `Absent` is the one wrong answer at an explicit disarm. `unlock` has none on Windows, where the deletes are issued
  by key. On macOS `unlock` reads the presence first: `Absent` returns `Ok` without touching pf, and `Unreachable` or
  `Indeterminate` is an error that names `sudo pfctl -f /etc/pf.conf`. The startup sweep acts only on intent `Off` with
  presence `Live`, `Recorded` or `Indeterminate`.
- **Order.** Unblock and untick release first and write the records after, so a failed release leaves the intent on and
  the cover present, with Unblock still on the menu. `unlock` and `release-covers` record the target `Off` first and
  release after, so a failed `unlock` leaves the target `Off` and the intent `On`.
- **`unlock` is not Unblock Network without the app.** When it succeeds the same three records end up written (target
  `Off`, intent `Off`, candidate cleared). The differences: it disengages the standing cover only, where Unblock releases
  every cover, so a transient cover left by an older bridge stays until the next start sweeps it; it refuses while a
  bridge runs; it does not bump `unblock_generation`, since no start can be in flight; and its order and presence
  handling are as above.
- **What `unlock` detects.** It takes the liveness lock of the service's state directory only. A bridge started by hand
  keeps its own state directory and is not seen: `unlock` then records `Off` in the service directory and, on Windows,
  deletes the machine-wide filters under that bridge. `release-covers` probes the peer directories as well ([Uninstall](kill-switch-uninstall.md)).

`hole bridge release-covers` and `hole bridge uninstall` also release, for the uninstaller; see [Uninstall and the
service](kill-switch-uninstall.md). `unlock` is the way out when no bridge runs, which the tray cannot reach. Its refusal
message names only the in-app action, and when the app cannot reach the bridge the way out is to stop the service first
([#1278](https://github.com/bindreams/hole/issues/1278)).

## The transient cover

`Routing::install_failclosed_cover` blocks everything except loopback and the server, with an optional permit for the
ECH-config resolver on TCP port 443. `ProxyManager` can hold one for a "covered" start, which `Coverage::plan` in
{src}`crates/bridge/src/coverage.rs` decides. But nothing in production constructs `Coverage::Covered`: the IPC start
handler always passes `Uncovered`, and the boot reconcile starts uncovered on purpose, so a failed boot connect installs
no block of its own ([#1270](https://github.com/bindreams/hole/issues/1270)). The host stays reachable unless a standing
cover is already in force, which a start that fails before its own install leaves as it is. The tray's "Blocked -
connect failed" state and its **Go Offline** item depend on a held transient cover, and so cannot be reached.

What is still live is the sweep. `recover_routes` removes a transient cover left behind by an older bridge on every
start, and `release_all` clears both cover kinds. The transient code, its resolver permit and the retry repair around it
remain in the tree; their detail is in the module docs of {src}`crates/bridge/src/proxy_manager.rs` and
{src}`crates/tun-engine/src/routing/failclosed.rs`.

```{dropdown} Residuals of the dormant transient cover
- **The repair has a gap.** A resolver drift releases the held cover and engages a corrected one. Windows' engage is
  delete-then-add, and on macOS the release reloads `/etc/pf.conf`, so the host is briefly open between the two; if both
  the corrected engage and the compensating restore fail, the attempt runs uncovered
  ([#758](https://github.com/bindreams/hole/issues/758)).
- **A crash then a downgrade leaves permits behind.** The resolver permit added filters to `FILTER_GUIDS` in
  {src}`crates/tun-engine/src/routing/failclosed/windows.rs`, so an older build's recovery sweep does not know them. They
  are permits, never blocks, and a later build that knows the GUIDs deletes them
  ([#754](https://github.com/bindreams/hole/issues/754)).
- **An operator's own `ech-doh` is never permitted.** Hole did not author that address, so under a transient cover it
  stalls to ex-ray's client timeout, and `start_cancellable` logs a warning naming it.
- **The standing cover has no resolver permit at all**, which is the same gap as the ECH note above.
- **The ECH-config reachability gate.** The resolver permit must not widen for a fetch that cannot happen.
  `ech_fetch_is_reachable` and `ex_ray_fatal_config_error` in {src}`crates/bridge/src/proxy/plugin.rs` model ex-ray's own
  decision, reading the plugin options as ex-ray's parser does and mirroring every config error that makes it exit; their
  doc comments hold the rule set, and a test pins each literal against the vendored source.
```

## Where the limits are today

Each of these is the code's present behaviour. Where an issue is open, the behaviour is under question.

```{dropdown} Behaviours of the kill switch
- Lockdown ticked while connected blocks nothing until the next connect ([#1271](https://github.com/bindreams/hole/issues/1271)).
- **Unblock Network** does not disconnect, although its label says it does ([#1282](https://github.com/bindreams/hole/issues/1282)).
- A proxy or plugin that dies on its own lifts the block when the app next polls, and is not noticed before
  ([#1285](https://github.com/bindreams/hole/issues/1285)).
- A start that fails after the cover is installed releases it, so a failed connect with Lockdown on can leave the host
  open.
- A restart under the kill switch on macOS has to look the server up again, and the ruleset passes only TCP to the
  server's address, so a hostname server can leave the restart failing and the block in force
  ([#1286](https://github.com/bindreams/hole/issues/1286)).
- The Windows App-ID permit covers the app and the command line as well as the bridge
  ([#1287](https://github.com/bindreams/hole/issues/1287)).
- Bypass traffic passes on Windows and is blocked on macOS ([#1283](https://github.com/bindreams/hole/issues/1283)); UDP
  to the server with no plugin is blocked on macOS ([#1284](https://github.com/bindreams/hole/issues/1284)).
- On macOS the ruleset does not survive a reboot: pf is off after boot, and egress is open until a connect passes the
  install step and engages the cover again, which `Reenable` in `engage_lockdown` does for a persisted record. The bridge
  starting does not do it. A boot connect that fails first, or the startup preference **Do not connect**, leaves the host
  open ([macOS](kill-switch-macos.md#no-reboot-survival) has the three outcomes). Windows is meant to cover that window
  with the boot-time twins, but nothing that spans a reboot has been measured. See [Windows](kill-switch-windows.md).
- With the startup preference **Do not connect**, every bridge start releases a standing cover it finds, after an update
  as after a reboot ([#1294](https://github.com/bindreams/hole/issues/1294)).
- **Disconnect** and **Exit** release a cover only when a session is running
  ([#1295](https://github.com/bindreams/hole/issues/1295)).
- On Windows, if the engage commits and the read-back of the boot-time twins then fails, `engage_lockdown` returns an
  error with the filters in force and no guard over them. The connect fails and the block stays until **Unblock
  Network** or `hole bridge unlock`.
- `hole bridge unlock` detects only the service's bridge. A bridge started by hand is not seen, and `unlock` lifts the
  Windows filters under it.
- SOCKS-only mode installs no cover and does not refresh one already adopted.
- Two bridges with different state directories can run at once, and the cover's Windows filters are machine-wide, so one
  can sweep or overwrite the other's cover ([#878](https://github.com/bindreams/hole/issues/878)).
```

## Read next

- [Recovery, adoption and the cover lock](kill-switch-recovery.md): what the bridge does at startup, and what keeps two
  mutations of a cover from overlapping.
- [Windows: filters and the boot window](kill-switch-windows.md) and [macOS: the pf ruleset](kill-switch-macos.md).
- [Uninstall and the service](kill-switch-uninstall.md): how the uninstaller avoids leaving a machine blocked.
