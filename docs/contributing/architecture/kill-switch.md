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
  startup**), which is folded into the target.
- What happens to a cover on each event is one table, [Transitions](#transitions), and the other pages link its rows.
- Every mutation of a cover runs under one lock. See [Recovery, adoption and the cover lock](kill-switch-recovery.md).

## Vocabulary

| Term               | Meaning                                                                                                                                                                                                                                            | Code                                                                                                                    |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Cover              | The installed rule, held in the bridge by an RAII guard. Dropping the guard removes the rule; `disarm` lets go and leaves it in force.                                                                                                             | `Routing::Cover`, `CoverGuard` in {src}`crates/tun-engine/src/routing.rs`                                               |
| Standing cover     | The kill switch. Persistent, adopted across a restart, removed by an escape or when the target or the intent says so.                                                                                                                              | `Routing::install_lockdown`                                                                                             |
| Transient cover    | A bounded block for a connect attempt. No start engages it today ([below](#the-transient-cover)).                                                                                                                                                  | `Routing::install_failclosed_cover`                                                                                     |
| Intent             | The Lockdown preference: `On`, `Off`, `Unset` (no record) or `Unreadable` (a record that cannot be read). Stored in the state directory.                                                                                                           | `Intent` in {src}`crates/tun-engine/src/routing/failclosed/lockdown_state.rs`                                           |
| Target             | What the user last asked for: `Off`, `Connected { config }` or `Unreadable`.                                                                                                                                                                       | `Target` in {src}`crates/bridge/src/target.rs`                                                                          |
| Startup preference | **On system startup**: `DoNotConnect`, `RestoreLastState` or `AlwaysConnect`. The app sends it with every connect; the bridge keeps it in `bridge-startup.json`.                                                                                   | `StartupBehavior` in {src}`crates/common/src/config.rs`, `resolve_startup_target` in {src}`crates/bridge/src/target.rs` |
| Presence           | What the operating system says about the standing cover; the values are below.                                                                                                                                                                     | `CoverPresence` in {src}`crates/tun-engine/src/routing.rs`                                                              |
| Armed              | The intent reads `On` or `Unreadable`: the Lockdown checkbox is ticked. It says nothing about whether a rule is in force, which is the presence, and it is unrelated to `disarm`.                                                                  | `Intent::reads_armed`                                                                                                   |
| Adopt              | A starting bridge finds a cover it did not install this run and keeps it: it records the claim "a cover is live and this process has not released it" and removes nothing itself. A later step can still release it ([T15 and T16](#transitions)). | `CoverRecovery::Adopt` in {src}`crates/tun-engine/src/routing.rs`                                                       |
| Disarm, kept       | `disarm` consumes the guard and lets go of the rule, which stays in force. A cover left that way is *kept*.                                                                                                                                        | `CoverGuard::disarm`                                                                                                    |
| Session event      | Why a session ended: `UserStopped`, `GaveUp`, `CutoverRestart`, `Blipped`, `ProcessExiting`.                                                                                                                                                       | `SessionEvent` in {src}`crates/bridge/src/target.rs`                                                                    |

The intent is `bridge-lockdown.json` and the target is `bridge-target.json`, both in the bridge's state directory. The
two are separate on purpose. The intent is a preference that survives a disconnect; the target says whether a connection
is wanted *now*. The target holds the whole connection config because the bridge must be able to reconnect at boot,
before any app exists and without reading the user's own config file, so the file lives in the bridge's state directory
and depends on no other process. For the `--service` bridge that directory is a system location; a bridge started by hand
keeps it in the invoking user's profile ([overview](overview.md)). An unreadable intent counts as armed for the Lockdown
checkbox and label, and installs no cover at connect ([T1](#transitions)); an unreadable target authorises neither connecting nor
disarming. The tray's **Unblock Network** item follows the measured presence of a cover, not the intent.

The presence values:

| Value           | Meaning                                                                                                                                     | Produced on |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `Live`          | The operating system shows the cover, or a residue of it. On Windows, at least one lockdown filter exists.                                  | Both        |
| `Recorded`      | The operating system shows no cover, but the bridge's own record of one remains and was never confirmed released. The state after a reboot. | macOS       |
| `Absent`        | The operating system was asked, said no, and no record contradicts it.                                                                      | Both        |
| `Indeterminate` | The operating system answered, but not in a usable way (a filter query denied by its access list).                                          | Windows     |
| `Unreachable`   | The operating system could not be asked (the Base Filtering Engine cannot be reached; `pfctl` is missing and no record exists).             | Both        |

Only `Absent` means nothing is blocking. `Indeterminate` and `Unreachable` mean the probe could not answer, and every
site that offers an escape resolves them toward "still blocked". `CoverPresence::is_present` is that rule written once;
comparing against a single variant at a call site would drop the two uncertain answers, and a test forbids it.

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
- The install is **fatal**. A failed engage aborts the start, and the session's teardown releases the routes. What a
  failed start does to the cover is T3 to T6 in [Transitions](#transitions).
- Ticking Lockdown while connected only records the intent. `turn_lockdown_on` installs nothing, so the block arrives at
  the next connect ([#1271](https://github.com/bindreams/hole/issues/1271)).
- Engaging over an adopted cover is safe. The engage deletes every filter whose condition holds a runtime value (the TUN
  LUID, the server address, the App-ID paths) inside its own transaction and adds them again, so a stale value from the
  previous run cannot survive the engage; the persistent block-all stays in force throughout.

## Transitions

This section is the one statement of what happens to a cover, event by event. The other pages name a row by its number
and add nothing to it. Up to four inputs decide a row (the effective intent, the target, the presence and the startup
preference); the row names the ones that matter. Where the platforms differ, the cell says so.

| #       | Event                                                                                                                                                    | What decides it                                                                                                                                                                              | The cover afterwards                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **T1**  | A connect that builds a tunnel (the app's Connect, or the boot connect)                                                                                  | `standing_cover_expected()`: the intent is `On`, or this run adopted a cover and the intent is not `Off`. `Unreadable` with no adopted cover answers no                                      | Yes: installed after the routes, or re-engaged in place when one is adopted. No: nothing is installed and a cover already in force is left as it is                                                                                                                                                                                                                                                                                                                      |
| **T2**  | A connect in SOCKS-only mode                                                                                                                             | Nothing                                                                                                                                                                                      | Unchanged: none is installed and an adopted one is not refreshed ([#1291](https://github.com/bindreams/hole/issues/1291))                                                                                                                                                                                                                                                                                                                                                |
| **T3**  | A connect fails before the install step                                                                                                                  | Nothing                                                                                                                                                                                      | Unchanged: a cover already in force stays                                                                                                                                                                                                                                                                                                                                                                                                                                |
| **T4**  | The install itself fails                                                                                                                                 | Platform                                                                                                                                                                                     | Windows: the transaction aborts and an adopted cover stays as it was. macOS: a failed ruleset load restores the host before the install returns, and that also removes an adopted or recorded cover ([#1296](https://github.com/bindreams/hole/issues/1296))                                                                                                                                                                                                             |
| **T5**  | Windows only: the install commits and the read-back of the boot-time filters then fails                                                                  | Nothing                                                                                                                                                                                      | In force with no guard over it, and the connect fails. Ways out: T11 and T12 while the bridge runs, T13 and T14 once the service is stopped, and T16 at the next bridge start when the startup-resolved target is `Off` ([#1292](https://github.com/bindreams/hole/issues/1292))                                                                                                                                                                                         |
| **T6**  | A connect fails after the install                                                                                                                        | Nothing                                                                                                                                                                                      | Released by `release_failed_start_cover`, whatever the intent. The code does this on purpose, so a failed connect with Lockdown on can leave the host open                                                                                                                                                                                                                                                                                                               |
| **T7**  | Disconnect, or Exit (the app sends a Stop), while a session is running                                                                                   | `UserStopped`; the target becomes `Off`                                                                                                                                                      | Released, whatever the intent and the presence say                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **T8**  | Disconnect, or Exit, with no session running (for example after a failed connect)                                                                        | The target becomes `Off`                                                                                                                                                                     | Not settled: a cover in force stays ([#1295](https://github.com/bindreams/hole/issues/1295)). T16 releases it at the next bridge start, because the target is `Off`                                                                                                                                                                                                                                                                                                      |
| **T9**  | The proxy or the plugin dies on its own (`GaveUp`)                                                                                                       | `check_health`, which only the status and metrics handlers call, so it is noticed when the app next polls ([#1285](https://github.com/bindreams/hole/issues/1285)); the target becomes `Off` | `cover_step` against `Off`: released when the presence is `Live`, `Recorded` or `Indeterminate`, otherwise left                                                                                                                                                                                                                                                                                                                                                          |
| **T10** | A settings change that cannot apply live (`Blipped`), an update cutover (`CutoverRestart`), the bridge stopped with no update pending (`ProcessExiting`) | `cover_step` over the effective intent, the presence and the target, which these events leave as it was ([The decisions](#the-decisions))                                                    | `Hold` and `Engage` keep it: the guard is disarmed and the filters stay. `Release` removes it                                                                                                                                                                                                                                                                                                                                                                            |
| **T11** | Untick **Lockdown**                                                                                                                                      | Nothing                                                                                                                                                                                      | Every cover is released, then the intent is recorded `Off`. The target is untouched and a running session stays up                                                                                                                                                                                                                                                                                                                                                       |
| **T12** | **Unblock Network**                                                                                                                                      | Nothing                                                                                                                                                                                      | Every cover is released, then the target and the intent are recorded `Off` and the auto-connect candidate is cleared. No session is stopped ([#1282](https://github.com/bindreams/hole/issues/1282))                                                                                                                                                                                                                                                                     |
| **T13** | `hole bridge unlock`                                                                                                                                     | No bridge holds the liveness lock of the service's state directory                                                                                                                           | The standing cover is released. A bridge started by hand is not seen, and its Windows filters are lifted under it ([#1290](https://github.com/bindreams/hole/issues/1290))                                                                                                                                                                                                                                                                                               |
| **T14** | `hole bridge release-covers`, and `hole bridge uninstall`                                                                                                | No bridge holds the liveness lock of the service's directory or of a peer directory                                                                                                          | Every cover kind is released. A bridge it cannot see has its machine-wide Windows filters deleted while its session runs, so that session runs uncovered from that moment until its next connect installs the cover again (T1)                                                                                                                                                                                                                                           |
| **T15** | A bridge starts: crash recovery                                                                                                                          | The intent and the presence (`decide_cover_recovery`, [Recovery](kill-switch-recovery.md#the-decision))                                                                                      | Intent `Off` with a presence of `Live`, `Recorded` or `Indeterminate`: removed. Otherwise adopted, or left alone                                                                                                                                                                                                                                                                                                                                                         |
| **T16** | A bridge starts: the reconcile after recovery                                                                                                            | The startup preference folded into the target (**Do not connect** makes it `Off`), the effective intent and the presence, through `cover_step`                                               | Released when `cover_step` answers `Release`: the target is `Off` and the presence is `Live`, `Recorded` or `Indeterminate`, whatever the intent ([#1294](https://github.com/bindreams/hole/issues/1294)); or the target is `Connected` and the effective intent is `Off` or `Unset`. Held when the target is `Unreadable`. Nothing is installed here; the install belongs to T1                                                                                         |
| **T17** | The host reboots                                                                                                                                         | Platform                                                                                                                                                                                     | Windows: the persistent filters return when the Base Filtering Engine starts, and the boot-time filters are meant to cover the time before that; nothing that spans a reboot has been measured ([Windows](kill-switch-windows.md#what-is-measured-and-what-is-not)). macOS: pf is off and the rule is gone; the record stays, so the presence is `Recorded`, and a bridge start alone does not install the rule again ([macOS](kill-switch-macos.md#no-reboot-survival)) |

A network drop with the processes still alive is not an event: no teardown runs and nothing changes.

Four rows read against the purpose of a kill switch: T6 (a failed connect lifts the block), T8 (Disconnect with no
session leaves it), T12 (Unblock Network does not disconnect, although its label says it does) and T16 with **Do not
connect** (every start lifts it). They are what the code does today. Open issues sit behind T8, T12 and T16; T6 is
deliberate in the code.

```{mermaid}
stateDiagram-v2
    [*] --> Absent
    Absent --> Live: T1 connect with the intent On
    Absent --> Live: T5 Windows read-back failure, the connect fails
    Live --> Live: T1 connect re-engages in place
    Live --> Live: T10 settings restart, update or shutdown
    Live --> Live: T8 Disconnect or Exit, no session
    Live --> Live: bridge exits or crashes, filters stay
    Live --> Absent: T7 Disconnect or Exit, session running
    Live --> Absent: T9 proxy or plugin found dead
    Live --> Absent: T6 connect fails after the install
    Live --> Absent: T4 macOS failed ruleset load
    Live --> Absent: T11 untick Lockdown
    Live --> Absent: T12 Unblock Network
    Live --> Absent: T13 unlock, T14 release-covers
    Live --> Absent: T15 next start, intent Off
    Live --> Absent: T16 next start, target Off, or intent Off or Unset
    Live --> Recorded: T17 macOS reboot, pf off and the record stays
    Recorded --> Live: T1 macOS connect installs from the record
    Recorded --> Absent: T16 next start releases the record
```

A session's teardown settles its cover with `teardown_cover_disposition` in {src}`crates/bridge/src/reconciler.rs`
(T7, T9 and T10). The target is moved first (`target_after`), so the decision reads the state *after* the event.
`UserStopped` releases regardless; `GaveUp` and the three events of T10 defer to `cover_step`, and `GaveUp` moves the
target to `Off` first, which makes `cover_step` release a present cover even though the intent is still `On`: the block
does not trap a machine whose connection Hole has abandoned. Whether one plugin crash should count as giving up is not
decided. An `Unreadable` target holds the cover whatever the intent says, because `cover_step` answers `Hold` for it
before it looks at anything else. The intent a teardown or a reconcile uses is `effective_lockdown_intent`
({src}`crates/bridge/src/proxy_manager.rs`), not the file alone: while this run holds an adopted cover it has not
released, the claim turns an `Unset` or `Unreadable` intent into `On`, and a recorded `Off` still wins.

*Kept* means `disarm`: the guard is consumed and the process lets go of its handle, but the filters stay. The next bridge
finds them (presence `Live`) and adopts them, and then decides again at its own start (T15, T16).

Two cases in T16 are easy to miss. On a measured `Live`, recovery adopts the cover and records the claim, so an `Unset`
intent reads `On` and the reconcile holds it. On macOS, a `Recorded` cover is adopted with no claim, because the
operating system did not confirm it, and on Windows an `Indeterminate` one is not adopted at all; both leave the intent
`Unset`, and with the target `Connected` the reconcile releases the cover with no user action.

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
because they share a consequence is what once let `ProcessExiting` inherit an answer chosen for a cutover. The sites are `SessionEvent::preserves_death_reason`,
`CoverPresence::is_present`, `StaleKeyPolicy::refuses_a_stale_key` and `Coverage::plan`, and a test for each fails on a
call site that re-derives the rule (`session_event_policy_lives_on_the_type_not_at_call_sites`,
`cover_presence_is_never_compared_against_a_variant`, `stale_key_policy_lives_on_the_type_not_at_call_sites`,
`coverage_policy_lives_on_the_type_not_at_call_sites`).

When a release and a tunnel step happen together, `step_order` puts the tunnel first: egress is never opened while the
tunnel is half-standing. For an engage and a tunnel start it lists the cover first, but the boot driver does nothing for
that step (`Phase::Cover(Engage)` in `reconcile_once`): the real engage runs inside `start_cancellable`, after the routes
([When a cover goes up](#when-a-cover-goes-up)). A boot connect therefore does not have the cover ahead of the tunnel.

## The escapes

Four doors release a cover on demand: T11 to T14 in [Transitions](#transitions). They differ in whether a presence probe
sits in front of the release, and in whether the records move before or after it.

| Door                                            | Entry                                                    | Runs while a bridge is up?   |
| ----------------------------------------------- | -------------------------------------------------------- | ---------------------------- |
| Untick **Lockdown** (T11)                       | `handle_lockdown` and `ProxyManager::turn_lockdown_off`  | Yes, under the proxy lock    |
| **Unblock Network** (T12)                       | `handle_unblock` in {src}`crates/bridge/src/ipc.rs`      | Yes, and takes no proxy lock |
| `hole bridge unlock` (T13)                      | `cutover::unlock` in {src}`crates/bridge/src/cutover.rs` | No: refuses                  |
| `hole bridge release-covers`, `uninstall` (T14) | `cutover::release_covers`                                | No: refuses                  |

- **Presence probe.** Unblock and untick have none: they call `release_all_covers`, which is documented idempotent, and a
  stale `Absent` is the one wrong answer at an explicit disarm. `unlock` has none on Windows, where the deletes are issued
  by key. On macOS `unlock` reads the presence first: `Absent` returns `Ok` without touching pf, and `Unreachable` or
  `Indeterminate` is an error that names `sudo pfctl -f /etc/pf.conf`.
- **Order.** Unblock and untick release first and write the records after, so a failed release leaves the intent on and
  the cover present, with Unblock still on the menu. `unlock` and `release-covers` record the target `Off` first and
  release after, so a failed `unlock` leaves the target `Off` and the intent `On`. `unlock` prints what it could not
  prove.
- **`unlock` is not Unblock Network without the app.** When it succeeds the same three records end up written (target
  `Off`, intent `Off`, candidate cleared). The differences: it disengages the standing cover only, where Unblock releases
  every cover, so a transient cover left by an older bridge stays until the next start sweeps it; it refuses while a
  bridge runs; it does not bump `unblock_generation`, since no start can be in flight; and its order and presence
  handling are as above.
- **What `unlock` detects.** It takes the liveness lock of the service's state directory only. A bridge started by hand
  keeps its own state directory and is not seen: `unlock` then records `Off` in the service directory and, on Windows,
  deletes the machine-wide filters under that bridge. `release-covers` probes the peer directories as well
  ([Uninstall](kill-switch-uninstall.md)).

`unlock` is the way out when no bridge runs, which the tray cannot reach. Its refusal message names only the in-app
action, which cannot work when the app cannot reach the bridge ([#1278](https://github.com/bindreams/hole/issues/1278)).
In that case stop the service first, then run `unlock`:

````{tab-set}
---
sync-group: os
---
```{tab-item} Windows
:sync: windows

Run `Stop-Service -Name HoleBridge -Force` in an elevated PowerShell, then `hole bridge unlock` as administrator.
```
```{tab-item} macOS
:sync: macos

Run `sudo launchctl bootout system/com.hole.bridge`, then `sudo hole bridge unlock`.
```
````

## The release contract

`failclosed::release_all` is the function behind Unblock and untick (T11, T12) and behind the sweep of `release-covers`.
It makes five promises, and each exists because a weaker one strands a user.

1. **Unconditional.** It never probes the live cover to decide whether to act, and a clean host returns `Ok`. On macOS
   "clean host" is read from Hole's own state file (`StateFile::Absent`), because pf has no query for who holds a ruleset.
   A state file lost under a live cover (an external wipe of the state directory, not a corrupt file) is therefore
   indistinguishable from a clean host, and the call answers `Ok` without touching pf. This is a
   [disclosed residual](kill-switch-recovery.md#disclosed-residuals).
1. **Total.** It clears both cover kinds. Clearing one would leave a user with no way out.
1. **No short-circuit.** Every clear is attempted before any failure is examined. The only early return is a Windows
   engine-open failure, where nothing could have been issued.
1. **No false success over a detected cover.** `Ok` means every cover the call could detect is cleared. The converse does
   not hold: it may answer `Err` over a host that is in fact open. The asymmetry is deliberate, because a false `Err`
   keeps the escape on the tray menu and the intent armed, while a false `Ok` over a detected cover is the lockout the
   function exists to remove. Promise 1's lost state file is the one `Ok` over a blocked host, and it is no violation:
   the cover left no evidence to detect. `Ok` is also qualified, by the `Clearance` it carries
   ([What `Ok` proves](kill-switch-uninstall.md#what-ok-proves)).
1. **Bookkeeping is best-effort, except the state-file clear.** The macOS `pfctl -X` refcount drop and the Windows
   sublayer and provider delete log a warning on failure: once the host's rules are restored, a refcount that will not
   drop blocks nothing, and a record kept for it would fail the same way on every retry. A cover's state-file clear is
   skipped whenever that cover's restore did not confirm, because the file is the cover's only record, and clearing it
   after an unconfirmed restore would make the next call read a clean host while the block persists. After a confirmed
   restore, a clear that cannot write is that cover's error. macOS orders the two so `pfctl -X` never runs while a
   record names its token ([Release](kill-switch-macos.md#release)). A record that could not be read is kept, after its
   restore, and the answer is an error.

Windows keeps no cover state file: the filter set is compiled-in fixed GUIDs, so nothing there can be corrupt or
version-skewed.

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

Each of these is the code's present behaviour. Where an issue is open, the behaviour is under question. Behaviours that
are transitions are rows of [Transitions](#transitions), and the rows that read against the purpose of a kill switch are
named under that table.

```{dropdown} Behaviours of the kill switch outside the table
- Lockdown ticked while connected blocks nothing until the next connect ([#1271](https://github.com/bindreams/hole/issues/1271)).
- A restart under the kill switch on macOS has to look the server up again, and the ruleset passes only TCP to the
  server's address, so a hostname server can leave the restart failing and the block in force
  ([#1286](https://github.com/bindreams/hole/issues/1286)).
- Two bridges with different state directories can run at once, and the cover's Windows filters are machine-wide, so one
  can sweep or overwrite the other's cover ([#878](https://github.com/bindreams/hole/issues/878)).
```

## Read next

- [Recovery, adoption and the cover lock](kill-switch-recovery.md): what the bridge does at startup, and what keeps two
  mutations of a cover from overlapping.
- [Windows: filters and the boot window](kill-switch-windows.md) and [macOS: the pf ruleset](kill-switch-macos.md).
- [Uninstall and the service](kill-switch-uninstall.md): how the uninstaller avoids leaving a machine blocked.
