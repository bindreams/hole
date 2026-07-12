# #553: Block-until-connected (unified fail-closed cover)

> **⚠️ SUPERSEDED — NOT the shipped design.** This spec describes the *full
> unified* design (bridge-persisted intent, lockdown-shaped TUN-permitting cover,
> engaged at bridge service start, crash/reboot-durable). What shipped for the
> beta is the **minimal-correct transient-cover** scope, authored in
> [`docs/superpowers/plans/2026-07-10-553-block-until-connected.md`](../plans/2026-07-10-553-block-until-connected.md)
> (user-ratified). The unified design here is deferred to **bindreams/hole#619**
> (full always-on posture). Read the plan, not this file, for the shipped #553.

**Status:** SUPERSEDED by the 2026-07-10 minimal-correct plan (unified design → #619).
**Issue:** bindreams/hole#553 — ratified privacy blocker for the next beta.
**Approach:** Unified (bridge-persisted intent + lockdown-shaped cover, one
mechanism). **Failure mode:** stay blocked (fail-closed). Supersedes the earlier
B-vs-C fork (both rejected: the transient cover can't permit the TUN and
collides with lockdown on macOS).

## What this closes (verified by the 2026-07-09 evaluation)

One mechanism closes every window a user who *intends to be connected* leaks in:

1. **Boot → tunnel-up, incl. pre-login** — the literal #553 window, plus the
   pre-login gap that a GUI-triggered cover can't reach.
1. **AlwaysConnect + lockdown-off leaks on every boot** (evaluation weakness #3,
   the widest routine exposure).
1. **Post-update relaunch reconnect** — same `arm_startup_auto_connect` path on
   the relaunched GUI (evaluation weakness #3, second half).
1. **macOS lockdown not reboot-durable** (evaluation weakness #1) — folded in
   because the cover now re-engages from persisted intent at bridge service
   start on macOS, not only at connect.

It also lets the **dead transient `install_failclosed_cover` (~350–450 LOC) be
deleted wholesale** (evaluation §5 overengineering), resolving the ambiguity the
evaluation flagged.

Out of scope (tracked separately, not silently dropped): #556 unbounded
teardown, #529 macOS per-UID GUI (this design is bridge-side so it does not need
per-UID GUI), the update-pipeline release-gate items (consent dialog, Windows
cutover recovery) — those are sibling PRs, not part of this one.

## Core model

Block-until-connected is **not a new user setting**. It is *derived* from the
existing `on_startup` policy: the intent is on exactly when the persisted
`StartupBehavior` implies a connect —

- `AlwaysConnect` → intent on
- `RestoreLastState` and last state was connected → intent on
- `DoNotConnect` / `RestoreLastState`-was-disconnected → intent off

The GUI is the source of the derived intent; the **bridge owns enforcement**
(engage/release/persist), mirroring exactly how the standing lockdown works
(GUI toggle → `SetLockdown` → `bridge-lockdown.json` → bridge enforces).

### Two intents, one cover shape

|                    | Standing lockdown (#527, exists)    | Block-until-connected (#553, new)                                                                           |
| ------------------ | ----------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Armed by           | explicit user kill-switch toggle    | derived from `on_startup`                                                                                   |
| Engage point       | on connect, after `routing.install` | **at bridge service start** (boot, pre-login) and at each connect attempt while intent-on-and-not-connected |
| Release point      | user disconnect only                | **connect success** (`routing.install` rendezvous); user disconnect/cancel                                  |
| While disconnected | stays engaged (blocks)              | stays engaged (blocks) — this is the point                                                                  |
| Reboot durability  | required                            | required                                                                                                    |

Both use the **same lockdown-shaped OS cover** (permit loopback + TUN + onward
server + resolver IPs + —Windows— Hole App-IDs; block all else). They differ
only in *lifecycle*. On macOS this MUST be a single composable pf ruleset (the
evaluation verified transient+lockdown covers collide on the singular main
ruleset); on Windows they are independent WFP filter sets keyed by distinct
GUIDs. See "macOS composition" below.

### Why lockdown-shaped, not the transient cover

The transient `install_failclosed_cover` permits loopback + server and
**explicitly not the TUN** (routing.rs:412-414). Engaging it around a connect
would hard-break the tunnel the instant `routing.install` brings TUN routes live
(TUN-routed egress classifies on the TUN LUID with no permit) — a connectivity
break, not a leak cover. #553 needs the TUN-permitting lockdown shape, held
*through* the connect and released only once the tunnel is up.

## Persisted state

New `bridge-blockuntilconnected.json` (sibling of `bridge-lockdown.json`,
owner-chowned, last-writer-wins):

```
{ "enabled": bool, "resolver_ips": [IpAddr], "server_ip": Option<IpAddr> }
```

- `resolver_ips` = the config's `dns.servers`, so a pre-login boot engage can
  permit the DoH bootstrap the eventual connect needs. Stable across server
  switches; the boot-time cover permits loopback + `resolver_ips` and blocks all
  else, with the concrete `server_ip` added when a Start resolves it.
- `server_ip` = last-resolved onward server IP, a best-effort optimization so a
  reboot re-engages with the server already permitted; refreshed on every
  successful resolve. Never trusted for anything but a permit (widening only).

Armed by a new IPC verb **`SetBlockUntilConnected { enabled, resolver_ips }`**
(`POST /v1/block-until-connected`), pushed by the GUI whenever `on_startup` or
`dns.servers` changes and once at GUI startup (idempotent, last-writer-wins).

## Lifecycle

### At bridge service start (boot, pre-login — both OSes)

The Windows service (`HoleBridge`, AutoStart) and macOS launchd daemon
(`com.hole.bridge`, RunAtLoad) both start before any login. After the IPC socket
binds and `recover_routes` runs:

1. Read `bridge-blockuntilconnected.json`. If `enabled` and no tunnel is up,
   **engage the lockdown-shaped cover** from `resolver_ips` (+ `server_ip` if
   present), owner-chowned. Fail-FATAL is wrong here (no user to see it, and the
   bridge must stay up to serve the GUI) → engage failure is logged + surfaced
   via Status; the host is then uncovered but the bridge runs (see failure
   modes). This is the reboot-durable re-engage that closes weakness #1 on macOS
   and the pre-login window on both.
1. The proxy is NOT auto-started here — connect stays GUI-driven via the #458
   reconciler. The cover simply holds the line until that connect succeeds.

### At connect (GUI issues Start via the reconciler latch)

`ProxyManager::start_inner`, with the intent on:

1. Ensure the cover is engaged (it usually already is from boot; a mid-session
   arm engages it now). Permit set widens only.
1. DoH resolves the server (permitted by `resolver_ips`); **widen** the cover to
   add the resolved `server_ip` (Windows add-filter; macOS atomic ruleset
   reload) and persist it. Add-only — no fall-open instant.
1. Phases proceed under the cover (plugin, SS, self-test, probe, dispatcher).
1. `routing.install` brings TUN routes live — the cover already permits the TUN,
   so no break.
1. **Release rendezvous:** once `RunningState` is fully built (tunnel up), the
   block-until-connected cover's job is done. If the standing *lockdown* intent
   is also on, hand off to the standing lockdown cover (already engaged in the
   existing flow); otherwise disengage. On macOS this is a ruleset transition,
   not a flush+reload (see composition).

### On connect failure / cancel

- **Failure (any Err):** stay blocked. The cover is retained (moved to a
  `ProxyManager` field), host stays fail-closed. Surfaced via Status → blocked
  UX. Lifted only by a later successful connect, user disconnect, or user
  cancel. (User's ratified decision.)
- **Cancel** (`ProxyError::Cancelled`, #465/#471 attempt-scoped): user
  interaction → release the cover (same trust as a user disconnect).

### On user disconnect

`handle_stop` releases the block-until-connected cover unconditionally
(user-approved opening) — same trust model as lockdown's `UserStop`.

## macOS composition (the collision fix)

The evaluation verified (major) that on macOS the transient and lockdown covers
cannot coexist: engage flushes the singular pf main ruleset and Drop reloads
`/etc/pf.conf`. Resolution: **one cover object on macOS** whose permit set is the
union (loopback + resolver + server + TUN-once-installed) and whose *kind*
transitions block-until-connected → standing-lockdown (or → released) at the
release rendezvous by an **atomic `pfctl -f` reload of the new ruleset**, never a
flush-then-reengage. The pf enable token refcount is held across the transition.
This same single-object design is what makes the cover reboot-durable: the
launchd daemon re-engages it at RunAtLoad from persisted intent.

On Windows the covers are independent WFP filter sets (distinct fixed GUIDs),
`FLAG_PERSISTENT`, BFE-enforced from boot — already reboot-durable; the
block-until-connected GUID set is swept/re-adopted by `recover_cover`.

## Probe interplay

`proxy_manager.rs` already suppresses the censorship misreport when Hole's own
lockdown cover is active (`cover_active`, ~line 869). Extend the predicate to
"block-until-connected cover engaged for this attempt" so a covered connect
cannot misreport its own cover as network censorship.

## UX (GUI)

- `BridgeResponse::Status` gains a `blocked_until_connected` state (shape at plan
  time; flows through `ProxyStateCell` → tray + `proxy-state-changed`, alongside
  the existing `lockdown_enabled`/`lockdown_active`).
- Tray icon/menu + dashboard render **"Blocked — connect failed"** with the two
  escapes: **Retry** (re-attempt under the cover) and **Disconnect** (release the
  cover, go open). Distinct from the plain Disconnected state.
- Toast on entering the blocked state (PII-free — no host, no path).
- The "engage failed → uncovered" state is a distinct, louder surface (the one
  case where intent-on does not mean protected).

## Failure modes (explicit)

- **Boot engage fails:** log + Status surface + bridge stays up uncovered. Not
  FATAL (no user present; bridge must serve the GUI). This is the only
  intent-on-but-unprotected state and it is surfaced loudly, never silent.
- **Connect fails:** stay blocked (above).
- **Bridge crash while blocked:** persisted intent + `recover_cover` re-engage on
  next bridge start — fail-closed across the crash (unlike today's transient
  sweep-to-open). This is the durability that closes weakness #1.
- **Whose-config-at-boot:** the persisted `resolver_ips`/`server_ip` from the
  last session; a server switch while disconnected updates them via
  `SetBlockUntilConnected` before the next boot. Stale `server_ip` only ever
  under-permits (a re-resolve widens it), never over-permits.

## Test plan (TDD)

- `protocol_tests`: `SetBlockUntilConnected` + `Status.blocked_until_connected`
  serde (defaults, roundtrip, elevation re-serialize path).
- `blockuntilconnected_state` (new, mirrors `lockdown_state`): persist/load,
  owner chown, last-writer-wins, resolver/server fields.
- `proxy_manager_tests` (mock `Routing` counts engages): boot engage when intent
  on / never when off; connect widens permit with server IP (recording-fake:
  add-only, never disengage-then-engage); release on success; **stay blocked on
  failure**; user stop releases; cancel releases; lockdown-intent handoff at
  release (no open gap); engage-failure surfaces + continues.
- Platform cover spec builders (pure, no OS): Windows block-until-connected spec
  = lo + resolver + server (+ App-IDs) permits over the block, weight
  arbitration per #531's lesson; macOS single composable ruleset text +
  transition-not-flush ordering.
- `ipc_tests`: `handle_set_block_until_connected` persists; boot-start engage
  reads it; `Status` exposes the blocked state; stop clears it.
- `tray_tests`: latch-applied connect runs under intent; blocked-state actions
  (Retry re-attempts, Disconnect releases); `SetBlockUntilConnected` pushed on
  `on_startup`/`dns.servers` change.
- Privileged real-engage lane (elevated Windows + root macOS, #527 pattern):
  boot-shaped engage against an unreachable server leaves the REAL cover engaged
  and egress blocked (incl. plaintext DNS); user stop opens it; macOS reboot
  durability exercised via re-engage-from-state. (#531's lesson: arbitration
  bugs are invisible to spec tests.)

## Invariants respected

- Cover I/O through the `Routing` trait only (clippy-enforced).
- Cooperative cancel tokens; no new `CancellationToken::new()` in bridge.
- No sleeps/timeout-polls; rendezvous primitives only (the release is the
  `routing.install` success edge, not a timer).
- UDP-drop policy untouched.
- `#[skuld::test]` + per-test subscribers.
- Deletes the transient cover + its stale docs; corrects `failclosed.rs:1-4` /
  `routing.rs:414` forward-references.
