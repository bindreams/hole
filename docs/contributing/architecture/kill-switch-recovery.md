# Recovery, adoption and the cover lock

The standing cover outlives the process that installed it, so a new bridge starts into a host that may already be
blocked, and nothing in memory says whether that is wanted. This page covers what the bridge does about it at startup,
the claim an adopted cover leaves in the process, and the lock that serialises every change to a cover. It assumes
[the kill switch](kill-switch.md).

## What a startup measures and reads

`boot::recover_then_reconcile` runs once, after the IPC socket is bound and before it is served. It has three steps, in
this order:

1. `route_recovery::recover_and_record` calls `recover_routes`: crash recovery of routes, then the cover decision below.
1. The plugin reap kills every plugin process the state directory records.
1. `reconcile_once` drives the persisted target ([the kill switch](kill-switch.md#the-decisions)).

The cover decision reads two things. The **intent** comes from `bridge-lockdown.json`. The **presence** is measured:

- **Windows** asks `FwpmFilterGetByKey0` about every lockdown filter GUID. `Live` means *at least one* is found, because a
  sweep that was interrupted midway leaves a partial cover, and probing a single filter would call it `Absent` for ever.
- **macOS** reads the rule label `hole-lockdown` back out of `pfctl -s labels`, and falls back to the record
  `bridge-lockdown-pf.json` when pf cannot be asked.

Windows can produce `Live`, `Absent`, `Indeterminate` and `Unreachable`; macOS produces `Live`, `Recorded`, `Absent` and
`Unreachable`. The facade is {src}`crates/tun-engine/src/routing/failclosed.rs` (`lockdown_cover_presence`).

## The decision

`decide_cover_recovery(intent, presence)` in {src}`crates/tun-engine/src/routing.rs` is a pure function over the two
axes. Four rules produce it:

1. `Absent` and `Unreachable` always give `Noop`.
1. `Sweep` needs intent `Off` and a presence of `Live`, `Recorded` or `Indeterminate`. It is the only action that removes
   protection, and the only one that touches the operating system.
1. `Adopt` needs one of those presences and an intent of `On`, `Unreadable` or `Unset`; `Unset` additionally needs
   positive evidence (`Live` or `Recorded`), because no record plus an unusable answer is no evidence in either direction.
1. The intent file is repaired to `enabled: true` only for `Unset` over `Live`, and never over `Unreadable`: that record
   already reads armed and may hold the user's `Off`, which a write would turn into `On`.

| Intent       | `Live`               | `Recorded` | `Indeterminate` | `Absent` / `Unreachable` |
| ------------ | -------------------- | ---------- | --------------- | ------------------------ |
| `On`         | Adopt                | Adopt      | Adopt           | Noop                     |
| `Off`        | Sweep                | Sweep      | Sweep           | Noop                     |
| `Unset`      | Adopt, repair intent | Adopt      | Noop            | Noop                     |
| `Unreadable` | Adopt                | Adopt      | Adopt           | Noop                     |

A sweep of the *transient* cover (`recover_cover`) runs after this, unconditionally and outside every presence branch,
and is told whether the standing cover is being adopted so that macOS skips the `/etc/pf.conf` reload that would wipe it.
It exists for the leftovers of an older bridge. Startup therefore always touches the transient cover's objects, and
touches the standing cover only on an explicit recorded `Off`.

## What Adopt does

Adopt keeps the host blocked across the restart, and it deliberately does almost nothing. It never disengages the cover,
on either platform. It records the claim *a standing cover is live this run and this process has not released it*
(`ProxyManager::set_standing_cover_adopted`), and it does that only for a *measured* `Live`, since `Adopt` also covers
`Recorded` and `Indeterminate`, which the operating system did not confirm.

- **The volatile permits are refreshed by the next connect, not by recovery.** The TUN and server permits name the
  previous run's interface and server. Deleting them at recovery time would let a second bridge started with a fresh
  state directory delete a *running* first bridge's server permit while the block-all stayed in force, so the refresh
  lives inside `engage_lockdown`'s own transaction. Until the next connect, the adopted cover keeps a stale server
  permit; the App-ID permit already lets the bridge and plugin binaries out in that window.
- **One reclaim, Windows only.** `reclaim_stale_tun_permit` deletes the TUN permit when the TUN name no longer resolves
  to an interface. A `NET_LUID` is a type and an index, and NDIS can hand a freed index to an unrelated wintun adapter,
  which would then inherit unconditional egress from the stale permit. A name that still resolves proves a bridge may be
  using the permit, so the reclaim cannot touch a running bridge's cover. It keys on this bridge's own last TUN name from
  `bridge-routes.json`, with `WINDOWS_TUN_ALIAS` as the fallback; macOS has no analogue, because its permit names the
  interface and not an index.
- **The claim carries two facts in two places.** "A cover is live now" is the in-process claim. "The kill switch is
  armed" is `bridge-lockdown.json`, which `promote_adopted_claim` writes (over `Unset` only) the moment a start honours the
  claim with a real `install_lockdown`. Keeping both in the claim once let an ordinary settings change disarm the switch,
  because its stop-and-start cleared the claim with the cover.
- **The claim is not a latch.** It is cleared at three sites, each only on a *confirmed* release (`turn_lockdown_off`,
  a session teardown's `apply_cover_disposition`, and the boot reconcile), and never by a guard's silent `Drop`.
  `lockdown_enabled` and `standing_cover_expected` read the claim together with the intent, and an explicit recorded `Off`
  wins over the claim, so an `unlock` run while a bridge is up is not undone by a stale claim.

`effective_lockdown_intent` is the same fold for the reconcile: a claim turns anything but `Off` into `On`.

## The cover lock

Every mutation of a cover inside the bridge runs under one lock per state directory, `CoverLock` in
{src}`crates/tun-engine/src/routing/failclosed/cover_lock.rs`, whose module doc is the reference. In short:

- **What it excludes.** An engage, a guard's release or drop, a sweep and crash recovery. A decision that reads cover
  state is made from a read taken *inside* the section that acts on it. Mutators take `&CoverLock` and readers take a
  path, so a mutation without the lock does not compile.
- **One directory, one owner.** The state directory and the owner of its files are read from `Routing::state_dir()` and
  `Routing::owner()` only, so a handler's records and its cover lock cannot name different directories.
- **Order.** `state.proxy`, then the cover lock, then the record files' own locks. The lock is `!Send` and `!Sync`, so no
  future holds it across an `.await`. The tray's Unblock takes the cover lock and not the proxy lock.
- **Stamps.** A guard keeps the stamp of its install and deletes only while it is current; a sweep outdates the stamps of
  the kinds it released. A guard that outlived its cover therefore deletes nothing (Windows keys are fixed and a macOS cover
  owns one pf token).
- **Drop rule.** A guard's `Drop` is the only code that deletes. On a thread that already holds the lock it deletes under
  the held one, and otherwise it acquires.
- **In-process only.** `unlock`, the uninstall and the cutover run with no live bridge, so nothing out of process writes a
  cover record while a bridge runs, and the lock does not try to exclude it.

The cost is disclosed in code and not hidden: an Unblock waits for an engage in flight, and a start that begins during an
Unblock waits and then reads `Off`. `unblock_generation` (read by the handler before the proxy lock, compared under the
cover lock) is what makes a start whose Unblock committed in between install nothing.

## Who owns a cover

Whether a cover exists is a measurement, `Routing::lockdown_cover_presence`, and not an answer derived from session state.
A model that derived it from the session could not see a cover stranded by an unclean exit or adopted at startup, since
those facts are about the host and not about anything a live process remembers. `Posture` in `ProxyManager` still tracks
whether the manager is idle, holds a pending start or holds a session, because teardown ordering needs it, but no site
derives cover state from it. Two structural tests hold this: `no_bridge_source_derives_cover_state_from_a_session`
counts reads of the session's cover field, and `cover_release_has_the_known_sanctioned_caller_set` lists every caller of
the unconditional `release_all_covers` (`handle_unblock`, `turn_lockdown_off`, `apply_cover_disposition` and
`reconcile_once`).

## Disclosed residuals

- **A second bridge with an explicit `Off` still sweeps machine-wide.** The Windows lockdown GUIDs are compile-time
  constants, and the presence probe ignores the state directory, so it answers "is *a* Hole cover present" and never "is
  it mine". An adopted second bridge's own next connect can also replace the first one's permits. Both need a per-install
  cover identity ([#878](https://github.com/bindreams/hole/issues/878)).
- **`Unset` over `Unreachable` leaves Unblock hidden.** The routes in are the Base Filtering Engine not running or an RPC
  failure; `unlock` would fail in the same states, so the next start, once BFE answers, adopts the cover and restores the
  item.
- **macOS: an unusable state file.** A corrupt record, or one at a version this release cannot read, costs the captured
  pre-cover rules (the release falls back to `/etc/pf.conf`) and, when no token can be read out of it, leaks a pf enable
  refcount until reboot. A record that cannot be read at all is left in place, and every later release answers an error
  until it reads again. A *missing* record reads as "no cover of this kind", and `release_all` answers `Ok` over a
  labelled cover that has no record, because it has no snapshot to restore.
- **An unreadable `bridge-lockdown.json` has two folds.** `reads_armed` (`On` or `Unreadable`) drives the status reply and
  the tray, so a corrupt record keeps Unblock on the menu. `installs_standing_cover` (`On` only) drives the connect path,
  so the same record installs nothing at connect, and the tray can read `Lockdown: On (warning: not engaged)`.
