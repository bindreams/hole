# macOS: the pf ruleset

On macOS the cover is a pf ruleset that the bridge loads by running `pfctl`, because pf has no programmatic API and
`pfctl` text I/O is the interface. It lives in {src}`crates/tun-engine/src/routing/failclosed/macos.rs`, whose module doc
is the reference for each pf argument: it names the constant or function that owns every claim and the test that holds
it. This page is the shape of it. It assumes [the kill switch](kill-switch.md).

## The ruleset

`build_lockdown_main_ruleset(tun_name, server_ip, nat_snapshot)` returns the whole main ruleset, loaded with `pfctl -f -`
and never with `-Fa`:

```text
set block-policy drop
set skip on lo0
<the host's nat rules, carried forward>
pass out quick on lo0 all no state
pass in quick on lo0 all no state
pass out quick proto tcp from any to <server> no state
pass out quick on <utunN> all no state
block drop out quick inet6 all
block drop out quick all label "hole-lockdown"
```

- **The ruleset is the host's whole egress policy while it is in force.** `set` lines are legal only in the main
  ruleset, and the host's `nat` rules (captured with `pfctl -sn`) are carried forward so the session does not flush
  translation. Order is `require-order`: options, translation, filter.
- **The server permit is by address and TCP only.** pf has no per-process match, so there is no equivalent of the Windows
  App-ID permit, and the source comment records that UDP is to be added "once a UDP-transport plugin lands". The permit
  precedes the IPv6 block so an IPv6 server is not killed.
- **The TUN permit names the kernel-assigned `utunN`**, read back from `TunIdentity` for the session.
- **The label is load-bearing.** `hole-lockdown` is the only evidence of a live cover that does not come from the state
  directory, and `lockdown_cover_presence` reads it back out of `pfctl -s labels`. Without it presence is file-only, which
  cannot produce `Live`.
- Neither ruleset carries a `block in`, so the cover blocks outgoing traffic only.

### Loopback twice, and `no state`

Loopback is exempted by `set skip on lo0` and by explicit `pass` rules, and both are mandatory. `pfctl` clears every
interface's skip flag at the start of a load, before it parses and before the rules commit, so across that span loopback
is filtered again while the *previous* ruleset is authoritative. If that ruleset is a live cover, loopback meets its block
and is discarded, which stalls an `ssh -L` forward or an IDE socket. Rules live inside the load's ticket and stay
authoritative until commit, so the *outgoing* ruleset's own loopback pass is what carries loopback across the *next*
load. The passes lead the filter section because `block drop out quick inet6 all` is `quick` and would otherwise end
evaluation on a `::1` packet.

Every permit is `no state` (`permit()`). `pfctl` rewrites a bare `pass out quick ... to <ip>` into `flags S/SA keep state`, which matches only a SYN: a mid-stream segment of a permitted flow that has no state entry falls through to the
block. The tunnel the ruleset protects is already carrying traffic when the ruleset commits, so a SYN-only permit would
drop it. A matching `nat` rule makes pf create state anyway, which is harmless.

## Engage

`engage_lockdown` is persist-before-mutate. It reads `pfctl -s info`, and `engage_pf_action` picks one of three cases from
whether pf is enabled and whether a record exists:

| pf enabled | record exists | Case          | What it does                                                                                                                                              |
| ---------- | ------------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| any        | no            | `FreshEnable` | `pfctl -E` and keep its token; snapshot the host's filter (`-sr`) and nat (`-sn`) rules; persist token and snapshots; load the ruleset                    |
| yes        | yes           | `ReuseToken`  | Reuse the persisted token and snapshots. Snapshotting again would capture the cover's own ruleset as the host's                                           |
| no         | yes           | `Reenable`    | A reboot reset pf and its refcount, so the token is stale: `pfctl -E` for a fresh token, re-persist it with the same host snapshot, then load the ruleset |

The load is last in every case, so it cannot overwrite a snapshot that has not been taken yet. A cover already loaded when
a record is first written means there is no pre-lockdown ruleset left to capture, so the record says so
(`main_snapshot_captured: false`) and a restore reloads `/etc/pf.conf`. A failed load restores the host before it returns,
and the caller, which is fail-fatal, aborts the start.

`pfctl -E` is refcounted: Hole's token is Hole's hold on pf being enabled. The token is parsed from the line
`Token : <n>` that `pfctl -E` prints, on stderr or on some hosts stdout; that line is the only place pf exposes it.

The standing engage does **not** purge pf's state table (`purges_state`). `pfctl -F states` is host-wide and would kill the
tunnel the cover exists to protect, and pf matches state before rules, so a flow that already had a state entry when the
ruleset loaded keeps flowing ([#1015](https://github.com/bindreams/hole/issues/1015)).

## Release

A release restores the host, then clears the cover's record, then drops the `pfctl -E` token, and drops it only if that
clear took the record that named it. A record names only a token Hole holds, because pf can hand a freed token's value to
the next `pfctl -E` of any app, so `pfctl -X` never runs while a record names the token it drops.

- The restore is the captured snapshot, composed by `build_lockdown_restore_ruleset`, or `/etc/pf.conf` when the record
  has no captured baseline or the snapshot will not load. Neither restores `set` options: pf exposes no dump of them, so
  both restore under pf defaults.
- A failed restore leaves the block, its record and its token in place and returns the restore's own error. The ways out:
  fix `/etc/pf.conf` and unblock again (the restore is retried); `sudo pfctl -d` turns pf off, and the record stays until a
  later restore succeeds; a reboot resets pf and keeps the record, and unless the target is `Off` the boot reconcile connects and `Reenable`
  re-arms the cover. The target is `Off` after `unlock`, `release-covers` or a Disconnect. A failed release in Unblock or
  untick writes no record, so it leaves the target as it was.
- A clear that cannot write is the release's error and drops nothing, so the retry still has its token. A token that will
  not drop is logged only: with the rules restored it blocks nothing.
- A record that cannot be read is never treated as absent and never removed. After a good restore the release answers an
  error, never success.

macOS never leaves a boot-time key unproven. pf has no boot-time analogue, so `STANDING_COVER_ARMS_BOOT_TIME` is `false`
(a compile-time assertion keeps a platform from arming boot-time keys without also writing the witness), every macOS
sweep answers `Clearance::proven()`, and the witness machinery is Windows-only.

## No reboot survival

A pf ruleset does not survive a reboot, and neither does pf being enabled. After a reboot the host is open until the
bridge starts and a connect engages the cover again: the persisted record survives, `engage_pf_action` reads
"record exists, pf disabled", and `Reenable` loads the ruleset into an *enabled* pf. The boot reconcile narrows the gap by
connecting sooner, but a boot connect that fails engages nothing. Windows is meant to cover the equivalent window with
[boot-time filters](kill-switch-windows.md#the-boot-window), which has not been measured across a reboot.

## What a macOS restart under the cover has to do

A restart keeps the block but tears down the TUN device and its routes, and the new start resolves a hostname server over
DoH straight to the resolver, which the ruleset (loopback, the TUN, TCP to the previous server address) does not permit.
A hostname server can therefore leave the restart failing with the block still in force until the user chooses Unblock
Network ([#1286](https://github.com/bindreams/hole/issues/1286)).
