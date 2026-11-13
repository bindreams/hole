# Windows: filters and the boot window

The Windows cover is a set of filters in the Windows Filtering Platform (WFP), written by
{src}`crates/tun-engine/src/routing/failclosed/windows.rs`. This page is the long reference for it: the filter set, the
weight arbitration, and the part that needs argument, covering the window between the kernel starting and the Base
Filtering Engine (BFE) starting. The module doc of that file is only a short summary that points here. It assumes [the
kill switch](kill-switch.md).

## The filter set

`build_lockdown_spec` is a pure builder of the data that `engage_lockdown` installs, in one FWPM transaction, under a
provider and a sublayer with fixed GUIDs:

| Filter                            | Layer                            | Condition                                    | Lifetime   |
| --------------------------------- | -------------------------------- | -------------------------------------------- | ---------- |
| Loopback permit (flag)            | `ALE_AUTH_CONNECT_V4`, `_V6`     | `IS_LOOPBACK`                                | persistent |
| Loopback permit (range)           | `ALE_AUTH_CONNECT_V4`, `_V6`     | remote address in `127.0.0.0/8`, `::1/128`   | persistent |
| Loopback permit (accept)          | `ALE_AUTH_RECV_ACCEPT_V4`, `_V6` | remote address in `127.0.0.0/8`, `::1/128`   | persistent |
| TUN permit                        | `ALE_AUTH_CONNECT_V4`, `_V6`     | local interface LUID                         | persistent |
| App-ID permits, one pair per path | `ALE_AUTH_CONNECT_V4`, `_V6`     | the plugin binary, and the bridge executable | persistent |
| Server permit                     | the server address's own family  | remote address is the server                 | persistent |
| Block-all                         | `ALE_AUTH_CONNECT_V4`, `_V6`     | none                                         | persistent |
| Block-all boot-time twins         | `ALE_AUTH_CONNECT_V4`, `_V6`     | none                                         | boot-time  |

**Why the loopback permits are matched by address range.** `IS_LOOPBACK` is not reliably set at either ALE layer under an
elevated token, so a permit that relied on the flag alone left a loopback connect blocked and its accept side dropped.
The range matches deterministically. The flag permit is kept at CONNECT as a harmless second match, and loopback needs the
accept side because a loopback connect is authorised in both directions.

**One sublayer, arbitrated by weight.** The permits sit at `PERMIT_WEIGHT` and the block-all at `BLOCK_WEIGHT`, so within
the sublayer the higher-weight permit wins. No persistent filter sets `CLEAR_ACTION_RIGHT`, which makes every persistent
action *hard*. This is the recipe wireguard-windows uses: its loopback, TUN and DHCP permits and its block-all are weight-ordered with
the flag off, and it sets the flag only on its own service App-ID permit, and Hole sets it on no persistent filter. An earlier layout put the flag on the permits and not on the
block-all, and the block-all then vetoed every permit, so the cover blocked everything. The cover's sublayer is created
with the highest weight WFP allows (`add_sublayer`). What a filter in another sublayer can still do to the cover has not
been measured here.

**Persistent, not dynamic.** A dynamic session deletes its filters when the engaging process exits, which would reopen the
host exactly when the bridge dies. Persistent filters survive a crash, and recovery deletes the compiled-in GUIDs, so recovery needs no
record of the filters themselves. The Windows cover still reads `bridge-lockdown.json` (the intent) and writes
`bridge-boottime.json` at every engage ([the witness](#the-witness)). The DNS-egress confinement is the opposite on purpose: it is a dynamic,
process-scoped session that dies with the bridge, because a DNS block that outlived the bridge would be pure harm with no
bridge left to release it. The two lifetimes are not to be unified. FWPM calls are disallowed methods in
{src}`clippy.toml` outside the two modules that are allowed to make them.

**Every engage pre-deletes.** Inside the same transaction, `engage_lockdown` deletes the filters whose condition holds a
runtime value (the TUN LUID, the server address, the App-ID paths) and the boot-time twins, then adds the whole set.
Without it, an add over a leftover would short-circuit on `FWP_E_ALREADY_EXISTS` and keep the previous engage's value: the
pre-update `hole.exe` path after a cutover, or a twin spent by the boot it covered. `add_filter` also refuses a duplicate
on such a filter. The persistent block-all is never in the pre-delete set; it stays live through the transaction. A
pre-delete that returns a code other than success or not-found aborts the engage, which means "cannot connect" and never
"leaks".

## The boot window

A persistent filter is not enforced from boot. BFE re-adds it when BFE starts, and between the kernel starting (tcpip.sys)
and BFE starting only `FWPM_FILTER_FLAG_BOOTTIME` filters apply. A persistent-only block-all therefore left an armed host
open on every reboot. So the standing cover's block-all pair also has **boot-time twins**. The two flags cannot be set on
one filter, so the twins are two more filters, and WFP documents the hand-off between the two kinds as atomic.

- **The twins carry the block and nothing else.** No loopback, TUN, server or App-ID permit is twinned: the TUN and server
  permits hold values nothing can refresh before BFE, a boot-time loopback or App-ID permit would have no hand-off to its
  persistent counterpart, and the leak being closed is network egress. The window is a total egress block with no
  exemptions. It is egress-only: the twins sit at `ALE_AUTH_CONNECT` and nothing is added at `RECV_ACCEPT`.
- **They are pre-deleted, never merely re-added.** A boot-time filter is spent by the boot it covered, and if the spent
  object survives with its key occupied, an add would report `FWP_E_ALREADY_EXISTS`, be read as success, and the switch
  would arm once and silently stop. Deleting the key first is correct under both readings of what BFE does.
- **The flag and the sweep's classification are one value.** `FilterLifetime` is a newtype over `KeyLifetime` with a
  private field. `filter_flags`, the crate's only producer of the filter's flag word, and the lifetime a sweep records for
  the key both read it, and the twins' key, layer, label and lifetime all come out of one `LOCKDOWN_BOOTTIME_TWINS` entry.
  Installing a boot-time filter whose key a sweep calls persistent is not expressible.
- **They reference the same provider and sublayer as the persistent filters.** That is a measured choice, not a
  documented one: WFP accepts it and stores the record with our provider and sublayer.

### The soft block, and what it costs

The twins are `Action::Block` *with* `CLEAR_ACTION_RIGHT`, so the block is **soft**: a higher-weight permit in another
sublayer can win. The flag is set on the boot-time arm of `FilterLifetime::filter_flags` and nowhere else. The reason is
that this window carries no permit of Hole's at all, so a hard block would be unoverridable by anything, including whatever
a host needs to finish booting and reach the BFE start that lifts the block (a PXE or iSCSI boot, a volume unlock against
a network key server). The flag is permission to be overridden, not a guarantee that anything will override: whether the
pre-BFE kernel arbitrates boot-time filters across sublayers at all, and whether an early-boot path ships a filter that
would win, has not been established. A soft block narrows the hazard for a host whose boot needs egress and does not
close it. The privileged lane asserts that WFP stores `BOOTTIME` and `CLEAR_ACTION_RIGHT` together rather than rejecting
the pair or dropping the flag.

```{warning}
The override runs both ways. The same higher-weight permit that lets a host finish booting also lets an ordinary
outbound flow leave an armed host, unencrypted and outside the tunnel, in the very window the twins exist to cover.
Windows provisions a boot-time policy of its own, and what a boot-time policy holds is permits. One unknown decides both
directions, whether the pre-BFE kernel arbitrates boot-time filters across sublayers at all, so the two hazards cannot be
traded apart. The owner took an unbootable host as the worse outcome; a leak in that window is the disclosed price.
```

The persistent half is unaffected in both directions. A boot-time filter is enforced only before BFE starts and the
persistent set exists only after, so the two are never arbitrated against each other, and a boot-time filter is absent
from the default enumeration view while it is live.

### Shipped precedent

What the twin pair, the block-only choice and the soft block rest on besides Hole's own reasoning. This is a reading of
other projects' source, made when the twins were designed and not re-checked since.

- **Twins.** Mullvad and TinyWall each install a rule twice, `BOOTTIME` and `PERSISTENT`, under their own persistent
  containers. TinyWall is cited for that shape only; its boot-time rule set was not read.
- **Blocks only.** Of the two boot-time rule sets that could be read, Fort Firewall's and Mullvad's, every filter is a
  block. Neither ships a boot-time permit.
- **Soft or hard.** Fort's boot-time blocks are soft, for the reason above. Mullvad's are hard. Fort also puts its
  boot-time filters in the default sublayer and its persistent ones in its own, which is consistent with treating the
  cross-sublayer question as a hazard; no Fort filter names a provider, so that is no evidence about Hole's provider.
- **When the block goes in.** Mullvad's boot-time blocks go in as the daemon shuts down under a blocking policy and are
  swept by provider enumeration on the way back up. Hole's go in at every engage and stay for as long as the kill switch
  is armed, a much wider window for a version skew to strand one.
- **Without boot-time filters.** wireguard-windows defines the boot-time flag and never uses it: its blocker runs a fully
  dynamic session under a per-run random provider GUID. OpenVPN's WFP blocker sets the dynamic-session flag, with the
  comment that its filters do not survive reboots or crashes. wireguard-windows was read closely because Hole takes its
  weight recipe from it, which is grounds for trusting that the survey did not miss a boot-time use, not for claiming its
  authors weighed boot-time filters and rejected them. Neither project ships an always-on kill switch meant to survive
  an arbitrary reboot, which is the requirement that makes `PERSISTENT` alone insufficient.

## Evidence about a boot-time key

A boot-time key has two things behind it: the runtime FWPM object, live only between kernel start and BFE start (or inside
the session that just added it), and the boot-time *policy record* that serves the next boot, which nothing the crate can
call reads. Every read available (a delete's code, a `BOOTTIME_ONLY` enumeration, `netsh wfp show boottimepolicy`) goes
through BFE. So three questions are answered separately, and the rule is symmetric: absence of evidence is never evidence
of absence, in either direction.

- **Armed.** Only a read of the boot-time enumeration view while the object is live. A commit code says the transaction
  reached the object store and nothing about the record behind it, so after the commit `engage_lockdown` runs
  `verify_boottime_twins` and refuses the engage when every view was read and none holds the twin, or when the twin it
  finds is not boot-time or is disabled. It reads the view and not the key, because `FwpmFilterGetByKey0` would answer for any object
  under that key whatever its lifetime. Absence is concluded only from a *complete* set of readable views
  (`readback::verdict`): one view erroring makes the other's empty answer evidence of nothing, and an unreadable view never
  fails an engage, because that would stop a user with the kill switch armed from connecting.
- **Gone.** Only a delete that *removed* a live object (`KeyOutcome::Removed`), and only under an assumption: that
  `FwpmFilterDeleteByKey0` purges the boot-time record together with the runtime object. Nothing in the crate can check it,
  because only a reboot separates "purged" from "still provisioned and invisible"
  ([#1043](https://github.com/bindreams/hole/issues/1043)). `FWP_E_FILTER_NOT_FOUND` is never evidence: the key answers
  empty on a host that armed the switch years ago and on one that never did. No lifetime-specific delete exists: a
  boot-time filter is removed by the same `FwpmFilterDeleteByKey0` as a persistent one, so every by-key sweep covers the
  twins once their GUIDs are in its list.
- **Possible on this host at all.** The twins' `PERSISTENT` sibling (`KeyRole::BootTimeSibling`) is added with every twin
  and BFE re-adds it every boot, so a sibling removed at this boot says a standing cover is installed *here*, and every
  sibling answering empty says none is.

A failed read-back leaves the committed cover standing: the transaction has already committed, so `engage_lockdown`
returns `Err` with the filters installed and no guard over them. They are not orphaned, since the next start reads `Live`
and adopts them. On a clean host's first engage this is a behaviour to know about: every other application loses egress
until the cover is released, and a retry that fails the same way repeats it. The escape is in-band (Unblock Network,
`hole bridge unlock`), and the direction was chosen over claiming the switch armed over a pre-BFE window nothing covers.

### The witness

The sibling is *live evidence a sweep consumes*: it is added with its twin and never removed with it, so the sweep that
deletes it destroys the only thing that could still report a twin. Turning the kill switch off and then uninstalling is an
ordinary sequence that does exactly that. So a sweep that can still see the sibling copies the finding into
`bridge-boottime.json` (`failclosed::boottime_witness`) before it deletes, even a sweep that fails (it issues every delete
before reading any code, so it is already holding what it removed; `SweepOutcome` carries both halves, not a `Result`). An
engage records the witness the instant `FwpmTransactionCommit0` returns (`commit_and_record`), deliberately *before* the
read-back that can fail over a cover already in force.

`Clearance::leftover_keys` reports when **either** source says a twin is possible, and is silent only when both are lost: a
wiped state directory still has its sibling, and a consumed sibling still has its record. Exactly one observation clears
the record, a sweep that watched every boot-time key it touched being removed. Everything else only arms it. The module doc
of {src}`crates/tun-engine/src/routing/failclosed/boottime_witness.rs` lists the residuals (a record per state directory
describing machine-wide filters, a witness write that fails, a peer directory's `Armed` that a SYSTEM sweep does not
retract). They over-report, which costs an operator a paragraph, where the silence they replace is the stranded host.

## The provider sweep

The full sweeps (`release_all`, `disengage_lockdown`) also delete every boot-time filter under `PROVIDER_GUID` that no key
list in the running build names ({src}`crates/tun-engine/src/routing/failclosed/windows/provider_sweep.rs`), so a
downgrade cannot strand a twin that a newer build installed under a GUID this one never learned. Scope is exactly
"boot-time and ours": a persistent filter under the same provider is left alone, since a live one may be another bridge's
cover; another provider's filter is never touched. A layer is required in the enumeration (a template naming none is
refused with `FWP_E_LAYER_NOT_FOUND`), so the layers are listed from the engine and the provider is selected in code.

A delete of such a stranger that the OS refuses, and a view that cannot be read, never fail a sweep: the code records
that a live boot-time filter is not enforced once BFE has started ([below](#what-is-measured-and-what-is-not)), and
failing `unlock` or Unblock over it would keep them from recording the intent off, so the next start would re-engage the
switch. Both are reported (`Clearance::refused_strangers`, `unenumerated_views`). A refused delete arms the witness. An
unreadable view arms it only when the twin's siblings leave one possible, and otherwise only keeps an armed record from
being disarmed. A persistent filter that a later build installed under a key this build never
learned survives unlock, `release-covers` and uninstall ([#1242](https://github.com/bindreams/hole/issues/1242)).

What the sweep does not reach: `recover_cover`, the transient sweep, stays by key, because a boot-time filter under the
provider may be the standing cover's. The presence probe reads the fixed keys, so a stranger alone on a host reads
`Absent` and no start-time recovery sweeps for it; the escapes (`hole bridge unlock`, Unblock Network, the uninstall
gate) are what reach it. A build older than this sweep cannot enumerate at all.

## What is measured, and what is not

The privileged lane measures, on the real firewall and with no reboot, in
{src}`crates/tun-engine/src/routing/failclosed/boottime_privileged_tests.rs` and
{src}`crates/tun-engine/src/routing/failclosed/provider_sweep_privileged_tests.rs`:

- WFP accepts a boot-time filter under the cover's own provider and sublayer, and stores it with `BOOTTIME` set,
  `PERSISTENT` clear and both containers intact.
- A by-key `FwpmFilterGetByKey0` finds it, and `FwpmFilterDeleteByKey0` removes the *live* object (the filter leaves the
  boot-time view). The probe filter is a permit on a documentation address, never a block, so the test cannot itself block
  the machine it runs on.
- Every engage re-creates the twins while the persistent block-all beside them is not re-created.

The code also records, as measured, that a live boot-time filter is not enforced once BFE has started, and relies on it:
it is why a refused delete of an unlisted twin and an unreadable view never fail a sweep, and on it a stranded twin
affects the next boot's early window and not the running host. No test in this tree makes that measurement. The privileged
lane's probes are permits on documentation addresses, because a boot-time block could lock the machine out, so if the
measurement was made by hand, its record is not in the tree.

Nothing measures anything that spans a reboot, and the lane does not reboot:

- whether the kernel enforces a twin in the boot-to-BFE window at all (the twins name a provider and sublayer that BFE
  provisions, so what the pre-BFE kernel does with them is undocumented);
- whether a by-key delete purges the record (above);
- whether a twin covers boots after the one that follows its install. Microsoft's pages disagree on the mechanic
  (boot-time filters are "removed" once BFE initialises, or "disabled") and none addresses re-provisioning at later boots.
  That silence is recorded as silence. Every path is correct under both readings, which is why the twins are pre-deleted;
- whether the provider-filtered enumeration returns a twin on a boot later than the one that armed it;
- whether Hole's provider survives a BFE start. `add_provider` passes no service name. The code's comments quote Microsoft's
  `FWPM_FILTER0` reference: a provider's filters are disabled when BFE starts if the provider has no associated service
  name or its service is not set to auto-start. If that applies to Hole's persistent provider, the persistent half would
  come back disabled every boot. The `FWPM_FILTER_FLAG_DISABLED` bit read in the tests is not evidence either way: the filters were added
  seconds earlier, so BFE had not started since.

A stranded boot-time leftover has no self-healing path: BFE re-adds a persistent leftover at every start, so a later build
can reach it by key, while nothing re-adds a boot-time one. Hole assumes the worse branch for safety and claims the weaker
one for coverage. Sizing the worst case: both Microsoft readings agree a boot-time filter stops applying once BFE starts,
so a stranded twin blocks egress from tcpip.sys until BFE and then stops, seconds per boot. That holds for a host whose boot
does not need egress; on a network-booted machine it is unestablished and possibly worse, because a boot that never reaches
BFE never reaches the thing that lifts the block.

## Out-of-band recovery

There is no in-box way to remove a WFP filter. `netsh wfp` is diagnostics only (its verbs are `capture`, `dump`, `help`,
`set` for capture options and `show`), and none takes a filter key. `netsh wfp show boottimepolicy` shows the operating
system's boot-time policy and `show filters` lists only what is active now, which excludes a boot-time filter once BFE has
started. Seeing is not removing: the only removal API is FWPM, and the only caller on a host is a Hole build that knows the
key. Reinstalling Hole and then releasing the cover is therefore the way back, which is why the uninstaller releases the
covers ([Uninstall and the service](kill-switch-uninstall.md)). With the reinstalled service running, the release is
**Unblock Network** or unticking Lockdown in the tray: `hole bridge release-covers` refuses while a bridge runs, so it
needs the service stopped first. The genuinely unrecoverable case is narrower than "a leftover":
BFE failing to start, where `FwpmEngineOpen0` fails and both `release_all` and `bridge unlock` return an error having issued
nothing.
