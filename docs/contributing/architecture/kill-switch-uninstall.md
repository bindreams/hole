# Uninstall and the service

A persistent cover has one sharp consequence: if Hole is uninstalled while the cover is in force, nothing is left that
can remove it. On Windows the filters are persistent, BFE re-adds them every boot, nothing shipped with Windows takes
them off (`netsh wfp` has no delete verb), and the uninstaller is about to delete the only binary that could. So the
uninstall releases the covers first, and most of this page is the care taken to make that release safe and to make it
tell the truth. It assumes [the kill switch](kill-switch.md). From [The Windows service stop](#the-windows-service-stop) on, the page is
about the service's lifecycle and not about the cover; stop before it if your question is the kill switch.

## The three releases

| Door                                                                                        | Refuses against a live bridge? | Failure is fatal for                                                         |
| ------------------------------------------------------------------------------------------- | ------------------------------ | ---------------------------------------------------------------------------- |
| `hole bridge unlock` (`cutover::unlock`, T13)                                               | Yes, the service's bridge only | The whole command                                                            |
| `hole bridge release-covers` (`cutover::release_covers`), and `hole bridge uninstall` (T14) | Yes                            | The target write and the release itself; the trailing bookkeeping only warns |
| The in-process doors (Unblock, untick; T12, T11)                                            | No: they run inside the bridge | Their request                                                                |

What each door releases is in [Transitions](kill-switch.md#transitions).

`unlock` clears only the standing cover because the transient cover's authority inside a live bridge is that bridge's own
posture, and an out-of-process delete would leave it claiming a cover that no longer exists. The uninstall is wider,
because no later bridge start exists to sweep a transient cover that an earlier crash stranded. The desync is prevented
structurally, not by ordering: both out-of-process doors take the bridge's **liveness lock** (`BridgeLiveness::try_acquire`),
the lock a running bridge holds for its whole life, and refuse when it is held. A lock held across the whole sequence also
stops a bridge that starts mid-way from having its live cover restored away.

The lock is per state directory, and the Windows covers are machine-wide. `unlock` probes the service's directory only.
`release_covers_with` probes the service's directory and every directory a foreground or elevated non-`--service` run can use (`peer_state_dirs`). Each one is locked,
including one that does not exist yet, since a peer left unlocked because it looked absent is a peer nothing excludes. A
path already probed is skipped, because the lock contends per open handle. The cost is kept and not cleaned up: an empty
`hole/state` holding a `bridge-liveness.lock` stays behind on an account that never ran a bridge. Removing it could only
happen after the peer locks are released, which is the moment a blocked bridge wakes and starts writing its own cover
record there, and a deleted record is the stranded-cover end state this path exists to prevent.

The release deletes no file. `scripts/network-reset.py`, the out-of-band escape for a host with no working bridge, reads
`bridge-routes.json` and the DNS records from the state directory to undo a leaked bypass route or a rewritten adapter's
DNS. An uninstall is the moment those become the only escape. What the release leaves on an installed host is
`bridge-target.json` reading `Off` and `bridge-lockdown.json` reading `Off`.

## The order of an uninstall

`uninstall_bridge_with` in {src}`crates/hole/src/setup.rs` runs its effects in this order, and none short-circuits another,
so the error names every failure:

1. **Take the start-type lock** (Windows; see below). If it cannot be taken, the stop and the deregistration are skipped,
   the uninstall fails, and the release still runs, since it never touches the start type.
1. **Stop the bridge.** It is gated on nothing. Whether a bridge runs and whether a registration record names it are
   independent facts, and the covers are held by the live process, not by the record. Gating the stop on the record made an
   uninstall a dead end: `DeleteService` on a live service *succeeds* by marking the row for deletion, after which the
   record reads as absent, every retry skipped the teardown, and the liveness lock refused the release for ever. On both
   platforms the stop is the act followed by a classification of what it left behind, never a probe before it and never the
   act's exit code: the job can leave the service manager between a probe and the act (a concurrent uninstall, an operator's
   own stop, the daemon exiting), and `launchctl bootout` of a label launchd does not have exits with neither 0 nor the
   "no such service" status. Only an answer taken after the act is about the world the act left.
1. **Deregister the service**, only after a *confirmed* stop and only when something is registered. An unconfirmed stop
   leaves the registration alone, because it is the only handle a later attempt has.
1. **Release the covers**, unconditionally unless `--keep-covers` is passed. It is never gated on registration and never
   skipped because an earlier step failed. Recording the target `Off` before the release is what makes a late failure
   safe: whatever happens after, a later start releases the cover (T16 in [Transitions](kill-switch.md#transitions)).

On macOS the uninstall runs only when the user takes it: the tray's **Uninstall Helper** runs `hole bridge uninstall`
elevated. Dragging the app to the trash runs none of this and leaves the launchd job, the helper and any cover in place,
which is survivable because pf does not survive a reboot.

## What the MSI guarantees

{src}`msi-installer/src/msi_installer/hole.wxs` wires the order, and {src}`msi-installer/tests/test_hole_wxs.py` holds the wiring.

- **`BridgeRelease` is `Return="check"`**, uniquely among the uninstall actions, so a failed release aborts and rolls the
  uninstall back with `hole.exe` still in place. A service that will not deregister is untidy; a cover that will not
  release is a lockout. The trailing bookkeeping only warns, since failing there would roll back an uninstall over a host
  that is already open.
- **An upgrade skips it.** `BridgeUninstall` passes `--keep-covers` and `BridgeRelease` is conditioned on `NOT UPGRADINGPRODUCTCODE`, because the standing cover is what holds the update-cutover gap (T10 in [Transitions](kill-switch.md#transitions)).
  `bridge release-covers` and the `--keep-covers` form of `uninstall` are hidden CLI surfaces: the uninstaller is their only
  sanctioned caller.
- **`MajorUpgrade Schedule="afterInstallInitialize"`.** An upgrade that leaves covers in force is survivable only if a failed
  upgrade puts the old product back. WiX's default removes the old product outside the new install's transaction, which
  leaves the filters in force and no binary. This placement puts `RemoveExistingProducts` inside the transaction, so a rollback
  reinstalls the old product, and it does so before the new files land over a service that still holds `hole.exe` open.
- **`BridgeUninstallRollback`** re-runs `bridge install` if the uninstall rolls back, because `BridgeRelease` can abort
  after `BridgeUninstall` has already torn the service down. Its return value is ignored by MSI, so it can only add
  recovery. The deleted service has no start type left to read, so an administrator's setting is not carried across.
- **`LEAVE_NETWORK_BLOCKED=1`** skips the release and so leaves every cover in place. It is the escape from the escape: a
  release that can never succeed (BFE stopped, `hole.exe` quarantined) would otherwise make the product unremovable. The
  way back from the block it leaves is to reinstall Hole and then release the cover from the running bridge (T11 or T12
  in [Transitions](kill-switch.md#transitions)). `hole bridge release-covers` (T14) refuses while the reinstalled service
  runs, so it needs the service stopped first ([#1289](https://github.com/bindreams/hole/issues/1289)).

The release runs against a dead bridge on purpose: the service is stopped first, so no in-process posture is left claiming
a cover that no longer exists.

## What `Ok` proves

A delete by key answers one of three things (removed, not found, failed), and "not found" was long read as benign. For a
persistent filter that is sound, because BFE's store is the key's only record. For a boot-time filter it proves less: a
boot-time object is live only between kernel start and BFE start, so on a later boot the key answers "not found" whether or
not a policy record survives behind it, and on the boot where uninstall matters most (installed in an earlier session,
uninstalled without connecting) every such key answers empty. A bare `Ok` once told the MSI it was safe to delete the only
binary that could act on that.

So `release_all` and `disengage_lockdown` return a `Clearance`. `Ok` still means no delete failed; `Clearance::is_proven`
is the narrower claim that every empty answer *proved* its key empty. It is `#[must_use]`, and the lifetime rides on the
swept key itself (`SweptKey`) and not in a parallel list that could drift. An unproven key does **not** fail the release:
a stranded boot-time record blocks egress across the boot-to-BFE window only, and refusing the uninstall over it would
trade a bounded early-boot block for a permanently unremovable product.

What replaces the silence is `release_clearance_report`, which `release-covers`, `uninstall` and `unlock` print. It reads
`leftover_keys` (the witness-gated set, see [Windows](kill-switch-windows.md#the-witness)) and not `unproven_keys`, which
would fire on essentially every Windows uninstall and teach operators to ignore the one host where it is real. It states
what the keys are and does not assert a leftover is present, because an unproven key is equally consistent with never
having been installed. It names `netsh wfp show boottimepolicy` to *see*, says outright that `netsh wfp` cannot remove, and
names reinstalling the running build's own release as the only remedy, since only a build whose key list names a key can
delete it. It runs at the last moment a Hole binary exists to say anything, so what it says has to be runnable. The in-process
escapes (`disengage_lockdown`, `turn_lockdown_off`, Unblock) share the blind spot and deliberately do not gate on it: the
binary stays on disk, the next engage installs the key again, and `unlock` stays reachable. `Routing::release_all_covers` is the
one site sanctioned to drop the `Clearance`.

## The Windows service stop

How the uninstall stops the bridge service and waits it out. It matters to anyone who changes that code.

```{dropdown} The stop contract
The bridge service carries restart-on-failure, so a killed bridge goes STOPPED, START_PENDING and RUNNING again within
seconds, and the SCM refuses a stop in every state but RUNNING. A stop decided from a state read before the act loses that
race. The contract, with the reference in the module docs it points at:

- **One SCM session, decided by observation.** `service_scm::retire::retire`
  ({src}`crates/bridge/src/service_scm/retire.rs`) opens the service once and runs *harden, settle, then restore or
  delete*. Hardening writes the record that the disable is ours, disables the start type and turns restart-on-failure off,
  because the SCM documents that a service must be explicitly disabled to stop it restarting. `settle_stopped`
  ({src}`crates/bridge/src/service_scm/settle.rs`) then loops over *looks* at the service, and each decision is taken on a
  look; every wait is set up before the act it waits for, or set up and followed by a confirming look. Nothing is
  concluded from a wait expiring, and no wait has a count.
- **The process, not the state, is what is waited out.** The SCM reports STOPPED before the process has exited, and the
  process id is not valid once it has. Processes the service shows are opened while named (`hold.rs`), and the settle ends
  only on a host-wide scan that finds no process carrying the service's token (`scan.rs`). Orphans (a plugin left by a crash,
  a cutover child) are terminated once the SCM reports STOPPED, and nothing is terminated before. A bridge that never exits
  on its stop hangs the uninstall: no bound is built.
- **The service SID is the identity.** A process id the SCM names is a claim, so `hole bridge install` gives the service a
  service SID, which the SCM puts in the token of every process it starts as the service, and children inherit it. A
  process is held only if its token carries it. The bridge also ensures the SID type at startup, since an in-app update is
  run by the old release's code. The gap is the one window after an update from a release without it, closed at that host's
  next service start.
```

## The Disabled service and its record

Why a retirement disables the start type, and how an interrupted one is told apart from an administrator's Disable.

```{dropdown} The record and the repair table
A retirement disables the start type so STOPPED is final, then restores it. A process killed in between would leave a
Disabled service that looks exactly like one an administrator disabled, and the two want opposite treatment. Two writes
cannot be one, so `disable_record` ({src}`crates/bridge/src/disable_record.rs`) holds a record, the registry value
`HoleDisabledByHole` under the service's own key, written *before* the Disabled write and cleared only *after* the start
type is written back or the service is deleted. Its presence is the fact. Record and start type together decide, one
exhaustive match (`RepairStep::of`):

| Record  | Start type   | Repair                                                       |
| ------- | ------------ | ------------------------------------------------------------ |
| present | Disabled     | Ours and interrupted: set Automatic, clear the record, start |
| present | not Disabled | Stale: clear the record, start                               |
| absent  | Disabled     | An administrator's: left Disabled, not started               |
| absent  | not Disabled | Nothing                                                      |

- **It is a registry value and not a file** because the GUI must read it unprivileged and the state directory's DACL admits
  SYSTEM and Administrators only. A service key grants Users read and nothing else, so the GUI reads it and no user can
  forge it. It dies with the service.
- **Whether the stamped process runs is read from the process where it can be opened.** The writer may be SYSTEM (the cutover
  child, an installer's custom action) and the GUI is an unprivileged user, and `OpenProcess` is refused for every SYSTEM
  process there (measured: `ERROR_ACCESS_DENIED` for `services.exe` and `svchost.exe`, even for
  `PROCESS_QUERY_LIMITED_INFORMATION`). A process that can be opened is running when its object is not signalled, which is an
  edge at exit. The system process list (`NtQuerySystemInformation`) kept an exited process listed, with a thread left, while a
  reader held a handle to it, so it decides only for a process that cannot be opened. For that case it was measured as a
  standard user holding no handle, right after a SYSTEM process stopped: about 6,500 rounds on the privileged CI runner (probe at
  `50d133c91`, CI run 41817171754) never listed the exited process with a thread left (`Stamp::is_running`).
- **It never blocks.** A record that cannot be read counts as present, and none of an uninstall, an install, a cutover or a
  connect is blocked by it: a record that could block them is the lockout this design removes.
- **An administrator's Disable survives every path that is not an explicit enable**: the retirement's restore, the update
  cutover, `bridge install` and the GUI's status read. `hole bridge enable` and the GUI's Enable action override it. A
  reinstall deletes and recreates the service, so a manual MSI major upgrade or a rolled-back uninstall registers it
  Automatic and starts it; no state is carried across.
```

### The start-type lock

```{dropdown} The machine-wide mutex and its two rules
Every path that reads the start type and the record and then writes either holds one machine-wide mutex, `StartTypeLock`
({src}`crates/bridge/src/platform/windows/start_type_lock.rs`), from its first read to its last write: a retirement, the
repair, `enable`, the update cutover and the elevated `install` and `uninstall`. Without it overlapping retirements left the
service Disabled with no record, and a repair or `enable` run during a live uninstall reset the start type and cleared the
record under it. The mutex lives in a private namespace whose boundary requires the Administrators SID and whose DACL
admits SYSTEM and Administrators, so a standard user can neither squat the name nor wait on the lock (a wait takes the
lock, so a right to wait is a right to hold it for ever).

Two rules keep the lock from deadlocking. A process that carries the service's SID must not wait for it, because whoever
holds the lock waits for such a process; the only one that takes it is the update cutover child, which *tries* the lock
once, abandons the update if it is held, and otherwise holds it through the cutover. And the GUI never touches the lock:
every writer stamps the record with its own process identity and creation time, and the GUI's status read asks whether
that process is still running. Running reads as `ChangeInProgress` (the connect gate offers neither Repair nor Enable, and
`hole bridge status` prints `installed (being changed)` and exits 4); gone, the change was interrupted and the table
above decides. A *change mark* in the service's key, set when the outermost hold begins and ends, makes the lock-free read
exact: the status read goes again unless the mark is equal before and after its reads.

The update cutover hardens the service the same way a retirement does (record, Disabled, no restart), stops and swaps, and
restores on every path out. A cutover killed between hardening and restore leaves what a killed retirement leaves, and the
next cutover, `bridge install` or the GUI's Repair resets it.
```

## Disclosed residuals

- **The live-bridge refusal probes a known set of directories.** `unlock` probes the service's alone, so a bridge started
  by hand is not seen by it. For `release-covers`, a bridge given an explicit `--state-dir` outside `peer_state_dirs`, or running under a different account than the uninstaller (the MSI's actions run as SYSTEM), holds a
  lock nothing here can see. On Windows the consequence is the desync the refusal exists to prevent: `release_all` sweeps by
  GUID and deletes that bridge's machine-wide filters while its session runs (T14 in
  [Transitions](kill-switch.md#transitions)). `release-covers` is hidden and uninstall-only for this reason.
- **Uninstall proves it issued the deletes, not that no filter remains.** On macOS `release_all` reads its own state files,
  so a cover engaged under a non-default `--state-dir` reads as absent against the fixed service directory and answers `Ok`
  over a blocked host. The recorded `Target::Off` limits the damage, since a later start reconciles toward it, and pf does
  not survive a reboot.
- **A stop that never returns is not covered.** The Windows stop wait has no bound, and neither does `ProxyManager`'s
  teardown, so against a hung stop the release never runs.
- **A release that succeeds while the trailing bookkeeping fails** leaves a stale auto-connect candidate or a stale legacy
  `bridge-lockdown.json` label. The target is already `Off`, so reconciliation still converges.
- **A persistent filter from a later Hole build under an unknown key** survives unlock and uninstall
  ([#1242](https://github.com/bindreams/hole/issues/1242)).
- **`unlock`'s refusal names only the in-app action**, which cannot work when the app cannot reach the bridge
  ([#1278](https://github.com/bindreams/hole/issues/1278)).
