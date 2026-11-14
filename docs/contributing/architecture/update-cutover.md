# Update cutover

An in-place update replaces the {term}`bridge`'s own running binary and restarts the service. This page covers what the
`POST /v1/update-apply` handler does, how the swap stays all-or-nothing, why Windows and macOS restart differently, and what
the update marker is for. It is for a developer who changes the update path. What becomes of the {term}`kill switch` across
the restart is on [the kill switch page](kill-switch.md#transitions) (T10, then T15 and T16 at the new bridge's start).

## The apply handler

The handler (`handle_update_apply` in {src}`crates/bridge/src/ipc.rs`, with its helpers in
{src}`crates/bridge/src/cutover/apply.rs`) treats the app as untrusted and relies on no check the app made. It runs these
steps in order:

1. **Refuse a second cutover.** A present marker is a cutover already in flight: HTTP 409.
1. **Check consent.** An update with the kill switch off requires `consent: true` in the request (`consent_gate`): the gap
   between the old bridge stopping and the new one starting can leak, and the app asks the user first. What a standing cover
   changes about that gap is on [the kill switch page](kill-switch.md#transitions).
1. **On macOS, validate the swap target** before anything is claimed: the `.app` path the app supplies must be a genuine
   `com.hole.app` bundle on a volume that can swap atomically. A bad target is a clean 400.
1. **Claim the marker.** The claim is a create-new, so two concurrent requests cannot both win, and only the winner ever
   stages a payload. A loser never touches the shared staging directory, where a loser's stage could clobber the winner's
   verified copy.
1. **Copy the payload into a bridge-private directory and verify that copy again**, offline, with minisign and the SHA-256
   list. The handler never reads the caller's path a second time, so the bytes verified are the bytes extracted, and a group
   member who can pass a genuinely signed file cannot swap it between the check and the use. A failed verify is HTTP 422, a
   corruption or tamper event the user must see as such.
1. **Extract the bare binaries** from the copy and spawn the OS actor.

`CutoverOs` ({src}`crates/bridge/src/cutover/os.rs`) is the trait of OS effects the actor drives. It exposes no
cover-mutating method, so a cutover structurally cannot engage a transient cover.

## The swap

The Windows swap is *rename-away, then move-in*, and it is all-or-nothing. The live binary is renamed aside to
`<file>.old-<version>` (a running image opened with `FILE_SHARE_DELETE` can be renamed), and the staged new file moves onto
the freed canonical path. The running process keeps the old image, and the canonical path now names a different file, which
is what the app's self-heal compares to decide to relaunch.

The swap covers the full set of bundled binaries (the `bindir` names from `xtask_lib::bindir`), not only `hole.exe`. If one
image fails midway, the swaps already committed are rolled back to the prior consistent set before the error returns, so the
service never boots a mix of old and new. Deleting the swapped-out images is deferred until the whole set has committed,
which is what makes the rollback possible; the next bridge start sweeps `*.old-*` once no process maps them.

On macOS the `.app` bundle is swapped with `renamex_np` and `RENAME_SWAP`, and the privileged helper is moved by a plain
rename. There is no `.old-<version>` and no `bindir` set.

## The restart differs by OS

````{tab-set}
---
sync-group: os
---
```{tab-item} Windows
:sync: windows

A service cannot restart itself through the SCM, so the handler spawns a detached LocalSystem child, `hole bridge cutover`,
suspended. It stamps the child's identity into the marker, then resumes it, so the marker names the driver before the child
can act. The child outlives the bridge it stops.

The child tries once to take the service's start-type lock and abandons the update if another change holds it (`WouldBlock`):
it carries the service's SID, so a change that holds the lock waits for the child to exit, and the child must never wait
for the lock in return. See [the start-type lock](kill-switch-uninstall.md#the-start-type-lock).

`run_cutover` then runs: hold and harden the service, stop it, swap while no bridge runs, put the hardening back, repair the
start type, start it. Hardening first makes the stop final, so restart-on-failure cannot start the old image under the swap.
The stop and the start wait on `NotifyServiceStatusChange`, a kernel notification gated on the callback seeing the state, not on
a sleep or a probe. A service an administrator disabled is not started, and that is a *successful* cutover: the new files are
in place and the child leaves the service stopped ([the Disabled service and its
record](kill-switch-uninstall.md#the-disabled-service-and-its-record)).
```
```{tab-item} macOS
:sync: macos

The actor runs inline in the bridge, on a task spawned before the handler sends its response. Nothing depends on it
running after the response: the marker is already written. It swaps first, and then runs `launchctl kill SIGTERM` against
its own service. SIGTERM takes the graceful shutdown (`pm.stop()`); the routes and DNS tear down, and what the shutdown does
to a cover while the marker is set is on [the kill switch page](kill-switch.md#transitions). It does not wait and does not start anything: it
cannot return past its own SIGTERM. launchd's `KeepAlive=true` respawns the now-swapped binary.
```
````

## The update marker

`update-in-progress.json` ({src}`crates/common/src/update_marker.rs`) lives in the service log directory. It is written by the
privileged bridge and is readable by the app across the privilege boundary, which is why the file is mode `0o644` on Unix. It
does two jobs:

- The app holds its last snapshot while a marker is set, instead of flashing *Disconnected*. A marker that names no
  identifiable driver reports the failed update instead.
- The bridge's shutdown reads it to name its cause: with a marker set the event is `CutoverRestart`, without one
  `ProcessExiting` (`shutdown_reason` in {src}`crates/bridge/src/foreground.rs`). Only the *transient* cover's fate
  depends on the choice: `transient_cover_disposition` keeps it for `CutoverRestart` and releases it for
  `ProcessExiting`. The standing cover goes through `cover_step` for either event, as T10 of the [kill switch
  Transitions table](kill-switch.md#transitions) says.

The marker holds the cutover driver's identity (a process id and its kernel start token, so a recycled id never matches), and
its presence is the single-occupancy claim. The new bridge clears it unconditionally, by removing the name and never by parsing
it first, in its sweep after the socket binds. Where no new bridge will bind, the Windows child clears it itself: after a
failure, and after a cutover that left a disabled service stopped.

Every write, the clear and the read go through the log directory's no-follow `Dir` handle ([privileged
folders](privileged-folders.md)). The read is the same for the app as the user and for the bridge as root, and the bridge
reads in a directory a user may own, so a FIFO planted at the name must not be waited for. A link or a FIFO at the name reads
as `Marker::Indeterminate`, which is not a claim of a cutover.

## The notify record is leaked on purpose

`service_scm::SystemScmActor` deliberately leaks the notify record of a `NotifyServiceStatusChangeW` call whose callback has
not run: one 88-byte record on 64-bit Windows (the size is asserted at compile time) per call that did not settle. That
includes each `ERROR_SERVICE_NOTIFY_CLIENT_LAGGING` return. Nothing caps the number of such calls, since the retry on that
return has no cap, so nothing caps the leak. Do not "fix" it without a Win32 measurement showing both that closing the
service handle recalls a queued APC and that a failed call queues none. The mechanics are in
{src}`crates/bridge/src/service_scm/registration.rs`.
