# Crash recovery

The {term}`bridge` changes the machine: routes, a plugin process or two, and on Windows a diagnostics session. A bridge that
is killed, loses power or crashes never runs its teardown. So while a proxy is active the bridge keeps small records in
its {term}`state directory`, clears them on a clean shutdown, and replays them at the next start. This page lists what is
recorded and what the replay does with each record. It is for a developer who adds state that has to survive a crash.

## When it runs

All recovery runs after the IPC socket has bound, so a second bridge instance that fails the bind never touches the first
one's state. The order, in {src}`crates/bridge/src/foreground.rs` and the two service entry points
({src}`crates/bridge/src/platform/windows.rs`, {src}`crates/bridge/src/platform/macos.rs`):

1. **DNS recovery** (`dns::recovery::recover_dns_config`) runs first of the state recoveries. If recovery itself is
   interrupted, the user is left with working DNS and broken routes, which is easier to diagnose than the reverse.
1. **`boot::recover_then_reconcile`** ({src}`crates/bridge/src/boot.rs`) runs the rest, in this order: route recovery
   (which also decides what becomes of a cover left behind), the plugin reap, then the reconcile of the persisted target.
   The reap comes before the reconcile because it kills every recorded plugin and cannot tell a previous bridge's from the
   one an auto-connect is about to start. IPC is not served until this returns.
1. **The crash-marker sweep** reports a native crash of an earlier run; see [native crashes](native-crashes.md).

The Windows service path differs. Right after the bind and the liveness lock it sweeps the stale update marker and reports
Running, before any other step. Its remaining steps (`registration::run_startup_steps`) then run in this order: the
startup repairs (`registration::run_startup_repairs`), DNS recovery, `boot::recover_then_reconcile`, the crash-marker
sweep, and last the sweep of `hole.exe.old-*` leftovers from a cutover. The foreground bridge and macOS sweep the update
marker last, after the crash markers. The ETW consumer, whose sweep is in the table below, starts after all the service
path's steps and before the crash-marker sweep on the foreground path.

## What is recorded

The state directory is described in [the architecture overview](overview.md). Its default is `default_state_dir` in
{src}`crates/common/src/paths.rs`; the service uses a system location.

| Record                                                                       | Holds                                                              | The replay                                                                                                           | Gone when                     |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| `bridge-routes.json`                                                         | The routes this run installed, and the identity they went in under | `routing::recover_routes` deletes the routes in `installed`, and nothing else: [route ownership](route-ownership.md) | Every route is confirmed gone |
| `bridge-plugins.json`                                                        | The identity of each running plugin process                        | `plugin_recovery::reap_recorded_plugins` kills each by exact identity                                                | Every record is accounted for |
| `bridge-dns.json`                                                            | What an older build's crashed run changed on an adapter            | `dns::recovery::recover_dns_config`, described below                                                                 | Always evaluated once         |
| The cover's records                                                          | Intent, pf state, the boot-time witness                            | [Recovery, adoption and the cover lock](kill-switch-recovery.md#what-a-startup-measures-and-reads)                   | Per that page                 |
| ETW sessions (Windows; no file)                                              | The `hole-bridge-etw-<pid>` trace session                          | `etw_sweep::sweep_sessions_with_prefix`, run when the bridge starts its ETW consumer                                 | Always                        |
| `HoleDisabledByHole` (Windows; a registry value under the service's own key) | That an uninstall's Disabled start type is in force                | [The Disabled service and its record](kill-switch-uninstall.md#the-disabled-service-and-its-record)                  | The service's key goes        |

### Routes

Route recovery is driven by the record and by nothing else. A bridge that finds no `bridge-routes.json` deletes no route:
a bridge that unconditionally deleted the split routes on start would tear down those of another bridge running at the
same time. The checkpointing that keeps the record accurate, and what recovery does with a group it cannot clear, are in
[route ownership](route-ownership.md#checkpointing).

### Plugins

The reap removes a record only for a plugin it accounted for: killed, provably gone, or provably unrestorable on this host
(a record from another platform or another boot). A record it cannot judge keeps the file, and so do a file that is
unreadable, from a newer release or corrupt: forgetting a record could leave a plugin running that holds a server
connection and a local port. A file at an obsolete schema is discarded, which accepts a one-time orphan leak. The same
reap runs at bridge start, in session teardown, and in the test harness's teardown.

### DNS

The bridge no longer writes `bridge-dns.json`. On Windows, DNS egress is confined to the TUN adapter by a firewall filter
set held in a process-scoped, dynamic session, so it has no recovery state: it ends with the process. What remains is a
sweep that undoes an older build's rewrite of another adapter's resolvers. For each recorded adapter, and each address
family on it separately, `recover_dns_config` restores the prior setting only if the *live* setting still equals what that
build advertised. A family someone else has changed since is left alone. The file is evaluated once: it is deleted if every
family settled, and otherwise renamed to `bridge-dns.superseded.json`, a name the bridge never reads again.

A confinement held by a bridge that is alive but unreachable has no file-based release. It ends only with its owning
process, and the escape below stops that process.

### ETW sessions

The bridge's session ends in `EtwGuard::drop`. When stopping it does not report success, `stop_session` issues a stop by
name as a backstop, and if that fails too the drop abandons the processing thread rather than risk an unbounded join. A
crashed bridge leaves its session running, so the sweep at the next consumer start stops every session whose name starts
with `hole-bridge-etw-`: by name prefix, not by the dead bridge's process id.

## Records that cannot be read

Every file record above is a `VersionedFile` ([file lock and state files](file-lock.md#state-files)), and each declares a
`Role` ({src}`crates/util/src/versioned_file/role.rs`) that decides what happens to a copy this release cannot read: one
from a newer release, a corrupt one, or one whose read failed. The ETW session is not a file and the
`HoleDisabledByHole` value is a registry value, so neither has a role. The records of what the bridge did to the machine are the
strictest. `bridge-routes.json` and `bridge-plugins.json` are `OsRecord`s: an unreadable one is never replaced, removed or
acted on, since it is the only evidence of what the run left behind, and a route record also refuses a connect. The
cover's records have a role of their own. `bridge-dns.json` is a `LegacyRecord`: kept, never
overwritten, and it never blocks a connect. The consequences for the cover's records are in [recovery and
adoption](kill-switch-recovery.md).

## The escape

When in-bridge recovery cannot run, {src}`scripts/network-reset.py` does an equivalent clean-up from outside. It reads both
DNS record names, so the escape survives the rename above. It does not honour the route record: see [route
ownership](route-ownership.md#the-escape).
