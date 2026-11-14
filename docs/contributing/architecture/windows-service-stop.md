# Windows service stop reporting

When Windows stops the {term}`bridge` service, the Service Control Manager (SCM) waits for the service to report that it has
stopped. A bridge that is stuck mid-teardown looks the same as one that is slow, unless it says where it is. This page covers
how the service reports its progress through a stop, so a hang points at a step. It is for a developer who adds a teardown
step, or who is debugging a wedged stop. The uninstall's side of the same stop, waiting it out, is under [the Windows service
stop](kill-switch-uninstall.md#the-windows-service-stop). Only Windows CI exercises the SCM side.

## Phases and checkpoints

`run_service` ({src}`crates/bridge/src/platform/windows.rs`) reports `SERVICE_STOP_PENDING` with one checkpoint per teardown
phase, and `Stopped` only after the last. The phases are the variants of `StopPhase`
({src}`crates/bridge/src/service_stop.rs`). Their declaration order is teardown order, and a phase's checkpoint is its position,
counting from 1 because checkpoint 0 means "no pending operation".

A phase is entered when the previous one has finished, and names the work *about to run*, so a checkpoint that stops moving
identifies the step that is stuck.

| Phase             | The work it announces                                                                                                                    |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `StopRequested`   | The Stop (or Shutdown) control arrived                                                                                                   |
| `AcquireProxy`    | Wait for the proxy-manager lock                                                                                                          |
| `PersistTarget`   | Record the session event in the target file                                                                                              |
| `RestoreDns`      | Restore the operating system's DNS configuration                                                                                         |
| `StopEngine`      | Shut down the TUN dispatcher: close the device, cancel the connection handlers                                                           |
| `ReapPlugins`     | Reap the plugin processes                                                                                                                |
| `StopProxy`       | Stop the Shadowsocks task                                                                                                                |
| `TearDownRoutes`  | Delete the installed routes                                                                                                              |
| `SettleCover`     | Release the covers (the transient cover of a pending start, or the standing one), and take the post-teardown firewall and NDIS snapshots |
| `CloseEtw`        | Close the ETW consumer                                                                                                                   |
| `DropResources`   | Drop the liveness lock, the shutdown token and the proxy manager                                                                         |
| `ShutdownRuntime` | Shut down the tokio runtime, which joins outstanding blocking tasks                                                                      |

The proxy-side phases are entered by `ProxyManager::stop_with_progress`, each just before the work it names, and only when
that work exists in the session: a SOCKS-only start has no TUN engine, a start with no plugin has no plugin chain, and a
bridge whose ETW consumer did not start has no `CloseEtw`. A path that fails before teardown, such as a failed bind, skips
every phase between the stop report and `ShutdownRuntime`, `AcquireProxy` and `DropResources` included.

Each phase has a wait hint (`StopPhase::wait_hint`). It is advisory: the SCM or a service control program *may* treat a
checkpoint stuck past it as a failed stop, so the hints err long.

## Who reports

The first report is made by the control handler the moment the Stop or Shutdown control arrives, before the main task is
signalled. A stop that lands during a startup `await` therefore does not read as `Running`. After that, every report is made
when the previous phase finishes. **Nothing reports on a timer**: a wedged phase freezes the checkpoint, and that frozen value
is the signal, visible to `sc queryex` and to the `NotifyServiceStatusChange` waiters of the cutover and the uninstall.

The control handler and the main task both enter phases, so `StopProgress` serialises the reports and drops an entry that
would not advance the checkpoint. A status report is the only thing done under its lock.

## Logging

Each phase entered is logged at info (`service stop phase`, with its checkpoint) to `bridge.log`. The control handler does no
log I/O of its own: the SCM gives the handler a bounded time, and the file appender can apply back-pressure, so a log write
there could fail the caller's `ControlService`. The shutdown forwarder task logs the first phase's hand-off the moment it wakes
from the shutdown signal, so a stop that wedges before the first entry still leaves a line. The handler also catches a
panicking report, because it runs inside the service's `extern "system"` entry point and an unwinding panic there aborts the
process; a panic still passes through the process-wide panic hook first.

A Stop control that lands after the last entry (`ShutdownRuntime`) is not logged. When an `msiexec` run times out, the CI
diagnostics print `sc queryex HoleBridge` and these log lines ({src}`.github/scripts/invoke-msiexec-bounded.ps1`).
