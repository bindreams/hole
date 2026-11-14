# Native crashes and test panics

A Rust panic runs the panic hook, which logs it. A native fault does not: a segmentation fault or access violation, a stack
overflow, `abort()`, an illegal instruction, heap corruption. The process just ends, and the log says nothing. The
`tombstone` crate ({src}`crates/tombstone/`) closes that gap by leaving a {term}`crash marker`, and the next start reports
it. This page covers what the marker is, what the handler may and may not do, and what each platform produces. It also
covers the panic-dump hook that tests use. It is for a developer who touches crash handling, or who wonders why a macOS
crash leaves no crash report.

## The marker

`tombstone::attach(kind, log_dir)` installs the crash handler. It is called from `init_dual` in
{src}`crates/common/src/logging.rs` (which `init` and `init_multi` delegate to), right after `install_panic_hook()`. That
covers the app, the command line and the bridge. galoshes calls it from its own `main`, with its own directory (see
[the sweep](#the-sweep)). A second call is a no-op. `kind` labels the process ("gui", "bridge", "gui-cli",
"galoshes", "test").

On a fault, `on_crash` runs in a compromised context: the heap and every lock may be held by a thread that will never run
again. It does only signal-safe work. It writes a fixed-format file, `crash-<kind>-<pid>.marker`, through raw system calls,
with no allocation, no lock, no `format!` and no tracing. It swallows every I/O error. Everything it needs, the open
directory and the marker's name, was prepared in `attach`.

A log directory may be the interactive user's while the bridge writes in it as root (a bridge run in the foreground, or
under `HOLE_LOG_DIR`), so `attach` opens it once through
`util::dir::Dir` ([privileged folders](privileged-folders.md)) and holds it for the process's life. The handler creates the
marker, and the Windows dev-only `.dmp`, relative to that handle with an exclusive create: `openat(O_CREAT | O_EXCL | O_NOFOLLOW)` on Unix, `NtCreateFile(FILE_CREATE)` on Windows. An entry already at the name is never written through,
truncated or replaced. `attach` picks a name that is free at that moment (`-1`, `-2` after the pid when an earlier process
with the same pid left an unswept marker), so a name planted afterwards costs that one crash its marker and the planted entry
nothing. A directory that cannot be opened leaves the handler attached and writing no marker.

## What each platform produces

|         | Marker | OS crash report  | `.dmp` (dev builds only)            |
| ------- | ------ | ---------------- | ----------------------------------- |
| Windows | yes    | WER / LocalDumps | yes, with the `crash-dumps` feature |
| Linux   | yes    | core dump        | none                                |
| macOS   | yes    | **none**         | none                                |

On Windows and Linux, `on_crash` returns `Handled(false)`, so the OS default path still runs. On macOS it never returns: it
calls `_exit(70)`, for every fault class, every `kind` and every build. A macOS crash therefore leaves the marker and neither
an `.ips` report nor a minidump. That cost is a decision and not a gap: no part of Hole should hang the process, even
sometimes. On macOS the handler runs on a separate thread while every other thread is suspended, and a thread suspended inside
`malloc` never releases the allocator lock, so anything that allocates can block for ever; the dump writer allocates. [The
section below](#the-macos-decision-in-detail) has the measurements and the three alternatives that were tried. Read it before
changing either half.

Two source-scanning tests in {src}`crates/tombstone/src/crash_tests.rs` hold the macOS callback's shape, because the deadlock
needs allocation pressure that CI does not reliably produce and the runtime tests stay green without it:
`macos_on_crash_terminates_unconditionally`, and `macos_on_crash_calls_nothing_that_can_allocate`, which scans the whole
handler path transitively, since an allocation one frame down deadlocks as surely as one in the callback.

The `crash-dumps` feature reads as cross-platform and is not. `minidump-writer` is declared under `cfg(windows)`, so the
feature links nothing on any other target. It is off by default and release builds never carry it, because process memory
holds keys and traffic.

### The macOS decision in detail

A hung bridge is far worse than a lost crash report: it still holds the TUN device, its routes and its pf rules, and never
reaches its own cleanup, so the user loses the network. Detecting an unclean shutdown does not depend on the marker, because
the bridge's `bridge-{routes,plugins,dns}.json` state files are swept on the next start and survive SIGKILL and power loss.
So the macOS `on_crash` writes the marker and then ends the process with `_exit` instead of returning to `crash-handler`,
because everything that runs after the callback returns is unbounded:

- **The SIGABRT relay never detaches.** macOS has no exception for `abort()`, so `crash-handler` hooks SIGABRT with a
  `sigaction` and relays it as a synthesized `EXC_SOFTWARE`/`EXC_SOFT_SIGNAL` (`mac/signal.rs`). A real fault's branch calls
  `detach(true)` (`mac/state.rs`, `MessageIds::Exception`); the relay's branch (`MessageIds::SignalCrash`) contains no
  `detach` at all, so the C-mandated re-raise of `abort()` fires with the task exception port still attached.
- **Allocation in the callback can deadlock outright.** `on_crash` runs on `crash-handler`'s message-loop thread with every
  other thread Mach-suspended (`ScopedSuspend` in `mac/state.rs`, constructed before `call_user_callback` on both the
  exception and the relay branch), and a thread suspended inside `malloc` never releases the allocator lock.
- **The system crash reporter's runtime** is not something this process can bound at all.

The termination is unconditional: no fault-class predicate, no attach-`kind` discriminator (`kind` never identified a
process; `hole-common`'s log-bridge test helpers attach as `"test"` too), and no cargo feature, because a shipped `hole`,
`hole bridge` and `galoshes` must not hang either. `tests/crash_child.rs` pins each of those three separately. The marker
still carries kind, pid, tid, exception code and fault address, which is what `sweep` reports; what is lost is the stack.

```{dropdown} Measurements and the alternatives that were tried
**The deadlock is observed, not predicted.** On darwin/arm64, with eight threads allocating 1 MiB blocks, an allocating
`on_crash` hung 8 runs in 10, and `sample(1)` of a hung child shows the handler thread parked in `_xzm_malloc_large_huge`,
`_os_unfair_lock_lock_slow` and `__ulock_wait2` while a suspended thread sits inside `_xzm_malloc_large_huge` holding that
lock. It is the only causal theory for this hang that survived measurement. `write_minidump_best_effort` allocates three
times over: a `PathBuf` for the dump path, a `CString` inside `File::create`, and `MinidumpWriter`'s own buffers. The marker
write allocates not at all (the log directory's handle and the marker's name are pre-encoded at `attach`, the buffer is on
the stack, and the calls are raw `openat`, `write` and `close`) and runs first, which is why it is what survives.

**The `_exit` itself.** Three runs each of abort, segfault, stack overflow, bus error, illegal instruction and trap on
darwin/arm64 all exit 70 in under 0.02 s. A stack overflow needs no special case: it arrives as a genuine `EXC_BAD_ACCESS`
guard-page fault, and terminating on that first delivery means Rust's own stack-overflow handler, which responds by calling
`abort()`, never runs.

**Three alternatives were built and measured:**

1. *Detach inside the callback, then let the OS reporter run.* Hangs, 2 of 2. `call_user_callback` holds `HANDLER.read()`
   across `on_crash`, and `state::detach` takes `HANDLER.write()` on that same non-reentrant `parking_lot::RwLock`; under it,
   `shutdown` would `handler_thread.join()` the very thread `on_crash` runs on. `CrashHandler::detach()` hardcodes
   `is_handler_thread: false`, so that join is not avoidable from the callback.
1. *Restore the task exception ports by hand*, which is `uninstall`'s effect without its lock. Measured to earn nothing: with
   the ports restored the abort class terminates exactly as it does without them (3 of 3), and a fault raised inside
   `on_crash` hangs either way (2 of 2 with, 2 of 2 without).
1. *Stop allocating but keep returning `Handled(false)`*, which is the `cfg(windows)` gate on `write_minidump_best_effort`
   without the `_exit`, and would keep the `.ips`. 20 of 20 clean terminations, all under 0.41 s, and nothing has falsified
   it. But that was on an idle darwin/arm64, carrying none of the allocation pressure the deadlock needs, so it says nothing
   yet about darwin/amd64 under CI load. `_exit` is preferred for a reason independent of the allocator: returning hands
   control back to a process whose handler is still installed (the relay branch never detaches), and the system reporter's
   runtime is not something this process can bound.

**What would reopen this.** Two candidates. The clean one is a minidump path that is signal-safe and allocation-free end to
end (buffers reserved at `attach` time, the dump file opened there too, a writer touching neither the allocator nor a lock),
which removes the reason outright. The cheap one is the third alternative, the option measurement currently favours;
reopening on it means answering the unbounded-return argument, not just re-running the 20. Neither is reopened by a change
that merely makes the deadlock rarer: the decision is about hanging at all.
```

## The sweep

`tombstone::sweep(log_dir)` runs at start. It reports each `crash-*.marker` it finds with a `tracing::error!` under the
target `crash`, then deletes the marker and leaves a sibling `.dmp`. Reporting and deleting are two steps, and a marker is
reported by whichever process sweeps the directory first: two sweeps that overlap can both report it. The app and the command
line share the per-user log directory (`resolve_log_dir`), and so does a bridge run in the foreground; the code treats that
directory as readable by the unprivileged app even when the bridge is elevated, so a marker the bridge writes is created
world-readable and left root-owned on purpose, since the signal-safe handler cannot chown it. Two bridges do not share it:

- The installed service bridge logs to the service log directory (`update_marker::service_log_dir`: `ProgramData\hole\logs`
  on Windows, `/var/log/hole` on macOS), and sweeps that directory at its own next start. The app never sweeps it, so the
  app does not report a service bridge's crash; the service's next start does, in `bridge.log`.
- galoshes attaches and sweeps its own per-user runtime directory, so its markers are reported on its next start and not by
  the bridge.

The sweep opens `log_dir` through `Dir` and reads each marker through a `ReadDir` by its name inside that handle. A symlink at a
marker name is reported unreadable and unlinked as itself, a FIFO is never waited for, and a marker the directory's owner cannot
vouch for (`ReadDir::read_vouched`) is reported unreadable too. The listing of names is by path, but it only supplies names.

## Plugins and the known gap

Every binary plugin (ex-ray among them) is spawned with `GOTRACEBACK=crash` ({src}`crates/garter/src/binary.rs`), so a Go
plugin dumps its goroutines to stderr on a native fault and the bridge relays that stderr. `record_exit` in
{src}`crates/garter/src/chain.rs` logs a plugin that dies mid-run with its exit code or a killed flag.

Windows `__fastfail` (`int 29h`, including `/GS` stack-cookie failures and `std::process::abort()` on Windows) cannot be
caught by design. The code does not exercise it. On macOS `abort()` is a SIGABRT and is caught.

## Panics in tests

`hole-test-observability` ({src}`crates/test-observability/src/panic_dump.rs`) installs a panic-hook dispatcher once per test
binary, from the constructor that `register!()` sets up. On a test panic the hook goes through the registered
`PanicDumpSource`s, writing each to stderr, and then chains to the previous hook. A source registers with
`panic_dump::register`, which returns a guard that unregisters it when dropped. The current consumer is
`BridgeChildLogSource`, which dumps the `bridge.log` of each live `DistHarness` child.

A source's `dump` is called inside a panic hook and must swallow every I/O error. A double panic from an `unwrap()` or `?`
would replace the original panic's message with an I/O error and destroy the diagnostic.
