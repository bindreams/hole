# Native crashes and test panics

A Rust panic runs the panic hook, which logs it. A native fault does not: a segmentation fault or access violation, a stack
overflow, `abort()`, an illegal instruction, heap corruption. The process just ends, and the log says nothing. The
`tombstone` crate ({src}`crates/tombstone/`) closes that gap by leaving a {term}`crash marker`, and the next start reports
it. This page covers what the marker is, what the handler may and may not do, and what each platform produces. It also
covers the panic-dump hook that tests use. It is for a developer who touches crash handling, or who wonders why a macOS
crash leaves no crash report.

## The marker

`tombstone::attach(kind, log_dir)` installs the crash handler. It is called from `init_multi` in
{src}`crates/common/src/logging.rs`, right after `install_panic_hook()`, which covers the app, the command line and the
bridge, and from galoshes' own `main`. A second call is a no-op. `kind` labels the process ("gui", "bridge", "gui-cli",
"galoshes", "test").

On a fault, `on_crash` runs in a compromised context: the heap and every lock may be held by a thread that will never run
again. It does only signal-safe work. It writes a fixed-format file, `crash-<kind>-<pid>.marker`, through raw system calls,
with no allocation, no lock, no `format!` and no tracing. It swallows every I/O error. Everything it needs, the open
directory and the marker's name, was prepared in `attach`.

The log directory is the interactive user's, and the bridge writes in it as root, so `attach` opens it once through
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
`malloc` never releases the allocator lock, so anything that allocates can block for ever; the dump writer allocates. The
crate's module doc is the canonical record, with the measurements and the three alternatives that were tried. Read it before
changing either half.

Two source-scanning tests in {src}`crates/tombstone/src/crash_tests.rs` hold the macOS callback's shape, because the deadlock
needs allocation pressure that CI does not reliably produce and the runtime tests stay green without it:
`macos_on_crash_terminates_unconditionally`, and `macos_on_crash_calls_nothing_that_can_allocate`, which scans the whole
handler path transitively, since an allocation one frame down deadlocks as surely as one in the callback.

The `crash-dumps` feature reads as cross-platform and is not. `minidump-writer` is declared under `cfg(windows)`, so the
feature links nothing on any other target. It is off by default and release builds never carry it, because process memory
holds keys and traffic.

## The sweep

`tombstone::sweep(log_dir)` runs at start. It reports each `crash-*.marker` it finds with a `tracing::error!` under the
target `crash`, then deletes the marker and leaves a sibling `.dmp`. Whichever process sweeps the directory first reports a
marker, so a marker is reported exactly once. The marker lands in the log directory and not the state directory because the
elevated bridge's marker must be readable by the unprivileged app.

The sweep opens `log_dir` through `Dir` and reads each marker through a `ReadDir` by its name inside that handle. A symlink at a
marker name is reported unreadable and unlinked as itself, a FIFO is never waited for, and a marker the directory's owner cannot
vouch for (`ReadDir::read_vouched`) is reported unreadable too. The listing of names is by path, but it only supplies names.

## Plugins and the known gap

ex-ray is spawned with `GOTRACEBACK=crash` ({src}`crates/garter/src/binary.rs`), and `record_exit` in
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
