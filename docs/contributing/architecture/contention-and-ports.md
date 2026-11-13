# Spawn contention and port allocation

Two small pieces of infrastructure absorb things the operating system does to a process that did nothing wrong: another
program holding a freshly built executable, and a port that is free to ask for and then refused. This page covers both, and
the rule for adding a new use of either. It is for a developer who spawns a child process or needs a free port.

## Spawn contention

A `Command::spawn` can fail for a reason that is gone a moment later. On Windows, Defender is scanning a freshly built
`hole.exe` and the open fails with `ERROR_ACCESS_DENIED` or `ERROR_SHARING_VIOLATION`. On macOS, a writer still holds a file
that something is trying to run, and the spawn fails with `ETXTBSY` or `EBUSY`. Two helpers handle it.

- **`util::retry`** ({src}`crates/util/src/retry.rs`) has `exp_backoff` and `retry_if(op, predicate, max_attempts, base_delay)`,
  which retries only an error the predicate accepts and returns anything else at once. `is_file_contention` is the predicate for
  the four codes above. `retry_if` sleeps with `tokio::time::sleep` between attempts, so it needs a Tokio runtime.
- **`handle-holders`** ({src}`crates/handle-holders/src/lib.rs`) answers "which processes hold a handle to this file": `find_holders`
  and a logging wrapper, `log_holders`. It is best-effort and never a new failure mode: a diagnostic that cannot run logs and
  returns nothing. On Windows it uses `NtQuerySystemInformation`, on macOS it runs `lsof`, and elsewhere it returns an empty
  list. It is a `[dev-dependencies]` entry of the {term}`bridge`, because a privileged binary must not run `lsof` by `PATH` (see
  [system tools](system-tools.md#what-the-compiler-refuses)).

`DistHarness::spawn` ({src}`crates/bridge/src/test_support/dist_harness.rs`) composes them: `retry_if(spawn, is_file_contention, MAX_SPAWN_ATTEMPTS, SPAWN_BACKOFF)`, and on the terminal failure it logs the holders of the executable after capturing the
spawn error, so a failing diagnostic cannot hide the real failure. It is test infrastructure, and runs where someone is
watching.

## Port allocation

A free local port goes through `util::port_alloc` ({src}`crates/util/src/port_alloc.rs`). The crate is Apache-2.0, so both
Hole's GPL crates and the Apache-licensed plugin crates can depend on it.

| Function                            | What it is                                                                                                                          |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `bind_ephemeral(ip, protocols, op)` | **The entry point.** Allocates a port, runs `op(port)`, and retries the whole cycle on `is_bind_race` errors.                       |
| `free_port`                         | A primitive that returns a verified-free port divorced from any bound socket. A direct call is a clippy `disallowed_methods` error. |
| `ensure_port_free`                  | A pure probe, with no allocation.                                                                                                   |

**The retry is unbounded.** The only ways out of `bind_ephemeral` are success and an error that is not a bind race. It yields
each iteration and logs at growing milestones, so the log stays small however long it runs. There is no "right" budget: a
saturated runner needs many retries and a healthy machine needs one, and a fixed cap would either hide real saturation or fail
on a transient one.

The retry exists because Windows keeps *independent* TCP and UDP excluded-port-range tables (Hyper-V, WSL and Docker
reserve ranges), so a port the OS hands out for one transport can be reserved for the other. The kernel has no "free for both"
call. `free_port` binds one transport with port 0 and then verifies the rest with `ensure_port_free`, and any race starts a new
iteration with a fresh candidate.

A caller that must hand the port to another process *before* it is bound cannot fold its bind into a closure. It takes an
`#[allow]` with a comment saying why. Two sanctioned sites do: `test_support::port_alloc::allocate_ephemeral_port` and
`plugin_e2e::ports`. `bind_ephemeral` retries only errors that come back from `op` as an `io::Error`; a subprocess that binds the port
reports failure by exit code or stderr, which is not classified as a bind race. The in-process probe before the spawn catches the
excluded-range case, and the gap between the probe and the subprocess's bind is a remaining race.

### Reserve for what the consumer will bind

Name the protocols the consumer will actually bind. Where the consumer is known when the port is reserved, name it exactly:
`PluginDescriptor::alloc_protocols` sizes the local port per plugin (galoshes binds TCP and UDP; every other plugin, TCP).
Where the reservation happens before the consumer is known, reserve the union of the possible consumers. `plugin_e2e::ports::reserve_ss_local`
is generic over the client plugin, and the set includes galoshes, so it always reserves both. Over-reserving UDP for a TCP-only
plugin costs a retry; under-reserving it for galoshes costs a race.

`garter::ChainRunner` ({src}`crates/garter/src/chain.rs`) picks each intermediate port itself, with no cap, one hop at a time just
before that hop starts, and verifies TCP only, because every hop in the repository that is not the public one binds only TCP. A hop
that loses its port to another process reports a typed `BindConflict`, and is run again alone on a fresh pick. A hop that does not
speak sitrep (`ReadinessMode::Probe`, in {src}`crates/garter/src/binary.rs`) cannot report it, so its lost port is a failed start
and the hop is not restarted.
