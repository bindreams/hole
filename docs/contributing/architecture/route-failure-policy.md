# Route commands and what failing means

The {term}`bridge` points the machine's routes at the {term}`TUN` device by running the platform's `route` and `netsh`
tools. Whether a failed command stops what is running is a security decision, and the code makes it by type. This page
is for a developer who changes route install, teardown or recovery. It assumes [the architecture
overview](overview.md). Which routes Hole may delete is a separate question, answered in [route
ownership](route-ownership.md).

## Two runners

Every route command runs in a *phase*, and a phase belongs to one of two families. The code is in
{src}`crates/tun-engine/src/routing.rs`.

|                                 | Fatal                                                                                                                             | Best-effort                                                                                                        |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Phases                          | `FatalPhase::Setup` (and the macOS firewall engage)                                                                               | `BestEffortPhase`: `Teardown`, `RecoverSplit`, `RecoverBypass` (and the macOS firewall recovery)                   |
| Runner                          | `run_setup_commands`, reached through `setup_routes`. The macOS firewall engage uses no route runner (`run_capturing`)            | `run_teardown_commands`, reached through `teardown_routes`; `recover_groups` for recovery and for install's sweep  |
| A command that does not confirm | Stops the phase and returns a `RouteCommandError`                                                                                 | Is logged and kept in the record; the next command still runs                                                      |
| Why                             | A route that was never installed but is reported as installed sends traffic outside the tunnel while the app says it is protected | A cleanup that stops at the first failure strands routes, and leaves the user worse off than if Hole had never run |

Install is not transactional: a command can fail halfway through the set. That is why *teardown* is best-effort too, and
not only crash recovery. The defensive teardown after a failed install may be asked to delete a route that never went in,
and the platform tools exit non-zero for that.

## The pairing is a type

A phase is a value of `FatalPhase` or `BestEffortPhase`. Both implement the sealed trait `Phase`, whose constant
`BEST_EFFORT` also picks the log level of the runner (an unconfirmed best-effort command is logged at debug, since a
failure is expected; the teardown and recovery callers then log it again at warn, keeping the route recorded) and which
question the runner asks of a command's result ([what confirmed means](#what-confirmed-means)). Each runner accepts only
its own family, and the two command types differ as well (`SetupCommand` and `RouteCommand`). Wiring a teardown phase into
the fatal runner does not compile.

The best-effort runners return no `Result`. `run_teardown_commands` narrows a `Vec<RouteId>` accumulator and returns
nothing, and `recover_groups` returns the groups it could not confirm. There is nothing for a later edit to `?` out of.
That is the second half of the guarantee: the cleanup path has no way to stop early.

## What confirmed means

The runner reports a command as confirmed when the route's state is now what the phase wanted: *it went in* for the fatal
phase, *it is gone* for every best-effort phase. The two questions are separate functions (`route_command_installed` and
`route_confirmed_absent`), and they read different evidence per platform. The evidence, and why a best-effort delete that
fails stays recorded, is under [what counts as gone](route-ownership.md#what-counts-as-gone).

## Fatality is per command

Within the fatal phase, one field decides: `SetupCommand::fatal`. The IPv4 splits and the server bypass are always fatal.
The two IPv6 splits (`::/1` and `8000::/1`) are fatal only when the TUN device has an IPv6 binding, which
`gateway::tun_ipv6_available` probes by the TUN's own name once the OS has created it. The probe is of the TUN, not of the
upstream interface that `GatewayInfo::ipv6_available` measures, because the TUN's name is what those commands carry.

The intent: where a host has no IPv6 on the TUN (a `DisabledComponents` setting, or an EDR policy that unbinds IPv6 from
new adapters), the two IPv6 commands may fail outright, a host with no IPv6 stack has no IPv6 traffic to leak, and so the
start should go on without them.

```{warning}
Today the tolerance does not reach the start. The flag stops at `run_setup_commands`: it drops a tolerated command from the confirmed set and carries on. `install_with`
then compares that set with `planned_routes`, which always lists both IPv6 splits, so on an unbound TUN the install
still fails ([a failed install](#a-failed-install)). The per-command flag decides whether the runner stops, not whether
the start succeeds. The unit tests cover the flag in `run_setup_commands` only; none runs `install_with` over it.
Tracked in [#1299](https://github.com/bindreams/hole/issues/1299).
```

## A failed install

A partial route set is a real state. When `setup_routes` reports a failure, `SystemRouting::install_with` does four
things and nothing else; its doc comment is the source of truth.

1. It issues no further setup commands.
1. It runs teardown narrowed to the routes that the per-command checkpointing confirmed installed, never to the planned set.
1. It clears the persisted record only once nothing is left unconfirmed. A command whose fate is unknown stays recorded for
   the next start to retry. That includes a command that could not be spawned, even though it certainly did not run: see
   [checkpointing](route-ownership.md#checkpointing).
1. It returns `Err(RoutingError::RouteSetup)`. No `SystemRoutes` guard is built, so no caller can report the tunnel up.

A command that ran but did not confirm is the same failure. If `setup_routes` finishes without error but fewer routes are
confirmed than `planned_routes(server_ip)` lists, `install_with` rolls back and returns `Err` too. A partial tunnel is
worse than no tunnel: the user believes traffic is captured when some of it is not. The error text names the suspected
cause, another process holding a conflicting route. A route whose command ran and did not confirm is not left in the record,
and Hole's stop leaves it alone; the exception is a command that could not be spawned.

## The accepted trade

A false start failure is preferred to a silent leak. Nothing in the tree measures whether a healthy install can legitimately
exit non-zero, for example over a route that is already there, and no test runs `setup_routes` against a real elevated
`netsh` or `route` under that condition. Install therefore treats every unconfirmed command as a failure. Do not add
tolerance for an "already exists" exit code to make a start succeed: a stranded route is better surfaced than routed around.

## Error text

`RouteCommandError`'s `Display` carries the program name and the command's position in the phase, then either the exit
code or, when the program could not start, the OS error text. It never holds the argv, so it does not hold the server
address or an interface name. It reaches a toast through `StartError::Failed`, and `redact_outgoing` in the bridge's IPC
layer runs the message through the server-address redactor on the way out. The full argv and the child's output go to
`bridge.log` from the runner (`run_command`).
