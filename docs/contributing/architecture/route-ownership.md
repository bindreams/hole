# Route ownership

When Hole stops, or recovers from a crash, it deletes routes. It must delete only the routes it put in, because the route
table is shared: if another VPN has taken over a prefix Hole failed to install, deleting that prefix takes the other VPN's
tunnel down. This page covers how the code decides what is Hole's, and what the record holds. It is for a developer who
changes route teardown, recovery or the record's format. It assumes [route commands and what failing
means](route-failure-policy.md).

## The rule

Teardown and recovery delete **only** the routes in the `installed` list of `bridge-routes.json`. A route whose install
failed is never recorded, so it is never deleted: it belongs to whoever holds it now.

The routes are the five values of `RouteId` ({src}`crates/tun-engine/src/routing.rs`): the four split routes (`0.0.0.0/1`,
`128.0.0.0/1`, `::/1`, `8000::/1`) and the server bypass, which keeps traffic to the proxy server out of the tunnel. A
loopback server has no bypass, and `planned_routes` leaves it out.

## Why only the record can say "ours"

A delete command could in principle say "delete this route only if it is mine". Neither platform's command can say it for
the split routes, so *provenance*, the record of what this run installed, is the only handle. It also outlives the
interface: the {term}`TUN` device is closed before the routes are dropped (see [what one connect
holds](overview.md#what-one-connect-holds)), and the device of a crashed run is gone.

````{tab-set}
---
sync-group: os
---
```{tab-item} Windows
:sync: windows

`route delete <server> mask 255.255.255.255 <gateway>` accepts a gateway, and it scopes which entry is deleted. The
install knows the gateway, so the record carries it as `original_gateway` and the bypass teardown uses it. A takeover
VPN's route to the same destination has a different gateway, so Hole's delete fails to match it and is a no-op. That
scoping is from `route.exe`'s documented syntax; nothing in the tree measures a takeover.

The split-route deletes cannot be scoped and rely on provenance alone.

A record from an old schema has no gateway. Schemas 1 and 2 never stored one, so `original_gateway` is `None` and the
bypass delete falls back to the unscoped form. That is a disclosed residual.
```
```{tab-item} macOS
:sync: macos

No qualifier on `route delete` can express "only if it is ours", and the code deliberately names no interface in any
macOS delete (`platform_split_teardown_commands`, `platform_bypass_teardown_command`).

- `route delete` is read, from the sources of `route(8)` and the kernel, as choosing its victim by destination and
  netmask alone. `-interface <name>` would then scope nothing, and with a name that no longer resolves the command exits
  before it reaches the kernel, so the delete never happens.
- `-ifscope` does scope, but a route carrying it is skipped by unscoped lookups. Scoping the install would leave the
  tunnel capturing nothing.
- Reading the table back before deleting is check-then-act: it narrows the window, not the race.

These are conclusions from reading source. Nothing in the tree measures them on a Mac, and the tests that touch the
oracle below use fixed `route(8)` output as their fixture.
```
````

## The record

`bridge-routes.json` is a {src}`RouteState <crates/tun-engine/src/routing/state.rs>` in a `VersionedFile` of role
`OsRecord`: it is the only evidence of what a run left in the route table, so a record this release cannot read is never
replaced, removed or acted on, and a connect is refused over it.

| Field                                     | Holds                                                                                                         |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `tun_name`, `server_ip`, `interface_name` | What the run installed against                                                                                |
| `original_gateway`                        | The gateway the bypass went through; `None` only for a record migrated from schema 1 or 2                     |
| `route_form`                              | `Via` or `OnLink`: which shape of bypass command was used                                                     |
| `installed`                               | The `RouteId`s this run got into the table: the only routes a delete may touch                                |
| `stale`                                   | Groups an earlier `install` or recovery could not confirm gone, each with its own copy of the identity fields |

`route_form` is a field of its own, apart from `original_gateway`, because "no gateway was ever recorded" (a migrated
record) and "the route was on-link" are different facts. A migrated record is read as `Via`.

## Checkpointing

Install rewrites the record before and after every single route command, not once per phase. At any instant, including
in a crash, `installed` names at most one route more than the table confirms: the command in flight. A pre-command write
that fails stops the install before the command runs, since a mutation Hole could not record is not run. Teardown and
recovery have no pre-write: they rewrite the record after each command, narrowing it. A route is dropped from the record
only once its delete is confirmed gone ([what counts as gone](#what-counts-as-gone)); one that is not confirmed, or whose
command fails to spawn, stays recorded so the next start retries it, and nothing after it is skipped.

"Next start" means the next `install`, not only the next process. `recover_routes` runs once per bridge process, but one
process can install several times (a reconnect, a server switch), so `install` itself sweeps a record a previous install
left (`sweep_leftover_before_install`). Whatever that sweep cannot confirm gone is carried forward in `stale`. The new
session's checkpoints touch only `installed`, never `stale`, so a leak from an earlier session survives being overwritten;
`recover_routes` tries every `stale` group as well as the primary one, and clears the file only when all are empty.

A record that cannot be read stops this: install refuses to run over it (`RoutingError::StateUnreadable`), and recovery
leaves it as it is and deletes no route, because what it names cannot be told apart from routes another VPN now holds.

## One command, issued once

`state::coalesce` is the one place that folds groups together. Groups with the same identity (`tun_name`, `server_ip`,
`interface_name`, `original_gateway`, `route_form`, the tuple that decides the argv) merge into one whose `installed` is the
union; each survivor is cut to `planned_routes(server_ip)`, because an id with no possible teardown command can never
drain and would keep `stale` non-empty for ever; an empty survivor is dropped.

Without that, a reconnect to the same server, which shares `tun_name` and often `server_ip` with a carried-forward group,
would issue a byte-identical delete twice. On Windows the first delete removes the route, the second finds it absent and
exits non-zero, which Windows never counts as confirmed ([what counts as gone](#what-counts-as-gone)), so the group stays
recorded. On macOS
the split deletes are unscoped, so the second one removes whatever a third party claimed after the first freed the prefix,
which is the harm this page exists to prevent. `recover_groups` also runs every group's split deletes before any bypass
delete, and issues each distinct argv once across all groups: a split delete's argv depends on `tun_name` alone, so two
groups with different servers can still produce the same command.

## What counts as gone

`exec_one` decides from the process result whether the route's state is confirmed. The fatal phase asks whether the add
worked; every best-effort phase asks whether the route is gone.

- **macOS** `route(8)` is read as exiting 0 whenever it gets as far as the routing socket, so a zero exit is no evidence
  of success. A non-zero exit is: the command never reached the kernel, so neither oracle confirms anything. Past that,
  the signal is text on stderr: `macos_route_command_succeeded` treats `writing to routing socket` as a failed add, and
  `macos_route_confirmed_absent` accepts a delete only if that text is absent or says `not in table` (already gone). Any
  other failure text keeps the route recorded. Parsing a tool's diagnostics is fragile. Like the reading of `route(8)`
  above, the oracle rests on source reading, not on a measurement in the tree.
- **Windows** `route.exe` and `netsh` exit non-zero on a failed add, so the exit code is enough there. For a delete it is
  not: the code records that an absent route and one that needed elevation both exited 1 with no distinguishing text. So
  `route_confirmed_absent` trusts only exit 0, and a delete that fails for any reason stays recorded rather than risk
  forgetting a route that is still there. That is a second disclosed residual. No test in the tree pins the observation
  itself.

## The on-link bypass

When the route to the server has no gateway (`NextHop::OnLink`), Windows has no address to scope the delete by, so the
bypass is added and deleted with `netsh interface ip ... route <server>/32 <interface>`, as the IPv6 bypass always is.
`route_form` says which argv to rebuild. macOS has no interface-scoped IPv4 bypass form, so `reject_macos_on_link`
refuses an on-link default route there before `install` is reached.

## What is not covered

A VPN that takes a prefix over *mid-session*, necessarily by deleting Hole's entry first, is still torn down by Hole's
stop on macOS, because macOS has no compare-and-delete. Closing that needs a different mechanism, not a different flag.
Windows has no equivalent: the takeover's route has a different gateway and Hole's scoped delete does not match it.

## The escape

`scripts/network-reset.py` deliberately does not honour the record's `installed` list. It reads only `server_ip` from it,
for the bypass, and stops the bridge and `ex-ray` processes. On macOS it deletes the four split routes unconditionally. On
Windows it removes them only on an interface whose alias starts with `hole-tun`, and the bypass by destination prefix. It is the escape for when the in-bridge
recovery cannot run; see [crash recovery](crash-recovery.md#the-escape).
