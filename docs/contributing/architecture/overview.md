# Architecture overview

Hole is one Rust binary, `hole`, that runs as two programs. This page names the layers inside it, what a connect
touches, and the three trait seams that keep operating-system changes out of unit tests. It is for a developer who knows
Rust and not necessarily VPNs. The user-level picture is in [How Hole is put together](../../how-it-works/overview.md).

## Two modes, one binary

`hole` with no arguments is the **app**: a Tauri program with the tray, the settings window and the config file. It runs
with the user's rights. `hole bridge run` is the {term}`bridge`: it manages the {term}`TUN` device, the routes, the
{term}`Shadowsocks` connection and the firewall block, and it needs administrator rights. Run by hand it stays in the
foreground; with `--service` the operating system's service manager (Windows SCM, macOS launchd) starts it. `main` in
{src}`crates/hole/src/main.rs` chooses the mode: no subcommand starts the app, and any subcommand goes to the command
line. `handle_bridge` in {src}`crates/hole/src/cli.rs` then dispatches the `bridge` subcommands, of which `run` is one;
`install`, `uninstall`, `unlock` and the rest do not start a bridge.

The two modes talk HTTP/1.1 with JSON bodies over an AF_UNIX socket on both platforms. The listener is
{src}`crates/bridge/src/socket.rs` (`tokio::net::UnixListener` on macOS, `socket2` on Windows), the server is axum in
{src}`crates/bridge/src/ipc.rs`, and the wire contract is {src}`crates/common/api/openapi.yaml`. Types shared by both
sides live in `hole-common`.

## The layers

```{mermaid}
flowchart TB
    subgraph app["hole (no arguments): the app, user rights"]
        tray["Tray, settings, dashboard"]
        client["Bridge client"]
    end
    client == "HTTP over AF_UNIX" ==> ipc
    subgraph bridge["hole bridge run: administrator rights"]
        ipc["ipc: axum handlers"]
        boot["boot: recovery, then reconcile"]
        pm["ProxyManager&lt;Proxy, Routing, Dns&gt;"]
        subgraph session["Session: what one connect holds"]
            direction LR
            dns["Dns: resolver steering"]
            disp["Dispatcher: TUN engine"]
            chain["Plugin chain"]
            proxy["Proxy: Shadowsocks client"]
            routes["Routing: routes"]
            cover["Routing: the kill-switch cover"]
        end
        ipc --> pm
        boot --> pm
        pm --> session
    end
    state[("State directory: bridge-*.json")]
    pm -.-> state
    boot -.-> state
    session --> os["Operating system: TUN device, route table, WFP or pf, DNS settings"]
```

- **`hole`** ({src}`crates/hole/`) is the binary: the Tauri app, the command line, and the entry points of the bridge.
- **`hole-bridge`** ({src}`crates/bridge/`) is the bridge as a library. {src}`crates/bridge/src/ipc.rs` answers the app;
  {src}`crates/bridge/src/proxy_manager.rs` owns at most one session; {src}`crates/bridge/src/boot.rs` runs recovery and
  reconciliation once at startup, after the socket is bound and before it is served.
- **`tun-engine`** ({src}`crates/tun-engine/`) holds the TUN device, the packet loop, route installation and the
  firewall covers.
- **`hole-common`** ({src}`crates/common/`) holds the protocol types, the config and the log setup both modes use.
- The **state directory** holds the bridge's records, such as `bridge-target.json` and `bridge-lockdown.json`. The
  `--service` bridge keeps it in a system location (`%ProgramData%\hole\state` on Windows, `/var/db/hole/state` on
  macOS), owned by the system. A bridge started by hand defaults to the invoking user's profile and gives its files to
  that user, so a directory the user can write holds the records of a privileged process. That is why records are
  written through `util::dir::Dir` handles.

## What one connect holds

A start builds a `Session` ({src}`crates/bridge/src/session.rs`). Every acquisition is recorded in it the moment it
exists, so a failure anywhere in the start, a stop and a health-check give-up all end in the same `Session::teardown`.
The field order of `Session` is the release order:

1. `dns`: the resolver steering, undone first so queries still in flight leave by the restored path.
1. `dispatcher`: closes the TUN device and cancels the connection handlers.
1. `plugins`: the plugin chain, then a reap of the plugin processes by their recorded identity.
1. `proxy`: the Shadowsocks client, stopped with `stop().await`.
1. `routes`: removed by RAII.
1. `lockdown`: the [standing kill-switch cover](kill-switch.md). `Session::teardown` does not release it: it hands the
   cover back still in force, after the routes are gone, and the caller releases it or lets go of it, so the cover's
   persistent filters can outlive the routes.

A teardown never observes a cancel token: a cancelled start still runs it to the end.

## The trait seams

Everything in the bridge that changes the machine goes through one of three traits, and `ProxyManager` is generic over
them:

| Trait     | Defined in                              | Owns                                                                        |
| --------- | --------------------------------------- | --------------------------------------------------------------------------- |
| `Proxy`   | {src}`crates/bridge/src/proxy.rs`       | Starting the Shadowsocks client; a single-use `RunningProxy` handle         |
| `Routing` | {src}`crates/tun-engine/src/routing.rs` | The route table and the kill-switch covers                                  |
| `Dns`     | {src}`crates/bridge/src/dns/system.rs`  | Pointing the operating system's resolvers at the TUN device, and undoing it |

The reason is test isolation. A unit test that reached the real `netsh`, `route` or `pfctl` would change the machine it
runs on, so tests substitute a mock whose guard type counts its drops. {src}`clippy.toml` keeps the seam closed: route
setup and teardown (`setup_routes`, `teardown_routes`) are disallowed methods outside `SystemRouting`, and so are the
Windows DNS-settings calls and the FWPM calls outside their sanctioned modules. Crash recovery of routes is the free
function `recover_routes`, which the bridge calls directly and not through the trait.

Resource guards are RAII: a `Routing::Installed` removes its routes on drop and a `Routing::Cover` removes its block on
drop, with the one exception that a cover can be *disarmed*, which leaves the block in force while the process lets go
of it (see [the kill switch](kill-switch.md)).

Cancellation is cooperative: a start carries a token and checks it, and nothing cancels a start by dropping its future.
Creating a token in `crates/bridge/src/` is a disallowed method in {src}`clippy.toml`, with a short list of sanctioned
sites that each carry an `#[allow]`: the roots, such as `handle_start` in {src}`crates/bridge/src/ipc.rs` for a start
from the app, and the process shutdown token that boot passes to `reconcile_once`, which connects with a child of it.

## Where to read next

- [The kill switch](kill-switch.md): the one subsystem that outlives the bridge process, and so the one with the most
  state to reconcile.
- The datapath, from a packet to an endpoint:
  - [The datapath](datapath.md): the router's cascade, the UDP drop policy and the listener the datapath dials.
  - [The TUN device](tun-device.md): where its name comes from, and its IPv6 address.
  - [TCP accept refusal](tcp-admission.md): admitting, refusing and retiring TCP connections.
  - [The DNS forwarder](dns-forwarder.md): carrying DNS over the tunnel, and the check before a connection starts.
- Plugins: [where the plugin binaries come from](plugin-binaries.md) and [the galoshes transport](galoshes-transport.md).
- Routes: [what a failed route command does](route-failure-policy.md), and [which routes Hole may delete](route-ownership.md).
- State and recovery: [crash recovery](crash-recovery.md) of what a killed bridge left behind, [config
  recovery](config-recovery.md) for the app's own file, and [native crashes](native-crashes.md).
- Privilege: [folders a user may own](privileged-folders.md), [the file lock and state files](file-lock.md), [system
  tools](system-tools.md) and [the update cutover](update-cutover.md).
- Windows service: [stop reporting](windows-service-stop.md). Test infrastructure: [spawn contention and
  ports](contention-and-ports.md).
- The process model is still in {src}`CONTRIBUTING.md`, under *Architecture*.
