# Architecture overview

Hole is one Rust binary, `hole`, that runs as two programs. This page names the layers inside it, what a connect
touches, and the three trait seams that keep operating-system changes out of unit tests. It is for a developer who knows
Rust and not necessarily VPNs. The user-level picture is in [How Hole is put together](../../how-it-works/overview.md).

## Two modes, one binary

`hole` with no arguments is the **app**: a Tauri program with the tray, the settings window and the config file. It runs
with the user's rights. `hole bridge run` is the {term}`bridge`: it manages the {term}`TUN` device, the routes, the
{term}`Shadowsocks` connection and the firewall block, and it needs administrator rights. Run by hand it stays in the
foreground; with `--service` the operating system's service manager (Windows SCM, macOS launchd) starts it. The mode is
chosen in `handle_bridge` in {src}`crates/hole/src/cli.rs`, and the subcommands that do not start a bridge (`install`,
`uninstall`, `unlock` and the rest) share the same entry point.

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
- The **state directory** holds the bridge's records, such as `bridge-target.json` and `bridge-lockdown.json`. It is
  owned by the bridge, not by the user. Records are written through `util::dir::Dir` handles, because a directory the
  user can write cannot be trusted by a privileged process.

## What one connect holds

A start builds a `Session` ({src}`crates/bridge/src/session.rs`). Every acquisition is recorded in it the moment it
exists, so a failure anywhere in the start, a stop and a health-check give-up all end in the same `Session::teardown`.
The field order of `Session` is the release order:

1. `dns`: the resolver steering, undone first so queries still in flight leave by the restored path.
1. `dispatcher`: closes the TUN device and cancels the connection handlers.
1. `plugins`: the plugin chain, then a reap of the plugin processes by their recorded identity.
1. `proxy`: the Shadowsocks client, stopped with `stop().await`.
1. `routes`: removed by RAII.
1. `lockdown`: the [standing kill-switch cover](kill-switch.md), released last, so its persistent filters outlive the
   routes. Its fate is decided by the caller, not by the session.

A teardown never observes a cancel token: a cancelled start still runs it to the end.

## The trait seams

Everything in the bridge that changes the machine goes through one of three traits, and `ProxyManager` is generic over
them:

| Trait     | Defined in                              | Owns                                                                        |
| --------- | --------------------------------------- | --------------------------------------------------------------------------- |
| `Proxy`   | {src}`crates/bridge/src/proxy.rs`       | Starting the Shadowsocks client; a single-use `RunningProxy` handle         |
| `Routing` | {src}`crates/tun-engine/src/routing.rs` | The route table, the kill-switch covers, and crash recovery of both         |
| `Dns`     | {src}`crates/bridge/src/dns/system.rs`  | Pointing the operating system's resolvers at the TUN device, and undoing it |

The reason is test isolation. A unit test that reached the real `netsh`, `route` or `pfctl` would change the machine it
runs on, so tests substitute a mock whose guard type counts its drops. {src}`clippy.toml` keeps the seam closed: route
setup and teardown (`setup_routes`, `teardown_routes`) are disallowed methods outside `SystemRouting`, and so are the
Windows DNS-settings calls and the FWPM calls outside their sanctioned modules. Resource guards are RAII: a `Routing::Installed` removes its routes on drop and a `Routing::Cover` removes its block on
drop, with the one exception that a cover can be *disarmed*, which leaves the block in force while the process lets go
of it (see [the kill switch](kill-switch.md)).

Cancellation is cooperative. The token a start observes descends from the root token that `handle_start` in
{src}`crates/bridge/src/ipc.rs` creates, and a bridge source file may not create a fresh one (a disallowed method in
{src}`clippy.toml`). Nothing cancels a start by dropping its future.

## Where to read next

- [The kill switch](kill-switch.md): the one subsystem that outlives the bridge process, and so the one with the most
  state to reconcile.
- The datapath (UDP policy, DNS forwarder, TUN naming, TCP admission), the route and recovery rules, and the process
  model are still in {src}`CONTRIBUTING.md`, under *Architecture*.
