# The seams: how tests stay off the machine

Everything in the {term}`bridge` that changes the machine goes through one of three traits, so a unit test can swap the
real operating system for a mock. This page is for a developer adding code that touches the operating system: it says
which trait to use, what keeps the rule from eroding, and where a mock lives. The [architecture
overview](overview.md#the-trait-seams) names the traits; this page is the contract.

A unit test that reached the real `netsh`, `route` or `pfctl` would change the routes of the machine it runs on, and on a
shared CI runner that machine is every other job's machine too. The rule is therefore absolute for what changes the
machine: **production I/O that changes the host's network state goes through the seam, including the cleanup in a
`Drop`.** Reads are held to it only where they decide something. The Windows WFP and NDIS diagnostic snapshots read host
state outside the seam (see [what the seam does not cover](#what-the-seam-does-not-cover)).

## The three traits

| Trait     | Defined in                              | Mock                                                           |
| --------- | --------------------------------------- | -------------------------------------------------------------- |
| `Proxy`   | {src}`crates/bridge/src/proxy.rs`       | `MockProxy` in {src}`crates/bridge/src/proxy_manager_tests.rs` |
| `Routing` | {src}`crates/tun-engine/src/routing.rs` | `MockRouting` in the same file                                 |
| `Dns`     | {src}`crates/bridge/src/dns/system.rs`  | `MockDns` in {src}`crates/bridge/src/test_support/mock_dns.rs` |

- `Proxy::start` returns a single-use `RunningProxy` handle. Starting a shadowsocks server, and stopping it, go
  through it.
- `Routing` owns route installation, the question "which gateway reaches this address" (`default_gateway`,
  `default_route`) and the kill-switch covers ([the kill switch](kill-switch.md)). `Routing::install` returns an
  `Installed` guard that removes the routes when dropped.
- `Dns` owns pointing the operating system's resolvers at the {term}`TUN` device. `Dns::apply` returns an `Applied` guard.

`ProxyManager` is generic over all three, and `ProxyManager::new_with_dns` is the constructor a test uses to hand it
all three mocks. A mock keeps its state in an `Arc` that the test clones out before moving the mock into the manager.

## Cleanup goes through the trait too

A type whose `Drop` undoes an operating-system change must reach that change through the trait's guard, not by calling
the underlying function. The real `Installed` guard (`SystemRoutes`) is where route teardown happens, so a mock's guard
can count its drops, and a test can assert that a failed start released everything. A helper that bypassed the guard
would run the real teardown from a unit test, where no mock can see it.

## What enforces it

{src}`clippy.toml` lists the free functions behind each seam as disallowed methods, so a call from anywhere else fails
the lint:

- `setup_routes` and `teardown_routes` in `tun_engine::routing`. `SystemRouting::install` is the one caller of
  `setup_routes`. `teardown_routes` has two callers, both inside `SystemRouting`'s guard: `SystemRoutes::teardown_with`
  (what `SystemRoutes::drop` runs) and `SystemRouting::rollback_and_record`, the rollback of a failed install. Crash
  recovery of routes is a different path: `recover_routes` is a free function that the bridge calls directly and not
  through the trait, and it does not call `teardown_routes`.
- The Win32 DNS calls `SetInterfaceDnsSettings`, `GetInterfaceDnsSettings` and `DnsFlushResolverCache`, banned by their
  `windows` crate paths. Only the `Win32Real` backend in {src}`crates/bridge/src/dns/system/windows.rs` calls them.
  `DnsFlushResolverCache` is the exception to the guarantee: `windows-rs` does not expose it, so `Win32Real` declares it
  with an inline `extern` block, and the ban names a path that this declaration does not have. Nothing makes the lint
  fire on a second caller of that `extern` function.
- The FWPM calls that install and remove firewall filters. The sanctioned callers are in
  [the kill switch](kill-switch-windows.md) and the DNS-egress confinement.
- Spawning a process: the spawn of an OS tool goes through `util::system_tool::SystemTool`, and a spawn of anything else
  takes an `#[allow]` with its reason.

A legitimate caller takes a per-site `#[allow(clippy::disallowed_methods)]` with a comment. The test
`proxy_manager_tests_never_spawn_routing_subprocess` is the runtime half: it asserts that start and stop cycles spawn no
routing subprocess, so a path that bypassed the `Routing` trait shows up there too.

## What the seam does not cover

- **Diagnostics reads on Windows.** `ProxyManager`'s stop path calls the WFP and NDIS post-teardown snapshots
  (`diagnostics::wfp::log_snapshot`, `diagnostics::ndis::log_snapshot`), and the bridge's foreground startup calls the
  same two, outside any trait. They run `netsh` and `pnputil` through `SystemTool`, so the lint is satisfied, but they read
  the real host. A `ProxyManager` test on Windows that stops a session with every trait mocked still runs them.
  They change nothing.
- **A second caller of the DNS flush.** See the `DnsFlushResolverCache` item above.

## `Dns` has two layers

`Dns` has a second seam below it. The outer mock (`MockDns`, handed to `ProxyManager::new_with_dns`) replaces
`SystemDns::apply` whole, so it cannot show what `SystemDns::apply` itself does, such as checking the cancel token
between engaging the confinement and setting the resolvers. The inner seam substitutes the per-platform backend under
the real `SystemDns`:

| Platform | Backend traits                      | Constructor                       |
| -------- | ----------------------------------- | --------------------------------- |
| Windows  | `WinDnsBackend` and `DnsConfiner`   | `SystemDns::new_with_backend`     |
| macOS    | `MacDnsBackend` and `MacDnsSteerer` | `SystemDns::new_with_mac_backend` |

Both layers are needed: the outer one tests the manager against a `Dns`, the inner one tests `SystemDns` against a
backend.

## Where to read next

- [Cancellation and teardown](cancellation.md): the guards these traits return, and the order they are released in.
- [Testing](../testing.md#which-lane-proves-what): which lane proves what, including the datapath seams.
