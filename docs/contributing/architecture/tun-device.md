# The TUN device: its name and its IPv6 address

`Device::build` ({src}`crates/tun-engine/src/device.rs`) opens the {term}`TUN` device the datapath reads. A change to it
has to respect two things: where the device's name comes from, and why the device holds an IPv6
address on the operating system's interface as well as inside Hole's own network stack. For the routes that point
traffic at the device, and what a user sees, read [the TUN device and the
routes](../../how-it-works/tun.md) first.

## The device name has one source

After the device is open, the only correct source of its name is `Device::identity().alias()`, a `TunIdentity`
({src}`crates/tun-engine/src/device/identity.rs`). A `TunIdentity` holds the adapter's LUID and alias, and nothing but an
opened `Device` can produce one (the `synthetic` constructor is test-only), so a name that was merely requested cannot
stand in for an opened device. `Dispatcher::new` captures it before the engine consumes the device and keeps it for the
life of the session.

The name is requested differently per platform, through `TunName`
({src}`crates/tun-engine/src/device/config.rs`):

| Platform | Variant                 | What happens                                                                                                                                                      |
| -------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Windows  | `Requested("hole-tun")` | wintun creates an adapter with that name. The alias is `WINDOWS_TUN_ALIAS` ({src}`crates/bridge/src/proxy/config.rs`), never read back.                           |
| macOS    | `KernelAssigned`        | The `tun` crate leaves the name unset, the kernel picks the next free `utunN`, and the name is read back from the open handle. A failed read-back fails the open. |

`Device::build` refuses `KernelAssigned` on any other platform with `DeviceError::InvalidConfig`. On macOS the `tun`
crate, not Hole, refuses a requested name that does not already look like `utunN`, which is why `Dispatcher::new` cannot
ask for `hole-tun` there.

Who reads the identity afterwards:

- `Routing::install` takes `tun.alias()` as the interface for the split routes, on both platforms.
- `Routing::install_lockdown` takes `tun.alias()` for the cover's permit on the TUN interface. How each platform turns
  the alias into a permit is in [what the cover permits](kill-switch.md#what-the-cover-permits).
- On Windows, the LUID goes to the DNS-egress confinement and to the interface-metric call in `Dispatcher::new`.
- The macOS DNS apply takes the identity as a parameter and does not read it: the steering key it publishes covers the
  machine, not one interface ([the DNS forwarder](dns-forwarder.md#how-the-operating-system-reaches-it)).

```{dropdown} Windows: an adapter already named hole-tun
`tun` opens an adapter of the requested name if one exists and creates one only when it does not, so a leftover from a
crashed run would be adopted silently, and so would someone else's adapter that happens to carry the name. Hole asks for
a fixed adapter GUID (`HOLE_ADAPTER_GUID`) on every create, and `probe_incumbent` reads the GUID of whatever the alias
resolves to *before* creating. The three answers are `Incumbent::None` (nothing there: create), `Ours` (adopt the
leftover) and `Foreign` (refuse with `DeviceError::ForeignAdapter`, having written nothing). A probe that cannot read is
an error, never `Foreign`: "cannot read the GUID" and "the GUID is not ours" are different facts, and only the second
may refuse on ownership grounds.

The probe does not retry. The alias lookup can transiently answer "not found" on a live machine, and a retry would need
a chosen delay. The cost is bounded and in the safe direction: a raced probe reads as `None`, so an existing adapter is
adopted without the check. Do not probe with `wintun_bindings::Adapter::open`: its `Drop` closes the adapter, which would
destroy a live sibling bridge's.
```

## IPv6 in the tunnel

IPv6 traffic is meant to travel through the tunnel. The `::/1` and `8000::/1` routes capture it, `Socks5Endpoint` carries
any IPv6 destination (`supports_ipv6_dst` is always true), and the cascade drops IPv6 only for a bypass flow
([the cascade](datapath.md#the-cascade)): a `Proxy` decision on an IPv6 flow goes to the proxy.

### The device holds the address twice

`TUN_SUBNET6` ({src}`crates/bridge/src/proxy/config.rs`) is configured in two places: on the operating system's
interface, and in the address list of the smoltcp interface (`SocketStack::new`). The second is what the packet loop's own stack answers
for. The first is what lets the kernel pick a source address for a packet that matches the `::/1` route.
Without it a host with no global IPv6 address has nothing to put in the source field, and every IPv6 flow fails instead
of travelling.

The `tun` crate's `Configuration` holds a single address, so the IPv4 address goes to the crate and the IPv6 address is
assigned by `ipv6_addr::assign` ({src}`crates/tun-engine/src/device/ipv6_addr.rs`), called from `Device::build` with the
interface index of the device just created.

`TUN_SUBNET6` is a unique local address ({term}`ULA`) whose 40-bit global ID was generated pseudo-randomly as RFC 4193
section 3.2.2 prescribes, not the easily typed `fd00::`. Hole's prefix becomes a real on-link route on the interface, so a
user whose own network used the same prefix would find it swallowed by the tunnel; WireGuard examples, Docker, Proxmox and
NAS defaults all hand out `fd00::`.

### Windows: wait for the IPv6 half, then assign

On Windows the interface's IPv6 half does not exist when the device is created. The `tun` crate waits for the IPv4 half
only, so `wait_for_ipv6_interface` ({src}`crates/tun-engine/src/device/ipv6_addr/windows.rs`) waits itself. The order
inside it is load-bearing: it registers the `NotifyIpInterfaceChange` callback first, then asks `GetIpInterfaceEntry`
whether the interface already exists, then blocks on the callback. `MibInitialNotification` only confirms the registration
and carries no row, so an interface the kernel published during `tun`'s own wait emits no later `MibAddInstance`; a
register-and-block would wait out the whole budget and report a present IPv6 half as absent.

The wait blocks on the callback and does not poll, up to `IPV6_INTERFACE_BUDGET`. When the budget expires the code
treats the interface as having no IPv6 half and returns `Assigned::Ipv6StackAbsent`, so it takes elapsed time as proof of
absence: an interface the kernel publishes after the budget gets no address, and the start only warns. Route
installation reads a [different measurement](#what-is-fatal) and can still find IPv6 usable, installing the two fatal IPv6
splits into a TUN with no IPv6 source address. This is a defect, tracked in
[#1301](https://github.com/bindreams/hole/issues/1301).

The address is then created with `CreateUnicastIpAddressEntry` and `DadState = IpDadStatePreferred`, which skips duplicate
address detection for this address alone, as the `tun` crate does for the IPv4 address. IP Helper is used and not
`netsh`, because `netsh interface ipv6 add address` stores the address persistently, keyed by the adapter GUID, and Hole
requests the same GUID on every create. A crash would leave the address waiting for the next `hole-tun`.
`CreateUnicastIpAddressEntry` has no persistence parameter, so by its contract nothing outlives the adapter and route
recovery has nothing to sweep. That is reasoned from the API, not measured.

### macOS: `ifconfig`, and a failure only warns

The macOS assignment runs `ifconfig <interface> inet6 <address> prefixlen <n> alias` through `SystemTool::Ifconfig`, since
`libc` has no `in6_aliasreq`. A spawn failure, a failed `if_indextoname` or a non-zero exit logs a warning and returns
`Assigned::Ipv6StackAbsent`; on success it also reads back, with a routing lookup for a different address inside the prefix,
whether the alias created a prefix route, and logs the answer.

The whole path is unproven on a real macOS run: no test asserts that the assignment succeeds, which is why a failure only
warns while Windows fails the start. The module doc names the condition for making macOS fatal too: the path has run
green on the darwin TUN lane. Two behaviours stay unmeasured even then: how long duplicate address detection keeps the
address tentative, and whether the alias creates a prefix route in every case.

### What is fatal

On Windows, the IPv6 wait expiring (see [above](#windows-wait-for-the-ipv6-half-then-assign)) and a missing IPv6 stack reported by
`CreateUnicastIpAddressEntry` (`ERROR_NOT_SUPPORTED`) both give `Assigned::Ipv6StackAbsent`, which only warns. Any other
IP Helper failure, in the registration, the existence query, the LUID lookup or the create, is
`DeviceError::Ipv6Assign` and fails the start. On macOS every `ifconfig` failure is `Ipv6StackAbsent`. On both
platforms, before any assignment, a device whose interface index is unavailable or not positive also fails the start with
`DeviceError::Ipv6Assign`.

`Device::build` logs a warning for `Ipv6StackAbsent` and records it; `Dispatcher::ipv6_assigned()` exposes it, and
`ProxyManager::bring_up_tunnel` logs it with the routes it installed.

**Route installation reads a different measurement.** Whether the two IPv6 split routes are fatal is decided by
`gateway::tun_ipv6_available(tun_name)` ({src}`crates/tun-engine/src/gateway.rs`), a probe of the TUN interface at install
time that asks whether a socket can bind to it over IPv6. The two split routes are fatal exactly when that probe says yes
(`SetupCommand::fatal` in {src}`crates/tun-engine/src/routing.rs`); the IPv4 splits and the server bypass are always fatal.
Non-fatal means issued and tolerated, never omitted. The upstream's IPv6 reachability (`GatewayInfo::ipv6_available`) is not an
operand: a host whose security software unbinds IPv6 from new adapters has a reachable upstream and an unusable tunnel,
and reading the upstream there would refuse a connection that works. The probe answers a different question from
`ipv6_assigned()`, which reports what the assignment did.

### The build is cooperative

`Device::build` can block on the Windows wait, so `Dispatcher::new` runs it through `build_or_cancel`: on
`spawn_blocking`, raced against the start's cancel token in a `biased` `select!`. On a covered (auto-connect) start the
whole host is blocked by [the cover](kill-switch.md) during this phase, so a Cancel the build could not see would extend
the window. Nothing is cancelled by dropping a future: when the cancel wins, the blocking task runs to completion and drops
its own `Device` on its own thread, which releases the adapter.

## Read next

- [TCP accept refusal](tcp-admission.md): the TCP side of the packet loop.
