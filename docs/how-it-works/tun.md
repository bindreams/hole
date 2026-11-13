# The TUN device and the routes

Hole captures traffic with a {term}`TUN` device, a virtual network adapter that the {term}`bridge` creates for the
length of a connection. This page explains why, how the operating system is made to use it, and what happens to a
connection once it arrives.

## Why not a system proxy

Windows and macOS both have a "system proxy" setting, but it is only a request: an application uses it if it chooses
to. Many do not, and many that do use it for some traffic only. A TUN device works one layer down. The operating system
sends the machine's packets to it as it would to any network card, so every application is covered whether or not it
knows Hole exists.

## Two routes per address family

Pointing the machine at a new adapter means changing its routing table. Hole does not replace the default route. It
adds four routes that are more specific than the default one, each covering half of an address space:

| Route         | Covers                  |
| ------------- | ----------------------- |
| `0.0.0.0/1`   | The first half of IPv4  |
| `128.0.0.0/1` | The second half of IPv4 |
| `::/1`        | The first half of IPv6  |
| `8000::/1`    | The second half of IPv6 |

Between them they cover every address, and a more specific route wins over the default, so all traffic goes into the
TUN device while the original default route stays in place untouched. When Hole disconnects it removes the routes it
added, and the machine is back as it was.

One address must not go into the tunnel: the {term}`Shadowsocks` server's. The tunnel's own connection to it would otherwise
loop back into the tunnel. Hole adds a fifth route, a host route for the server's address that goes out through the
machine's real network, not the tunnel. It names the real gateway as the next hop, or the real network interface itself
where there is no gateway to name: for an IPv6 server always, and on Windows for an IPv4 server whose route has no
gateway. It is left out when the server is on the same machine, since loopback is already more specific
than the halves.

```{dropdown} Why Hole deletes only routes it recorded
Hole writes down each route it installs, and teardown and crash recovery delete only those. A route that failed to
install belongs to whoever holds it now, often another VPN, and deleting it would take that VPN's tunnel down. The
record is {src}`crates/tun-engine/src/routing/state.rs`; the route list is `RouteId` in
{src}`crates/tun-engine/src/routing.rs`.
```

## Names and addresses

On Windows the adapter is always called `hole-tun`, and you can see it in the list of network adapters while Hole is
connected. On macOS the kernel picks the name, a `utun` followed by a number, and Hole reads it back rather than
assuming one; the routes and the {term}`kill switch` take the name from what the kernel assigned.

The tunnel's own addresses are fixed, one IPv4 and one IPv6 network, named `TUN_SUBNET` and `TUN_SUBNET6` in
{src}`crates/bridge/src/proxy/config.rs`.

## IPv6

IPv6 goes through the tunnel like IPv4: the proxy path carries any IPv6 destination, and reaching it is up to the server. The tunnel's IPv6 network is a
private one whose prefix was chosen at random once, as RFC 4193 prescribes, instead of the easily typed `fd00::` that
many tools hand out. The tunnel's network becomes a real on-link route on the adapter,
so a prefix shared with one of your own networks would let the tunnel swallow its traffic.

The adapter holds its IPv6 address with the operating system as well as inside Hole's own network stack. A machine with
no global IPv6 address would otherwise have no source address for the IPv6 routes, and every IPv6 connection would fail
instead of going through the tunnel.

If the tunnel adapter has no IPv6 at all, Hole still issues the two IPv6 routes but tolerates their failing, rather than
failing the connect.

## From packets to connections

An application's packets arrive at the TUN device as raw IP. Hole runs a small TCP/IP stack of its own inside the bridge
(the `smoltcp` library) that answers the application as if it were the remote server, completing each TCP handshake
and reading each UDP datagram. Each connection or UDP flow becomes one unit of work that the bridge routes on its own.

```{mermaid}
flowchart TD
    pkt["Packets from an app, via the TUN device"] --> stack["Hole's TCP/IP stack"]
    stack --> peek["TCP: read the first bytes for a domain name (only when a filter rule names a domain)"]
    peek --> rules["Filter rules: the last matching rule wins"]
    stack -- "UDP: IP address only" --> rules
    rules -- "Proxy" --> proxy["Relay through the local Shadowsocks client"]
    rules -- "Bypass" --> bypass["Open a socket on the real network interface"]
    rules -- "Block" --> drop["Close (TCP) or discard (UDP)"]
```

For TCP, if any {term}`filter` rule names a domain, the bridge waits briefly for the first bytes the application sends and
reads the destination domain from the TLS handshake's server name or from the HTTP `Host` header. Without a
domain rule it does not wait. UDP has no such peek, so a UDP flow is matched on its IP address alone. The rules are
checked from the bottom of the list up, and the first one that matches decides; when none matches, the connection is
proxied.

What the decision means:

- **Proxy.** The bridge connects to its own Shadowsocks client's {term}`SOCKS5` listener on the loopback address and
  copies bytes both ways. UDP is subject to [the UDP rule](udp.md).
- **Bypass.** The bridge opens its own connection to the destination on the machine's real network interface, outside
  the tunnel. If the destination is IPv6 and the real network has no IPv6, the flow is dropped.
- **Block.** A TCP connection is accepted and then closed with an ordinary close, not a reset. A UDP flow is discarded
  without a reply.

DNS is the exception: a UDP lookup to port 53 always goes to the {term}`DNS forwarder`, whatever the rules say. See
[DNS through the tunnel](dns.md).

```{dropdown} Where in the code
The decision loop is {src}`crates/bridge/src/filter/engine.rs`; the three outcomes and the UDP and IPv6 drop cases are
in `HoleRouter::resolve_endpoint` ({src}`crates/bridge/src/hole_router.rs`). The packet loop is
{src}`crates/tun-engine/src/engine.rs`.
```
