# DNS through the tunnel

A DNS lookup turns a name into an address, and it is the part of browsing that most obviously gives you away: the
network you are on sees every name you ask for. It is also the part a tunnel most easily breaks. This page explains how
Hole carries your lookups through the tunnel, what it changes on the machine to do so, and what it checks before it
does.

## The problem

Two things go wrong if Hole leaves DNS alone. The lookups go to whatever resolver the network handed out, and that
resolver, and anyone watching the path to it, learns what you browse. And ordinary DNS is UDP, which [the UDP rule](udp.md)
drops when the server's plugin cannot carry UDP. With {term}`ex-ray`, a TCP-only plugin, the machine would have no DNS at all.

So Hole answers DNS itself. Its {term}`DNS forwarder` sits inside the {term}`bridge`, takes lookups arriving through
the {term}`TUN` device, and sends them to the resolver you chose over a transport that does ride the tunnel.

## The path of a lookup

```{mermaid}
sequenceDiagram
    participant App as An application
    participant OS as Operating system
    participant T as TUN device and bridge
    participant F as DNS forwarder
    participant R as Your chosen resolver
    App->>OS: Look up example.com
    OS->>T: UDP to port 53 of a configured resolver address
    T->>F: Intercept before any filter rule is read
    F->>R: Same question, over the tunnel (DoH by default)
    R-->>F: Answer
    F-->>T: Reply with the application's own transaction ID
    T-->>OS: Answer
    OS-->>App: Address
```

Hole points the operating system's DNS at the resolver addresses in its settings. Public resolver addresses, such as the defaults, fall in the halves of
the address space that [the routes](tun.md#two-routes-per-address-family) send into the TUN device, so the
lookup arrives at the bridge. A UDP packet to port 53 is handed to the forwarder before any [filter](tun.md#from-packets-to-connections)
rule is read. This holds for any destination, not only the configured resolvers, so an application that hard-codes its
own resolver is answered by the forwarder too, and a rule that blocks that resolver does not stop the answer.

The forwarder tries your resolvers in order and returns the first answer. Each question goes out over one of four
transports: {term}`DoH` (the default), DNS over TLS, plain DNS over TCP, or plain DNS over UDP. The first three work
with any plugin. Plain UDP works only if the connection to the server can carry UDP (see [the UDP rule](udp.md)). If every
resolver fails, the forwarder answers the application with a server failure rather than with silence.

The forwarder reaches its resolvers through the Shadowsocks client's local {term}`SOCKS5` listener, the same path
proxied connections take. A rule that blocks traffic to a resolver therefore cannot cut the forwarder off from it.
Only UDP to port 53 is intercepted. DNS over TCP to port 53 is an ordinary connection that the filter rules and the
proxy carry to the real resolver.

## What Hole changes on the machine

Hole writes DNS settings only for the tunnel it created. It never edits the settings of your Wi-Fi or Ethernet adapter,
so there is nothing of yours to restore, and a crash cannot leave your own DNS configuration altered. How the operating
system is pointed at the forwarder differs by platform.

`````{tab-set}
````{tab-item} Windows
Hole sets the DNS servers on its own adapter, `hole-tun`, IPv4 and IPv6 separately. So that no lookup leaves through another
adapter, Hole also adds a firewall filter set that permits DNS (UDP and TCP port 53) only on
`hole-tun`, on loopback and to the Shadowsocks server, and blocks it everywhere else. The filters belong to a session
that Windows deletes when the bridge process ends, however it ends, so they need no cleanup after a crash.

Only port 53 is confined. DNS over TLS on port 853 is not.
````
````{tab-item} macOS
The `networksetup` tool can only change DNS per network service, such as "Wi-Fi", and has no way to name a tunnel
interface. Instead, Hole publishes a resolver entry in the system's dynamic store under a made-up service that applies
to every name and ranks above the machine's usual resolvers. The entry belongs to the bridge's own session with the
system's configuration daemon, which discards it when that session closes, including if the bridge is killed. Nothing of
your own DNS configuration is read or changed.
````
`````

On both platforms a failure to set this up fails the connection. A session that said "connected" while lookups leaked
would be worse than one that said it could not connect.

## What Hole checks first

Before it opens the TUN device, installs any route or touches any DNS setting, the bridge sends one test lookup,
`example.com`, through the forwarder and the proxy. If the lookup is not answered, the connection fails with an error
that says which of three things happened: every attempt to open a connection into the tunnel failed outright, a
connection was still being set up when the time ran out, or the tunnel opened and then nothing came back. The message
does not pick a side where it cannot tell: a dead plugin and a server that cannot reach your resolver look the same
from here. Because the check runs first, a dead tunnel never takes the
machine's DNS with it.

## Settings

The forwarder is on by default. Its transport, its resolvers and the **Allow insecure bootstrap** switch are in the
settings. With the forwarder off, Hole leaves DNS settings alone and lookups travel like any other traffic, under the
filter rules and [the UDP rule](udp.md). The resolvers stay in use for [looking up the server and for ECH](ech-and-doh.md)
whether or not the forwarder is on.

```{dropdown} Where in the code
The forwarder: {src}`crates/bridge/src/dns/forwarder.rs`. The in-tunnel intercept:
{src}`crates/bridge/src/endpoint/local_dns.rs`. The self-test: {src}`crates/bridge/src/dns/self_test.rs`. The Windows
filters: {src}`crates/tun-engine/src/dns_confine.rs`. The macOS entry: {src}`crates/tun-engine/src/dns_steer.rs`.
```
