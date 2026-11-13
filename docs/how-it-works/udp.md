# UDP: dropped, never bypassed

Hole is a {term}`VPN client`, and one rule follows from that. When a UDP flow is supposed to go through the proxy and the
connection to the server cannot carry UDP, Hole **drops** the flow. It does not send it around the tunnel to its
destination, even though that would make the application work. This page explains the rule and who it affects.

## The rule

A {term}`filter` decides, for each connection, whether it goes through the proxy, around it, or nowhere. Everything is
proxied unless a rule says otherwise. If a flow that is meant to be proxied has to leave the machine outside the tunnel
to work, the application would reach its destination, but with its address, and the content if it is not itself
encrypted, visible to the network the tunnel is there to hide from. Hole counts that as a leak and prefers a flow that
fails to one that leaks.

```{mermaid}
flowchart TD
    udp["A UDP flow"] --> dns{"UDP to port 53, and the DNS forwarder is on?"}
    dns -- "yes" --> fwd["Answered by the DNS forwarder"]
    dns -- "no" --> action{"What do the filter rules say?"}
    action -- "Block" --> d1["Dropped"]
    action -- "Bypass" --> v6{"IPv6 destination and no working IPv6 on the real network?"}
    v6 -- "yes" --> d2["Dropped"]
    v6 -- "no" --> direct["Sent directly, outside the tunnel"]
    action -- "Proxy" --> cap{"Can the connection to the server carry UDP?"}
    cap -- "yes" --> relay["Relayed through the tunnel"]
    cap -- "no" --> d3["Dropped"]
```

Only the last drop is the UDP rule. The others are a **Block** rule doing what it says, and a **Bypass** flow that has no
usable route. Each drop is recorded in the {term}`bridge`'s log with the reason and, for the UDP rule, the plugin that cannot
carry the flow.

## Who can carry UDP

It depends on what runs between the {term}`Shadowsocks` client and your server.

| The config's plugin             | UDP through the tunnel                                                                             |
| ------------------------------- | -------------------------------------------------------------------------------------------------- |
| None                            | Yes: the Shadowsocks client relays UDP to the server, and Hole assumes the server relays it onward |
| {term}`ex-ray` (`v2ray-plugin`) | No: it carries TCP only                                                                            |
| {term}`galoshes`                | Yes: it carries UDP over its multiplexed connection                                                |

Hole does not guess from the plugin's name. Each plugin reports the transports it can carry when it starts, and Hole
uses that report. The dashboard shows the result as the **UDP proxy** dot, red when UDP is unavailable on the current
connection.

## What you notice

With a TCP-only plugin, anything that is proxied and needs UDP stops working, and anything that can fall back to TCP
does. A web browser that tries HTTP/3 over UDP falls back to ordinary HTTPS over TCP; a voice call, a game or a service
with no TCP alternative does not connect. With the default settings DNS is not affected, because the forwarder carries it over TCP.

If an application has to work without a UDP-capable plugin, there are two ways, and both are yours to choose:

- Use a server and a client that run {term}`galoshes`. It carries UDP through the tunnel.
- Add a **Bypass** rule for the destination. The traffic then goes outside the tunnel, with all that implies. It is
  your decision to make, for a destination you choose, not a fallback Hole takes for you.

```{dropdown} Where in the code
The cascade is `HoleRouter::resolve_endpoint` in {src}`crates/bridge/src/hole_router.rs`; the capability comes from the
transports the plugin reports, read in `udp_available_from_chain` in {src}`crates/bridge/src/proxy_manager.rs`. The drop
reasons are the methods of `DropSink` in {src}`crates/bridge/src/drop_sink.rs`.
```
