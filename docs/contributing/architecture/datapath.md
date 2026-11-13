# The datapath: from a packet to an endpoint

The datapath is what happens to traffic once the routes have sent it into the {term}`TUN` device: the packet loop reads
it, a router decides what to do with each connection or UDP flow, and an endpoint carries it. This page is for a
developer who has to change one of those steps. The user-level picture, which this page does not repeat, is in
[the TUN device and the routes](../../how-it-works/tun.md) and [UDP: dropped, never
bypassed](../../how-it-works/udp.md).

## The path of a flow

```{mermaid}
flowchart TB
    tun["TUN device"] --> driver["Driver (tun-engine): packet loop and TCP/IP stack"]
    driver -- "new TCP connection, new UDP flow" --> router["HoleRouter (bridge): filter decision, then cascade"]
    router --> proxy["Socks5Endpoint: the Shadowsocks client's listener"]
    router --> bypass["InterfaceEndpoint: a socket on the real interface"]
    router --> dns["LocalDnsEndpoint: the DNS forwarder"]
    router --> drops["DropSink: records a drop, nothing is served"]
```

`tun-engine` ({src}`crates/tun-engine/`) knows nothing about filters, proxies or DNS. Its `Driver`
({src}`crates/tun-engine/src/engine/driver.rs`) runs the packet loop and the TCP/IP stack
([smoltcp](https://github.com/smoltcp-rs/smoltcp)), and hands each accepted TCP connection and each new UDP flow to a
`Router` trait object ({src}`crates/tun-engine/src/engine/router.rs`). The {term}`bridge` supplies the one implementation,
`HoleRouter` ({src}`crates/bridge/src/hole_router.rs`), built by `Dispatcher::new`
({src}`crates/bridge/src/dispatcher.rs`) together with the TUN device and the engine.

Every endpoint implements `Endpoint` ({src}`crates/bridge/src/endpoint.rs`): it serves a TCP flow or a UDP flow, and it
reports two capabilities, `supports_udp` and `supports_ipv6_dst`, which the cascade below reads. `HoleRouter` holds three
endpoints, named by the *role* they play (the filter action that picks them), and a drop sink:

| Field       | Type                                                                 | Carries                                                                        |
| ----------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `proxy`     | `Socks5Endpoint` ({src}`crates/bridge/src/endpoint/socks5.rs`)       | Flows to dial through the {term}`Shadowsocks` client's {term}`SOCKS5` listener |
| `bypass`    | `InterfaceEndpoint` ({src}`crates/bridge/src/endpoint/interface.rs`) | Flows to send from a socket bound to the real network interface                |
| `local_dns` | `LocalDnsEndpoint` ({src}`crates/bridge/src/endpoint/local_dns.rs`)  | UDP port 53 flows, answered by [the DNS forwarder](dns-forwarder.md)           |
| `drops`     | `DropSink` ({src}`crates/bridge/src/drop_sink.rs`)                   | Where a refused flow is recorded                                               |

Per flow, the router does four things. For TCP, and only when the rule set has a domain rule (`has_domain_rules`), it
peeks at the first bytes (at most `PEEK_BUF_SIZE`, waiting at most `PEEK_TIMEOUT`) to recover a TLS server name or an
HTTP `Host` header. UDP is never peeked and always matches on the address. It then builds a `ConnInfo` and calls
`filter::engine::decide`, runs the cascade, and either serves the flow on the chosen endpoint or records the drop.

## The cascade

`HoleRouter::resolve_endpoint` maps the {term}`filter` decision plus the shape of the flow to an endpoint or to a drop.
It is the only place that does, and it reads top to bottom:

| Flow                                                                     | Result                                     |
| ------------------------------------------------------------------------ | ------------------------------------------ |
| UDP to port 53, and a `local_dns` endpoint is present                    | `LocalDnsEndpoint`, whatever the rules say |
| `Proxy`, UDP, and the proxy endpoint cannot carry UDP                    | drop: `UdpProxyUnavailable`                |
| `Proxy`                                                                  | `Socks5Endpoint`                           |
| `Bypass`, an IPv6 destination, and the bypass endpoint cannot reach IPv6 | drop: `Ipv6BypassUnreachable`              |
| `Bypass`                                                                 | `InterfaceEndpoint`                        |
| `Block`                                                                  | drop: `RuleBlock`                          |

A drop is not a dispatch: `resolve_endpoint` returns a drop reason in place of an endpoint, and the router closes the
flow itself. The three reasons each have their own method on `DropSink`, so a test can tell an explicit rule block from
the privacy drop from an unreachable destination. Production wires `LoggingDropSink`
({src}`crates/bridge/src/drop_sink/logging.rs`), which logs them; tests wire a recording sink, which is what makes the
invariant below assertable.

## UDP is dropped, never bypassed

Hole is a {term}`VPN client`. A flow whose decision is `Proxy` has to leave through the tunnel, and a UDP flow cannot
when the plugin on the connection to the server carries only TCP. The cascade drops it. It never falls back to the
`bypass` endpoint, because that would send the flow to its destination outside the encrypted tunnel. Do not "fix" a
failing UDP application by cascading to `InterfaceEndpoint`: the drop is the product's behaviour, and the user-facing
escape (a Bypass rule the user writes) is in [the how-it-works page](../../how-it-works/udp.md#what-you-notice).

Where `supports_udp` comes from for the proxy endpoint:

- `udp_available_from_chain` in {src}`crates/bridge/src/proxy_manager.rs` reads the transports the running plugin chain
  reported when it became ready. With no plugin the answer is yes, since the SOCKS5 listener always relays UDP.
- {term}`galoshes` reports TCP and UDP (`GALOSHES_TRANSPORTS`). {term}`ex-ray` in client mode reports TCP only, so
  `v2ray-plugin` configs are TCP-only. The name of the plugin plays no part in the decision.
- The result is passed to `Dispatcher::new` as `plugin_supports_udp` and fixed for the life of the endpoint. The same
  value feeds the dashboard's **UDP proxy** dot.

`Socks5Endpoint::serve_udp` carries a `debug_assert!` that its capability is true: the cascade is what keeps a UDP flow
away from a TCP-only endpoint, and the assertion states that contract.

**UDP port 53 is the exception, and it comes first.** With DNS enabled the router sends every UDP/53 flow to
`LocalDnsEndpoint` before reading the filter decision, to any destination, so DNS keeps working on a TCP-only plugin and
a hard-coded resolver is answered too. TCP port 53 is not intercepted; it takes the normal cascade. `Driver` also has a
generic `DnsInterceptor` hook ({src}`crates/tun-engine/src/engine/dns.rs`), but the bridge does not register one:
`Dispatcher::new` leaves it unset, and the interception lives in the cascade.

## The listener the datapath dials

The `proxy` endpoint dials the Shadowsocks client's SOCKS5 listener on `127.0.0.1`. In a full-tunnel start that
listener is either the one the user enabled (**Local proxy server** on) or an internal one on an ephemeral port
(**Local proxy server** off, the pure-VPN start). The rules that pick between them are in
{src}`crates/bridge/src/proxy/config.rs`:

- `build_ss_config` pushes at most two local instances: SOCKS5 (`Mode::TcpAndUdp`, always) and HTTP CONNECT
  (`Mode::TcpOnly`, because CONNECT is TCP-only).
- `validate_proxy_config` rejects four combinations before anything starts, each a `ProxyError`:

| Error                   | When                                                                     |
| ----------------------- | ------------------------------------------------------------------------ |
| `TunnelRequiresSocks5`  | Full tunnel, HTTP listener enabled, SOCKS5 listener disabled             |
| `NoListenersEnabled`    | SOCKS-only mode with neither listener enabled                            |
| `DuplicateListenerPort` | both listeners enabled on the same port                                  |
| `InvalidListenerPort`   | an enabled listener has port 0 (`local_port` or `local_port_http` named) |

- Full tunnel with neither listener enabled is the pure-VPN start, not an error. `start_inner` allocates a loopback
  port with `port_alloc::bind_ephemeral` (TCP and UDP), `build_ss_config` receives it as `internal_socks5_port`, and
  nothing is bound on the configured ports. The GUI sends this configuration when the master toggle is off:
  `build_proxy_config` ({src}`crates/hole/src/commands.rs`) ANDs both listener flags with `proxy_server_enabled`.
- `TunnelRequiresSocks5` exists because the mixed case (a fixed HTTP port next to an internal SOCKS5 one) would put the
  fixed port inside `bind_ephemeral`'s retry loop, which has no bound by design. A real conflict on a fixed port must
  surface instead.

The dispatcher, the DNS forwarder and its self-test all dial the port `start_inner` ends up with
(`socks5_port`), never the configured one blindly.

## Read next

- [The TUN device](tun-device.md): the name, the addresses and IPv6 of the device the `Driver` reads.
- [TCP accept refusal](tcp-admission.md): what the `Driver` does between a SYN and a connection reaching the router.
- [The DNS forwarder](dns-forwarder.md): what `LocalDnsEndpoint` calls.
