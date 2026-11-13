# The DNS forwarder

A plugin that carries only TCP, such as {term}`ex-ray`, cannot carry ordinary DNS, which is UDP, and [the datapath drops
UDP it cannot carry](datapath.md#udp-is-dropped-never-bypassed). So the {term}`bridge` runs a {term}`DNS forwarder` that carries DNS over the
tunnel's TCP path. This page is for a developer changing the forwarder, the way the operating system is pointed at it, or
the check that runs before a connection starts. The user-level story is [DNS through the tunnel](../../how-it-works/dns.md).

## The pieces

| Piece              | Where                                            | What it does                                                                                                                            |
| ------------------ | ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| `DnsForwarder`     | {src}`crates/bridge/src/dns/forwarder.rs`        | Takes a wire-format query, returns a wire-format reply. Walks the configured resolvers in order over one transport.                     |
| `LocalDnsEndpoint` | {src}`crates/bridge/src/endpoint/local_dns.rs`   | The router's endpoint for UDP port 53. Each datagram goes to `DnsForwarder::forward`, and the reply is written back into the same flow. |
| `Socks5Connector`  | {src}`crates/bridge/src/dns/socks5_connector.rs` | The forwarder's way out: every upstream connection goes through the Shadowsocks client's local {term}`SOCKS5` listener.                 |
| `SystemDns`        | {src}`crates/bridge/src/dns/system.rs`           | Points the operating system's resolvers at the TUN interface, and undoes it.                                                            |
| The self-test      | {src}`crates/bridge/src/dns/self_test.rs`        | Sends one lookup through the forwarder before anything on the machine changes.                                                          |

**The forwarder.** `DnsConfig` ({src}`crates/common/src/config.rs`) picks one transport, `DnsProtocol`: plain UDP, plain
TCP, DNS over TLS or {term}`DoH`. The forwarder uses that one transport against each resolver in `servers`, in order,
and returns the first reply. Bytes go through unmodified, so the client's transaction ID survives, and a resolver whose
address is IPv6 is skipped, with one warning per address, when the upstream interface has no IPv6
(`ipv6_bypass_available`). When every resolver fails, `forward` returns a synthesized SERVFAIL that copies the
transaction ID and question (`synthesize_servfail`), because the in-tunnel endpoint must always have bytes to write back.

**The connector.** Going through the SOCKS5 listener is what keeps a user's `Block` rule for a resolver from stranding
the forwarder: the forwarder's own traffic is a loopback connection to the listener, not a flow through the TUN device,
so no filter sees it. TCP transports use `tokio-socks`; plain UDP uses a hand-written UDP ASSOCIATE (RFC 1928), which
the Shadowsocks listener can only relay when the plugin carries UDP.

**The endpoint.** UDP/53 reaches `LocalDnsEndpoint` before the filter decision does
([the cascade](datapath.md#the-cascade)). TCP port 53 does not: it takes the ordinary cascade to the real resolver, over
the tunnel. The endpoint refuses TCP by contract (`debug_assert!`), since port 53 over TCP is not necessarily DNS.

`DnsConfig::default()` is enabled and uses DoH with its default resolvers. `AppConfig` is `#[serde(default)]`, so a
config file written before the forwarder existed enables it silently on upgrade. With `enabled` and an empty `servers`,
`build_local_dns` refuses the start with `ProxyError::ForwarderSelfTestFailed` ("no DNS servers configured"), because a
live TUN with nothing to forward to would strand every DNS flow.

## How the operating system reaches it

`Dns::apply` points the operating system's resolvers at the configured resolver addresses, but on the TUN interface only.
Those addresses fall in the halves the split routes send into the device, so a lookup arrives at the bridge, and
`LocalDnsEndpoint` intercepts it. Hole writes DNS to no adapter or service except the one of the tunnel it created, and
it reads nothing of the user's own DNS configuration, so there is nothing to capture or restore on a fresh apply. How
the pointing is done differs.

`````{tab-set}
````{tab-item} Windows
`apply_windows` runs two leak-bearing steps, in this order:

1. **Confine.** `tun_engine::dns_confine` ({src}`crates/tun-engine/src/dns_confine.rs`) engages a WFP filter set that
   permits UDP and TCP port 53 only on `hole-tun` (by LUID), on loopback and to the Shadowsocks server, and blocks it
   elsewhere. The server permit has no port condition, so the tunnel's own handshake survives a server on port 53. The set
   lives in a **dynamic, process-scoped** FWPM session, so it dies with the bridge and needs no crash recovery. That is
   the opposite lifetime from [the kill-switch cover](kill-switch-windows.md), on purpose: a cover that outlives the
   bridge is the user's intent, and a DNS block that outlives it is harm with nobody left to release it. The two are not to
   be unified.
1. **Set servers.** The resolver addresses are set on the adapter, IPv4 and IPv6 separately, each family from its own
   configured resolvers. A family with none is left untouched, never cleared.

`Dispatcher::new` also gives `hole-tun` the lowest interface metric (`TUNNEL_INTERFACE_METRIC`) so Windows prefers the
resolver Hole advertises over a physical adapter's. Only port 53 is confined: DNS over TLS on port 853 is not.
````
````{tab-item} macOS
`networksetup`'s DNS commands take a network *service* name such as "Wi-Fi", never an interface name, so the TUN
interface cannot be named to it. `apply_macos` instead publishes a supplemental resolver at a synthetic
`SCDynamicStore` key ({src}`crates/tun-engine/src/dns_steer.rs`): a dictionary naming a service that does not exist, whose
empty match-domain makes `configd` merge it as a resolver for every query, ranked above its own default.

The store session is opened with `session_keys(true)`, so the key belongs to the bridge's own dynamic-store session and
`configd` discards it when the session closes, including on `SIGKILL`. This is the analogue of the Windows session's
process-scoped lifetime. Two live bridges publish two keys, and `configd` merges both.

The resolver list is filtered to the address families the tunnel carries (`RoutedFamilies`), read once from the routes
`Routing::install` just landed, never from the TUN's IPv6 read-back or the upstream's IPv6 reachability, which answer
different questions. An empty filtered list is refused rather than advertising nothing. The `TunIdentity` parameter is not
used: the key covers the whole machine.
````
`````

**Both platforms fail the start when the pointing fails.** A session that reports connected while DNS leaks is worse than
no session. The type system enforces it: `phase::run` ({src}`crates/bridge/src/dns/system/phase.rs`) is the only place an
apply step's result is consumed, and each call picks a sealed `DnsPhase`, `LeakBearing` (the error propagates) or
`Cosmetic` (a warning). Warning on a leak-bearing call means choosing `Cosmetic` at the call site, a reviewable act, and
mirrors `FatalPhase` and `BestEffortPhase` in route installation. Only the resolver-cache flush, and the best-effort
withdraw after a cancel, are `Cosmetic`.

Residuals the design accepts: DoH to an on-link resolver is indistinguishable from ordinary HTTPS to that host on both
platforms, and on Windows DoT on port 853 is not confined. macOS has no per-port egress filter to evade, since the key only
adds a resolver. An older build's own rewrite of another adapter's DNS after a crash is still undone by
{src}`crates/bridge/src/dns/recovery.rs`; this build never writes `bridge-dns.json`.

## The start-time gate

The order of `bring_up_tunnel` in {src}`crates/bridge/src/proxy_manager.rs` is load-bearing:

1. The Shadowsocks client starts and binds its SOCKS5 listener.
1. `build_local_dns` builds the endpoint and the forwarder.
1. **The self-test runs.** A failure ends the start, and the session's teardown releases the client and the plugin chain.
1. `Dispatcher::new` opens the TUN device; only now is `LocalDnsEndpoint` reachable.
1. `routing.install` makes routes live, and later `Dns::apply` points the system at the resolvers.

The gate sits before steps 4 to 5 so a dead tunnel never takes the machine's DNS with it. Reordering them brings back a
DNS hijack into a dead tunnel with the GUI reporting *Running*; `start_blocks_on_forwarder_self_test_failure` asserts that
`routing.install` was not called when the gate fails.

`run_forwarder_self_test` sends an `example.com` A query through `try_forward` once, giving each resolver
`TUNNEL_QUERY_TIMEOUT`, the same call and bound `forward` makes at run time, so the gate can never be looser than the
forwarder. There is no retry: with two or more resolvers a single walk already dials each, and a retry would only add
cost to slow but working tunnels. Success is any well-formed reply that is not SERVFAIL; NXDOMAIN counts, since it proves
the path. The walk races the cancel token and drops on cancel.

**Reading a failure.** `classify_failure` turns what the run observed into the claim the error may make. Each claim rests
on a positive observation and never on an error code, because a local hop that hangs never reaches the connect layer, so
its code would file it under the wrong sentence. The first row that holds wins:

| Observed                                               | `SelfTestReason`        | `ProxyError`              |
| ------------------------------------------------------ | ----------------------- | ------------------------- |
| no upstream was dialled (every resolver skipped)       | `Other`                 | `ForwarderSelfTestFailed` |
| a reply arrived and was rejected (SERVFAIL, too short) | `Other`                 | `ForwarderSelfTestFailed` |
| any byte came back from an upstream                    | `Other`                 | `ForwarderSelfTestFailed` |
| a SOCKS5 CONNECT completed                             | `TunnelSilent`          | `TunnelSilent`            |
| only a UDP ASSOCIATE completed                         | `InconclusiveTransport` | `ForwarderSelfTestFailed` |
| a connect was still outstanding when its budget fired  | `TunnelSetupPending`    | `TunnelSetupIncomplete`   |
| nothing opened, and every attempt failed definitely    | `NoConnection`          | `NoTunnelConnection`      |

A SOCKS5 CONNECT is not acknowledged until the plugin's outer connection is up, so an outstanding one means the tunnel was
still being set up, not that the local proxy turned the attempt away. An ASSOCIATE never reaches the plugin and proves
nothing about it. An out-of-band reachability probe of the server runs beside the gate, so it adds no latency, and its
verdict can replace the self-test's reading (`self_test_error_for`): `Blocked` becomes `ProxyError::NetworkBlocked`, and a
refused or timed-out server port rewrites the reason. The probe is skipped when a cover is, or is about to be, in force
(`suppresses_reachability_probe`), because Hole's own block would read as censorship. The plugin's recent output is quoted
beside a failure only when the self-test's reading implicates the transport and the probe has not blamed the network
(`implicates_plugin_transport`).

## Failure reporting and budgets

`forward` is infallible by design. `try_forward` is the same walk without the SERVFAIL: it returns the observed
`UpstreamCause` of highest `UpstreamCause::rank`, ties keeping the first, because a rejected certificate says more than a
refused connect. It takes the per-upstream budget as a parameter and callers must pass it rather than wrap the call in
their own `timeout`: an outer timer that fires first drops the future before the upstream's own deadline, so nothing is
classified and nothing is logged. A walk costs at most `servers × budget`.

The DoH bootstrap resolver also uses `try_forward`, with `DIRECT_UPSTREAM_TIMEOUT`, so `BootstrapError` can tell a user
that something is intercepting TLS (a certificate chain that did not verify, decided by `is_trust_chain_rejection`) from a
resolver that simply did not answer. `is_trust_chain_rejection` is deliberately narrow: an expired certificate or a name
mismatch is the user's configuration or clock, and switching resolvers would fix it. See
[ECH and DoH](../../how-it-works/ech-and-doh.md) for the user-level view.

## Read next

- [The datapath](datapath.md): the cascade that diverts UDP/53.
- [The kill switch on Windows](kill-switch-windows.md): the persistent filters the DNS confinement is contrasted with.
