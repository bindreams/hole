# Shadowsocks and its plugins

Everything Hole proxies leaves the machine through a {term}`Shadowsocks` client that runs inside the {term}`bridge`.
This page describes that client, the {term}`SIP003 plugin` that can sit between it and the server, and the two plugins
Hole ships.

## The Shadowsocks client

The bridge embeds the Rust `shadowsocks-service` library, so there is no separate Shadowsocks process. It listens on the
loopback address with a {term}`SOCKS5` listener. [The TUN engine](tun.md) hands every proxied connection to that
listener, and the client encrypts it and sends it to your server.

With **Local proxy server** on in the settings, the same listener, and an optional HTTP one, is also open to your own
applications on the ports you chose. With it off, which is the pure-VPN setup, Hole still needs the listener for its own
use, so it starts one on a free port that nothing else is told about.

## What a SIP003 plugin does

A plugin wraps Shadowsocks traffic in some other protocol, so the connection to the server looks like something else.
The specification, SIP003, says how a plugin is started: Shadowsocks gives it the address to listen on locally and the
address of the server, as environment variables (`SS_LOCAL_HOST` and `SS_LOCAL_PORT`, `SS_REMOTE_HOST` and
`SS_REMOTE_PORT`) and a free-form option string (`SS_PLUGIN_OPTIONS`). The plugin listens on the local address, wraps
what arrives, and connects to the server, where a matching plugin unwraps it before the Shadowsocks server sees it.

```{mermaid}
flowchart LR
    ss["Shadowsocks client"] -->|"plain Shadowsocks"| plugin["Plugin"]
    plugin -->|"wrapped: for example WebSocket over TLS"| server["Server-side plugin, then Shadowsocks server"]
```

Hole runs the plugin as a child process of the bridge. It picks a free loopback port, starts the plugin, and waits for
the plugin to report that it is ready, over a small protocol on the plugin's standard output that reports which
transports, TCP and UDP, the plugin can carry. Only then does it start the Shadowsocks client, with the plugin's local
address as the server address. The component that runs plugins is `garter`, which can also chain several plugins; Hole
uses a chain of one. The server's real address, already looked up over {term}`DoH`, is handed to the plugin, so the
plugin does no lookup of its own.

## The plugins Hole runs

| Name in a config | Program          | What it adds                                    |
| ---------------- | ---------------- | ----------------------------------------------- |
| `v2ray-plugin`   | {term}`ex-ray`   | WebSocket, optionally over TLS, and {term}`ECH` |
| `ex-ray`         | {term}`ex-ray`   | The same program under its own name             |
| `galoshes`       | {term}`galoshes` | Everything ex-ray does, and UDP                 |

A config that names any other plugin is refused at import with an error that lists the plugins Hole ships. The bridge
has administrator rights, and a plugin runs under its control, so it runs only the plugins Hole ships, from the one
folder where the installer or the service put them, and never one found by searching the `PATH`. On a Mac the
`hole` program carries both plugins inside itself, and the service writes them into a folder only an administrator can
change.

## ex-ray

ex-ray is built on v2ray-core and makes the same connection as the widely used `shadowsocks/v2ray-plugin`, so a Hole
client with ex-ray works against a server running the stock plugin, and the other way around. Its options include
`tls`, `host`, `path`, `mode` (WebSocket by default) and `mux`, in the usual v2ray-plugin spelling, plus `ech` and
`ech-doh` for [ECH](ech-and-doh.md). TLS is off unless the options turn it on, so a config whose plugin options do not
say `tls` uses plain WebSocket (the Shadowsocks payload inside it is still encrypted). A typical client option string looks like this:

```text
tls;host=example.com;path=/ws
```

With TLS on, the connection is an HTTPS WebSocket connection to the name in `host`, which is what camouflages it.
[Postern](https://postern.readthedocs.io) generates configs of this kind.

## galoshes

ex-ray carries TCP only. galoshes is Hole's other plugin, and it adds UDP. It is two layers in one program: a
multiplexing layer, built on the yamux protocol, and an embedded copy of ex-ray underneath it. The multiplexing layer
turns every TCP connection and every UDP exchange from the client into a numbered stream inside **one** connection to
the server, and ex-ray carries that one connection as before. UDP datagrams travel on those streams with a length
prefix, so a UDP flow is reliable and ordered, unlike UDP itself.

The server needs galoshes too, since a stock plugin does not know the multiplexing layer.

The multiplexing layer already merges all streams into one connection, so galoshes tells its embedded ex-ray not to
multiplex them a second time (`mux=0`). This is only a default. ex-ray reads the first value it finds for an option,
so a `mux=` the operator wrote earlier in the options wins. The setting also changes how the server's ex-ray reads
what arrives, so a client with `mux=0` cannot talk to a server that expects `mux=1`; both sides must agree.

```{dropdown} When the connection to the server breaks
The multiplexing layer is the one place where one dead connection stops everything, so it heals itself. It notices a
connection that ended and reconnects, waiting a short minimum between attempts and a longer one after repeated failures
(`REMOTE_BACKOFF_BASE` and `REMOTE_BACKOFF_MAX` in {src}`crates/galoshes/src/yamux.rs`). A reconnect after a reset is
how a tunnel survives a brief outage.

A connection that goes silent without being reset, as a black-holed network does, is caught by a keepalive. When
nothing at all has arrived for an interval, the client sends a tiny probe, and if still nothing arrives within a
deadline the connection counts as dead (`KEEPALIVE_INTERVAL` and `KEEPALIVE_TIMEOUT` in
{src}`crates/galoshes/src/yamux/keepalive.rs`). A busy tunnel is never probed.

When it does reconnect, any stream in flight is cut off.
```

```{dropdown} Where in the code
Plugin descriptors: {src}`crates/common/src/plugin.rs`. Starting and waiting for a plugin:
{src}`crates/bridge/src/proxy/plugin.rs`. Where the plugins live per platform:
{src}`crates/bridge/src/proxy/plugin_source.rs`. galoshes: {src}`crates/galoshes/src/main.rs`.
```
