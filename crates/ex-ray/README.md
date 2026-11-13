# ex-ray

ex-ray is a [SIP003](https://shadowsocks.org/doc/sip003.html) plugin for Shadowsocks. It carries the connection between
a Shadowsocks client and its server inside WebSocket (or QUIC), optionally over TLS, so that the connection looks like
ordinary web traffic. It is [Hole](https://github.com/bindreams/hole)'s own plugin, built on
[v2ray-core](https://github.com/v2fly/v2ray-core).

## Who it is for

- **People who run a Shadowsocks server or client** and want a plugin that is wire-compatible with
  [`shadowsocks/v2ray-plugin`](https://github.com/shadowsocks/v2ray-plugin): ex-ray talks to a stock v2ray-plugin
  server, and a stock v2ray-plugin client talks to an ex-ray server. That makes it the way to pair a Hole client with a
  server that already runs v2ray-plugin, or the other way around.
- **People who want its additions:** Encrypted Client Hello and a tighter TCP keepalive, both below.

If you use the Hole app you already have ex-ray: Hole ships it and runs it for you.

ex-ray is not the upstream `shadowsocks/v2ray-plugin` project. It is a separate module, maintained in this repository,
so it can have bugs the upstream project does not, and can fix ones it has. Its config-building code is derived from
`shadowsocks/v2ray-plugin` (MIT-licensed); [`LICENSE`](LICENSE) carries the attribution.

## Install

Download the binary for your platform from a release tagged `releases/ex-ray/v<version>` on the
[releases page](https://github.com/bindreams/hole/releases). Releases cover Windows, macOS and Linux, each on amd64
and arm64, and the file is named `ex-ray-<version>-<os>-<arch>` (`.exe` on Windows). To build it yourself,
`cargo xtask ex-ray` builds it; the [contributor guide](https://hole.readthedocs.io/en/latest/contributing/index.html)
starts from a clean machine.

## Use

You do not run ex-ray by hand. A Shadowsocks client or server starts it as its plugin and hands it the SIP003
environment (`SS_LOCAL_HOST`, `SS_LOCAL_PORT`, `SS_REMOTE_HOST`, `SS_REMOTE_PORT` and `SS_PLUGIN_OPTIONS`). The
options go in `SS_PLUGIN_OPTIONS`, separated by semicolons. A typical client:

```text
tls;host=example.com;path=/ws
```

The same string with `server` added runs the server end; a TLS server also needs a certificate (`cert` and `key`). TLS is off unless `tls` is set, and the transport is
WebSocket unless `mode=quic` says otherwise (QUIC always uses TLS). `ex-ray -h` lists every option with its default.

ex-ray also speaks [sitrep](https://github.com/bindreams/hole/blob/main/crates/garter/SITREP.md) to the program that
started it: a line-delimited JSON stream on standard output that reports readiness and any start failure. Everything
else it and v2ray-core log goes to standard error.

## ECH (Encrypted Client Hello)

ECH keeps the real server name out of the cleartext TLS handshake. It needs `tls`, and two options control it:

- `ech-doh=<DoH URL>` is where ex-ray fetches the server's ECH config. It is empty by default, which turns ECH off;
  Hole sets it for you.
- `ech=auto|always|never` is the policy, `auto` by default. `auto` uses ECH when a config can be fetched and otherwise
  connects with the name in the clear. `always` never sends the name in the clear: a dial that cannot get a config
  fails, and ex-ray refuses to start without `tls` or without `ech-doh`. `never` leaves ECH off.

When a server has rotated its ECH key, the client's old config is rejected and the rejection carries the new ones. ex-ray
retries once with them and refreshes its cached copy.

[ECH and DoH](https://hole.readthedocs.io/en/latest/how-it-works/ech-and-doh.html) explains how Hole uses this.

## TCP keepalive

A connection to the server that a network silently black-holes stays open and idle, and nothing errors. ex-ray tightens
the keepalive of the socket it opens to the server, so the kernel gives up on a dead connection sooner.

`tcp-keepalive=<seconds>` is the idle time before probing starts; its default is `tcpKeepAliveDefault` in
[`config.go`](config.go). A fixed number of probes (`keepAliveProbeCount`) then follows at the same spacing, so a dead
idle connection is dropped after about the idle time plus the probes. `tcp-keepalive=0` turns keepalive off on that
connection, including Go's own default keepalive, which is a full opt-out and not a return to the old behaviour.

It applies to the client's TCP connection to the server whatever `mux` says. It does nothing in `mode=quic`, which
runs over UDP, or in server mode. A connection stalled with unacknowledged data is governed by the TCP retransmit timer
instead, which keepalive does not shorten.

## Documentation

- [Shadowsocks and its plugins](https://hole.readthedocs.io/en/latest/how-it-works/plugins.html), including how Hole
  runs ex-ray.
- [What ships from the Hole repository](https://hole.readthedocs.io/en/latest/reference/distributions.html).
- [The vendored v2ray-core and its patches](third_party/VENDORING.md), for people changing ex-ray.

## License

Apache-2.0. [`LICENSE`](LICENSE) is the full text, and also holds the MIT notice for the code derived from
`shadowsocks/v2ray-plugin`.
