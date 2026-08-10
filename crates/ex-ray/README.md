# ex-ray

ex-ray is a first-party SIP003 shadowsocks plugin built on
[v2ray-core](https://github.com/v2fly/v2ray-core). It builds the same
v2ray-core data-plane configuration that
[`shadowsocks/v2ray-plugin`](https://github.com/shadowsocks/v2ray-plugin)
builds, so it is **wire-compatible** with stock v2ray-plugin servers and
clients: a Hole client running ex-ray talks to a server running stock
v2ray-plugin, and vice versa.

ex-ray is **not** the upstream `shadowsocks/v2ray-plugin` project. It is
our own module, maintained in this repository. That means it can have
bugs the upstream project does not (and can fix bugs the upstream project
has). Its config-building construction is derived from
`shadowsocks/v2ray-plugin` (MIT-licensed); see the root
[`NOTICES.md`](../../NOTICES.md) for attribution.

ex-ray exists to give Hole a plugin it fully controls: it speaks a "sitrep"
control protocol on stdout (see [`../garter/SITREP.md`](../garter/SITREP.md))
and forces all v2ray-core logs to stderr.

## ECH (Encrypted Client Hello)

ex-ray supports ECH to keep the real proxy domain out of the cleartext TLS SNI.
SIP003 opts: `ech=auto|always|never` (default `auto` — opportunistic; `always`
fails closed) and `ech-doh=<DoH URL>` (where to fetch the rotating ECH config;
the bridge injects this).

The vendored v2ray-core (`third_party/v2ray-core`, a git-subrepo of v5.51.2 and
the build truth via the local `go.mod replace`) carries a **first-party ECH
patch** beyond stock v2ray-core, in two parts:

- **Fail-closed gate.** Client dials build their TLS config via
  `(*tls.Config).GetTLSConfigForClient` (ECH-capable transports) or
  `GetTLSConfigForUnsupportedClient` (ECH-incapable engines: uTLS, hysteria2);
  `RequireEchSatisfied` aborts an `ech=always` dial that cannot obtain an ECH
  config, so the real SNI is never sent in cleartext. Server listeners keep
  calling bare `GetTLSConfig`.
- **`retry_configs` recovery (RFC 9849).** On an `*tls.ECHRejectionError` (a
  stale config after the server rotated its ECH key), `DialClientWithECHRetry`
  retries once with the server-provided configs threaded directly into the retry
  (and best-effort-refreshes the ECH cache via `RefreshECHCache`). Wired for
  tcp, websocket, http, quic, and the `transportcommon` transports
  (httpupgrade / request-assembly); gRPC is an upstream follow-up (no
  `security.Engine` seam); hysteria2 is ECH-incapable.

**Maintenance.** On every `third_party/v2ray-core` subrepo bump, re-verify the
patch survives — the `ex-ray-tests` CI lane (`cargo xtask run ex-ray-tests`)
runs the gate / refuse / `retry_configs` Go tests plus a fake-TLS-server
reject-then-accept behavioral test, so a bump that drops or breaks the patch
fails CI. (golangci-lint excludes the vendored tree, so this go-test lane — not
the linter — is the guard.)

## TCP keepalive

A transport that is silently black-holed leaves an idle connection wedged:
nothing is written, so nothing errors. ex-ray tightens the socket's own keepalive
timers on the connection to the server so the kernel notices sooner.

SIP003 opt: `tcp-keepalive=<seconds>` — idle time before probing (default `15`).
Three probes follow at the same spacing, so a black-holed idle connection is
dropped after roughly `4 x seconds`. Without it, Go's defaults give 15s idle + 9
probes ≈ 150s.

`tcp-keepalive=0` turns keepalive off on that connection entirely, including the
~150s Go would otherwise apply — a full opt-out, not a return to the previous
behaviour. Other internal dials (the ECH DoH bootstrap) keep Go's defaults either
way.

This sits on the WAN socket, below Mux.Cool, so it applies regardless of `mux`.
It has no effect in `mode=quic`, which is UDP and carries its own keepalive, nor
in server mode. A connection stalled with unacknowledged data is governed by the
retransmit timer rather than keepalive and is not covered here (see
[#707](https://github.com/bindreams/hole/issues/707)).

**Maintenance.** `TestDialSystemAppliesKeepAlive` pins the two vendored
behaviours this leans on — a registered dialer controller still reaching the fd,
and `SocketConfig`'s keepalive fields still suppressing Go's own post-connect
defaults — so a `third_party/v2ray-core` bump that breaks either fails CI rather
than silently restoring the 150s bound.

## Build

```sh
go build ./...
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).
