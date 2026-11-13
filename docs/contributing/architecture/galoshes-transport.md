# The galoshes transport: self-heal and the mux default

{term}`galoshes` puts every TCP connection and UDP exchange of a client onto streams of one {term}`yamux` connection to
the server, and the embedded {term}`ex-ray` carries that one connection. One connection means one point of failure, so
the yamux client in {src}`crates/galoshes/src/yamux.rs` has to notice when the connection is dead and replace it, and the
tunnel must not hang meanwhile. This page covers how it does that, and the one option galoshes sets on ex-ray. It is for a
developer changing the galoshes client or server. The user-level summary is in [Shadowsocks and its
plugins](../../how-it-works/plugins.md#galoshes).

## A session and its listeners

`run_client` binds the local TCP listener and UDP socket once, for the life of the client, and loops over *sessions*. A
session is one yamux connection to the server: `SessionTransport::spawn` wraps the TCP stream in a
`TransportLivenessTap`, builds a yamux client connection and spawns a driver task that owns it. The listeners outlive every
session, so a reconnect does not rebind a port that the previous session's detached tasks may still hold.

`run_client_session` is a `select!` over: shutdown, the keepalive, the driver's inbound-stream channel, a local TCP
accept, a local UDP receive, and association clean-up. Shutdown ends the session, the keepalive ends it, and the
inbound-stream channel ends it when it closes. A stream the server opens arrives on that channel too; it is logged and
dropped, and the session goes on.

## Telling that the transport is dead

There are two ways a transport dies, and two detectors.

**A visible death**, a FIN, a reset or a yamux protocol error, ends the driver, and the driver drops its inbound-stream
sender. The client never expects the server to open a stream, so `inbound_rx.recv()` returning `None` is the death signal,
with no separate liveness poll. A driver that *panics* drops the sender too and so looks the same; `driver_panicked` tells
them apart, and a panic ends the client with an error rather than reconnecting.

**A silent death**, a black-holed link that delivers no reset, is caught by the client keepalive
({src}`crates/galoshes/src/yamux/keepalive.rs`). Without it nothing would notice until ex-ray's own idle timeout.

- Every `KEEPALIVE_INTERVAL` in which `TransportLivenessTap` counted no inbound read, the client opens a substream tagged
  `StreamTag::Keepalive` and writes an 8-byte nonce. The probe exists only to give an idle transport a reason to speak. A
  transport that delivered anything during the interval is not probed (`KeepaliveCycle::Skipped`), so a busy tunnel carries no
  keepalive traffic.
- The verdict is not whether the echo came back. The client reads the substream once and never inspects the answer. The
  question is whether the tap counted *any* inbound read before `KEEPALIVE_TIMEOUT` ran out. The tap sits below yamux framing,
  so a relayed byte, a window update, a pong and a stream reset all count.
- That is what makes the wire addition safe across versions. A server that does not know the tag rejects
  that one substream and keeps serving the session (`an_unknown_stream_tag_costs_one_substream_not_the_session`). The
  rejection is inbound traffic, and it must arrive before the probe's own read can end, so the tap counts it and the tunnel
  behaves as it did before the probe existed.
- The deadline covers the whole cycle, including opening the substream, because opening parks for ever once enough
  substreams await an acknowledgement, which is exactly what a black hole produces. A probe that cannot be sent reads the
  same as silence: reconnecting is the fail-safe choice for a VPN.
- Detection is bounded by `2 × KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT` from the last inbound byte, which holds only while
  the deadline is no longer than the interval. The interval also may not drop below yamux's own ping cadence, which is what
  keeps a healthy but slow server off the fatal path. A `const` assertion pins each relation at the constants, and
  `Cadence::new` is the only way to build another pair; production never does.

The keepalive's `KEEPALIVE_TIMEOUT` is a failure bound on an external event, a peer that may never answer, and not a
synchronisation delay between our own code.

## Reconnecting

When a session ends with `TransportDied`, `run_client` aborts the driver, then waits and connects again. The wait has a
floor and an escalation:

- `next_failures` counts consecutive failed sessions. A session is **productive** when the tap counted at least one inbound
  read (`was_productive`), which resets the count; an unproductive one increments it.
- `session_reconnect_backoff(failures)` is at least `REMOTE_BACKOFF_BASE` and doubles with each failure up to
  `REMOTE_BACKOFF_MAX`. The floor bounds a peer that flaps right after delivering one byte.
- "Productive" is **transport-level**, not application-level, for the reason above: a bare ping counts.
- Connecting itself, `connect_retrying`, retries with no limit until it succeeds or the client is told to stop, since the
  peer is expected to come up. A loopback peer (a sibling ex-ray) is retried at the fixed `LOOPBACK_CONNECT_RETRY`, and a
  routable one backs off on the same exponential curve, warning each attempt. Work sent to the client's local listener
  waits in the operating system's backlog meanwhile.

## What teardown costs

On session end the driver is `abort()`ed, not drained, so any relay stream still in flight is truncated. That trades a
handful of interrupted flows for a bounded teardown instead of waiting on the chain's drain timeout; `drive_connection`
has no shutdown hook to ask it to finish.

A local error does not tear the tunnel down. A failed accept or receive on the client's loopback listener, or a failed
accept on the server's inbound listener, is logged and the loop continues: reconnecting the transport would not fix a local
socket error, and these are transient (a stray `ECONNABORTED`, a momentary `EMFILE`).

## The mux default

ex-ray reads its options with the first value for a key winning (`Args.Get` in {src}`crates/ex-ray/args.go`), and its own
default for `mux` is `muxDefault`, on. galoshes' yamux has already put every stream on one connection, so Mux.Cool in
v2ray-core would only add framing and a second connection lifecycle that can fail on its own. So `ex_ray_options`
({src}`crates/galoshes/src/exray_options.rs`) appends `mux=0` to the `SS_PLUGIN_OPTIONS` it hands the embedded ex-ray.

- Because ex-ray is first-wins, the appended pair is a *default*: an operator's earlier `mux=` overrides it.
- `mux` also selects the server's dokodemo destination. With multiplexing on (`mux` nonzero in WebSocket mode), the server's inbound targets the address
  `v1.mux.cool` and expects Mux.Cool frames (`connectionReuse` in {src}`crates/ex-ray/config.go`). A client with `mux=0`
  therefore cannot talk to a server whose ex-ray has `mux` on, and both ends must run a galoshes that agrees. Pinning `mux=1`
  in the plugin options on both ends restores the earlier wire format.
- A mismatched pair fails to tunnel, and slowly. `galoshes_ws_mux_default_cannot_reach_a_mux1_server`
  ({src}`crates/plugin-e2e/tests/roundtrip.rs`) shows the break against a control with `mux=1` on both ends. On a frame it cannot parse,
  the server's Mux.Cool worker (`ServerWorker.run` in the vendored v2ray-core, `common/mux/server.go`) interrupts its
  input and returns. Whether that tears the underlying connection down promptly is not shown; the test's comment and
  its read budget fit a client that learns of the failure only when the yamux keepalive declares the transport dead,
  but nothing here proves that mechanism.
- The append goes through `garter::{split_plugin_options, join_plugin_options}`, so the escaping cannot drift from the
  parser's. A naive strip-and-append turns `path=/a\;` into `path=/a\;mux=0`, which ex-ray reads as one pair with no `mux`
  key. Two shapes have no correct output and are refused at startup: a dangling final escape, and a segment with an empty
  key, because ex-ray rejects either string whole, and a rewriter that made one parseable would turn that loud startup
  failure into a silently different configuration.
