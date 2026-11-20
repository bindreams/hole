# Unanswered connections to a server behind Cloudflare

In August 2026 two clients in Russia could not hold a working tunnel to a server behind Cloudflare. The {term}`ECH`
config lookup succeeded on every attempt, and the connection to Cloudflare was made, but almost nothing came back
through it. A later capture showed each connection being reset about 20 seconds after it was made. The cause was not
determined.

## Setup

:Date: August 2026
:Clients: Two Windows machines in Russia with Hole 0.5.0: a user's machine, and the project's test machine (the client
of the [June 2026 report](2026-06-tls-handshake-block.md))
:Server: Shadowsocks with {term}`galoshes` over WebSocket and TLS, behind Cloudflare. The TLS server name (`host`) is a
domain.
:ECH: No `ech` plugin option, so the default, `auto`. The config lookup went to Cloudflare's {term}`DoH` resolver.
:Other options: `fast-open`. {term}`ex-ray` reads this option only when it is spelled `fastOpen`, so
{term}`TCP Fast Open` was off.

## Timeline

1. 9 August, the user's machine. Chrome, with no VPN running, times out opening the server's site. Switching the system
   DNS to a public DoH resolver makes no difference.
1. Of four connect attempts in Hole, one succeeds and Hole shows **Connected**.
1. While connected, the traffic graph shows bytes going out and none coming back, and no site loads. Hole decides
   **Connected** once, from its start-time {term}`self-test`, and does not check again.
1. The connection to the server is made again about every 19 seconds until the log ends. No traffic comes back on any
   of them.
1. The same day, the test machine, updated to 0.5.0 and given the same config, makes six connect attempts. None
   succeeds.
1. 13 August. Another user in Russia, with a server behind Cloudflare, sees the same silence: ex-ray dials the
   Cloudflare address and logs nothing more, and the self-test fails after three attempts in 4.5 seconds.
1. 14 August. A second capture records one connect in detail. The connection to the Cloudflare address opens. The
   self-test passes 0.6 seconds later and Hole shows **Connected**. From 1.3 seconds on, every DNS query through the
   tunnel times out. 20.7 seconds after it was made, the connection is reset from the remote side. galoshes reconnects,
   and the new connection is reset after 20.1 seconds.

## Measurements

From the log of the {term}`bridge` on the user's machine, 9 August:

- The ECH config lookup succeeded on every attempt and returned a real config.
- One attempt of the start-time self-test passed, after 2.2 seconds. That is how the one connect succeeded.
- ex-ray's error on each failed attempt began
  `wsarecv: A connection attempt failed because the connected party did not properly respond...`.
- The bridge's network trace recorded five TCP connects to the server's address, none with a completion event.

From the test machine, the same day: all eight ECH lookups succeeded, and the network trace recorded ten TCP connects,
none with a completion event.

From the capture of 14 August: the reset arrived as
`wsasend: An existing connection was forcibly closed by the remote host`. On each connection the first exchange got
through, and traffic stopped before the reset.

## ECH was sent on every attempt

With `ech=auto`, a successful lookup means the ECH extension is sent. ex-ray's WebSocket client sends a
{term}`ClientHello` shaped like Chrome's by default, and that ClientHello carries ECH. So on every attempt that got as
far as a ClientHello, the server's name was encrypted.

## What the errors indicate

`wsarecv` is a receive on a socket that is already connected; a connect that fails on Windows reports `connectex`
instead. The error describes a TCP connection that was established and then received nothing, not a connection attempt
that went unanswered. The capture of 14 August shows the same shape directly: the connection is made, a first exchange
passes, traffic stops, and the connection is reset about 20 seconds after it was made.

That reset also explains the 19-second rhythm of 9 August. It is not a retry timer: each connection lives about 20
seconds, and galoshes reconnects when it dies.

The network trace adds nothing to this. It covers only the bridge's own process, and ex-ray is a separate one, so the
trace does not show ex-ray's connections. In other logs the completion event was also missing for connections that
worked.

## Possible causes of the failure

- Interference with the connection after its first exchange. Inspection equipment such as the {term}`TSPU` lets the
  handshake and a first exchange through, then drops the traffic and resets the connection. The ECH extension, or the
  public name beside it, may be what it reacts to.
- A block on the address. Traffic to the Cloudflare address is cut the same way whatever the ClientHello carries. ECH
  and the server's name then play no part.
- A fault on the path that has nothing to do with blocking.

Three machines failing against Cloudflare addresses do not separate these causes. Chrome's timeout adds nothing if
Chrome also sent ECH. An earlier failure from Russia with similar symptoms turned out to be a fault in Hole's transport
that a lossy path exposed, not a block.

## Tests that would identify the cause

Two connections from the same machine, at the same time as a failing attempt:

- A plain HTTPS connection to a different site behind Cloudflare. If it works for longer than 20 seconds, the problem is
  this address or this ClientHello. If it fails, the network is cutting Cloudflare addresses broadly, and neither this
  server nor ECH explains the failure.
- A TLS connection to the server's Cloudflare address without ECH, under the name of an unrelated site behind
  Cloudflare. If it is cut the same way, neither ECH nor the server's name is what the network reacts to.

[Diagnosing a failed connection](../hostile-networks.md#diagnosing-a-failed-connection) has the commands.
