# When the server is fine but the handshake dies

A beta tester in Russia clicked Connect and it failed. The server was healthy: from anywhere else it answered at once. The
network between the two let the TCP connection through and killed the TLS handshake on top of it. This page is about what
that looks like, why the server is not the one being targeted, what fixes it, and how Hole tells it apart from a wrong
password.

## What it looked like

These are observations from a test box in Russia, probing the tester's server and other hosts.

| Probe from the test box                                                                         | Result                          |
| ----------------------------------------------------------------------------------------------- | ------------------------------- |
| TCP connect to the server on ports 443 and 80                                                   | Connects in about 50 ms         |
| Traceroute to the server                                                                        | Reaches it through Russian hops |
| TLS ClientHello to the server                                                                   | Reset or dropped                |
| The same, with a harmless server name                                                           | The same                        |
| The same, to the bare IP address with no name                                                   | The same                        |
| Every live host in three /24 ranges of the server's hoster, and in one range of a second hoster | All blocked the same way        |
| Hosts at two other hosting providers, and CDN anycast addresses                                 | All worked                      |

From a clean vantage point the server answered the handshake quickly, and served its login page.

## How to read it

Three facts decide the reading:

- **TCP completes and the handshake does not.** Something on the path acts after the TLS handshake begins, so this is not
  an unreachable address. It differs from [the failure where the SYN gets no
  reply](hostile-networks.md#telling-the-failures-apart).
- **The block does not depend on the server name.** A harmless name and no name at all fail alike, so it is not keyed on
  the domain.
- **It covers whole ranges.** Every live host in the server's neighbouring ranges failed, and other providers did not.
  The server is not individually targeted. It shares address space with other VPN hosts and is blocked with them.

The reading recorded at the time was that this is a {term}`TSPU` block of VPN-hosting ranges. What the probes show is the
three facts above, the range scope above all. That a particular operator's equipment is doing it is an inference.

## What fixes it

| Remedy                                   | Result                                                                                                                                                                                                                               |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A different address from the same hoster | Does not help: the blocked ranges were whole networks, and the probes found every live host in them blocked.                                                                                                                         |
| Putting the endpoint behind a CDN        | Works while CDN anycast addresses stay reachable, as they were here. The endpoint has to be WebSocket over TLS ({term}`ex-ray` with `tls` and a `host`): a CDN speaks HTTP to its customers, which plain {term}`Shadowsocks` is not. |
| Moving to a provider that is not blocked | Works for now. The expectation is whack-a-mole, as the blocked ranges grow. That is a forecast, not something measured.                                                                                                              |

## Why a longer wait is the wrong fix

A reset is not slowness, so waiting longer for an answer cannot produce one. Hole does not stretch its start-time check to
cover this case. It asks a different question instead, described next.

## How Hole reports it

Hole tells a network that drops the handshake apart from a server that rejects the credentials, in both places a
connection can fail.

**When you connect.** The bridge starts an out-of-band probe of the server's address beside the start-time DNS
self-test, so the probe adds no wait. If the self-test passes, the probe is cancelled. If it fails, the probe's verdict
decides what you are told:

| The probe found                                                     | The message                                                                                         |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| A connect, then no first byte back: reset, silence or end of stream | "The network is blocking the connection to this server…", with the advice to try a different server |
| The server refused the TCP connection                               | "The server refused the connection."                                                                |
| Nothing answered the TCP connect, or it failed some other way       | "The server did not respond (connection timed out)."                                                |
| It could not tell                                                   | The self-test's own message                                                                         |

**When you press Test.** If the tunnel test ends as "Server rejected the connection" or "Server cannot reach the public
internet", the bridge runs the same probe. When it says the handshake was blocked, Test shows the network-blocked message
and not the credential one. Every other outcome passes through unchanged, so a reachable server is never reported blocked.

The probe aims at the server's address as the bridge resolved it, never at its domain name, and mirrors the plugin's
transport: a bare TCP connect with no plugin, a TLS or WebSocket first flight with one, a QUIC handshake for a QUIC
server. For TLS it sends a ClientHello and accepts any answering byte, without checking the certificate: the question is
whether the network lets the handshake through, not whose certificate comes back.

```{admonition} What the probe cannot say
---
class: note
---
- **It is skipped while a cover is in force or about to be.** With Lockdown on, the bridge's own block would make the
  probe's traffic fail, so the connect failure keeps the self-test's own message and the network-blocked one does not
  appear.
- **It runs only with the DNS forwarder on.** The self-test it accompanies is the forwarder's.
- **Its hello is not ex-ray's.** The probe sends no ECH and no domain name, so "reachable" means a plain ClientHello got
  an answer, not that the one ex-ray sends would.
- **Its deadlines are fixed.** A reply later than the first-flight deadline reads as blocked, and a TCP connect that fails
  for any reason except a refusal reads as "did not respond", whether the cause was the network, a firewall on the
  machine, or a reset.
```
