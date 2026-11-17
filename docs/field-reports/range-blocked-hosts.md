# When the server is fine but the handshake dies

A beta tester in Russia clicked Connect and it failed. The server was healthy: from a clean vantage point it answered at
once. The network between the two let the TCP connection through and killed the TLS handshake on top of it. This page is
about what that looks like, how to read it, what might fix it, and how Hole tells it apart from a wrong password.

## What it looked like

These are second-hand observations of a test box in Russia probing the tester's server and other hosts. They do not say
which tool sent the probes.

| Probe from the test box                                                                         | Result                                          |
| ----------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| TCP connect to the server on ports 443 and 80                                                   | Connects in about 50 ms                         |
| Traceroute to the server                                                                        | Reaches it through Russian hops                 |
| TLS ClientHello to the server                                                                   | Reset or dropped (the probes do not tell which) |
| The same, with a different, benign server name                                                  | The same                                        |
| The same, to the bare IP address with no name                                                   | The same                                        |
| Every live host in three /24 ranges of the server's hoster, and in one range of a second hoster | All blocked the same way                        |
| Hosts at two other hosting providers, and CDN anycast addresses                                 | All worked                                      |

From a clean vantage point the server answered the handshake quickly, and served its login page.

## How to read it

Three facts decide the reading:

- **TCP completes and the handshake does not.** The address is reachable, and something on the path acts on the TLS
  hello, or on what follows the connect. It differs from [the failure where the SYN gets no
  reply](hostile-networks.md#telling-the-failures-apart). The probes sent only plain TLS ClientHellos: none sent a non-TLS
  payload to port 443 or TLS to another port, so they do not show whether the hello's shape matters or any payload to that
  address and port would die.
- **The block does not depend on the server name.** A benign name and no name at all fail alike, so it is not keyed on
  the domain.
- **It covers whole ranges.** Every live host the probes found in the server's neighbouring ranges failed, and hosts at
  two other providers did not. The notes give no count of hosts. So the server was not singled out; whether the other
  blocked hosts were also VPN servers is not stated.

The reading recorded at the time was that this is a {term}`TSPU` block of VPN-hosting ranges (the traffic-inspection
equipment of Russian internet providers). That a
particular operator's equipment is doing it, and that the ranges are blocked for hosting VPNs, are inferences.

## What might fix it

None of these was tried for this tester. Each is advice, with what the probes do and do not show.

| Remedy                                   | Status                                                                                                                                                                                                                                                                                                                                                                                 |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A different address from the same hoster | Advice against, by inference: the probes found every live host blocked in the ranges they covered, so "whole networks" is a reading. They did not probe other ranges of that hoster, so an address elsewhere in its space is untested.                                                                                                                                                 |
| Putting the endpoint behind a CDN        | Advice. The probes found CDN anycast addresses reachable at the TLS layer. It is not shown to work: the one case here that used a CDN, [the Russian case](russia-ech-investigation.md), is open and its cause unknown. The endpoint has to be WebSocket over TLS ({term}`ex-ray` with `tls` and a `host`): a CDN speaks HTTP to its customers, which plain {term}`Shadowsocks` is not. |
| Moving to a provider that is not blocked | Advice. The probes found hosts at two other providers reachable. The expectation is whack-a-mole, as the blocked ranges grow. That is a forecast, not something measured.                                                                                                                                                                                                              |

The server-side steps, such as the plugin options a server needs and putting a server behind a CDN, belong to the
server's own documentation; for a [Postern](https://postern.readthedocs.io/en/latest/) server, that is Postern's.

## Why a longer wait is the wrong fix

A reset is not slowness, so waiting longer cannot turn it into an answer.

## How Hole reports it

Hole tells a network that drops the handshake apart from a server that rejects the credentials, in both places a
connection can fail.

**When you connect.** The {term}`bridge` probes the server's address beside the start-time DNS {term}`self-test`. If the
self-test fails, the probe's verdict decides what you are told:

| The probe found                                                                                                     | The message                                                                                         |
| ------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| A connect, then no first byte back: reset, silence or end of stream                                                 | "The network is blocking the connection to this server…", with the advice to try a different server |
| The server refused the TCP connection                                                                               | "The server refused the connection."                                                                |
| Nothing answered the TCP connect, or it failed some other way                                                       | "The server did not respond (connection timed out)."                                                |
| Anything else: the server was reachable, the lookup failed, the probe could not tell, or it was skipped (see below) | The self-test's own message                                                                         |

**When you press Test.** If the tunnel test ends as "Server rejected the connection" or "Server cannot reach the public
internet", the bridge runs the same probe. When it says the handshake was blocked, Test shows the network-blocked message
and not the credential one. Every other outcome passes through unchanged. A block is reported only when the probe saw the
handshake fail; the limits below say what that can and cannot prove.

The probe aims at the server's address as the bridge resolved it, never at its domain name, and mirrors the plugin's
transport: a bare TCP connect with no plugin, a TLS or WebSocket first flight with one, a QUIC handshake for a QUIC
server. For TLS it sends a ClientHello and accepts any answering byte, without checking the certificate: the question is
whether the network lets the handshake through, not whose certificate comes back.

```{admonition} What the probe cannot say
---
class: note
---
- **On connect, it is skipped while {term}`Lockdown <lockdown>`'s standing {term}`cover` is in force.** A cover is a
  firewall block. The bridge's own block would make the probe's traffic fail, so the connect failure keeps the
  self-test's own message and the network-blocked one does not appear. Test is not skipped, but its traffic passes through
  the same block: a Test run while Lockdown's block is in force can report Hole's own block as "No response from the
  server." or as a blocked network. Choose **Unblock Network** in the tray before you trust it
  ([details](hostile-networks.md#telling-the-failures-apart)).
- **On connect, it runs only with the {term}`DNS forwarder` on.** The self-test it accompanies is the forwarder's.
- **Its hello is not ex-ray's.** The probe sends no ECH and no domain name. So "reachable" means a plain ClientHello got
  an answer, not that the one ex-ray sends would, and a server that itself drops a hello with no domain name would read
  as blocked.
- **Its deadlines are fixed.** A reply later than the first-flight deadline reads as blocked, and a TCP connect that fails
  for any reason except a refusal reads as "did not respond", whether the cause was the network, a firewall on the
  machine, or a reset.
```
