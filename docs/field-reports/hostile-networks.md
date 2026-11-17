# Recommendations for hostile networks

This page is for someone who runs a server for people on a network that interferes with traffic, or who sets up their
client. It opens with how to tell three failures apart, because each has a different remedy, then lists what to set and
what to leave alone. Every recommendation names the [field report](index.md) it comes from and the setting in the code.

```{admonition} What these rest on
---
class: warning
---
A handful of cases, two of them with readings that were never confirmed. The page says what to try and what to read
first. It does not say what a given censor will do, and a recommendation here is a precaution, not a guarantee.
```

## Telling the failures apart

When a connection fails or a tunnel dies, ask how far the connection got. The three failures below stop at different
places.

```{mermaid}
flowchart TD
    start["Connecting fails, or the tunnel is dead"] --> tcp{"Does a TCP connect to the server's<br/>address and port get a reply?"}
    tcp -- "no reply" --> f1["1. The SYN gets no reply"]
    tcp -- "yes" --> hello{"Does a TLS ClientHello<br/>get any answer?"}
    hello -- "reset, or silence" --> f2["2. The ClientHello dies"]
    hello -- "yes" --> up{"Does the tunnel carry traffic?"}
    up -- "it did, then stopped" --> f3["3. Established, then silent"]
    up -- "never did" --> other["Not these three: check the password,<br/>the cipher and the plugin options"]
```

| Failure                         | What the network does                                                                 | What Hole says                                                                                      | Seen in                                                                         |
| ------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| **1. The SYN gets no reply**    | Drops connection attempts to the address, or to its port.                             | Connect: "…The server did not respond (connection timed out)." Test: "No response from the server." | [The Russian case](russia-ech-investigation.md), where it is still unexplained. |
| **2. The ClientHello dies**     | Lets TCP complete, then resets or ignores the TLS handshake, whatever the name in it. | Connect and Test: "The network is blocking the connection to this server…".                         | [Range-blocked hosts](range-blocked-hosts.md).                                  |
| **3. Established, then silent** | The connection comes up and carries something, then stops, with or without a reset.   | Nothing on screen: "Connected" is decided once, at start. The log shows the reconnects.             | Observed on a test box in Russia; see below.                                    |

**Failure 3, in the field.** On a test box in Russia the connection to the server was reset by the remote about 20 seconds
after connecting, with only the first exchange getting through, and silence before the reset. On an earlier release the
same box's tunnel went dead roughly every two minutes with no reset at all, and recovered only through ex-ray's idle
timeout, about five minutes. Both are consistent with a middlebox, and neither is proven to be one. A transport that dies
visibly is replaced by the {term}`galoshes` client; a silent one is caught by its keepalive, which fires when no byte has
come in for a whole interval. The detection bound and the constants are on [the galoshes transport
page](../contributing/architecture/galoshes-transport.md#telling-that-the-transport-is-dead).

```{admonition} Reading Hole's message
---
class: note
---
"The server did not respond" is also what Hole says when the connect failed for any reason other than a refusal: an
unreachable network, a firewall on the machine, a reset. The network-blocked message is not shown while Lockdown is
armed, or with the {term}`DNS forwarder` off. A wrong password is reported only when the probe has not found the network
blocking: "Server rejected the connection (wrong password, cipher, or plugin config)." The [probe's
limits](range-blocked-hosts.md#how-hole-reports-it) apply to every row above.
```

## Recommendations

### Run a control before you blame the network

**Because.** Two machines failing against one address cannot tell a network block from a fault in that address or path.
An earlier case that looked the same had a different cause. **From** [the Russian case](russia-ech-investigation.md#the-control-that-was-never-run).

**Do.** From the same machine, in the same window, connect to something else: a different host behind the same CDN, and a
bare TCP connection to the server's port with no TLS. If those work, the problem is the address or the hello. If they do
not, it is broader.

### Keep the server out of ranges that get blocked

**Because.** A network that blocks whole ranges of hosting providers blocks the server with them, whatever name the
handshake carries, and another address from the same provider does not help. **From** [range-blocked
hosts](range-blocked-hosts.md#what-fixes-it).

**Do.** Put the endpoint behind a CDN, as WebSocket over TLS, or move to a provider that is not blocked. The plugin
options are `tls` and `host=<domain>`; TLS is off unless `tls` is set ({src}`crates/ex-ray/config.go`). Moving is
whack-a-mole, and fronting works only while the CDN's addresses stay reachable.

### Give the TLS server name as a domain, behind a CDN that publishes ECH

**Because.** ECH needs a domain to look up, and it hides the name, not the address. With `host` set to an IP address
nothing is looked up. **From** [ECH in practice](ech-in-practice.md#what-ech-does-not-do).

**Do.** Set `host` to the domain. {term}`ECH` applies only when the domain publishes an ECH config.

### Choose the `ech` mode on purpose

**Because.** `auto`, the default, connects with the name in the clear when the config cannot be fetched. `always` refuses
instead, and the refusal is not explained on screen. **From** [ECH in practice](ech-in-practice.md#three-ways-it-can-fail-and-which-way-each-one-fails).

**Do.** Use `always` where an exposed name is worse for the user than no connection, and tell them that a failed connect
may be this refusal. Use `auto` where connecting matters more. `always` needs TLS and a DoH address, or ex-ray will not
start.

### Leave `ech-doh` to Hole

**Because.** A hostname in `ech-doh` costs a plaintext system-DNS lookup. Hole gives ex-ray an IP-literal address of its
own. **From** [ECH in practice](ech-in-practice.md#the-lookup-that-gave-the-name-away).

**Do.** Do not set `ech-doh` in a client config. If one is there, Hole replaces a hostname value, and an IP-literal value
too once its own resolver answered; ex-ray itself keeps the first value it reads. The logic is
`hole_ech_doh_outranks` in {src}`crates/bridge/src/proxy/plugin.rs`.

### Keep the secure lookup on

**Because.** Hole resolves the server's address over DoH and, by default, refuses to fall back to the operating system's
resolver. On a network that intercepts some TLS connections, the failure is explicit. **From** [ECH in
practice](ech-in-practice.md#the-lookup-that-gave-the-name-away).

**Do.** Leave **Allow insecure bootstrap** off (`dns.allow_insecure_bootstrap`). Turn it on only where every DoH
resolver is blocked, knowing that the network then sees which server you looked up and could change the answer.

### Leave the keepalive and the fingerprint at their defaults

**Because.** A black hole that sends no reset is caught by keepalives. `tcp-keepalive=0` turns the connection's keepalive
off completely. The default Chrome hello is a precaution that costs nothing, and no option changes it. **From** [failure
3](#telling-the-failures-apart) and [ECH in practice](ech-in-practice.md#the-shape-of-the-hello).

**Do.** Do not set `tcp-keepalive`. Keep the WebSocket transport if you want the Chrome-like hello, since QUIC does not
use it.

### Test from the network that matters

**Because.** A server that answers from your desk can be blocked from theirs, and the Test button tells the network
apart from a bad password. **From** [range-blocked hosts](range-blocked-hosts.md#how-hole-reports-it).

**Do.** Have someone on that network press **Test** before you hand out the config. A pass is the first check, not the last:
Test opens one tunnel and fetches one sentinel, and connecting does more.
