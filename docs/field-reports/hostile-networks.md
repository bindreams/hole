# Recommendations for hostile networks

This page is for someone who runs a server for people on a network that interferes with traffic, or who sets up their
client. It opens with how to tell three failures apart, because they stop at different places, then lists what to set and
what to leave alone. Each recommendation names the [field report](index.md) it comes from and says whether it is advice
or was observed to work. None of it was observed to work, so all of it is advice.

```{admonition} What these rest on
---
class: warning
---
A handful of cases, two of them with readings that were never confirmed. The page says what to try and what to read
first. It does not say what a given censor will do, and a recommendation here is a precaution, not a guarantee. Only
failure 2 has a remedy to offer, and that remedy is advice; for failures 1 and 3 the page says what is known and what is
not.
```

Where each setting lives matters, so the page says. **Plugin options** are the semicolon-separated string in a server's
entry (`tls;host=example.com`, and the like), which Hole passes to the plugin: `tls`, `host`, `mode`, `ech`, `ech-doh` and
`tcp-keepalive` are plugin options. {term}`ex-ray` takes them; {term}`galoshes` embeds ex-ray, so it takes them too.
**Hole's dashboard**, its main window, holds the **Test** button on each server and the settings **DNS forwarder** and
**Allow insecure bootstrap**; {term}`Lockdown <lockdown>` is the tray setting for the {term}`kill switch`. What a *server*
needs in its own plugin options, and how to put a server behind a CDN, is the server's own documentation: for a
[Postern](https://postern.readthedocs.io/en/latest/) server, Postern's. This page does not repeat it.

The messages and options below are from the current source. The reachability probe and its "network blocked" message
shipped in Hole 0.4.0; the {term}`keepalive` and the IP-literal `ech-doh` first shipped in 0.6.0. A client on an older
release does not have them.

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

The two questions are asked of the machine on that network, from outside Hole. Any TCP connect tool answers the first (for
example `nc -vz <address> 443`, or `Test-NetConnection <address> -Port 443` in Windows PowerShell), and `openssl s_client -connect <address>:443` the second. The second applies only to a server that uses TLS (`tls` in the plugin options): a
server without TLS has no TLS hello to answer, so ask the third question instead.

| Failure                         | What the network does                                                                 | What Hole says                                                                                                                                                        | Seen in                                                                                                                                                     |
| ------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. The SYN gets no reply**    | Drops connection attempts to the address, or to its port.                             | Connect: "…The server did not respond (connection timed out)." Test: "No response from the server." Hole shows the same for failures other than a refusal; see below. | No case here establishes it. [The Russian case](russia-ech-investigation.md) was first read this way, but its error text reads as failure 3, so it is open. |
| **2. The ClientHello dies**     | Lets TCP complete, then resets or ignores the TLS handshake, whatever the name in it. | Connect and Test: "The network is blocking the connection to this server…".                                                                                           | [Range-blocked hosts](range-blocked-hosts.md).                                                                                                              |
| **3. Established, then silent** | The connection comes up and carries something, then stops, with or without a reset.   | Nothing on screen: "Connected" is decided once, at start. The log shows the reconnects.                                                                               | Observed on a test box in Russia; see below.                                                                                                                |

Hole's message alone does not pick a row: failures 1 and 2 can both end as "did not respond", so use the two questions.

**Failure 1: what to do.** No remedy is established. Run the control, the first recommendation below.

**Failure 3, in the field.** Observed on a test box in Russia, in a later triage of two logs: the connection to the server
was reset by the remote about 20 seconds after connecting, with only the first exchange getting through, and silence
before the reset. Observed on the same box on a development build from before the keepalive existed: the tunnel went dead
roughly every two minutes with no reset at all, and recovered only through ex-ray's idle timeout, about five minutes. Both
are consistent with a middlebox, and neither is proven to be one.

**Failure 3: what to do.** There is nothing to set. A transport that dies visibly is replaced by the galoshes client; a
silent one is caught by galoshes' {term}`keepalive`, which fires when no byte has come in for a whole interval. Both need
galoshes on the server too, not ex-ray alone. The detection bound and the constants are on [the galoshes transport
page](../contributing/architecture/galoshes-transport.md#telling-that-the-transport-is-dead). The log, `bridge.log` in the
bridge's log directory ([where](../contributing/architecture/logging.md)), shows the reconnects.

```{admonition} Reading Hole's message
---
class: note
---
"The server did not respond" is also what Hole says when the connect failed for any reason other than a refusal: an
unreachable network, a firewall on the machine, a reset. When you *connect*, the network-blocked message is not shown while
any firewall {term}`cover` is in force or about to be, which includes {term}`Lockdown <lockdown>`, or with the
{term}`DNS forwarder` off. So turning on Lockdown for someone costs this diagnostic on connect; Test is unaffected. A wrong
password is reported only when the probe has not found the network blocking: "Server rejected the connection (wrong
password, cipher, or plugin config)." The [probe's limits](range-blocked-hosts.md#how-hole-reports-it) apply to every row
above.
```

## Recommendations

### Run a control before you blame the network

**Status.** Advice. The control in the case was never run.

**Because.** Two machines failing against one address cannot tell a network block from a fault in that address or path.
An earlier case that looked the same had a different cause. **From** [the Russian case](russia-ech-investigation.md#the-control-that-was-never-run).

**Do.** From the same machine, in the same window, connect to something else: a different host behind the same CDN, and a
bare TCP connection to the server's port with no TLS (the tools above). If those work, the problem is the address or the
hello. If they do not, it is broader.

### Keep the server out of ranges that get blocked

**Status.** Advice. None of the remedies was tried for the tester in the case.

**Because.** A network that blocks whole ranges of hosting providers blocked the server with them, whatever name the
handshake carried. The probes covered several ranges of the server's hoster, not all of it, so an address elsewhere in that
hoster's space is untested. **From** [range-blocked hosts](range-blocked-hosts.md#what-might-fix-it).

**Do.** Put the endpoint behind a CDN, as WebSocket over TLS, or move to a provider that is not blocked. The plugin options
are `tls` and `host=<domain>`, on the server as well as the client; TLS is off unless `tls` is set
({src}`crates/ex-ray/config.go`). Setting the server side up is in the server's own documentation (Postern's, above).
Two cautions. The one case here that used a CDN, [the Russian case](russia-ech-investigation.md), is open and its cause
unknown, so fronting is not shown to fix a block. And moving is whack-a-mole. This page has no way to check a candidate
provider before you use it; the last recommendation, **Test**, from that network, is the check.

### Give the TLS server name as a domain whose DNS publishes an ECH config

**Status.** Advice, from what the code does.

**Because.** ECH needs a domain to look up, and it hides the name, not the address. With `host` set to an IP address
nothing is looked up. **From** [ECH in practice](ech-in-practice.md#what-ech-does-not-do).

**Do.** Set `host`, in the plugin options, to the domain. {term}`ECH` applies only when that domain's DNS publishes an ECH
config; whether a given CDN offers one is that CDN's documentation. Where it does not, `auto` connects with the name in the
clear.

### Choose the `ech` mode on purpose

**Status.** Advice, from what the code does.

**Because.** `auto`, the default, connects with the name in the clear when the config cannot be fetched. `always` refuses
instead, and the refusal is not explained on screen. **From** [ECH in practice](ech-in-practice.md#three-ways-it-can-fail-and-which-way-each-one-fails).

**Do.** In the plugin options of the server's entry, use `ech=always` where an exposed name is worse for the user than no
connection, and tell them that a failed connect may be this refusal. Use `auto` where connecting matters more. `always`
needs TLS and a DoH address; Hole supplies the DoH address itself (next recommendation), so the options need only `tls`, a
`host` and `ech=always`.

### Leave `ech-doh` to Hole

**Status.** Advice.

**Because.** A hostname in `ech-doh` costs a plaintext system-DNS lookup. Hole gives ex-ray an IP-literal address of its
own. **From** [ECH in practice](ech-in-practice.md#a-lookup-that-can-give-the-name-away).

**Do.** Do not set `ech-doh` in the plugin options. A config from Postern arrives with `ech` and `ech-doh` already
appended; leave it. Hole replaces a hostname value, and an IP-literal value too once its own resolver answered; ex-ray
itself keeps the first value it reads. The logic is `hole_ech_doh_outranks` in {src}`crates/bridge/src/proxy/plugin.rs`.

### Keep the secure lookup on

**Status.** Advice.

**Because.** Hole resolves the server's address over DoH and, by default, refuses to fall back to the operating system's
resolver. On a network that intercepts some TLS connections, the failure is explicit. **From** [ECH in
practice](ech-in-practice.md#a-lookup-that-can-give-the-name-away), and [the concept
page](../how-it-works/ech-and-doh.md) for the default.

**Do.** In Hole's settings, leave **Allow insecure bootstrap** off (`dns.allow_insecure_bootstrap`). Turn it on only where
every DoH resolver is blocked, knowing that the network then sees which server you looked up and could change the answer.
This page has no test for "every resolver is blocked".

### Leave the keepalives and the fingerprint at their defaults

**Status.** Advice. No case shows either setting making a difference.

**Because.** There are two keepalives. galoshes' own probes a quiet transport and is what catches a silent black hole (see
failure 3). ex-ray's `tcp-keepalive` is the operating system's TCP keepalive on the connection to the server: it drops an
idle dead connection, not one stalled with unacknowledged data, and it does nothing in QUIC mode or on a server. Its
default is 15 seconds, and `tcp-keepalive=0` turns the connection's keepalive off completely. The Chrome hello is a
precaution, and no option changes it. **From** [failure 3](#telling-the-failures-apart) and [ECH in
practice](ech-in-practice.md#the-shape-of-the-hello).

**Do.** Do not set `tcp-keepalive`, which is a client-side plugin option. Leave `mode` unset to stay on the WebSocket
transport, which is the one that uses the Chrome-like hello; `mode=quic` chooses QUIC instead, which does not.

### Test from the network that matters

**Status.** Advice.

**Because.** A server that answers from your desk can be blocked from theirs, and the Test button tells the network
apart from a bad password. **From** [range-blocked hosts](range-blocked-hosts.md#how-hole-reports-it).

**Do.** Have someone on that network press **Test** on the server's entry in Hole's dashboard before you rely on the
config. A pass is the first check, not the last: Test opens one tunnel and fetches a header from a public address, trying
a second address if the first returns nothing, and a connect does more, including the start-time {term}`self-test`.
