# Recommendations for hostile networks

Some networks do more than watch traffic: they block servers outright. If the people you run a server for
are on such a network, a few choices in the server's setup and in the config you hand out decide whether their
connection holds.

Most of the settings below are plugin options: the `plugin_opts` string of a server's entry in the config, which Hole
passes to [the plugin](../how-it-works/plugins.md). The server side of each one is in the server's own documentation;
for a Postern server, [Postern's](https://postern.readthedocs.io/en/latest/).

## Choosing where to host the server

A network can block whole address ranges of hosting providers. A server in such a range fails whatever name it uses:
the connection is accepted and the TLS handshake then gets no answer. In June 2026, from an MGTS connection in Russia,
[every host tested](field-reports/2026-06-tls-handshake-block.md) in ranges of LeaseWeb and OVH failed this way, while
hosts at Hetzner and DigitalOcean answered. In November 2026 the same ranges
[answered again](field-reports/2026-11-cloudflare-and-direct-tunnels.md) from that connection.

If the server's range is blocked, move the server to a provider that still answers from that network, or put it behind a
CDN. A CDN proxies HTTP, so the server has to speak WebSocket over TLS: set the plugin options `tls` and
`host=<domain>` on the server and in the config.

```{warning}
A CDN is not a guarantee. In August 2026 [a server behind Cloudflare](field-reports/2026-08-cdn-fronted-server.md)
could not carry traffic for clients in Russia. In November 2026, from an MGTS connection,
[tunnels through Cloudflare](field-reports/2026-11-cloudflare-and-direct-tunnels.md) failed for 42 hours while tunnels straight to the same server passed every probe. A
download from the domain proxied by Cloudflare stopped after about 17 KB on every attempt, and the same download
straight from the server completed.
```

## Hiding the server's name

With `tls` set, every connection announces the server's domain in its TLS handshake, where the network can read it.
{term}`ECH` encrypts that name. Hole uses it when `host` is a domain whose DNS publishes an ECH config, which is up to
the CDN or host serving the domain. ECH hides the name and not the address: a server blocked by address stays blocked.

The `ech` plugin option decides what happens when the ECH config cannot be fetched:

| `ech`               | When the config cannot be fetched          | Use it when                                               |
| ------------------- | ------------------------------------------ | --------------------------------------------------------- |
| `auto`, the default | Hole connects, with the name in the clear. | Getting connected matters more than hiding the name.      |
| `always`            | Hole refuses to connect.                   | An exposed name is worse for the user than no connection. |

With `ech=always`, tell the people using the config that a failed connect can be this refusal. Hole reports it as an
ordinary connection failure, and only the {term}`bridge`'s log names ECH.
[ECH in practice](ech-in-practice.md#failure-modes-of-ech) covers the other ways ECH can fail.

## Testing from the client's network

A server that answers from your desk can be blocked from theirs. Before you rely on a config, have someone on that
network press **Test** on the server's entry in Hole's dashboard. Test opens a tunnel through the server and
makes a request through it, and its result tells a network block from a mistake in the config:

| Test says                                                                    | Meaning                                                                                    |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| "The network is blocking the connection to this server…"                     | The handshake was reset or ignored. [Move the server](#choosing-where-to-host-the-server). |
| "Server rejected the connection (wrong password, cipher, or plugin config)." | Hole's {term}`reachability check` did not find the handshake blocked. Check the config.    |
| "No response from the server."                                               | Nothing answered. See [Diagnosing a failed connection](#diagnosing-a-failed-connection).   |

A passing Test shows that the server answers and the config works. Connecting also runs Hole's DNS
{term}`self-test`, so have them connect as well.

```{note}
While {term}`Lockdown <lockdown>` is blocking traffic, it lets through only the server it was set up for. A Test of any
other server then fails on Hole's own block and can read as a network block. Choose **Unblock Network** in the tray menu
first. That also turns Lockdown off.
```

## Settings to leave at their defaults

Four settings are best left alone:

| Setting                                        | Leave it because                                                                                                                                                                                                                                                                                             |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ech-doh` (plugin option)                      | Hole supplies its own resolver address for the ECH lookup. A hostname here is itself looked up through the system's plaintext DNS, [in view of the network](ech-in-practice.md#plaintext-lookup-of-the-doh-resolvers-hostname). If a config already carries one, leave it: Hole replaces it where it has to. |
| **Allow insecure bootstrap** (Hole's settings) | Off, Hole looks the server's address up over {term}`DoH` and fails if it cannot. On, it falls back to the system's DNS, and the network sees which server you asked for and can change the answer.                                                                                                           |
| `mode` (plugin option)                         | Unset, the connection is WebSocket with a {term}`ClientHello` [shaped like Chrome's](ech-in-practice.md#clienthello-fingerprint). `mode=quic` gives that up.                                                                                                                                                 |
| `tcp-keepalive` (plugin option)                | The default already drops a dead idle connection. `tcp-keepalive=0` turns that off.                                                                                                                                                                                                                          |

## Diagnosing a failed connection

A connection to the server passes three points in turn, and a hostile network can stop it at each one.

| How far the connection gets                         | Failure                                                           |
| --------------------------------------------------- | ----------------------------------------------------------------- |
| The TCP connect is not answered                     | [No reply to the TCP connection](#no-reply-to-the-tcp-connection) |
| The TCP connect is answered, the ClientHello is not | [TLS handshake blocked](#tls-handshake-blocked)                   |
| The tunnel carries traffic, then stops              | [Tunnel stops carrying traffic](#tunnel-stops-carrying-traffic)   |

A tunnel that comes up and never carries traffic is none of the three: check the password, the cipher and the plugin
options.

The first two can be checked from a machine on that network without Hole. The TLS check applies only to a server with
`tls` in its plugin options.

```sh
nc -vz <ip> 443                                       # TCP connect (Linux, macOS)
Test-NetConnection <ip> -Port 443                     # TCP connect (Windows PowerShell)
openssl s_client -connect <ip>:443 -noservername      # TLS ClientHello
```

```{warning}
Use the server's IP address and keep `-noservername`. A domain in these commands is looked up through plaintext DNS and
sent in the clear in the ClientHello, which shows the network the name the setup is meant to hide. Take the address from the
server's own setup: Hole's logs do not show it.
```

### No reply to the TCP connection

The network drops connection attempts to the server's address or port. Hole says "The server did not respond
(connection timed out)" on connect and "No response from the server." on Test. It says the same when the connect fails
for another reason, such as a firewall on the machine, so check with the commands above before blaming the network.

In November 2026, from an MGTS connection, one server's address stopped answering on every port and protocol tried, while
it answered from outside Russia and other addresses at the same provider still answered from that connection.
Connections opened before the block went on carrying traffic: TCP connections for 23 minutes, until they closed, and two
UDP flows for more than four hours. Moving the service to another address at the same provider restored it.

To find out whether a block is on one address, try another host at the same provider, or behind the same CDN, from the
same machine.

On connect, Hole gives this message and the one for a blocked handshake only when its {term}`DNS forwarder` is on and
Lockdown is off. Otherwise, press **Test**.

### TLS handshake blocked

TCP connects, and the ClientHello is reset or ignored. Hole says "The network is blocking the connection to this
server…".

Some servers do not answer a ClientHello without the {term}`SNI` extension, whatever the network does. Run the same `openssl` command from
a network you trust: if the server answers there, the network is what kills the handshake.

Then send the ClientHello to another host at the same provider. If that fails too, the provider's range is blocked, as
in [the June 2026 report](field-reports/2026-06-tls-handshake-block.md). If it answers, only your server's address is. Either way the remedy is to
[move the server](#choosing-where-to-host-the-server), and for a blocked range that means another provider
or a CDN.

### Tunnel stops carrying traffic

The connection comes up, carries traffic, then stops, with or without a reset. In August 2026 a connection through Cloudflare
was reset about 20 seconds after it was made, having carried only its first exchange
([report](field-reports/2026-08-cdn-fronted-server.md)).

{term}`galoshes` recovers from this by itself: it replaces a connection that was reset, and its {term}`keepalive` notices
one that has gone silent. Both need galoshes on the server as well as in the config. Hole keeps showing **Connected**
throughout, and the reconnects appear in the [bridge's log](../contributing/architecture/logging.md).

Reconnecting helps only if the new connection fares better. In November 2026 galoshes replaced a stalled connection
through Cloudflare about once a minute for 40 hours, and five of some 4,100 connections carried traffic
([report](field-reports/2026-11-cloudflare-and-direct-tunnels.md)).
