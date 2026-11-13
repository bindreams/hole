# ECH and DoH

When a client opens a TLS connection, the first message it sends, the ClientHello, normally carries the name of the
server it wants to reach in the clear, as the server name indication ({term}`SNI`). Anyone watching the network can read
it. For a proxy that is a problem: the name of the server's domain is visible, and a network that wants to block the
proxy can block that name. This page covers the two techniques Hole uses so that the name is not exposed, {term}`ECH`
and {term}`DoH`.

## ECH hides the server's name

Encrypted Client Hello encrypts the real server name inside the ClientHello. The server's domain publishes an *ECH
config* in its DNS records, and the client uses it to wrap the real name. An observer sees only the public name
that config carries.

In Hole, ECH is done by {term}`ex-ray`, for the connection from the plugin to your server, and it hides the proxy
server's domain, not the sites you browse. It applies only when the plugin's options turn TLS on. The `ech` option has
three values:

| `ech=`               | Behaviour                                                                                                        |
| -------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `auto` (the default) | Use ECH when the server's ECH config can be fetched. When it cannot, connect anyway, with the name in the clear. |
| `always`             | Never send the name in the clear. If the config cannot be fetched, refuse to connect.                            |
| `never`              | Do not use ECH.                                                                                                  |

Choose `always` when exposing the name is worse than failing to connect. ECH also needs a server whose domain actually
publishes an ECH config; against one that does not, `auto` connects without it.

```{dropdown} When the server rotates its ECH key
A server can rotate its ECH key. A client holding an old config is rejected, and the rejection carries the new
configs (`retry_configs`, RFC 9849). ex-ray retries once with them and also refreshes its cached copy, so a rotation
costs one extra handshake and not a failed connection. The cache lives in ex-ray's patched copy of v2ray-core; see
{src}`its README <crates/ex-ray/README.md#ech-encrypted-client-hello>`.
```

## DoH carries the lookups Hole must make privately

ECH needs a DNS lookup, and so does finding the server's address in the first place. A lookup over ordinary DNS is
visible to the network and can be altered by it. Hole therefore does three jobs over DoH, which sends the DNS query
inside an HTTPS connection to a resolver:

1. **Finding the server.** Before it connects, Hole looks up the server's name over DoH, through the resolvers in
   its DNS settings, and never through the operating system. The connection to the resolver is made straight to the
   resolver's address, with the provider's name, where Hole knows it, used only to check the certificate, so nothing has to
   be looked up to look something up. A server given as an IP address needs no lookup.
1. **Fetching the ECH config.** ex-ray asks a DoH resolver for the server's domain, and its lookup supports only DoH.
1. **DNS inside the tunnel,** when the DNS protocol is DoH, which is the default. See [DNS through the
   tunnel](dns.md).

The first lookup is the strictest. If no resolver answers properly, Hole does not fall back to the operating system:
the connection fails with a message that says what went wrong, for instance that a resolver's certificate could not be
verified, which can mean something on the network is intercepting encrypted connections. The only way around it is the
**Allow insecure bootstrap** setting, off by default, which lets a failed lookup fall back to the computer's ordinary
DNS. It exists for networks where every DoH resolver is blocked; with it on, the network can see which server you looked
up, and could change the answer. It applies whether or not the {term}`DNS forwarder` is on.

A resolver you add yourself must therefore speak DoH, since the server lookup always uses it, whichever protocol you
chose for DNS in the tunnel.

## Which resolver ex-ray is told to use

Hole gives ex-ray the address of one resolver, as a URL of the form `https://<ip>/dns-query` with an IP address and no
name. A name in that URL would send ex-ray to the system's DNS to find the resolver, which is the lookup this design
avoids. The resolver is the one that answered the server lookup. When none did (the server is an IP address, or no resolver
completed an exchange), it is the first IPv4 resolver in the settings, or the first one at all. ex-ray accepts one
URL and does not fail over to another.

```{dropdown} When the config also sets ech-doh
A plugin's options may carry an `ech-doh` of their own. Hole replaces it only when its own resolver answered the lookup,
or when the option names a host rather than an IP address, since that would cost a system DNS lookup. Otherwise the
option in the config stands. The logic is `hole_ech_doh_outranks` in {src}`crates/bridge/src/proxy/plugin.rs`.
```

```{dropdown} Where in the code
The server lookup: {src}`crates/bridge/src/dns/bootstrap.rs`. The ECH resolver choice:
{src}`crates/bridge/src/dns/ech.rs`. ex-ray's options: {src}`crates/ex-ray/config.go`.
```
