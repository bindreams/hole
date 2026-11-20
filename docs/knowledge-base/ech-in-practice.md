# ECH in practice

A TLS handshake normally announces the server's name in the clear, as the {term}`SNI`. A network that watches
connections can read it, tie a client's address to the proxy's domain, and block the domain or follow its clients.
{term}`ECH` encrypts the name. What stays visible is the public name from the server's ECH config, which is usually
shared with many other sites behind the same CDN. [ECH and DoH](../how-it-works/ech-and-doh.md) explains the mechanism.

## Failure modes of ECH

ECH can fail at three points. The `ech` plugin option decides whether a failure ends the connection or exposes the
name. Hole's dashboard has no switch for it; it is set in the server entry's plugin options.

| What goes wrong                                                                                         | `ech=auto` (the default)                                                                                                                 | `ech=always`        |
| ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| The config cannot be fetched: no record, an unreachable resolver, or `host` is an IP address.           | Connects, with the name in the clear.                                                                                                    | Refuses to connect. |
| The server rejects the config, because its key has changed.                                             | Retries once with the configs the server sent back. If that fails, or the server sent none, the connection fails. The name stays hidden. | The same.           |
| The transport cannot carry ECH: its TLS engine drops the config when it builds the {term}`ClientHello`. | Connects, with the name in the clear, and logs a warning.                                                                                | Refuses to connect. |

The first and third rows are where `auto` gives the name away. `always` is for people who are worse off exposed than
disconnected. It also makes {term}`ex-ray` refuse to start without TLS or without a {term}`DoH` address to fetch the
config from.

```{note}
When `always` refuses, Hole shows a general tunnel failure. Only the {term}`bridge`'s log names ECH
([where it is](../contributing/architecture/logging.md)).
```

## Plaintext lookup of the DoH resolver's hostname

ex-ray fetches the ECH config with a DNS query for the server's HTTPS record, sent to the DoH address in the `ech-doh`
plugin option. If that address is a hostname, ex-ray first has to find the hostname's IP, and it asks the operating
system's resolver: a plaintext query, visible on the network, which the network can also answer falsely.

Hole avoids this by giving ex-ray an `ech-doh` with an IP address in it, `https://<ip>/dns-query`, so there is nothing
to resolve. The address is the resolver that answered Hole's own lookup of the server, or the first IPv4
resolver in Hole's settings when none did. We checked that every resolver in Hole's list accepts a DoH request addressed by IP, over
HTTP/2 and with a certificate that verifies. A resolver you add yourself
must list its IP address in its certificate
([details](../how-it-works/ech-and-doh.md#doh-carries-the-lookups-hole-must-make-privately)).

A server's config can carry an `ech-doh` of its own: [Postern](https://postern.readthedocs.io/en/latest/) adds
`ech=<mode>;ech-doh=<url>` to the config of a connection that has ECH on. Hole replaces the config's value when it holds a hostname,
or when Hole's own resolver answered, and leaves an IP address alone otherwise.

Hole 0.5.0 still passed the hostname. [A lookup failure from August 2026](field-reports/2026-08-ech-lookup-failure.md)
dates from that release.

## ECH key rotation

A server can rotate its ECH key, and a CDN may do it often: Cloudflare rotated the key of ESNI, ECH's predecessor,
[every hour](https://blog.cloudflare.com/encrypted-client-hello/). A client holding the old config is rejected, and the rejection carries the new configs
(`retry_configs` in [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849)). ex-ray retries once with them and updates its
cache, so a rotation costs one extra handshake.

ex-ray keeps a fetched config for at least 600 seconds, whatever lifetime the DNS record carries. A server that rotates
more often leaves the client with a stale config for part of each interval, and each such stretch costs one rejected
handshake and its retry, not a failed connection.

## ClientHello fingerprint

The server's name is not the only thing a ClientHello gives away. The order and choice of its extensions and ciphers
identify the program that sent it, and a Go program's default ClientHello is not a browser's. ex-ray's WebSocket client
therefore sends the ClientHello of the newest Chrome its TLS library knows. No option changes this.

The Chrome ClientHello has a slot for ECH, and ex-ray fills it with the real config. QUIC connections do not use it:
QUIC manages its own TLS. No field report shows the fingerprint making a difference; it is a precaution.

## Limits of ECH

- It does not hide the address. The network still sees which IP the client connects to, so a block on an address, as
  in [the June 2026 range block](field-reports/2026-06-tls-handshake-block.md), is untouched. ECH
  helps most when the address is shared with many other sites, as a CDN's is.
- It needs a domain. With `host` set to an IP address there is nothing to look up: `auto` connects without ECH and
  `always` refuses.
- It is not invisible. A network can see that a ClientHello uses ECH, even though it cannot read the name inside.
