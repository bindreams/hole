# ECH in practice

{term}`ECH` keeps the real server name out of the TLS handshake. The [concept page](../how-it-works/ech-and-doh.md)
explains how it works and what Hole's options are. This page is about what happens when it meets real networks.

## Why the name is worth hiding

A TLS ClientHello normally carries the server's name in the clear, as the {term}`SNI`. A network that watches connections
can read it, tie a client's address to the proxy's domain, and block that domain or follow its clients. ECH puts the real
name inside an encrypted part of the hello. What is left in the clear is the *public name* from the server's ECH config,
which is normally a name shared with many other sites behind the same CDN.

## Three ways it can fail, and which way each one fails

ECH has three steps that can go wrong. The `ech` option decides whether a failure ends the connection or lets the name
out. `ech` is a plugin option: it goes in the plugin options of the server's entry in Hole (the `SS_PLUGIN_OPTIONS` string
of the config), and Hole's dashboard (its main window) has no switch for it.

| What goes wrong                                                                                                            | `ech=auto` (the default)                                                                                                                                    | `ech=always`        |
| -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| **The config cannot be fetched.** No record, an unreachable resolver, or no domain to ask about (`host` is an IP address). | Connects, with the name in the clear.                                                                                                                       | Refuses to connect. |
| **The server rejects the config.** The key it holds is not the one the client used.                                        | Retries once with the configs the server returned. If that fails too, or the server returned none, the connection fails. The name is not sent in the clear. | The same.           |
| **The transport cannot carry ECH.** A TLS engine that drops the config when it builds the hello.                           | Connects, with the name in the clear, and logs a warning.                                                                                                   | Refuses to connect. |

The middle row has no cleartext fallback in either mode: Go's TLS stack, which ex-ray builds on, completes a handshake
started with an ECH config only if ECH is negotiated. The first and third rows are where `auto` gives the name away.
`always` exists for clients whose users are worse off exposed than disconnected. It also makes ex-ray refuse to start
without TLS, or without a DoH address to fetch the config from.

```{admonition} The refusal does not say "ECH"
---
class: note
---
When `always` refuses, the plugin's own error names ECH but reaches only `bridge.log`, the {term}`bridge`'s log (its
location is on [the logging page](../contributing/architecture/logging.md)). The message on screen is one of the general
tunnel failures.
```

## A lookup that can give the name away

ex-ray fetches the config with a DNS query for the server's HTTPS record, sent to the {term}`DoH` address in `ech-doh`
(another plugin option). Reading the code, if that address is a hostname, ex-ray has to find the hostname's IP first, and
it does so through the operating system's resolver: a plaintext query, visible on the network, for a name that the lookup
was meant to protect. The lookup that was meant to hide one name would leak another.

**Observed.** A tester in Russia, on a Windows machine tethered through a phone, could not connect. Every ECH lookup failed
with "no ech record found", though the record itself was healthy: a JSON query the tester ran by hand returned a
healthy record, with the same config bytes as the server side. The config asked for `ech=always`, so ex-ray refused to handshake
rather than send the name in the clear, and no tunnel came up. The screen said only that the DNS {term}`self-test` failed.

That error is reached only after an HTTP 200 whose body is a valid DNS message holding no HTTPS answer whose owner name
is the queried domain and that carries an `ech` parameter. A network failure, a non-200 reply or a malformed message each
give a different error. So the query reached something that answered, and what answered held no such answer.

**Not confirmed.** Whether this was the tester's actual trigger was never settled. The notes took the hand-run query as
ruling out the first guess, a middlebox stripping the answer. But it was a JSON GET, and ex-ray sends a wireformat POST,
so it did not reproduce ex-ray's query.

**Hypothesis.** The server's domain may be a CNAME to another name, as a CDN-fronted domain often is. A resolver that
follows it answers with the CNAME and the HTTPS record under the target's name, and ex-ray's match on the owner name does
not accept that record. A healthy record would then fit both the hand-run query and "no ech record found".

Three datapoints would settle it, and none was collected: what the tester's own system resolver returns for the DoH
resolver's hostname, whether a wireformat POST to that resolver returns the HTTPS record from the tester's machine, and
whether the server's domain is a CNAME to another name.

**Unexplained.** On the same machine Hole's secure lookup of the server's address failed four times with a certificate
that could not be verified, then worked about 45 seconds later. That fits something on that network
interfering with some TLS connections and not others, and the observation does not say what. Hole's error says only that
"something on this network may be intercepting encrypted connections".

**What Hole does.** The `ech-doh` it gives ex-ray is an IP-literal URL of the form `https://<ip>/dns-query`, so there
is nothing to resolve. The address is the resolver that answered Hole's own lookup of the server, where one did. Every
endpoint in Hole's resolver table was measured to accept an IP-literal DoH request over HTTP/2 with a verified
certificate, so no per-provider exception is needed. A resolver you add yourself must list its IP address in its
certificate; [the concept page](../how-it-works/ech-and-doh.md#doh-carries-the-lookups-hole-must-make-privately) covers
that.

A server's config can carry an `ech-doh` of its own, and ex-ray keeps the first value it reads for a key. A config issued
by [Postern](https://postern.readthedocs.io/en/latest/), Hole's companion project, arrives with `ech=<mode>` and `ech-doh=<url>` already appended. So Hole replaces the
config's value when the config's address is a name, or when Hole's own resolver answered, and leaves an IP-literal one
alone otherwise.

## When the key rotates

A server can rotate its ECH key. A client that cached the old config is rejected, and the rejection carries the new
configs (`retry_configs`, in [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849)). ex-ray retries once with them and updates its cache, so a rotation costs one extra
handshake. Without that handling a client would fail until its cache expired.

ex-ray keeps a fetched config for at least 600 seconds, whatever lifetime the DNS record carries. A CDN that rotates keys
more often than that leaves the client holding a stale config for part of every interval. Each such stretch costs one
rejected handshake and the retry, not a failed connection.

**Reported, not re-checked.** The investigators' notes say Cloudflare rotates its ECH keys hourly and accepts no old key after
rotation, relying on clients that retry with `retry_configs`. The interval is unconfirmed; treat the figure as a
hypothesis. The retry itself does not depend on it.

## The shape of the hello

The name is not the only thing a hello gives away. Its shape, the order and choice of extensions and ciphers, identifies
the program that sent it, and a Go program's default hello is not what a browser sends. By default ex-ray's WebSocket
client sends the hello of the newest Chrome its TLS library knows (`chrome_auto`). That is not an option: no setting
changes it.

- It applies to the client's WebSocket transport only. A server sends no ClientHello, and QUIC manages its own TLS and ECH.
- It composes with ECH. The Chrome hello has an ECH slot, and ex-ray fills it with the real config, with the same
  fail-closed behaviour as the table above. A fingerprint whose hello cannot hold ECH would fall to the table's third row.
- Whether a particular censor looks at hello shapes is not established by any case here. The default is a precaution,
  and none of the reports shows it making a difference.

## What ECH does not do

- **It does not hide the address.** An observer still sees which IP the client connects to. A block on an address, as in
  [the Russian case](russia-ech-investigation.md) or in [range-blocked hosts](range-blocked-hosts.md), is not touched by
  ECH. ECH helps most when the address is shared with many other sites, as a CDN's is.
- **It needs a domain.** With `host` set to an IP address there is nothing to look up, so ECH is not applied: `auto`
  connects without it and `always` refuses.
- **Its use is visible.** Whether a network treats that as a signal in itself is not established by any case here.
