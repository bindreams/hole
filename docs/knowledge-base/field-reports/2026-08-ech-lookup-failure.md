# ECH config lookup failure with `ech=always`

In August 2026 a tester in Russia, on a Windows machine tethered through a phone, could not connect. The server's config
asked for `ech=always`. Every lookup of the {term}`ECH` config failed, so {term}`ex-ray` refused to connect, and Hole
reported only that its DNS {term}`self-test` had failed. The record the lookup asks for was healthy. Why the lookup did
not find it was not determined.

## Setup

:Date: August 2026
:Client: Windows, Hole 0.5.0
:Client network: A mobile network in Russia, through an iPhone's hotspot
:Server: Shadowsocks with a plugin over WebSocket and TLS, behind Cloudflare. The TLS server name (`host`) is a domain.
:ECH: `ech=always`. Hole 0.5.0 passed ex-ray the hostname URL of Cloudflare's {term}`DoH` resolver as `ech-doh`.

## Timeline

1. The tester clicks Connect. Hole reports that the DNS self-test failed.
1. The bridge's log shows every ECH config lookup failing with "no ech record found". ex-ray then refuses to send a
   {term}`ClientHello` that would carry the server's name in the clear, which only `ech=always` makes it do, so no
   tunnel comes up.
1. The tester queries the same DoH resolver by hand for the server's HTTPS record, as a JSON request. The record comes
   back. Its ECH config matches the server's byte for byte, and its address hints are those of Cloudflare's edge in
   Russia.
1. On the same machine, Hole's own DoH lookup of the server's address fails four times in a row, against both of
   Cloudflare's resolver addresses: a certificate chain arrives, and its issuer is unknown. About 45 seconds later the
   same lookup succeeds.

## What "no ech record found" means

ex-ray gives this error only after a resolver has answered with a valid DNS message that holds no HTTPS record for the
queried name with an ECH config in it. A network failure, a reply other than HTTP 200 and a malformed message each give
a different error. So a resolver answered, and ex-ray found no usable record in the answer.

## Possible causes of the lookup failure

- The two queries were not alike. The tester's query was a JSON GET and ex-ray sends the binary wire format as a POST,
  so the hand-run query does not show what ex-ray's query was answered with.
- The server's domain may be a CNAME, as a domain behind a CDN often is. The HTTPS record then sits under the CNAME's
  target, and ex-ray accepts only a record under the queried name.
- ex-ray may have asked a different resolver. It found the DoH resolver's address through the system's plaintext DNS
  ([details](../ech-in-practice.md#plaintext-lookup-of-the-doh-resolvers-hostname)), where the network can change the
  answer.

Two measurements would have settled it and were not taken: what the system resolver returned for the DoH resolver's
hostname, and what a wire-format POST to that resolver returned.

The certificate failures mean that something on that machine or its network presented its own certificate on some TLS
connections to the resolver and not on others. The log does not show what.

## Changes in Hole since

- Hole now passes ex-ray a DoH address by IP, so ex-ray makes no plaintext lookup
  ([#694](https://github.com/bindreams/hole/issues/694)).
- A tunnel that fails to come up has messages of its own, in place of the bare self-test timeout
  ([#695](https://github.com/bindreams/hole/issues/695)), and a resolver certificate that cannot be verified has a
  message of its own ([#696](https://github.com/bindreams/hole/issues/696)).
