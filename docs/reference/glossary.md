# Glossary

Terms that Hole's documentation uses.

```{glossary}
---
sorted:
---
bridge
  The privileged half of Hole. It runs as a background service with administrator rights, owns the {term}`TUN` device
  and the routes, and does what the app asks over a local socket. See [How Hole is put together](../how-it-works/overview.md).

DoH
  DNS over HTTPS: DNS queries sent inside an HTTPS connection, so the network can neither read nor alter them. Hole uses
  it for DNS inside the tunnel by default, and ex-ray uses it to fetch {term}`ECH` configs. See
  [ECH and DoH](../how-it-works/ech-and-doh.md) and [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484).

ECH
  Encrypted Client Hello, a TLS extension that hides the name of the server you connect to from anyone watching the
  connection. In Hole, {term}`ex-ray` uses it to hide the proxy server's domain, not the sites you browse. See
  [ECH and DoH](../how-it-works/ech-and-doh.md) and [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849).

ex-ray
  Hole's own {term}`SIP003 plugin`, built on v2ray-core and wire-compatible with `shadowsocks/v2ray-plugin`. See
  {src}`its README <crates/ex-ray/README.md>`.

DNS forwarder
  The part of the {term}`bridge` that answers the machine's DNS lookups by sending them to the resolver you chose, through
  the tunnel. See [DNS through the tunnel](../how-it-works/dns.md).

filter
  A rule that sends traffic to an address through the tunnel (proxy), around it (bypass) or nowhere (block). Rules are
  checked per connection, and the last rule that matches wins.

galoshes
  A {term}`SIP003 plugin` that embeds {term}`ex-ray` and adds UDP support by carrying many streams over one multiplexed
  connection. See [Distributions](distributions.md).

kill switch
  An optional setting, off by default, that the tray calls **Lockdown**. While it is on and Hole is connecting or
  connected, traffic that would leave outside the tunnel is blocked, including to devices on your local network such as
  a printer, through brief drops, reconnects and restarts; the block lifts when you disconnect or Hole gives up on the
  connection. See {src}`the contributor reference <CONTRIBUTING.md#lockdown-mode>`.

lockdown
  See {term}`kill switch`: the name the tray menu uses.

Postern
  A self-hosted portal that runs Shadowsocks servers and gives each person you invite a ready-made client config. It is
  Hole's companion project. See [its documentation](https://postern.readthedocs.io).

SNI
  Server Name Indication: the name of the server a client wants to reach, which a TLS handshake normally sends unencrypted.
  {term}`ECH` is what hides it. See [ECH and DoH](../how-it-works/ech-and-doh.md).

Shadowsocks
  An encrypted proxy protocol. A client sends traffic to a Shadowsocks server, which forwards it to the open internet.
  See [shadowsocks.org](https://shadowsocks.org/).

split tunnel
  Another name for what Hole calls a {term}`filter`.

SOCKS5
  A simple proxy protocol (RFC 1928). The Shadowsocks client in the {term}`bridge` listens for it on the loopback address,
  and every proxied connection goes through that listener. See
  [Shadowsocks and its plugins](../how-it-works/plugins.md).

SIP003 plugin
  A program that Shadowsocks starts on each end to wrap its traffic in another protocol, such as WebSocket over TLS.
  SIP003 is the specification of how it is started and configured. See
  [Shadowsocks and its plugins](../how-it-works/plugins.md) and [the specification](https://shadowsocks.org/doc/sip003.html).

TUN
  A virtual network adapter that a program creates through the operating system. Hole routes the machine's traffic into
  one, so it sees the packets of every app. See [the TUN device and the routes](../how-it-works/tun.md) and
  [TUN/TAP](https://en.wikipedia.org/wiki/TUN/TAP).

VPN client
  An app that sends a machine's traffic through a server somebody else runs. Hole is a client of that kind, not a VPN
  service: it comes with no server.

Unblock Network
  The tray action, shown while Hole is blocking traffic, that disconnects and turns the {term}`kill switch` off.
```
