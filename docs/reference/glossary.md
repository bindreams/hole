# Glossary

Terms that Hole's documentation uses.

```{glossary}
---
sorted:
---
bridge
  The privileged half of Hole. It runs as a background service with administrator rights, owns the {term}`TUN` device
  and the routes, and does what the app asks over a local socket. See [Hole in one picture](../index.md#hole-in-one-picture).

DoH
  DNS over HTTPS: DNS queries sent inside an HTTPS connection, so the network can neither read nor alter them. Hole uses
  it for DNS inside the tunnel by default, and ex-ray uses it to fetch {term}`ECH` configs. See
  [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484).

ECH
  Encrypted Client Hello, a TLS extension that hides the name of the server you connect to from anyone watching the
  connection. In Hole, {term}`ex-ray` uses it to hide the proxy server's domain, not the sites you browse. See
  [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849).

ex-ray
  Hole's own {term}`SIP003 plugin`, built on v2ray-core and wire-compatible with `shadowsocks/v2ray-plugin`. See
  {src}`its README <crates/ex-ray/README.md>`.

filter
  A rule that sends traffic to an address through the tunnel (proxy), around it (bypass) or nowhere (block). Rules are
  checked per connection, and the last rule that matches wins.

galoshes
  A {term}`SIP003 plugin` that embeds {term}`ex-ray` and adds UDP support by carrying many streams over one multiplexed
  connection. See [Distributions](distributions.md).

kill switch
  An optional setting, off by default. While Hole is meant to be connected, it blocks traffic that would otherwise
  leave outside the tunnel, so a tunnel that drops, crashes or restarts cannot leak; a deliberate Disconnect releases
  it. While it blocks, devices on your local network, such as a printer or a NAS, are unreachable too. The tray calls
  it **Lockdown**. See {src}`the contributor reference <CONTRIBUTING.md#lockdown-mode>`.

lockdown
  See {term}`kill switch`: the name the tray menu uses.

Postern
  A self-hosted portal that runs Shadowsocks servers and gives each person you invite a ready-made client config. It is
  Hole's companion project. See [its documentation](https://postern.readthedocs.io).

Shadowsocks
  An encrypted proxy protocol. A client sends traffic to a Shadowsocks server, which forwards it to the open internet.
  See [shadowsocks.org](https://shadowsocks.org/).

split tunnel
  Another name for what Hole calls a {term}`filter`.

SIP003 plugin
  A program that Shadowsocks starts on each end to wrap its traffic in another protocol, such as WebSocket over TLS.
  SIP003 is the specification of how it is started and configured. See
  [the specification](https://shadowsocks.org/doc/sip003.html).

TUN
  A virtual network adapter that a program creates through the operating system. Hole routes the machine's traffic into
  one, so it sees the packets of every app. See [TUN/TAP](https://en.wikipedia.org/wiki/TUN/TAP).

VPN client
  An app that sends a machine's traffic through a server somebody else runs. Hole is a client of that kind, not a VPN
  service: it comes with no server. Get a config from whoever runs one, or run your own with {term}`Postern`.

Unblock Network
  See {term}`kill switch`: the tray action, shown whenever Hole is blocking traffic, connected or not, that disconnects and turns it off.
```
