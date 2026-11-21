# How Hole is put together

Hole is one program that runs in two modes, and the split between them explains most of how it behaves. This page
introduces the two halves and walks through what happens between a click on **Connect** and the first byte through the
tunnel. The pages after it zoom in on the parts.

## Two modes

|            | The app                                                                         | The {term}`bridge`                                                                                                                           |
| ---------- | ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Started by | You, from the Start menu or Applications (the `hole` program with no arguments) | The operating system, as a service, with `hole bridge run --service`                                                                         |
| Runs with  | Your own rights                                                                 | Administrator rights                                                                                                                         |
| Does       | The tray icon, the dashboard, the settings, the config file                     | Everything that changes how the machine's network behaves: the {term}`TUN` device, the routes, DNS, the firewall block, the plugin processes |

The two talk over a local socket. The app sends requests such as "connect to this server" and "what is the status?",
and the bridge answers.

Splitting the program keeps the part that needs administrator rights apart from the window, and it lets the bridge
outlive it. Closing the dashboard does not disconnect, and the bridge makes its decision about connecting at system startup
before any app exists. The service is registered by the Windows installer; on a Mac, Hole asks for your password to
register it at the first connect.

## What the bridge is made of

Every app's traffic arrives at the bridge. The bridge sends it to your server through a {term}`Shadowsocks` client, or
straight to the internet where a {term}`filter` rule says **Bypass**.

```{raw} html
<div class="diagram-scroll">
```

```{raw} html
---
file: bridge.svg
---
```

```{raw} html
</div>
```

The pieces, each with its own page:

- The **TUN engine** receives every packet the apps send and turns it into connections it can route one by one. See
  [the TUN device and the routes](tun.md).
- The {term}`Shadowsocks` **client** and the optional **plugin** carry the connections to your server. See
  [Shadowsocks and its plugins](plugins.md).
- The {term}`DNS forwarder` answers the machine's DNS lookups through the tunnel. See [DNS through the tunnel](dns.md).
- Two cross-cutting policies decide what is allowed to leave the machine: [the UDP rule](udp.md) and
  [the kill switch](kill-switch.md).

## What happens when you connect

The app asks the bridge to connect to a server, and the bridge works in this order:

1. It looks up the server's name over {term}`DoH`, not through the operating system, before any tunnel exists. See
   [ECH and DoH](ech-and-doh.md).
1. It starts the {term}`SIP003 plugin`, if the config names one, and waits for it.
1. It starts the {term}`Shadowsocks` client, pointed at the plugin, or at the server directly.
1. With the DNS forwarder on, which is the default, it sends one test lookup through the proxy. If the lookup fails, the
   connection fails here, before the bridge has changed any network setting.
1. It opens the TUN device and installs the routes. This is the moment traffic starts to flow through Hole.
1. With the {term}`kill switch` on, it blocks everything else, right after the routes.
1. With the forwarder on, it points the operating system's DNS at the TUN device. With it off, Hole leaves DNS settings
   alone.
1. It tells the app that the connection is up.

With the forwarder on, the order is chosen so that no network setting of the machine changes until one lookup has gone
through the proxy. With it off, there is no such test, and the TUN device and the routes go in as soon as the proxy is up.

A start that fails at any step releases everything it had already taken, including the kill switch's block, and
reports an error. Disconnecting does the same release on purpose.

```{dropdown} Where in the code
The phases are numbered in `ProxyManager`'s start path: {src}`crates/bridge/src/proxy_manager.rs`. The packet loop is the
`tun-engine` crate ({src}`crates/tun-engine/src/lib.rs`), and the control API is described by
{src}`crates/common/api/openapi.yaml`.
```
