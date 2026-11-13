# Hole

Hole is a {term}`Shadowsocks` client for macOS and Windows. It routes traffic through a {term}`TUN` interface, so by
default every application on the machine goes through the tunnel, including the ones that ignore system proxy settings,
and carries DNS through the tunnel too.

Hole is a client, not a VPN service: it needs a Shadowsocks server to connect to. Someone who runs one can send you a
config file to import, or you can run your own with [Postern](https://postern.readthedocs.io), Hole's companion
project.

If the server's config names a plugin with TLS turned on, as Postern's configs do, the traffic is camouflaged as
WebSocket over TLS. The plugin is the first-party {term}`ex-ray`, which appears in configs under the name
`v2ray-plugin`, or {term}`galoshes`, which adds UDP support. Hole's own install includes both, so a config can name
either without you installing anything. Without a plugin, Hole speaks plain Shadowsocks.

## Where to start

- **Using Hole:** the [README](https://github.com/bindreams/hole#readme) has the download and the server options. The
  [glossary](reference/glossary.md) explains the terms, and the [command line](reference/cli.md) lists the commands.
- **How it works:** the picture below, then [how Hole is put together](how-it-works/overview.md) and the pages that
  follow it.
- **Contributing:** {src}`CONTRIBUTING.md` covers building Hole, running its tests and how it is put together.

## Hole in one picture

```{mermaid}
flowchart LR
    apps["Your apps"] --> tun["TUN device"]
    tun --> ss
    subgraph bridge["Hole bridge (administrator rights)"]
        ss["Shadowsocks client"]
        plugin["Plugin: ex-ray or galoshes"]
    end
    ss -->|"no plugin in the config"| server["Your Shadowsocks server"]
    ss -. "optional: plugin in the config" .-> plugin
    plugin -. "optional" .-> server
    gui["Hole app (tray, settings)"] == "controls, over a local socket" ==> bridge
```

Hole is one program that runs in two modes. The **app** is what you click: the tray icon, the settings, the dashboard.
It runs as you. The **bridge** is a background service with administrator rights, and it is the only part that changes
how the machine's network behaves. The app tells the bridge what to do over a local socket.

The bridge creates the {term}`TUN` device and points the machine's routes at it, so the traffic of every app lands in
the bridge. It sends that traffic through a Shadowsocks client to your server. If the server's config names a
{term}`SIP003 plugin`, the traffic goes through that plugin on the way, which disguises it (the dotted path).

Component versions: hole {{ hole_version }}, galoshes {{ galoshes_version }}, garter {{ garter_version }}, ex-ray {{ exray_version }}.

Hole is free software under the [GNU GPL version 3 or later](reference/licensing.md); the source lives in the
[GitHub repository](https://github.com/bindreams/hole).

```{toctree}
---
caption: How it works
hidden:
---
How Hole is put together <how-it-works/overview.md>
The TUN device and the routes <how-it-works/tun.md>
Shadowsocks and its plugins <how-it-works/plugins.md>
ECH and DoH <how-it-works/ech-and-doh.md>
DNS through the tunnel <how-it-works/dns.md>
UDP: dropped, never bypassed <how-it-works/udp.md>
The kill switch <how-it-works/kill-switch.md>
```

```{toctree}
---
caption: Reference
hidden:
---
Command line <reference/cli.md>
Glossary <reference/glossary.md>
Distributions <reference/distributions.md>
Licensing <reference/licensing.md>
```

```{toctree}
---
hidden:
---
GitHub repository <https://github.com/bindreams/hole>
```
