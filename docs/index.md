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
- **Contributing:** [Contributing](contributing/index.md) covers building Hole, running its tests and developing it. How
  it is put together starts at the [architecture overview](contributing/architecture/overview.md).

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
caption: Contributing
hidden:
---
Contributing <contributing/index.md>
Set up and build <contributing/setup.md>
The workspace <contributing/workspace.md>
Architecture overview <contributing/architecture/overview.md>
The kill switch <contributing/architecture/kill-switch.md>
Recovery, adoption and the cover lock <contributing/architecture/kill-switch-recovery.md>
Windows: filters and the boot window <contributing/architecture/kill-switch-windows.md>
macOS: the pf ruleset <contributing/architecture/kill-switch-macos.md>
Uninstall and the service <contributing/architecture/kill-switch-uninstall.md>
The datapath <contributing/architecture/datapath.md>
The TUN device: name and IPv6 <contributing/architecture/tun-device.md>
TCP accept refusal <contributing/architecture/tcp-admission.md>
The DNS forwarder <contributing/architecture/dns-forwarder.md>
Plugin binaries <contributing/architecture/plugin-binaries.md>
The galoshes transport <contributing/architecture/galoshes-transport.md>
Route commands and what failing means <contributing/architecture/route-failure-policy.md>
Route ownership <contributing/architecture/route-ownership.md>
Crash recovery <contributing/architecture/crash-recovery.md>
Config corruption recovery <contributing/architecture/config-recovery.md>
Privileged code in folders a user may own <contributing/architecture/privileged-folders.md>
File lock and state files <contributing/architecture/file-lock.md>
System tools and absolute paths <contributing/architecture/system-tools.md>
Update cutover <contributing/architecture/update-cutover.md>
Native crashes and test panics <contributing/architecture/native-crashes.md>
Windows service stop reporting <contributing/architecture/windows-service-stop.md>
Spawn contention and port allocation <contributing/architecture/contention-and-ports.md>
The app process <contributing/architecture/app-process.md>
The seams: how tests stay off the machine <contributing/architecture/test-isolation.md>
Cancellation and teardown <contributing/architecture/cancellation.md>
The proxy shutdown contract <contributing/architecture/proxy-shutdown.md>
Logging and diagnostics <contributing/architecture/logging.md>
Server-address redaction <contributing/architecture/redaction.md>
Development <contributing/development.md>
Testing <contributing/testing.md>
Continuous integration <contributing/ci.md>
Commit messages <contributing/commit-messages.md>
Building in detail <contributing/build.md>
The installers <contributing/installers.md>
Bridge and proxy commands <contributing/bridge-cli.md>
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
