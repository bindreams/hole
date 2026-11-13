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
and the bridge answers. The socket is a local one, not a network port.

Splitting the program keeps the part that needs administrator rights apart from the window, and it lets the bridge
outlive it. Closing the dashboard does not disconnect, and the bridge makes its decision about connecting at system startup
before any app exists. The service is registered by the Windows installer; on a Mac, Hole asks for your password to
register it at the first connect.

## What the bridge is made of

```{mermaid}
flowchart LR
    app["Hole app"] == "local socket" ==> ipc
    subgraph bridge["Hole bridge"]
        ipc["Control API"]
        engine["TUN engine and filter rules"]
        dnsf["DNS forwarder"]
        ss["Shadowsocks client (SOCKS5 listener on loopback)"]
        ipc --> engine
        engine --> ss
        engine --> dnsf
        dnsf --> ss
    end
    os["Your apps, through the TUN device"] --> engine
    engine -. "Bypass rules: out the real network interface" .-> net["Internet"]
    ss -. "optional" .-> plugin["Plugin process: ex-ray or galoshes"]
    ss --> server["Your Shadowsocks server"]
    plugin -.-> server
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

```{mermaid}
sequenceDiagram
    participant App as Hole app
    participant B as Bridge
    participant OS as Operating system
    App->>B: Connect to this server
    B->>B: Look up the server's name over DoH
    B->>B: Start the plugin, if the config names one
    B->>B: Start the Shadowsocks client
    B->>B: Test the DNS forwarder through the proxy
    B->>OS: Open the TUN device
    B->>OS: Install the routes
    B->>OS: Block everything else (kill switch on only)
    B->>OS: Point DNS at the TUN device
    B-->>App: Connected
```

The order matters. With the DNS forwarder on, which is the default, it is chosen so that nothing about the machine
changes until one lookup has gone through the proxy. With it off, there is no such test, and the TUN device and the
routes go in as soon as the proxy is up.

1. When the server is given by name, the name is looked up over {term}`DoH` through your configured resolver, not through the operating system,
   and before any tunnel exists. See [ECH and DoH](ech-and-doh.md).
1. A configured {term}`SIP003 plugin` is started and waited for, and the {term}`Shadowsocks` client is started pointing
   at it, or at the server directly.
1. With the DNS forwarder on, it is built and sends one test lookup through the proxy. If that fails the connection
   fails here, before the bridge has changed any network setting.
1. Only then does the bridge open the TUN device and install the routes, which is the moment traffic starts to flow
   through Hole. With the {term}`kill switch` on, the block goes up right after the routes.
1. Last, with the forwarder on, the operating system's DNS is pointed at the TUN device, so lookups reach the forwarder.
   With it off, Hole leaves DNS settings alone.

A start that fails at any step releases everything it had already taken, including the kill switch's block, and
reports an error. Disconnecting does the same release on purpose.

```{dropdown} Where in the code
The phases are numbered in `ProxyManager`'s start path: {src}`crates/bridge/src/proxy_manager.rs`. The packet loop is the
`tun-engine` crate ({src}`crates/tun-engine/src/lib.rs`), and the control API is described by
{src}`crates/common/api/openapi.yaml`.
```
