# Settings explained

Everything Hole offers is on the {term}`dashboard`, apart from a few actions in the {term}`tray` menu. This page goes
through it control by control. You do not have to change any of it to use Hole: the defaults connect and carry all of the
computer's traffic through the server.

Settings take effect the next time you connect. The exceptions are filters, which apply at once if Hole is connected, and
the login setting and the theme, which apply at once.

The dashboard has two columns. The left column holds **Servers**, **Filters** and **Settings**, and each section folds
away when you click its title. The right column shows the connection. The screenshots show Windows.

```{figure} ../_static/screenshots/dashboard-settings.png
---
alt: The Settings section of the dashboard, listing Start Hole on login, On 
  system startup, Theme, Local proxy server, DNS forwarder and their options.
width: 90%
---
The **Settings** section.
```

## Servers

The server list, its **Test** buttons and the import button are covered in [Connect](connect.md).

## Filters

A {term}`filter` decides what Hole does with traffic to an address. Each rule has an address, a way of matching it and
an action.

```{figure} ../_static/screenshots/dashboard-filters.png
---
alt: The Filters section of the dashboard, with a table of rules in Address, 
  Matching and Action columns, a locked first row for the default rule, an Add 
  rule button and a Test filtering box.
width: 90%
---
The **Filters** section with one added rule.
```

**Actions**

| Action     | What Hole does                                 |
| ---------- | ---------------------------------------------- |
| **Proxy**  | Sends the traffic through the server.          |
| **Bypass** | Sends the traffic directly, around the tunnel. |
| **Block**  | Refuses the traffic.                           |

**Matching**

| Matching            | Address to type                | What it matches                                                              |
| ------------------- | ------------------------------ | ---------------------------------------------------------------------------- |
| **exactly**         | `example.com` or `203.0.113.7` | That domain or that IP address only.                                         |
| **with subdomains** | `example.com`                  | The domain and everything under it, such as `www.example.com`. Domains only. |
| **wildcard**        | `*.example.com`                | A domain pattern: `*` stands for any run of characters and `?` for one.      |
| **subnet**          | `203.0.113.0/24`               | Every IP address in the block.                                               |

**Order matters.** Hole reads the list from top to bottom and the last rule that matches decides, so a rule lower in the
list overrides one above it. The first row is the default rule, which sends everything through the server; it is locked
and cannot be edited, moved or deleted. Drag a rule by its handle to reorder it.

To add a rule, click **+ Add rule**, type the address, press Enter, and then pick the matching and the action from the
rule's drop-downs. A new rule starts as **wildcard** with the action **Proxy**. A rule Hole cannot apply, for instance a
subnet that is not valid, shows a **⚠** that says why ("Rule not applied: ..."). The **⚠** appears only while Hole is
connected, because it is the running connection that rejects the rule.

To see what the rules do, type a domain or an IP address into **Test filtering**. It reports the action and the rule that
decided it.

```{dropdown} How domain rules find a name
For web traffic Hole reads the name from the start of the connection: the server name a TLS connection announces, or the
`Host` header of plain HTTP. A domain rule matches on that name, so it cannot match a connection that hides it. UDP
traffic is matched by IP address only.
```

## Settings

### Start Hole on login

Starts Hole when you sign in to the computer. Hole starts in the tray without opening the dashboard. It is the same
setting as **Start at Login** in the tray menu, and it reads the operating system's current state, so a change made in
Windows or macOS shows up here.

### On system startup

What Hole does when the computer starts.

| Choice                 | What happens                                                                                                                            |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Do not connect**     | Hole does not connect.                                                                                                                  |
| **Restore last state** | Hole connects if the last thing you asked it to do was connect, and Hole has not since given up on the connection. This is the default. |
| **Always connect**     | Hole connects to the last server it connected to, even if you had disconnected.                                                         |

The choice is carried out by the {term}`bridge` when it starts, which is when the computer starts, so the connection can
come up before you sign in and without the dashboard open. If the automatic connection fails, the internet works as it
did before Hole, unprotected, unless the {term}`kill switch` is on and its block is already in force. Hole puts the block
in place partway through connecting, so a connection that fails before that point leaves the internet open even with the
kill switch on.

### Theme

**Light**, **Dark** or **System**. **System** follows the operating system's theme and changes when it does. The default
is **Dark**.

### Local proxy server

Hole's tunnel needs no setup in the apps you use: the {term}`TUN` device catches their traffic. The local proxy server is
for the occasional app that you want to point at Hole yourself. It is a proxy that listens on this computer only.

| Control                        | What it does                                                                                              |
| ------------------------------ | --------------------------------------------------------------------------------------------------------- |
| **Local proxy server**         | The master switch. Off, Hole opens no port you can point an app at, and the next two keep their settings. |
| **SOCKS5**                     | A SOCKS5 proxy on the SOCKS5 port. On by default.                                                         |
| **HTTP**                       | An HTTP proxy on the HTTP port. Off by default.                                                           |
| **SOCKS5 port**, **HTTP port** | The ports to listen on. The HTTP port shows only when **HTTP** is on.                                     |

With **Local proxy server** on, two rules apply, and connecting fails with a message that says so when one is broken.
**HTTP** cannot be on alone: turn on **SOCKS5** as well, or turn **HTTP** off. When both are on, their ports must
differ. With **Local proxy server** off, neither rule applies.

### DNS forwarder

A DNS lookup turns a website's name into an address. With the forwarder on, which is the default, Hole sends the
computer's lookups to the resolver you pick, through the tunnel, so the network you are on does not see them. Turned off,
Hole leaves the computer's DNS settings alone.

| Control                      | What it does                                                                                                                                          |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Protocol**                 | How Hole talks to the resolver: **DNS over HTTPS** (the default), **DNS over TLS**, **Plain TCP** or **Plain UDP**.                                   |
| **Resolver**                 | **Cloudflare** (the default), **Google**, **Quad9**, **OpenDNS**, **AdGuard**, or **Custom...**.                                                      |
| **Resolver IPs**             | Shown only while the saved resolver list matches no preset: one or more IP addresses, separated by commas. Hole tries them in order, first one first. |
| **Allow insecure bootstrap** | Off by default. See below.                                                                                                                            |

Choosing **Custom...** on its own does not reveal **Resolver IPs**: the row appears only when the saved list is already
custom, for instance after the config file was edited by hand. A custom resolver must speak {term}`DoH`, because Hole
always looks the server's name up over DoH through these IPs before it connects, whatever **Protocol** you chose. The
presets all do.

**Plain UDP** works only if the server's plugin can carry UDP traffic ({term}`galoshes` can; {term}`ex-ray` cannot) or the
resolver is covered by a **Bypass** rule. Otherwise Hole drops the lookups. The other three protocols work with any
plugin.

The resolver also answers the lookup that {term}`ex-ray` makes for its {term}`ECH` settings.

```{dropdown} What "Allow insecure bootstrap" means
Before it connects, Hole must turn your server's name into an address. It does that over {term}`DoH`, through the
resolver you picked, and never through the computer's own DNS, because the network can read and alter those lookups. If
the secure lookup fails, Hole stops and says why, for instance that a resolver's certificate could not be verified, which
can mean something on the network is interfering.

With **Allow insecure bootstrap** on, a failed secure lookup falls back to the computer's ordinary DNS. Hole then
connects, but the network can see which server you looked up and could have changed the answer. The setting applies
whether or not the forwarder is on.
```

## The right-hand column

- **The power button and status.** Click the button to connect or disconnect. The status reads **Disconnected**,
  **Connecting...**, **Connected**, **Disconnecting...**, **Cancelling...** (after you click the button while it connects),
  **Connection failed** or **Disconnect failed**.
- **The address.** The public IP address websites see, with its country's flag. The copy button beside it copies the
  address.
- **The graph and the figures.** Throughput over the last minute, then **Downloaded**, **Uploaded**, **Download speed**,
  **Upload speed** and **Uptime**.
- **Diagnostics.** Five dots, from the app to the internet. Gray is unknown, green is fine and red is a problem. They are
  coarse checks. **App** is green whenever the dashboard is running. **Bridge** turns red when the bridge's last start,
  reload or stop failed. **Network** is green when the computer has a default route, and does not probe it. **VPN Server**
  and **Internet** come from the selected server's last test, and hovering over either shows the result; the other three
  have no hover text. **VPN Server** is red after a failed test. **Internet** turns green only after a real **Test**, not
  merely after connecting, and is gray otherwise, never red.
- **Capabilities.** Two dots that describe the current connection and change nothing. Both are gray while Hole is
  disconnected. **UDP proxy** is green when the
  connection can carry UDP traffic. It is red with a plugin that carries TCP only, such as ex-ray; Hole then drops the UDP
  traffic that would go through the server, rather than sending it around the tunnel. **IPv6 bypass** is red when the
  computer's network has no working IPv6, so a **Bypass** rule cannot send IPv6 traffic around the tunnel.

## The tray menu

The tray menu has the status, **Connect** or **Disconnect**, **Start at Login**, **Lockdown**, **Dashboard...** and
**Exit**, plus **Install Update (v...)** with the version when a new one is found, and **Unblock Network** while a block
is in force. **Connect**, **Disconnect**, **Dashboard...** and **Exit**
are covered in [Connect](connect.md), and **Start at Login** is described above.

### Lockdown

**Lockdown** is the {term}`kill switch`, and it is off by default. Click the item in the tray menu to turn it on or off.
With it on, while Hole is connecting or connected, traffic that would leave outside the tunnel is blocked, including traffic to devices on your local network such as a
printer. The block holds through brief drops, reconnects and restarts, so a dropped connection never quietly sends your
traffic around the tunnel. It lifts when you disconnect, or when Hole gives up on the connection.

The menu item shows **Lockdown: On** when the switch is on and the block is in force. **Lockdown: On (warning: not
engaged)** means the switch is on but no block is in force right now. That is the case when Hole is not connected, and
also when you turned Lockdown on while connected: the block starts at the next connect, so disconnect and connect again
to be protected.

While a block is in force, the menu offers **Unblock Network (disconnects, turns Lockdown off)**. It disconnects Hole,
removes the block and turns Lockdown off. If Hole cannot reach its bridge, [Troubleshooting](troubleshooting.md) has the
command-line route.

## Next

[Troubleshooting](troubleshooting.md): error messages, and what to do when the internet stops working.
