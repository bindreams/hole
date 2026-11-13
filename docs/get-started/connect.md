# Connect

You have a {term}`config` file and Hole is installed. This page imports the config, switches Hole on and checks that it
works. The screenshots show Windows; the {term}`dashboard` looks the same on a Mac apart from the window frame.

## Open the dashboard

The dashboard is Hole's main window. It opens by itself when Hole starts, unless Hole was started in the tray only. If you
closed it, click Hole's icon in the {term}`tray` or choose **Dashboard...** from the tray menu.

```{figure} ../_static/screenshots/dashboard-no-servers.png
---
alt: The Hole dashboard before any server is added. Under Servers there is only 
  a "+ Import servers from file" button.
width: 90%
---
A new Hole has no servers. The status on the right reads "You are Disconnected".
```

## Import the config

There are three ways to import a config. They all do the same thing.

- Click **+ Import servers from file** under **Servers**.
- Choose **File** → **Import...** (Ctrl+O on Windows, Cmd+O on a Mac). On a Mac the menu bar is at the top of the screen
  and shows while the dashboard is open.
- Drag the config file onto the dashboard window.

```{figure} ../_static/screenshots/file-menu-import.png
---
alt: The dashboard's File menu open, showing Import... and Exit.
width: 60%
---
**File** → **Import...** opens a file picker. It shows files whose names end in `.json`.
```

Hole reads the file, adds its servers to the list and shows a message such as "Imported 1 server(s)." If a server is
already in the list, the message says "No new servers — already in the list." If something is wrong with the file, a
dialog says what, for instance that the file is not valid JSON or that it names a plugin Hole does not ship.

Hole imports `.json` files only. It does not read `ss://` links or QR codes.

## Look at the server and test it

Each server is a card in the list.

```{figure} ../_static/screenshots/server-card-tested.png
---
alt: A server card showing a name, its address and port, a "v2ray-plugin" badge,
  a green status dot with its tooltip open, a Test button and a delete button.
width: 90%
---
A server card. The tooltip on the status dot shows the result of the last test.
```

- The name is the config's `remarks` field, or the address and port if it had none.
- The badge shows which plugin the server uses, if it uses one.
- The dot is gray for a server that has not been tested, green for one that answered and red for one that did not.
  Hover over it to read the message.
- **Test** checks the server on demand, without switching Hole on. Hole also tests every server it imports.
- The **✕** removes the server from the list at once.

Click a card to select it. The selected server is the one Hole connects to. After an import, Hole selects the first new
server if none was selected.

A red dot does not stop you from trying to connect, but it says why a connection is likely to fail. The messages are
listed in [Troubleshooting](troubleshooting.md#what-a-test-result-means).

## Switch Hole on

Click the round power button at the top of the right-hand column. The status next to it changes from **You are
Disconnected** to **Connecting...** and then **Connected**. Clicking the button again while it says **Connecting...**
cancels the attempt.

You can also choose **Connect** from the tray menu.

If Hole says **Connection failed**, a message names the reason. [Troubleshooting](troubleshooting.md) lists them.

On a Mac, the first connection asks to install Hole's background helper; see
[Install](install.md#why-hole-asks-for-administrator-rights).

## Check that it works

Under the status, Hole shows the public IP address that websites see for this computer, with the flag of the country it
is in.

```{figure} ../_static/screenshots/dashboard-connected.png
---
alt: The Hole dashboard while connected. The right-hand column reads "You are 
  Connected" with an IP address and a country flag, followed by a throughput 
  graph, traffic figures, and the Diagnostics and Capabilities dots.
width: 90%
---
A connected Hole. The address and flag are the server's.
```

1. Before you connect, note the address and flag: they are your internet provider's.
1. Connect. After a moment the address and flag change to the server's. Websites now see the server's address.
1. If you want a second opinion, open a "what is my IP" website in a browser. It should show the same address.

Hole looks the address up when the connection state changes and once a minute while the dashboard is open. A `--` means the
lookup failed, not that Hole is disconnected.

If the address does not change, or no website loads, see [Troubleshooting](troubleshooting.md).

## Switch Hole off

Click the power button again, or choose **Disconnect** from the tray menu.

Closing the dashboard window does not disconnect: Hole keeps running in the tray. To disconnect and quit, choose **Exit**
from the **File** menu or the tray menu.

## The tray

Hole puts an icon in the {term}`tray`: the notification area at the right of the Windows taskbar (it may be tucked under
the **^** arrow), or the menu bar on a Mac. Click the icon to open the dashboard. Right-click it for a menu.

```{figure} ../_static/screenshots/tray-menu.png
---
alt: Hole's tray menu showing the status "Connected", Disconnect, Start at 
  Login, Lockdown, Dashboard... and Exit.
width: 50%
---
The tray menu while connected.
```

The menu shows the status, a **Connect** or **Disconnect** item, **Start at Login**, **Lockdown**, **Dashboard...** and
**Exit**. When a new version is found, an **Install Update** item appears too.

**Lockdown** is the {term}`kill switch`. With it on, traffic that would leave outside the tunnel is blocked while Hole is
connecting or connected, so a dropped connection does not quietly send your traffic around the tunnel. It is off by
default. The [settings page](settings.md#the-tray-menu) explains what it blocks and how to lift it.

## Next

[Settings explained](settings.md) describes every control on the dashboard.
