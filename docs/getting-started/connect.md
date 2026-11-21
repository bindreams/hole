# Connecting

With a {term}`config` file and Hole installed, connecting takes three steps: import the config, switch Hole on, and
check that it works.

## Opening the dashboard

The {term}`dashboard` is Hole's main window. It opens by itself when Hole starts, unless Hole was started in the tray only. If you
closed it, click Hole's icon in the {term}`tray` or choose **Dashboard...** from the tray menu.

## Importing the config

There are three ways to import a config.

- Click **+ Import servers from file** under **Servers**.
- Choose **File** → **Import...** (Ctrl+O on Windows, Cmd+O on a Mac). On a Mac the menu bar is at the top of the screen
  and shows while the dashboard is open.
- Drag the config file onto the dashboard window.

Hole reads the file, adds its servers to the list and shows a message such as "Imported 1 server(s)." If a server is
already in the list, the message says "No new servers — already in the list." If something is wrong with the file, a
dialog says what, for instance that the file is not valid JSON or that it names a plugin Hole does not ship. A file is
imported whole or not at all: if one server in it is refused, none of its servers are added.

Hole imports `.json` files only. It does not read `ss://` links or QR codes.

## Testing the server

Each server is a card in the list.

- The name is the config's `remarks` field, or the address and port if it had none.
- The badge shows which plugin the server uses, if it uses one.
- The dot is gray for a server that has not been tested, green for one that answered and red for one that did not.
  Hover over it to read the message.
- **Test** checks the server on demand, without switching Hole on. Hole also tests every server it imports. The test
  runs in Hole's {term}`bridge`, so on a Mac it works only once the first connect has installed the bridge: until then,
  the dots of imported servers turn red with a message that begins "Internal error: bridge unreachable". Connect once, then test again.
- The **✕** removes the server from the list at once.

Click a card to select it. The selected server is the one Hole connects to. After an import, if no server in the list is
selected, Hole selects the first one.

A red dot does not stop you from trying to connect, but it says why a connection is likely to fail. The messages are
listed in [Troubleshooting](troubleshooting.md#test-results).

## Switching Hole on

Click the round power button at the top of the right-hand column. The status next to it changes from **You are
Disconnected** to **Connecting...** and then **Connected**. Clicking the button again while it says **Connecting...**
cancels the attempt, and the status reads **Cancelling...** until it has stopped.

You can also choose **Connect** from the tray menu.

If Hole says **Connection failed**, a message names the reason. [Troubleshooting](troubleshooting.md) lists them.

On a Mac, the first connection asks to install Hole's background helper; see
[Installing Hole](install.md#administrator-rights).

## Checking the connection

Under the status, Hole shows the public IP address that websites see for this computer, with the flag of the country it
is in.

1. Before you connect, note the address and flag: they are your internet provider's.
1. Connect. After a moment the address and flag change to the server's. Websites now see the server's address.
1. If you want a second opinion, open a "what is my IP" website in a browser. It should show the same address.

Hole looks the address up with a request to Cloudflare, so Cloudflare sees it; while connected, the request goes through
the tunnel. A `--` shows before the first lookup has answered, and again whenever a lookup fails.

If the address does not change, or no website loads, see [Troubleshooting](troubleshooting.md).

## Switching Hole off

Click the power button again, or choose **Disconnect** from the tray menu.

Closing the dashboard window does not disconnect: Hole keeps running in the tray. To disconnect and quit, choose **Exit**
from the **File** menu or the tray menu.

## The tray

Hole puts an icon in the {term}`tray`: the notification area at the right of the Windows taskbar (it may be tucked under
the **^** arrow), or the menu bar on a Mac. Click the icon to open the dashboard. Right-click it for a menu.

The menu shows the status, a **Connect** or **Disconnect** item, **Start at Login**, **Lockdown**, **Dashboard...** and
**Exit**. When a new version is found, an **Install Update (v...)** item with the version appears too, and while a block
is in force, an **Unblock Network** item.

**Lockdown** is the {term}`kill switch`. Click it to turn it on or off; it is off by default. The
[settings page](settings.md#the-tray-menu) explains the menu item and how to lift a block.
