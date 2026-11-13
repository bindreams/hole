# Troubleshooting

This page starts with the quickest check, then lists the messages Hole shows and what they usually point at, and ends with
what to do when the computer has no internet at all.

## Start with the server's test

Most problems are between the computer and the server, so test the server first. In the {term}`dashboard`, click **Test**
on its card. Hover over the status dot to read the result. The test does not need Hole to be connected.

### What a test result means

| Message                                                                                                                                                                  | What it usually means                                                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Reachable. Round-trip N ms.                                                                                                                                              | The server answered and passed traffic. The problem is elsewhere.                                                                           |
| Validated by a recent successful connect.                                                                                                                                | Hole connected to this server not long ago. It is not a fresh test.                                                                         |
| DNS resolution failed.                                                                                                                                                   | The server's domain name could not be turned into an address through the secure lookup. See below the table.                                |
| Connection refused by the server.                                                                                                                                        | Something answered at that address but nothing is listening on the port. Is the server running, and is the port right?                      |
| No response from the server.                                                                                                                                             | Nothing answered in time. The server may be off, the address wrong, or the network may be dropping the traffic.                             |
| Plugin failed to start: ...                                                                                                                                              | The server's plugin did not start. The text after the colon says why.                                                                       |
| Server rejected the connection (wrong password, cipher, or plugin config).                                                                                               | The server was reached but refused the connection. Compare the password, cipher and plugin settings with the server's.                      |
| The network is blocking the connection to this server — the handshake was reset or got no response. This usually means a firewall or censorship; try a different server. | The network between the computer and the server is cutting the connection. A different server, or a different network, is the way round it. |
| Server cannot reach the public internet.                                                                                                                                 | The tunnel works but the server cannot get out to the internet. The problem is on the server.                                               |
| Unexpected response from the test sentinel: ... / Internal error: ...                                                                                                    | Something unexpected happened. [Collect the logs](#collect-the-logs). The one exception is "bridge unreachable", below.                     |

**DNS resolution failed.** Hole looks the server's name up over {term}`DoH`, through the **Resolver** you chose, and never
through the computer's own DNS. Every failure of that lookup shows this one message: the resolver could not be reached
or did not answer in time, something on the network is interfering, the reply was not valid, or the resolver has no
address for the name. On a filtered network the usual cause is the resolver, not a typo. Try another **Resolver**, or see
**Allow insecure bootstrap** in [Settings](settings.md#dns-forwarder); then check the address in the config. A config
whose address is already an IP address never gets this result.

**Internal error: bridge unreachable.** The test goes through the {term}`bridge`, so a test cannot run without it. On a
Mac the bridge is installed the first time you connect, so the servers Hole tests when you import them show this until
then. It also appears for an account that is not allowed to talk to the bridge. Connect once (see
[Install](install.md#why-hole-asks-for-administrator-rights)), then press **Test** again.

If you run the server yourself, check its side as well: Postern's
[Operations](https://postern.readthedocs.io/en/latest/operations/index.html) pages cover logs and the state of each
connection.

## When connecting fails

If Hole says **Connection failed**, a message explains why. Most are shown with the prefix "Bridge error:", and the ones
that begin with a lower-case letter below follow it.

| Message                                                                                                                                            | What it usually means                                                                                                                                                                                  |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| No server is selected. Open the Dashboard and select a server before connecting.                                                                   | Click a server card to select it.                                                                                                                                                                      |
| The Hole bridge must be installed to connect.                                                                                                      | You chose **Later** at the setup prompt. Connect again and choose **Install**. See [Install](install.md#why-hole-asks-for-administrator-rights).                                                       |
| The network is blocking the connection to this server ...                                                                                          | Same as the test result of that name above.                                                                                                                                                            |
| Nothing came back through the tunnel (... ms). Either the proxy connection could not be established, or the server cannot reach your DNS resolver. | Check the server with **Test**. If it passes, try another **Resolver** in [Settings](settings.md#dns-forwarder).                                                                                       |
| Could not open a connection into the tunnel (... ms). Every attempt to open one failed outright.                                                   | Hole cannot tell which side refused: the local proxy, or the connection onward to the server. Check the server with **Test**.                                                                          |
| The tunnel did not finish connecting (... ms). The connection to the server was still being set up ...                                             | The server is slow, or unreachable from this network.                                                                                                                                                  |
| could not reach a secure DNS resolver / a secure DNS resolver did not respond in time / the connection to a secure DNS resolver failed             | Hole looks up the server's name through the **Resolver** over {term}`DoH`, and could not reach it. Try another resolver, or see **Allow insecure bootstrap** in [Settings](settings.md#dns-forwarder). |
| a secure DNS resolver presented a certificate that could not be verified ...                                                                       | Something on the network may be intercepting encrypted connections. Try another network.                                                                                                               |
| could not resolve the proxy server address via secure DNS                                                                                          | The resolver answered but has no address for the server's name. Check the address in the config.                                                                                                       |
| a secure DNS resolver returned a reply that is not valid DNS                                                                                       | The resolver's answer was unusable. Try another **Resolver**.                                                                                                                                          |
| server hostname is not a valid DNS name                                                                                                            | The address in the config is not a valid domain name. Check it for typos.                                                                                                                              |
| tunnel_mode=full with proxy_http requires the SOCKS5 listener ...                                                                                  | **HTTP** is on without **SOCKS5**. See [Settings](settings.md#local-proxy-server).                                                                                                                     |
| local_port and local_port_http must differ ...                                                                                                     | The SOCKS5 and HTTP ports are the same. Change one.                                                                                                                                                    |
| wintun.dll not found ... / wintun.dll load failed ...                                                                                              | Part of the Windows install is missing or damaged. Reinstall Hole.                                                                                                                                     |

A message that is not here, or one that keeps coming back, is a reason to [collect the logs](#collect-the-logs).

## When the internet stops working

Hole changes the computer's routes and DNS settings to send traffic through the tunnel, and it puts them back when it
disconnects. If it is stopped in the middle, or the {term}`kill switch` is holding traffic back, the computer can be left
without internet. Work down this list and stop when the internet is back. The first three steps need no terminal; the last resorts after them do.

1. **Disconnect.** Click the power button, or choose **Disconnect** in the {term}`tray` menu. If the cause was a brief
   drop with Lockdown on, this lifts the block.

1. **Unblock Network.** If the tray menu shows **Unblock Network (disconnects, turns Lockdown off)**, choose it. It
   disconnects, removes the block and turns the {term}`kill switch` off.

1. **Restart the computer.** Hole's bridge starts with the computer, and when it starts it cleans up the routes, DNS
   settings and plugin processes that a crashed run left behind. This is also the way out when the bridge is running
   but the app cannot reach it, which is the one case the next step refuses. A restart does not lift a block while Lockdown is still on.

### Last resorts, for someone comfortable with a terminal

The two steps below need an administrator terminal. If the person at the computer is not comfortable with one, they are
for someone technical to do, in person.

1. **Run `hole bridge unlock`** in an administrator terminal, if Lockdown is still blocking traffic and Hole's app
   cannot reach its {term}`bridge`. It turns Lockdown off and clears the block it left behind. It refuses while any
   bridge is running, reachable or not; the message then tells you to use **Unblock Network**, which cannot help if the
   app cannot reach the bridge, so restart instead. On a Mac, run it with `sudo` and the full path:
   `sudo /Applications/Hole.app/Contents/MacOS/hole bridge unlock`. See the
   [command line reference](../reference/cli.md#hole-bridge-unlock).

1. **Run the network reset script**, if the cleanup did not fix it. The script is not installed with Hole: it is
   `scripts/network-reset.py` in [Hole's repository](https://github.com/bindreams/hole), and needs `scripts/_lib.py`
   saved in the same folder. You need Python 3.9 or newer, and you may have to fetch the two files from another computer
   or a phone, since this computer has no internet.

   Run it from an administrator terminal. On Windows, open PowerShell as administrator and run:

   ```powershell
   python network-reset.py
   ```

   On a Mac, in Terminal:

   ```sh
   sudo python3 network-reset.py
   ```

   It stops Hole's bridge and plugin processes and removes Hole's routes and, on Windows, Hole's network adapter. It
   restores the DNS settings Hole recorded. What it can do depends on Hole's record files being readable: without the
   route record on Windows, it cannot tell which host route is Hole's and prints how to remove it by hand. On a Mac
   it deletes Hole's four split routes whether or not the record is readable. Restart the computer afterwards. If DNS
   still looks wrong, run it again with `--force-dns-restore`: by default it restores only DNS settings that still look
   like Hole's own.

The script does not remove the block that Lockdown installs. Disconnect, Unblock Network and `hole bridge unlock` are
the steps that lift it.

## Collect the logs

Choose **Help** → **Collect Logs...** in the dashboard. Hole gathers its logs into a zip file and asks where to save it.
Hole replaces the server's address in the logs with a placeholder token. The zip's `REDACTION.txt` lists what that does
not cover, such as older log lines. Read the logs before you post them anywhere public.

## Where to ask

- A problem with the server, or a message that points at it, goes to whoever runs the server.
- A problem with Hole goes to [Hole's issue tracker](https://github.com/bindreams/hole/issues). Say which version you
  have, which operating system, what you did and the message you saw, and attach the zip if you are comfortable with it.
