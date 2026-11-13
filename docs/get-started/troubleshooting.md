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

If Hole says **Connection failed**, a message explains why. Hole writes the first six messages below, and the
network-blocked one, itself and shows them as they are. Every other row is a message the {term}`bridge` sent, and Hole
puts the prefix "Bridge error:" in front of it, for instance "Bridge error: server hostname is not a valid DNS name".
Where a message contains "(1234ms)", the number is how long the attempt ran, in milliseconds.

| Message                                                                                                                                            | What it usually means                                                                                                                                                                                  |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| No server is selected. Open the Dashboard and select a server before connecting.                                                                   | Click a server card to select it.                                                                                                                                                                      |
| The Hole bridge must be installed to connect.                                                                                                      | You chose **Later** at the setup prompt. Connect again and choose **Install**. See [Install](install.md#why-hole-asks-for-administrator-rights).                                                       |
| An interrupted uninstall or update left Hole's service disabled; it must be repaired to connect.                                                   | You declined the **Repair** prompt. Connect again and choose **Repair**.                                                                                                                               |
| The Hole service is disabled on this computer; it must be enabled to connect.                                                                      | You declined the **Enable** prompt. Connect again and choose **Enable**.                                                                                                                               |
| The Hole service is being changed by an uninstall, a repair or an update that is in progress. Try again when it finishes.                          | Wait for that to finish, then connect again.                                                                                                                                                           |
| Another connect or disconnect is already in progress.                                                                                              | Wait for the one in progress to finish.                                                                                                                                                                |
| The network is blocking the connection to this server ...                                                                                          | Same as the test result of that name above.                                                                                                                                                            |
| Nothing came back through the tunnel (1234ms). Either the proxy connection could not be established, or the server cannot reach your DNS resolver. | Check the server with **Test**. If it passes, try another **Resolver** in [Settings](settings.md#dns-forwarder).                                                                                       |
| Could not open a connection into the tunnel (1234ms). Every attempt to open one failed outright.                                                   | Hole cannot tell which side refused: the local proxy, or the connection onward to the server. Check the server with **Test**.                                                                          |
| The tunnel did not finish connecting (1234ms). The connection to the server was still being set up ...                                             | The server is slow, or unreachable from this network.                                                                                                                                                  |
| could not reach a secure DNS resolver / a secure DNS resolver did not respond in time / the connection to a secure DNS resolver failed             | Hole looks up the server's name through the **Resolver** over {term}`DoH`, and could not reach it. Try another resolver, or see **Allow insecure bootstrap** in [Settings](settings.md#dns-forwarder). |
| a secure DNS resolver presented a certificate that could not be verified ...                                                                       | Something on the network may be intercepting encrypted connections. Try another network.                                                                                                               |
| could not resolve the proxy server address via secure DNS                                                                                          | The resolver answered but has no address for the server's name. Check the address in the config.                                                                                                       |
| a secure DNS resolver returned a reply that is not valid DNS                                                                                       | The resolver's answer was unusable. Try another **Resolver**.                                                                                                                                          |
| server hostname is not a valid DNS name                                                                                                            | The address in the config is not a valid domain name. Check it for typos.                                                                                                                              |
| tunnel_mode=full with proxy_http requires the SOCKS5 listener ...                                                                                  | **HTTP** is on without **SOCKS5**. See [Settings](settings.md#local-proxy-server).                                                                                                                     |
| local_port and local_port_http must differ ...                                                                                                     | **SOCKS5** and **HTTP** are both on and use the same port. Change one.                                                                                                                                 |
| wintun.dll not found ... / wintun.dll load failed ...                                                                                              | Part of the Windows install is missing or damaged. Reinstall Hole.                                                                                                                                     |

A message that is not here, or one that keeps coming back, is a reason to [collect the logs](#collect-the-logs).

## When the internet stops working

Hole changes the computer's routes and DNS settings to send traffic through the tunnel, and it puts them back when it
disconnects. If it is stopped in the middle, or the {term}`kill switch` is holding traffic back, the computer can be left
without internet. Work down this list and stop when the internet is back. The first two steps need no terminal; the last
one is for someone technical.

1. **Disconnect or Unblock Network.** Click the power button, or choose **Disconnect** in the {term}`tray` menu. If the
   tray menu shows **Unblock Network (disconnects, turns Lockdown off)**, choose that instead: it disconnects, removes
   the block and turns the {term}`kill switch` off.

1. **Restart the computer.** Hole's bridge starts with the computer, and when it starts it cleans up the routes, DNS
   settings and plugin processes that a crashed run left behind. If **Unblock Network** is in the tray menu afterwards,
   choose it.

1. **Last resort, for someone comfortable with a terminal.** The steps below need an administrator terminal. If the
   person at the computer is not comfortable with one, they are for someone technical to do, in person.
   `hole bridge unlock` refuses while any bridge is running, including one the app cannot reach, so stop the service
   first, then unlock.

   On Windows, in PowerShell run as administrator:

   ```powershell
   Stop-Service -Name HoleBridge -Force
   (Start-Process -Wait -PassThru -FilePath hole -ArgumentList 'bridge', 'unlock').ExitCode
   ```

   `hole.exe` is a graphical program, so PowerShell would not wait for a plain `hole bridge unlock`; `Start-Process -Wait` makes it wait, and the number it prints is the result. `0` means the block is lifted. Anything else means
   unlock refused or failed: run both lines again.

   On a Mac, in Terminal:

   ```sh
   sudo launchctl bootout system/com.hole.bridge
   sudo /Applications/Hole.app/Contents/MacOS/hole bridge unlock
   ```

   On a Mac, if `launchctl bootout` says the service could not be found, it is already stopped: run the unlock line.
   If stopping the service does not finish, restart the computer and begin again from the top of this list. See
   the [command line reference](../reference/cli.md#hole-bridge-unlock). The bridge starts again the next time the
   computer starts.

If that did not fix it, run the network reset script. It is also for someone technical.

### The network reset script

The script is not installed with Hole: it is `scripts/network-reset.py` in
[Hole's repository](https://github.com/bindreams/hole), and needs `scripts/_lib.py` saved in the same folder. You need
Python 3.9 or newer, and you may have to fetch the two files from another computer or a phone, since this computer has
no internet.

Run it from an administrator terminal. On Windows, open PowerShell as administrator and run:

```powershell
python network-reset.py
```

On a Mac, stop the bridge's launchd job first, so launchd does not start the bridge again behind the script, and then run
it:

```sh
sudo launchctl bootout system/com.hole.bridge
sudo python3 network-reset.py
```

What it does depends on the platform. Both remove Hole's four split routes, restore the DNS settings Hole recorded and
flush the DNS cache; both need Hole's route record to find the host route that leads to the server, and print how to
remove that route by hand when the record is missing or unreadable.

- **Windows:** it stops the `HoleBridge` service, ends any bridge process and any `ex-ray` process, and removes Hole's
  network adapter.
- **macOS:** it ends bridge processes and `ex-ray` processes, and flushes the route table. It does not remove an adapter.

The script does not stop `galoshes`, the other plugin Hole ships, so a `galoshes` process left behind by a crashed
connection survives it. Restart the computer afterwards. If DNS still looks wrong, run it again with
`--force-dns-restore`: by default it restores only DNS settings that still look like Hole's own.

The script does not remove the block that Lockdown installs. Disconnect, Unblock Network and `hole bridge unlock` are the
steps that lift it.

## Collect the logs

Choose **Help** → **Collect Logs...** in the dashboard. Hole gathers its logs into a zip file and asks where to save it.
Hole replaces the server's address in the logs with a placeholder token. The zip's `REDACTION.txt` lists what that does
not cover, such as older log lines. Read the logs before you post them anywhere public.

## Where to ask

- A problem with the server, or a message that points at it, goes to whoever runs the server.
- A problem with Hole goes to [Hole's issue tracker](https://github.com/bindreams/hole/issues). Say which version you
  have, which operating system, what you did and the message you saw, and attach the zip if you are comfortable with it.
