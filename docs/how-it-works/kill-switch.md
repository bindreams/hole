# The kill switch

A tunnel protects you only while it is up. If it drops and the machine falls back to its ordinary route, applications
carry on, now unencrypted and visible to the network, and nothing tells you. A {term}`kill switch` closes that gap:
while it is in force, traffic that would leave the machine outside the tunnel is blocked instead of sent. Hole's kill
switch is the **Lockdown** item in the tray menu. It is off by default.

## What it is

The kill switch is a rule in the operating system's own firewall, installed by the {term}`bridge`, and not a check
inside Hole's own code. That is the point: a rule in the firewall stays in force if Hole stops, crashes or is being
updated, which a check in a program that is not running cannot do. Windows holds it as persistent filters in the Windows
Filtering Platform; macOS holds it as a ruleset that Hole loads into the `pf` packet filter.

While the rule is in force, an outgoing connection is allowed only if it is one of these:

- traffic to the machine itself (loopback);
- traffic through Hole's own {term}`TUN` device, so [everything the tunnel carries](tun.md) flows normally;
- traffic to your {term}`Shadowsocks` server's address, from any program, since Hole's own connection to it has to leave
  outside the tunnel (on Windows any protocol, on macOS TCP only);
- on Windows, anything run from the files of Hole's own programs, the bridge and the plugin, which are identified by
  their file. The bridge, the app and the `hole` command line are one file, so the app's own connections pass too.
  That includes the connections the bridge opens for a **Bypass** rule, so on Windows Bypass traffic still leaves. macOS
  cannot tell programs apart, so there a Bypass rule's traffic is blocked like the rest.

Everything else is blocked, and that includes devices on your local network, such as a printer or a file server. The rule
stops connections leaving the machine and sets no rule against incoming ones.

## When it is in force

Ticking **Lockdown** records a preference, which the bridge keeps across disconnects and restarts. The block is not
installed until Hole next connects. During a connect, it goes up right after the routes, before DNS is pointed at the
tunnel. If you tick Lockdown while connected, nothing is blocked yet: the block arrives at the next connect.

A connect in SOCKS-only mode has no tunnel, so it installs no block and does not refresh one that is already in force.

After that, what happens to the block depends on whether you or Hole decided to disconnect. The last column names the
row of the contributor reference's [transition table](../contributing/architecture/kill-switch.md#transitions) that
holds the exact rule.

| What happens                                                         | The block                                                                                                                 | Rule        |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ----------- |
| The network drops and comes back while Hole's processes keep running | Stays in force                                                                                                            | None needed |
| Hole restarts the session to apply a changed setting                 | Stays in force                                                                                                            | T10         |
| The bridge is restarted by an update                                 | Stays in force, and the new bridge takes it over, unless it starts with **On system startup** set to **Do not connect**   | T10, T16    |
| A connect fails before it installs the block                         | A block already in force stays                                                                                            | T3          |
| A connect fails while it installs the block                          | Windows: a block already in force stays. macOS: lifted                                                                    | T4          |
| A connect fails after the block went up                              | Lifted. On Windows, if the check that the boot-time part is in place fails, the block stays                               | T5, T6      |
| You click **Disconnect**, or choose **Exit**                         | Lifted, when a connection is running; with none running, for instance after a failed connect, it stays                    | T7, T8      |
| The Shadowsocks client or the plugin stops on its own                | Lifted when the app next asks for the status, because Hole gives up and disconnects then                                  | T9          |
| The machine shuts down or restarts while Hole is connected           | Windows: meant to stay in force, but nothing that spans a reboot has been measured. macOS: gone until Hole connects again | T17         |
| You choose **Unblock Network** in the tray                           | Lifted, and Lockdown is switched off. A connection that is running is not ended                                           | T12         |
| You untick **Lockdown**                                              | Lifted at once, while still connected                                                                                     | T11         |
| You run `hole bridge unlock`                                         | Lifted, and Lockdown is switched off; it refuses while the bridge service is running                                      | T13         |

The block follows one model: it holds while Hole is *meant* to be connected, and lifts when it is not. A disconnect you
asked for, and a connection Hole has given up on, both mean it is not, so the block does not trap a machine whose
tunnel Hole has abandoned. Hole notices a Shadowsocks client or plugin that stopped only when the app next asks the bridge
for its status. With no app running, for instance after a boot-time connect with the tray gone, the block stays until one
does.

Four rows read against what a kill switch is for: a failed connect lifts the block, Disconnect with no connection
running leaves it, **Unblock Network** does not disconnect although its label says it does, and a start with **Do not
connect** lifts it. This is what the code does today and not a mistake in how you read the table. Open issues sit behind
the last three: [#1295](https://github.com/bindreams/hole/issues/1295),
[#1282](https://github.com/bindreams/hole/issues/1282) and [#1294](https://github.com/bindreams/hole/issues/1294).

On macOS, a connection that restarts under the block has to look the server up again, and the block there lets through
only TCP to the server's address. When the server is given by name the lookup can fail, the restart then fails, and the
block stays until you choose **Unblock Network**.

If you are left with a block, choose **Unblock Network** in the tray. When the app cannot reach the bridge, stop the
bridge service and then run `hole bridge unlock` (see the [command reference](../reference/cli.md)):

````{tab-set}
---
sync-group: os
---
```{tab-item} Windows
:sync: windows

In an elevated PowerShell, run `Stop-Service -Name HoleBridge -Force`, then `hole bridge unlock`.
```
```{tab-item} macOS
:sync: macos

Run `sudo launchctl bootout system/com.hole.bridge`, then `sudo hole bridge unlock`.
```
````

## What the block does not do

A connection that the list permits is not inspected: the server connection
leaves outside the tunnel by design, and on Windows the programs of Hole itself are trusted to behave. It also protects
only the computer it runs on, and only outgoing traffic.

The contributor reference covers the rest in detail: the platform differences, how the block and the tunnel are
reconciled toward the state you last asked for, and the cases in which a block outlives a connection.
See [the kill switch](../contributing/architecture/kill-switch.md).

```{dropdown} Where in the code
The permitted set: `Routing::install_lockdown` in {src}`crates/tun-engine/src/routing.rs` and the platform code under
{src}`crates/tun-engine/src/routing/failclosed/`. The decisions in the table: `cover_step` and
`teardown_cover_disposition` in {src}`crates/bridge/src/reconciler.rs`; the events that produce them are
`SessionEvent` in {src}`crates/bridge/src/target.rs`.
```
