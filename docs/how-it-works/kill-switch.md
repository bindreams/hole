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

After that, what happens to the block depends on whether you or Hole decided to disconnect.

| What happens                                                         | The block                                                                                                                                                                                                                                                                                                |
| -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The network drops and comes back while Hole's processes keep running | Stays in force                                                                                                                                                                                                                                                                                           |
| Hole restarts the session to apply a changed setting                 | Stays in force across the restart (see the macOS note below)                                                                                                                                                                                                                                             |
| The bridge is restarted by an update                                 | Stays in force, and the new bridge takes it over (see the macOS note below), unless **On system startup** is set to **Do not connect**: the new bridge then lifts it                                                                                                                                     |
| A connect fails after the block went up                              | Lifted, with one Windows exception: if the check that the boot-time part is in place fails, the block stays until you choose **Unblock Network**. A connect that fails before it installs the block leaves any block already in force                                                                    |
| You click **Disconnect**, or choose **Exit**                         | Lifted, when a connection is running. Lockdown stays ticked, so the next connect puts it back. With no connection running, for instance after a failed connect, the block stays                                                                                                                          |
| The machine shuts down or restarts while Hole is connected           | Windows: meant to stay in force through the reboot, but nothing that spans a reboot has been measured. macOS: the firewall forgets the rule at reboot, and traffic is open until Hole connects again (see the macOS note below)                                                                          |
| The Shadowsocks client or the plugin stops on its own                | Lifted when the app next asks for the status, because Hole gives up and disconnects then                                                                                                                                                                                                                 |
| You choose **Unblock Network** in the tray                           | Lifted, Lockdown is switched off, and Hole will not reconnect by itself at the next start. A connection that is running is not ended                                                                                                                                                                     |
| You untick **Lockdown**                                              | Lifted at once, while still connected                                                                                                                                                                                                                                                                    |
| You run `hole bridge unlock`                                         | Lifted, and Lockdown is switched off and Hole will not reconnect by itself, as for Unblock Network. It lifts only the Lockdown block and refuses while the bridge service is running; then **Unblock Network** is the way. It does not detect a bridge you started by hand: the block is lifted under it |

The block follows one model: it holds while Hole is *meant* to be connected, and lifts when it is not. A disconnect you
asked for, and a connection Hole has given up on, both mean it is not, so the block does not trap a machine whose
tunnel Hole has abandoned. Hole notices a Shadowsocks client or plugin that stopped only when the app next asks the bridge for its
status. With no app running, for instance after a boot-time connect with the tray gone, the block stays until one does.

On startup, the bridge asks what you want: with **On system startup** set to **Do not connect**, it decides at every
start that Hole is not meant to be connected, and so lifts a block it finds, whether the start follows an update or a
reboot. The setting the bridge uses is the one the app last sent it with a connect.

On macOS, a restart of the machine leaves no block until a connect puts it back. The bridge starting is not enough: the
connect has to get as far as installing the block. A bridge that starts and does not connect, because of **Do not
connect** or because the connect fails first, leaves the machine open.

On macOS, a connection that restarts under the block has to look the server up again, and the block there lets through
only TCP to the server's address. When the server is given by name the lookup can fail, the restart then fails, and the
block stays until you choose **Unblock Network**.

If you are left with a block, choose **Unblock Network** in the tray. When no bridge is running, run
`hole bridge unlock` as administrator (`sudo` on macOS) instead; see the [command reference](../reference/cli.md).

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
