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
- the connection from Hole to your {term}`Shadowsocks` server, which has to leave outside the tunnel (on Windows any
  protocol, on macOS TCP only);
- on Windows, anything started by Hole's own programs, the bridge and the plugin, which are identified by their file.
  That includes the connections the bridge opens for a **Bypass** rule, so on Windows Bypass traffic still leaves. macOS
  cannot tell programs apart, so there a Bypass rule's traffic is blocked like the rest.

Everything else is blocked, and that includes devices on your local network, such as a printer or a file server. The rule
stops connections leaving the machine and sets no rule against incoming ones.

## When it is in force

Ticking **Lockdown** records a preference, which the bridge keeps across disconnects and restarts. The block is not
installed until Hole next connects. During a connect, it goes up once the TUN device and the routes exist, before DNS is
pointed at the tunnel, so from the moment traffic starts to flow it is already held. If you tick Lockdown while
connected, nothing is blocked yet: the block arrives at the next connect.

After that, what happens to the block depends on whether you or Hole decided to disconnect.

| What happens                                                         | The block                                                                                                                            |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| The network drops and comes back while Hole's processes keep running | Stays in force                                                                                                                       |
| Hole restarts the session to apply a changed setting                 | Stays in force across the restart                                                                                                    |
| The bridge is restarted by an update                                 | Stays in force, and the new bridge takes it over                                                                                     |
| You click **Disconnect**, or choose **Exit**                         | Lifted. Lockdown stays ticked, so the next connect puts it back                                                                      |
| The machine shuts down or restarts while Hole is connected           | Stays in force, and is still there after the next boot                                                                               |
| The proxy or the plugin process dies on its own                      | Lifted when the app next asks for the status, because Hole gives up and disconnects then                                             |
| You choose **Unblock Network** in the tray                           | Lifted, Lockdown is switched off, and Hole will not reconnect by itself at the next start. A connection that is running is not ended |
| You untick **Lockdown**                                              | Lifted at once, while still connected                                                                                                |
| You run `hole bridge unlock`                                         | Lifted, with the same effects as Unblock Network. It refuses while a bridge is running, and then **Unblock Network** is the way      |

The block follows one model: it holds while Hole is *meant* to be connected, and lifts when it is not. A disconnect you
asked for, and a connection Hole has given up on, both mean it is not, so the block does not trap a machine whose
tunnel Hole has abandoned. Hole notices a proxy or plugin that died only when the app next asks the bridge for its
status. With no app running, for instance after a boot-time connect with the tray gone, the block stays until one does.

If you are left with a block and no way to lift it from the app, the recovery steps are in the Get started guide, under
troubleshooting.

```{note}
The block is installed late in a connect, after the routes, so a connect that fails before then has installed none. The
block holds traffic only once Hole has connected with Lockdown on.
```

## What the block does not do

It is only as complete as the list above. A connection that the list permits is not inspected: the server connection
leaves outside the tunnel by design, and on Windows the programs of Hole itself are trusted to behave. It also protects
only the computer it runs on, and only outgoing traffic.

The contributor reference covers the rest in detail: the platform differences, how the block and the tunnel are
reconciled toward the state you last asked for, and the cases in which a block outlives a connection.
See {src}`Lockdown mode <CONTRIBUTING.md#lockdown-mode>`.

```{dropdown} Where in the code
The permitted set: `Routing::install_lockdown` in {src}`crates/tun-engine/src/routing.rs` and the platform code under
{src}`crates/tun-engine/src/routing/failclosed/`. The decisions in the table: `cover_step` and
`teardown_cover_disposition` in {src}`crates/bridge/src/reconciler.rs`; the events that produce them are
`SessionEvent` in {src}`crates/bridge/src/target.rs`.
```
