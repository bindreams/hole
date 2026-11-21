# Getting started

Hole is an app for Windows and Mac computers. Switch it on and it sends the computer's internet traffic through an
encrypted tunnel to a {term}`Shadowsocks` server that somebody runs for you, and the server passes it on to the internet.

The network you are on may be hostile: it may watch what you do, or block sites. It sees the tunnel but not what is
inside it: which sites you open, or what you send them. A site sees the server's address in place of yours.

```{raw} html
<div class="diagram-scroll">
```

```{raw} html
---
file: overview.svg
---
```

```{raw} html
</div>
```

## Who does what

Hole is a client, not a VPN service: it comes with no server and there is nothing to sign up for. Setting it up is
therefore two jobs, often done by two people, for instance when you set Hole up for a relative in another country. Do the
server's job first: it takes the longest, and the other job needs what it produces.

| Job                         | Who does it                                   | What it produces or needs                                                |
| --------------------------- | --------------------------------------------- | ------------------------------------------------------------------------ |
| 1. Run the server           | You, or someone you know who already runs one | A {term}`config` file for each person who will use the server            |
| 2. Install Hole and connect | Whoever uses the computer                     | The config file, the installer, and administrator rights for the install |

If you are setting Hole up for someone else, you can do the second job over a video call or in person.

## Requirements

- **A computer running Windows or macOS.** On Windows: Windows 10 version 2004 or later (Windows 11 included), 64-bit
  Intel or AMD. Windows on ARM is not supported. On a Mac: Apple silicon or Intel. There is no phone, tablet or Linux
  version.
- **A config file** from the person who runs the server, or from a server you set up yourself.
- **Administrator rights on the computer, once.** Hole installs a small background service that makes the network
  changes, and installing a service needs permission. [Installing Hole](install.md) explains the prompts you will see.

## Steps

1. [Getting a server](server.md): where a config comes from, and what running a server takes.
1. [Installing Hole](install.md): which download to pick, and what the permission prompts mean.
1. [Connecting](connect.md): import the config, switch Hole on, and check that it works.

Two more pages are for later: the [Settings reference](settings.md) says what each control on the dashboard does, and
[Troubleshooting](troubleshooting.md) what the error messages mean and what to do when the internet stops working.

```{toctree}
---
hidden:
---
Getting a server <server.md>
Installing Hole <install.md>
Connecting <connect.md>
Settings reference <settings.md>
Troubleshooting <troubleshooting.md>
```
