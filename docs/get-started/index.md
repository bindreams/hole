# Get started

Hole is an app for Windows and Mac computers. Switch it on and the computer's internet traffic goes through a
{term}`Shadowsocks` server somebody runs for you. This guide takes you from nothing to a working connection, one step at
a time.

Hole is a client, not a VPN service: it comes with no server and there is nothing to sign up for. The first step is
getting a server, and that is the step that takes the longest.

## Two jobs, one order

Setting Hole up involves two jobs. They are often done by two people, for instance when you set Hole up for a relative in
another country. Do the server's job first, because the other job needs what it produces.

| Job                         | Who does it                                   | What it produces or needs                                                | Page                                              |
| --------------------------- | --------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------- |
| 1. Run the server           | You, or someone you know who already runs one | A {term}`config` file for each person who will use the server            | [Get a server](server.md)                         |
| 2. Install Hole and connect | Whoever uses the computer                     | The config file, the installer, and administrator rights for the install | [Install](install.md), then [Connect](connect.md) |

If you are setting Hole up for someone else, you can do the second job over a video call or in person: the config file
and the installer are the only two things that have to reach them.

## What you need

- **A computer running Windows or macOS.** On Windows: Windows 10 version 2004 or later (Windows 11 included), 64-bit
  Intel or AMD. Windows on ARM is not supported. On a Mac: Apple silicon or Intel. There is no phone, tablet or Linux
  version.
- **A config file** from the person who runs the server, or from a server you set up yourself.
- **Administrator rights on the computer, once.** Hole installs a small background service that makes the network
  changes, and installing a service needs permission. [Install](install.md) explains the prompts you will see.

## The steps

1. [Get a server](server.md): where a config comes from, and what running a server takes.
1. [Install Hole](install.md): which download to pick, and what the permission prompts mean.
1. [Connect](connect.md): import the config, switch Hole on, and check that it works.
1. [Settings explained](settings.md): what each control on the dashboard does.
1. [Troubleshooting](troubleshooting.md): what the error messages mean, and what to do when the internet stops working.

```{admonition} What the disguise is, and what it is not
---
class: note
---
Whether Hole's traffic is disguised is decided by the server's config, not by Hole. If the config names a plugin with
TLS turned on, as the configs from {term}`Postern` do, the traffic looks like ordinary HTTPS web traffic. Without a
plugin, Hole speaks plain Shadowsocks. Whether a particular network lets the disguised traffic through is something only
trying it shows: Hole cannot promise it.
```

```{toctree}
---
hidden:
---
Get a server <server.md>
Install <install.md>
Connect <connect.md>
Settings explained <settings.md>
Troubleshooting <troubleshooting.md>
```
