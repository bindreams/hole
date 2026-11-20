# Getting started

Hole is an app for Windows and Mac computers. Switch it on and the computer's internet traffic goes through a
{term}`Shadowsocks` server somebody runs for you.

Hole is a client, not a VPN service: it comes with no server and there is nothing to sign up for. The first step is
getting a server, and that is the step that takes the longest.

```{mermaid}
flowchart LR
    subgraph computer["Your computer"]
        apps["Your apps"] --> hole["Hole"]
    end
    hole == "encrypted tunnel" ==> network["The network you are on<br/>Wi-Fi, internet provider, any filtering"]
    network == "encrypted tunnel" ==> server["The server<br/>run by you or someone you know"]
    server --> web["Websites and services"]
```

The network you are on sees one encrypted connection to the server. It does not see which sites you open, and a site
sees the server's address in place of yours. A network that filters traffic can still block the server itself;
[the knowledge base](../knowledge-base/hostile-networks.md) covers what to do then.

## Who does what

Setting Hole up involves two jobs. They are often done by two people, for instance when you set Hole up for a relative in
another country. Do the server's job first, because the other job needs what it produces.

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
1. [Settings reference](settings.md): what each control on the dashboard does.
1. [Troubleshooting](troubleshooting.md): what the error messages mean, and what to do when the internet stops working.

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
