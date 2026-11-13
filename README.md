# Hole

Hole is a free [Shadowsocks](https://shadowsocks.org/) client for Windows and macOS computers; there is no phone or
Linux version. Switch it on and, by default, your computer's internet traffic goes through a Shadowsocks server,
including the apps that ignore proxy settings. When the server is set up to disguise its traffic, as
[Postern](https://github.com/bindreams/postern) does, the traffic looks like ordinary HTTPS web traffic, for networks
that filter VPNs.

## Hole is a client, not a VPN service

Hole does not come with a server, and there is nothing to sign up for. To use it you need a Shadowsocks server, and
there are two ways to get one:

- **Someone gives you a config.** Whoever runs the server sends you a config file, and Hole imports it.
- **You run a server yourself.** [Postern](https://github.com/bindreams/postern) is Hole's companion project for that:
  a self-hosted portal that sets up Shadowsocks servers, including the plugins that disguise their traffic, so you do
  not pick or install those by hand. It hands each person you invite a ready-made client config. Its
  [documentation](https://postern.readthedocs.io) walks through the setup.

## Download

Get the installer for your system from the [latest release](https://github.com/bindreams/hole/releases/latest):

- **Windows:** the `.msi` installer, for 64-bit Intel or AMD PCs (`amd64`). Windows on ARM is not supported.
- **macOS:** the `.dmg` for your Mac, `arm64` for Apple silicon or `amd64` for Intel. To tell which you have, open the
  Apple menu, choose **About This Mac**, and look at the **Chip** line: "Apple" followed by a name such as M1 means Apple
  silicon.

Apple doesn't recognise Hole's developer yet, so macOS blocks the first launch with a warning that Apple could not
verify Hole is free of malware. To open it anyway:

- **macOS 15 or later:** click **Done**, open **System Settings** → **Privacy & Security**, scroll down and click
  **Open Anyway** next to Hole.
- **Earlier macOS:** Control-click Hole and choose **Open**.

## Learn more

- The [documentation](https://hole.readthedocs.io/en/latest/) has a [glossary](https://hole.readthedocs.io/en/latest/reference/glossary.html) of Hole's terms (TUN, SIP003 plugins, ECH, the
  kill switch), the [command line](https://hole.readthedocs.io/en/latest/reference/cli.html), and lists [what else ships from this
  repository](https://hole.readthedocs.io/en/latest/reference/distributions.html), such as plugins for running your own server.
- To build Hole, run its tests or learn how it is put together, start at [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright (C) 2026, Anna Zhukova

Hole is licensed under the [GNU GPL version 3 or later](LICENSE.md), unless a component's own `LICENSE` file says
otherwise: several libraries and plugins are Apache-2.0. [Licensing](https://hole.readthedocs.io/en/latest/reference/licensing.html) lists them.
