# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin
support (the v2ray-plugin wire protocol, served by the bundled first-party
`ex-ray` binary) for macOS and Windows.

## Features

- **Transparent proxy** via TUN interface — zero config for all apps, including
  those that ignore system proxy settings
- **SOCKS5 proxy** on port 4073 for advanced users
- **DNS leak prevention** — all DNS traffic routed through the tunnel
- **System tray** — Enable/Disable, Start at Login, Settings, Exit
- **Server import** — from shadowsocks client config files (single and multi-server)
- **v2ray-plugin** support — served by the bundled first-party `ex-ray` binary
- **Logging** to stderr + a size-rotated file (10 MiB, one backup kept)

## Architecture

`hole` is a single binary that serves as both the Tauri GUI and a privileged
bridge, depending on CLI arguments:

| Mode              | Privilege     | Role                                                        |
| ----------------- | ------------- | ----------------------------------------------------------- |
| `hole` (no args)  | User          | Tauri GUI — system tray, settings window, config management |
| `hole bridge run` | Root / SYSTEM | Privileged helper — TUN, routing, shadowsocks-service       |

The two communicate over IPC (Unix socket on macOS, named pipe on Windows) using
HTTP/1.1 REST (JSON).

## Install

Download the installer for your platform from the
[latest release](https://github.com/bindreams/hole/releases/latest).

**macOS first launch:** Hole is ad-hoc-signed but not yet notarized by Apple. On
first launch after installing from the DMG, macOS says "Hole cannot be opened
because the developer cannot be verified." Right-click the app → **Open** →
**Open** in the dialog. This is a one-time step per machine and goes away once the
app is notarized.

## Commands

The GUI is the primary interface; these CLI commands are also available:

| Command                              | Description                                      |
| ------------------------------------ | ------------------------------------------------ |
| `hole [--show-dashboard]`            | Launch the GUI (default)                         |
| `hole version`                       | Print version information                        |
| `hole upgrade`                       | Check for updates and install the latest version |
| `hole path add` / `hole path remove` | Add / remove `hole` from the system PATH         |

## Distributions

Four products ship from this repository, each tagged
`releases/<product>/v<X.Y.Z>` with its own GitHub release. Build and release
details are in [CONTRIBUTING.md](CONTRIBUTING.md#releases).

- **`hole`** — the Tauri GUI for end users. MSI + DMG installers (amd64 + arm64),
  signed via minisign for auto-update integrity.
- **`galoshes`** — standalone SIP003u plugin binaries for shadowsocks server
  operators who want to pair non-Hole servers with Hole clients (YAMUX-multiplexed
  TCP+UDP, embedded ex-ray). 6 platforms. Apache-2.0.
- **`garter`** — the plugin-chain runner library on
  [crates.io](https://crates.io/crates/garter), plus `garter` CLI binaries for
  plugin developers. Apache-2.0.
- **`ex-ray`** — the first-party SIP003u plugin (wire-compatible with
  shadowsocks/v2ray-plugin) for pairing with a non-Hole shadowsocks deployment.
  6 platforms. Apache-2.0.

## Contributing

Building from source, the development workflow, the architecture, and the test
suite are documented in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

TBD
