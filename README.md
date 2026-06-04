# Hole

Shadowsocks GUI with transparent proxy (TUN), system tray, and v2ray-plugin support (via the bundled first-party `ex-ray` binary) for macOS and Windows.

## Features

- **Transparent proxy** via TUN interface — zero config for all apps, including those that ignore system proxy settings
- **SOCKS5 proxy** on port 4073 for advanced users
- **DNS leak prevention** — all DNS traffic routed through the tunnel
- **System tray** — Enable/Disable, Start at Login, Settings, Exit
- **Server import** — import from shadowsocks client config files (single and multi-server)
- **v2ray-plugin** support — the v2ray-plugin wire protocol, served by the bundled first-party `ex-ray` binary (built from Go source)
- **Logging** to stderr + a size-rotated file (10 MiB, one backup kept)

## Architecture

Single-binary design — `hole` serves as both the Tauri GUI and the privileged bridge depending on CLI arguments:

| Mode              | Privilege     | Role                                                        |
| ----------------- | ------------- | ----------------------------------------------------------- |
| `hole` (no args)  | User          | Tauri GUI — system tray, settings window, config management |
| `hole bridge run` | Root / SYSTEM | Privileged helper — TUN, routing, shadowsocks-service       |

Communication happens over IPC (Unix socket on macOS, named pipe on Windows) using HTTP/1.1 REST (JSON).

## Install

**macOS first launch:** Hole is ad-hoc-signed but not yet notarized by Apple.
On first launch after installing from the DMG, macOS will say "Hole cannot be
opened because the developer cannot be verified." Right-click the app →
**Open** → **Open** in the confirmation dialog. This is a one-time step per
machine; subsequent launches work normally. This step goes away once the app
is notarized.

## Build

Prerequisites: Rust toolchain, Go toolchain, Node.js (for Tauri CLI and E2E tests).

```sh
# One-time fetch of runtime deps (builds ex-ray from Go source,
# downloads + verifies wintun.dll on Windows). Cached after the first run.
cargo xtask deps

# Build all crates (Tauri dev mode — for production use `cargo xtask build hole-msi`
# or `cargo xtask build hole-dmg`; see CLAUDE.md → Tauri dev/prod feature toggle).
cargo build --workspace --no-default-features

# Run GUI in dev mode
npx tauri dev

# Run all tests
cargo test --workspace --no-default-features
```

## Project layout

```
crates/
  common/    hole-common — shared types (protocol, config, import)
  bridge/    hole-bridge — privileged bridge library
  hole/      hole        — Tauri app + CLI + bridge entry point (binary name: "hole")
  garter/    garter      — SIP003u plugin-chain runner library (Apache-2.0, on crates.io)
  garter-bin/ garter-bin — `garter` CLI binary for plugin developers (Apache-2.0)
  galoshes/  galoshes    — bundled+standalone SIP003u plugin (yamux + embedded ex-ray) (Apache-2.0)
  ex-ray/    ex-ray      — first-party Go SIP003u plugin on v2ray-core, wire-compatible with v2ray-plugin (Apache-2.0)
  mock-plugin/ mock-plugin — minimal SIP003u echo plugin for garter tests (Apache-2.0)
xtask/      workspace task runner (`cargo xtask <stage|deps|version|...>`)
xtask-lib/  shared helper crate used by xtask AND crates/hole/build.rs
msi-installer/  WiX MSI installer (Python project: thin wrapper around xtask + WiX)
ui/             Frontend HTML/CSS/JS
scripts/        Utility scripts
tests/       E2E test specs (WebDriverIO)
```

## Distributions

Four independent release tracks, each tagged as
`releases/<product>/v<X.Y.Z>` with its own GitHub release. Detail in
[CLAUDE.md](CLAUDE.md#releases):

- **`hole`** — Tauri GUI for end users. MSI + DMG installers signed via
  minisign for auto-update integrity.
- **`galoshes`** — standalone SIP003u plugin binaries for shadowsocks
  server operators who want to pair non-Hole servers with Hole clients.
  6 platforms (windows amd64/arm64, darwin amd64/arm64, linux
  amd64/arm64). Apache-2.0.
- **`garter`** — plugin-chain runner library on
  [crates.io/crates/garter](https://crates.io/crates/garter), plus
  `garter` CLI binaries via GitHub release for plugin developers.
  Apache-2.0.
- **`ex-ray`** — first-party SIP003u plugin built on v2ray-core,
  wire-compatible with shadowsocks/v2ray-plugin. 6-platform binaries for
  users who want to pair it with a non-Hole shadowsocks deployment.
  Apache-2.0.

## Testing

Unit tests use the [skuld](https://github.com/bindreams/skuld) framework. Test files are siblings to their source files (`foo.rs` → `foo_tests.rs`).

```sh
cargo test --workspace --no-default-features   # all unit tests
npm run test:e2e                                # E2E tests (requires release build)
```

## Emergency network reset

If routing gets into a bad state during development:

```sh
# macOS
sudo python scripts/network-reset.py

# Windows (run as Administrator)
python scripts/network-reset.py
```

## License

TBD
