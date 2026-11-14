# Distributions

Nobody who only uses Hole needs this page: the installer is on the [releases page](https://github.com/bindreams/hole/releases/latest),
and [Postern](https://postern.readthedocs.io) sets up the server-side plugins for you. It is for people who build their
own server or tools.

Four products ship from this repository. Each is tagged `releases/<product>/v<X.Y.Z>` and has its own
[GitHub release](https://github.com/bindreams/hole/releases).

- **`hole`**: the desktop app, for everyone who uses Hole. A `.msi` installer for 64-bit Intel or AMD Windows (amd64;
  Windows on ARM is not supported) and a `.dmg` for macOS (amd64 and arm64). It is the product that GitHub's
  [latest release](https://github.com/bindreams/hole/releases/latest) points at, and each release's `SHA256SUMS` is
  signed with minisign (`SHA256SUMS.minisig`).
- **`galoshes`**: a {term}`SIP003 plugin` for people who run a Shadowsocks server. Pair it with a Hole client to carry
  UDP as well as TCP: it multiplexes streams over one connection and embeds {term}`ex-ray`. A standalone binary for
  Windows, macOS and Linux, each on amd64 and arm64. Apache-2.0.
- **`garter`**: the library that runs a chain of SIP003 plugins, published on
  [crates.io](https://crates.io/crates/garter), and its `garter` command-line binaries for plugin developers, on the
  same six platforms. Apache-2.0.
- **`ex-ray`**: Hole's own {term}`SIP003 plugin`, wire-compatible with `shadowsocks/v2ray-plugin`. Use it to pair a Hole
  client with a server that runs a stock v2ray-plugin, or the other way around. A standalone binary on the same six
  platforms. Apache-2.0.

Build and release steps for contributors are in [the maintainers' release page](../contributing/maintainers/releases.md).
