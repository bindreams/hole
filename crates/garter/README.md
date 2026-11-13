# garter

[![Crates.io](https://img.shields.io/crates/v/garter.svg)](https://crates.io/crates/garter)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/bindreams/hole/blob/main/crates/garter/LICENSE)

garter is a Rust library that runs a chain of [SIP003](https://shadowsocks.org/doc/sip003.html) Shadowsocks plugins as
if they were one. Shadowsocks starts a plugin and hands it an address to listen on and an address to forward to; garter
starts several plugins, wires each one's output to the next one's input, waits until the whole chain is ready, and shuts
it down together.

It is part of [Hole](https://github.com/bindreams/hole), a Shadowsocks client, which uses it to run its plugins.

## Who it is for

- **Developers building something that runs SIP003 plugins**, such as a Shadowsocks launcher or a plugin that wraps
  another plugin.
- **People who want two plugins at once**, for example one that wraps the connection in WebSocket and one that obfuscates the result. The
  `garter` command (below) does this from a config file, with no Rust.

## Install

```sh
cargo add garter
cargo add tokio --features macros,rt-multi-thread
```

`garter` is a library. The `garter` command is a separate binary, on the Hole
[releases page](https://github.com/bindreams/hole/releases) for Windows, macOS and Linux (each on amd64 and arm64).

## Use

```rust,no_run
use garter::{BinaryPlugin, ChainRunner, Mode, PluginEnv};

#[tokio::main]
async fn main() -> garter::Result<()> {
    let env = PluginEnv::from_env()?;
    // `server` in SS_PLUGIN_OPTIONS selects Server; otherwise Client.
    let mode = Mode::from_plugin_options(env.plugin_options.as_deref())?;

    let chain = ChainRunner::new()
        .mode(mode)
        .add(Box::new(BinaryPlugin::new("v2ray-plugin", Some("host=example.com;tls"))))
        .add(Box::new(BinaryPlugin::new("obfs-local", Some("obfs=tls"))));

    chain.run(env).await
}
```

Plugins are added data-source side first in both modes. In `Mode::Client` (the default) data flows from the Shadowsocks
client through the chain to the server; in `Mode::Server` it flows the other way, to a local Shadowsocks server. In the example, `v2ray-plugin` takes the Shadowsocks client's traffic and `obfs-local`
is the outermost layer, the one that talks to the server.

A `BinaryPlugin` decides it is ready by connecting to the port it was given, unless `.readiness(ReadinessMode::ExpectSitrep)`
says the plugin speaks sitrep (below), which also lets the chain restart a hop that loses its port.

Without `.cancel_token(...)`, `run` ends the chain on SIGTERM, SIGINT or Ctrl+C. With one, `run` registers no signal
handler and the embedder routes signals into its token.

## Highlights of the crate

- `ChainPlugin`, the trait a link in the chain implements, with `BinaryPlugin` (an external SIP003 plugin executable) and
  `TapPlugin` (wraps another plugin and logs byte counts and time to the first upstream byte per connection; meant for diagnostics, since it adds a loopback hop).
- `ChainRunner`, which composes plugins into one transport.
- `CountingStream` and `StreamCounters`, byte counters for any `AsyncRead + AsyncWrite` stream.
- `parse_plugin_options`, which parses the semicolon-separated `SS_PLUGIN_OPTIONS` string.
- `sitrep`, the types of the readiness protocol below.

The crate also exports `Mode`, `PluginEnv`, `ReadinessMode`, the `LogSink` and `PidSink` hooks, the error types and the
option-string helpers. The [API documentation](https://docs.rs/garter) lists everything and covers start order,
restarts and failures in detail.

## sitrep

A plugin can report its startup to the program that spawned it, meaning readiness, the address it bound, the transports it
serves and any typed start failure, as **sitrep**: a one-way, line-delimited JSON stream on its standard output. It
replaces probing the plugin's port and scraping its logs. garter is the reference implementation, and any SIP003 plugin
or host can adopt the protocol without depending on garter. The specification is
[SITREP.md](https://github.com/bindreams/hole/blob/main/crates/garter/SITREP.md).

## The `garter` command

The `garter` binary runs a chain from a YAML file, so it can be named as the plugin of a Shadowsocks client or server.
Shadowsocks launches it with the usual SIP003 environment, and `SS_PLUGIN_OPTIONS` names the file with `config=`:

```yaml
chain:
  - plugin: ./v2ray-plugin
    options: "tls;host=example.com"
  - plugin: ./obfs-local
    options: "obfs=tls"
```

A relative `plugin` path is read relative to the config file. `garter --version` prints the version and `garter --help`
a short help text.

## Documentation

- [What ships from the Hole repository](https://hole.readthedocs.io/en/latest/reference/distributions.html), including
  the `garter` command.
- [Shadowsocks and its plugins](https://hole.readthedocs.io/en/latest/how-it-works/plugins.html), including how Hole
  runs plugins through garter.

## License

Licensed under [Apache-2.0](https://github.com/bindreams/hole/blob/main/crates/garter/LICENSE).
