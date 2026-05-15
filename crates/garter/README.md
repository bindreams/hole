# garter

[![Crates.io](https://img.shields.io/crates/v/garter.svg)](https://crates.io/crates/garter)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Plugin-chain runner for [SIP003](https://shadowsocks.org/doc/sip003.html) /
SIP003u shadowsocks plugins.

`garter` lets you compose multiple SIP003 plugins into a chain and run them
as one. It handles the SIP003 environment variables (`SS_REMOTE_HOST`,
`SS_REMOTE_PORT`, `SS_LOCAL_HOST`, `SS_LOCAL_PORT`, `SS_PLUGIN_OPTIONS`),
per-link port allocation, lifecycle (graceful shutdown propagation), and
byte-level diagnostics.

## What's in the box

- **`ChainPlugin`** — the core trait. Anything implementing it can be a
  link in the chain. The crate ships `BinaryPlugin` (wraps an external
  SIP003 plugin executable) and `TapPlugin` (instruments byte counts +
  TTFB on the wire).
- **`ChainRunner`** — composes a sequence of `ChainPlugin`s into a single
  end-to-end transport.
- **`CountingStream` / `StreamCounters`** — wire-level instrumentation
  for any `tokio::io::AsyncRead + AsyncWrite` stream.
- **`parse_plugin_options`** — parses the SIP003 `;`-separated options
  string into a typed `HashMap`.

## Example

```rust,no_run
use garter::{BinaryPlugin, ChainRunner, PluginEnv};

#[tokio::main]
async fn main() -> garter::Result<()> {
    let env = PluginEnv {
        remote_host: "203.0.113.1".into(),
        remote_port: 8388,
        local_host: "127.0.0.1".into(),
        local_port: 0, // shadowsocks picks
        options: String::new(),
    };

    let chain = ChainRunner::new()
        .push(BinaryPlugin::new("v2ray-plugin", "host=example.com;tls"))
        .push(BinaryPlugin::new("obfs-local", "obfs=tls"));

    chain.run(env).await
}
```

See [the SIP003 spec][sip003] for the broader context on shadowsocks
plugins, and the [`hole`](https://github.com/bindreams/hole) repository
for a worked example (the `galoshes` plugin embeds `garter` to compose a
YAMUX-multiplexed v2ray-plugin transport).

## License

Licensed under [Apache-2.0](LICENSE).

[sip003]: https://shadowsocks.org/doc/sip003.html
