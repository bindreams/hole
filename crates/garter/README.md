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
- **`Mode`** — selects chain direction (`Client` / `Server`); see below.

### Modes

`ChainRunner` supports two SIP003 chain directions selected via
`.mode(...)`:

- `Mode::Client` (default) — data flows from the SS client's listener
  (`SS_LOCAL_*`) through the chain to the SS server's public endpoint
  (`SS_REMOTE_*`).
- `Mode::Server` — data flows from the public-facing endpoint
  (`SS_REMOTE_*`) through the chain back to a local `ssserver`
  (`SS_LOCAL_*`). The plugin add-order stays the same in both modes
  (data-source-side first); in Server mode garter inverts the address
  wiring — including which plugin position faces the public endpoint.
  Per-plugin readiness is declared by each link (see the sitrep
  protocol below) and aggregated by the runner.

Use `Mode::from_plugin_options(env.plugin_options.as_deref())` to derive
the mode automatically from the SIP003 `server` keyword in
`SS_PLUGIN_OPTIONS`.

## sitrep protocol

A SIP003 plugin reports its startup to the host that spawned it —
readiness, the actual bound listen address, the transports it serves,
and any typed start failure — over **sitrep**, a one-way,
line-delimited JSON control stream on the plugin's stdout. It replaces
connect-probing the plugin's port and scraping its logs.

`garter` is the reference implementation of sitrep, but the protocol is
independently adoptable: any SIP003 / SIP003u plugin or host may
implement it without depending on `garter`.

See [SITREP.md](SITREP.md) for the full normative specification.

## Example

```rust,no_run
use garter::{BinaryPlugin, ChainRunner, Mode, PluginEnv};

#[tokio::main]
async fn main() -> garter::Result<()> {
    let env = PluginEnv::from_env()?;
    // Detect SIP003 chain mode from SS_PLUGIN_OPTIONS (`server` keyword
    // = Server; default = Client). Same parse used by v2ray-plugin and
    // other SIP003 plugins.
    let mode = Mode::from_plugin_options(env.plugin_options.as_deref());

    let chain = ChainRunner::new()
        .mode(mode)
        .add(Box::new(BinaryPlugin::new("v2ray-plugin", Some("host=example.com;tls"))))
        .add(Box::new(BinaryPlugin::new("obfs-local", Some("obfs=tls"))));

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
