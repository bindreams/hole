# Galoshes

A Shadowsocks SIP003u plugin that chains [YAMUX](https://github.com/libp2p/rust-yamux) multiplexing with [v2ray-plugin](https://github.com/shadowsocks/v2ray-plugin) for obfuscated UDP-over-TCP traffic.

Built on **Garter**, a general-purpose library and binary for chaining arbitrary SIP003u plugins.

## Crates

| Crate        | Type           | Description                                                                                        |
| ------------ | -------------- | -------------------------------------------------------------------------------------------------- |
| `garter`     | lib            | Core plugin chaining library: `ChainPlugin` trait, `BinaryPlugin`, `ChainRunner`                   |
| `garter-bin` | bin (`garter`) | Config-driven chainer binary — chains arbitrary SIP003u plugins via YAML                           |
| `galoshes`   | bin            | Turnkey plugin bundling YAMUX + v2ray-plugin. Same config as v2ray-plugin, UDP works transparently |
| `xtask`      | bin            | Build tooling (`cargo xtask v2ray-plugin`)                                                         |

## Using Galoshes

Galoshes is a drop-in replacement for v2ray-plugin that transparently adds UDP support via YAMUX multiplexing. Configure it exactly like v2ray-plugin:

```bash
# Client
ss-local --plugin galoshes --plugin-opts "tls;host=example.com;mode=websocket"

# Server
ss-server --plugin galoshes --plugin-opts "server;tls;host=example.com;mode=websocket"
```

## Using Garter (the chainer binary)

Garter chains arbitrary SIP003u plugin binaries via a YAML config:

```yaml
# chain.yaml
chain:
  - plugin: /usr/bin/shadowsocks-yamux-plugin
    options: "mux=8"
  - plugin: /usr/bin/v2ray-plugin
    options: "tls;host=example.com;mode=websocket"
```

```bash
ss-local --plugin garter --plugin-opts "config=/path/to/chain.yaml"
```

Relative paths in the YAML resolve from the config file's parent directory.

## Using Garter as a library

```rust
use garter::{BinaryPlugin, ChainRunner, PluginEnv};

let env = PluginEnv::from_env()?;

let runner = ChainRunner::new()
    .add(Box::new(my_custom_plugin))
    .add(Box::new(BinaryPlugin::new("/usr/bin/v2ray-plugin", Some("tls"))));

runner.run(env).await?;
```

Implement `garter::ChainPlugin` for in-process plugins. Each plugin receives `(local_addr, remote_addr, shutdown_token)` and manages its own networking.

## Building

```bash
# Build garter (library + chainer binary)
cargo build -p garter -p garter-bin

# Build galoshes (requires Go toolchain for v2ray-plugin)
cargo xtask v2ray-plugin
cargo build -p galoshes
```

## License

Copyright 2026, Anna Zhukova

This project is licensed under the Apache 2.0 license. The license text can be found at [LICENSE.md](/LICENSE.md).
