# tun-engine

Cross-platform TUN device, OS routing, gateway discovery, and a
smoltcp-backed packet-loop engine for building split-tunnel VPN / proxy
daemons in Rust.

`tun-engine` is protocol-agnostic. It handles the mechanics common to any
tun2socks-style forwarder — opening a TUN device, running a smoltcp TCP/IP
stack over the packets it reads, and dispatching each inbound TCP
connection or UDP flow to a caller-supplied `Router`. Policy (what to do
with each connection) stays in the consumer.

## Status

**Pre-release.** Currently consumed path-locally by the `hole-bridge`
crate in this repository. Published documentation, crates.io release, and
API stabilization will happen once the public surface has proven itself
across a second consumer.

## Architecture

Three independently-usable modules:

- **`routing`** — an OS-level `Routing` trait plus a production
  `SystemRouting` impl that shells out to `netsh` (Windows) or
  `route(8)` (macOS), with a JSON state file for crash recovery.
- **`device`** — cross-platform TUN open (`Device::build`). Windows
  additionally provides `device::wintun` for `wintun.dll` pre-loading so
  missing-DLL failures report a descriptive path list.
- **`engine`** — the packet-loop `Engine`. Construction is closure-based
  (no chained builders); per-connection dispatch goes through the
  caller-supplied `Router` trait.

Plus:

- **`helpers`** — ready-made splice primitives (SOCKS5 CONNECT, SOCKS5
  UDP ASSOCIATE, interface-bound bypass sockets) that a typical `Router`
  impl uses inline.
- **`gateway`** — detect the system's default gateway + interface.
- **`net`** — small OS-level socket-binding utilities.

## Quickstart

```rust
use std::sync::Arc;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use tun_engine::{Device, Engine, Router, TcpFlow, TcpMeta, UdpFlow, UdpMeta};

struct MyRouter;

#[async_trait]
impl Router for MyRouter {
    async fn route_tcp(&self, meta: TcpMeta, mut flow: TcpFlow) -> std::io::Result<()> {
        // Optionally peek at the first bytes (e.g. for SNI-based routing).
        let peeked = flow.peek(2048, std::time::Duration::from_millis(100)).await?;
        // ... decide + splice: tun_engine::helpers::socks5_connect(...), etc.
        drop(peeked);
        drop(flow);
        Ok(())
    }

    async fn route_udp(&self, _meta: UdpMeta, mut flow: UdpFlow) -> std::io::Result<()> {
        while let Some(_pkt) = flow.recv().await {
            // ... dispatch, optionally reply via flow.send(...)
        }
        Ok(())
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let device = Device::build(|c| {
        c.tun_name = "my-tun".into();
        c.mtu = 1400;
        c.ipv4 = Some("10.255.0.1/24".parse().unwrap());
    })?;

    let engine = Engine::build(device, Arc::new(MyRouter), |c| {
        c.max_connections = 4096;
    })?;

    let cancel = CancellationToken::new();
    engine.run(cancel).await;
    Ok(())
}
```

## Test-isolation contract

Production I/O that mutates the host's routing tables MUST go through the
`Routing` trait. The free functions `setup_routes` / `teardown_routes` are
lint-disallowed outside the crate's own internals (see workspace
`clippy.toml`). Consumers that author their own `Routing` impls can ignore
the lint; consumers that only use `SystemRouting` get the guard-rail for
free. Motivation: see [bindreams/hole#165][issue-165].

## License

GPL-3.0-or-later. See [LICENSE.md](../../LICENSE.md).

[issue-165]: https://github.com/bindreams/hole/issues/165
