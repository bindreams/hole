# tun-engine

tun-engine is a Rust library for building a split-tunnel VPN or proxy daemon on Windows and macOS. It opens a TUN
device, installs the operating system's routes, and runs a [smoltcp](https://github.com/smoltcp-rs/smoltcp) TCP/IP
stack over the packets it reads. Each TCP connection or UDP flow that arrives is handed to a `Router` you write, which
decides what to do with it. The crate knows nothing about the protocol you tunnel into.

It is part of [Hole](https://github.com/bindreams/hole), a Shadowsocks client, whose bridge is its one consumer.

## Who it is for

Developers writing a tun2socks-style forwarder: something that captures a machine's traffic and relays it to a proxy,
or filters it, or drops it. tun-engine does the operating-system work and the packet loop; the policy is yours.

It is not published to crates.io and its API is not stable. Depend on it by path or by git from a checkout of this
repository, and expect it to change until a second consumer has shaped it.

## Use

```toml
[dependencies]
tun-engine = { git = "https://github.com/bindreams/hole" }
async-trait = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
tokio-util = "0.7"
```

A `Router` has two methods, one per flow. This one drops everything; a real one would splice the flow to an upstream,
for which `tun_engine::helpers` has SOCKS5 and interface-bound sockets.

```rust
use std::sync::Arc;
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use tun_engine::{Device, Engine, Router, TcpFlow, TcpMeta, UdpFlow, UdpMeta};

struct MyRouter;

#[async_trait]
impl Router for MyRouter {
    async fn route_tcp(&self, _meta: TcpMeta, flow: TcpFlow) -> std::io::Result<()> {
        // `flow.peek` reads the first bytes without consuming them, for routing on SNI or a Host header.
        drop(flow); // dropping the flow resets the connection
        Ok(())
    }

    async fn route_udp(&self, _meta: UdpMeta, mut flow: UdpFlow) -> std::io::Result<()> {
        while let Some(_datagram) = flow.recv().await {
            // `flow.send` replies to the sender.
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

    let engine = Engine::build(device, Arc::new(MyRouter), |_| {})?;
    engine.run(CancellationToken::new()).await;
    Ok(())
}
```

Opening the device and changing routes needs an elevated process (administrator on Windows, root on macOS).

## What is in the crate

- `device`: opens the TUN device. On Windows it loads `wintun.dll` and names the adapter as you ask; on macOS you can
  leave the name to the kernel (`TunName::KernelAssigned`).
- `engine`: the packet loop, `Engine`, and the `Router` trait it dispatches to.
- `routing`: a `Routing` trait and `SystemRouting`, which installs and removes the split routes with `netsh` on Windows
  and `route` on macOS. It records what it installed in a state file so a crashed run can be cleaned up, and it can
  install a fail-closed cover that blocks the machine's egress except to loopback, the proxy server and, when a plugin
  needs one, the DoH resolver it fetches ECH configs from.
- `gateway`: finds the default gateway and its interface.
- `helpers`: SOCKS5 CONNECT and UDP ASSOCIATE clients, and sockets bound to a chosen interface to bypass the tunnel.
- `dns_steer` (macOS) publishes a resolver that sends the operating system's DNS to the tunnel; `dns_confine` (Windows)
  blocks DNS on every path but the tunnel, loopback and the proxy server.
- `sim` (behind the `test-utils` feature): in-memory doubles, so a `Router` can be tested without an operating-system
  device.

The API is documented in the source: run `cargo doc -p tun-engine --open` in a checkout. How Hole uses the crate is in
[The TUN device and the routes](https://hole.readthedocs.io/en/latest/how-it-works/tun.html).

## License

[GPL-3.0-or-later](https://github.com/bindreams/hole/blob/main/LICENSE.md).
