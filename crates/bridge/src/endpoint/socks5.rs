//! `Socks5Endpoint` — carries flows through a SOCKS5 server.
//!
//! L4 mechanism (speaks SOCKS5 over L3 TCP) satisfying the L3 [`Endpoint`]
//! contract. The SOCKS5 server's address is a full [`SocketAddr`]; today
//! hole always points it at `127.0.0.1:<ss_local_port>` but the type is
//! not loopback-constrained.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::copy_bidirectional;
use tun_engine::helpers::{socks5_connect, Socks5UdpRelay};
use tun_engine::{TcpFlow, UdpFlow, UdpSender};

use super::Endpoint;

pub struct Socks5Endpoint {
    addr: SocketAddr,
    /// Plugin name threaded through from [`crate::proxy::config`], used
    /// as a diagnostic in warn logs when the router drops UDP for a
    /// TCP-only plugin. Read via [`Socks5Endpoint::plugin_name`]. `None`
    /// when no plugin is configured.
    plugin_name: Option<String>,
    /// Whether the SS↔server chain can carry UDP. Not a property of
    /// SOCKS5 itself (SOCKS5 always supports UDP via ASSOCIATE) — this
    /// reflects the plugin's capability, plumbed from
    /// [`crate::proxy::config::plugin_supports_udp`].
    udp_supported: bool,
    /// Static label for [`Endpoint::name`].
    label: String,
}

impl Socks5Endpoint {
    pub fn new(addr: SocketAddr, plugin_name: Option<String>, udp_supported: bool) -> Self {
        let label = match &plugin_name {
            Some(name) => format!("socks5({name})"),
            None => "socks5".to_string(),
        };
        Self {
            addr,
            plugin_name,
            udp_supported,
            label,
        }
    }

    /// SOCKS5 server address. Exposed for diagnostics.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Plugin name (if configured). Used by `HoleRouter` to emit the
    /// `plugin = %name` structured log field when dropping UDP.
    pub fn plugin_name(&self) -> Option<&str> {
        self.plugin_name.as_deref()
    }
}

#[async_trait]
impl Endpoint for Socks5Endpoint {
    async fn serve_tcp(&self, flow: &mut TcpFlow, dst: SocketAddr) -> io::Result<()> {
        let mut upstream = socks5_connect(self.addr, dst).await?;
        // Peeked bytes are still buffered inside `flow` — copy_bidirectional
        // will include them naturally.
        copy_bidirectional(flow, &mut upstream).await?;
        Ok(())
    }

    async fn serve_udp(&self, mut flow: UdpFlow, dst: SocketAddr) -> io::Result<()> {
        // Defense-in-depth for the privacy invariant. The cascade
        // (`HoleRouter::resolve_endpoint`) is supposed to keep UDP off
        // this endpoint when `!self.udp_supported`, but we refuse to
        // rely on comments alone for a leak-critical invariant in
        // release builds. Log and drop on violation.
        if !self.udp_supported {
            debug_assert!(false, "Socks5Endpoint::serve_udp called despite udp_supported=false");
            tracing::error!(
                plugin = self.plugin_name.as_deref().unwrap_or("<none>"),
                "privacy invariant violated: serve_udp called on TCP-only SOCKS5 endpoint; dropping"
            );
            return Ok(());
        }

        let relay = Arc::new(Socks5UdpRelay::associate(self.addr).await?);

        // Reader task: pull replies from the relay and inject back into the flow.
        let relay_rx = Arc::clone(&relay);
        let sender: UdpSender = flow.sender();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, _src)) = relay_rx.recv_from(&mut buf).await {
                if sender.send(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });

        // Forwarder: pull inbound datagrams from the flow, send via relay.
        while let Some(payload) = flow.recv().await {
            if relay.send_to(dst, &payload).await.is_err() {
                break;
            }
        }
        Ok(())
    }

    fn supports_udp(&self) -> bool {
        self.udp_supported
    }

    fn supports_ipv6_dst(&self) -> bool {
        // SOCKS5 supports IPv6 destinations natively via ATYP=IPv6. The
        // upstream SS server is responsible for reaching the address;
        // from hole's perspective any v6 dst is always deliverable.
        true
    }

    fn name(&self) -> &str {
        &self.label
    }
}
