//! `LocalDnsEndpoint` — the router's sink for in-tunnel UDP/53 flows.
//!
//! When the HoleRouter cascade matches `proto == Udp && dst.port() == 53`
//! and a `local_dns` endpoint is present, it dispatches to this endpoint
//! instead of the [`Socks5Endpoint`](super::Socks5Endpoint). This catches
//! apps that hard-code DNS destinations (Chrome DoH to 8.8.8.8,
//! systemd-resolved stub) so they never hit the UDP-drop privacy invariant.
//!
//! The endpoint owns an `Arc<DnsForwarder>` and runs each incoming UDP
//! datagram through `forward()` directly, with no OS-loopback hop: the reply
//! is written back into the same flow.
//!
//! TCP is not served: TCP/53 to an external IP takes the normal proxy
//! cascade, since port 53 TCP is not necessarily DNS (zone transfers, any
//! service on that port).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tun_engine::{TcpFlow, UdpFlow, UdpSender};

use crate::dns::forwarder::DnsForwarder;
use crate::endpoint::Endpoint;

pub struct LocalDnsEndpoint {
    forwarder: Arc<DnsForwarder>,
}

impl LocalDnsEndpoint {
    pub fn new(forwarder: Arc<DnsForwarder>) -> Self {
        Self { forwarder }
    }
}

#[async_trait]
impl Endpoint for LocalDnsEndpoint {
    async fn serve_tcp(&self, _flow: &mut TcpFlow, _dst: SocketAddr) -> io::Result<()> {
        // TCP/53 is not intercepted here; a TCP flow routed to this endpoint is a cascade bug. Asserted in debug,
        // dropped silently in release.
        debug_assert!(
            false,
            "LocalDnsEndpoint::serve_tcp called; router cascade misconfigured"
        );
        Ok(())
    }

    async fn serve_udp(&self, mut flow: UdpFlow, _dst: SocketAddr) -> io::Result<()> {
        let sender: UdpSender = flow.sender();
        let forwarder = Arc::clone(&self.forwarder);
        // Per-datagram: forward through the DnsForwarder, write reply back
        // into the same 5-tuple via `sender.send`. Each datagram is an
        // independent DNS request — we don't batch or keep state.
        while let Some(payload) = flow.recv().await {
            let sender = sender.clone();
            let forwarder = Arc::clone(&forwarder);
            tokio::spawn(async move {
                let reply = forwarder.forward(&payload).await;
                let _ = sender.send(&reply).await;
            });
        }
        Ok(())
    }

    fn supports_udp(&self) -> bool {
        // The forwarder always carries UDP — that is its entire purpose.
        true
    }

    fn supports_ipv6_dst(&self) -> bool {
        // The forwarder reaches upstream via the shadowsocks tunnel, which
        // carries IPv6 via the SS ATYP field; the destination address the
        // *client* used is irrelevant — the local endpoint answers any
        // destination. Match `Socks5Endpoint` by reporting `true`.
        true
    }

    fn name(&self) -> &str {
        "local-dns"
    }
}

#[cfg(test)]
#[path = "local_dns_tests.rs"]
mod local_dns_tests;
