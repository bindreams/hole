//! `LocalDnsEndpoint` — the router's sink for in-tunnel UDP/53 flows.
//!
//! When the HoleRouter cascade matches `proto == Udp && dst.port() == 53
//! && dns.intercept_udp53`, it dispatches to this endpoint instead of the
//! [`Socks5Endpoint`](super::Socks5Endpoint). This catches apps that hard-
//! code DNS destinations (Chrome DoH to 8.8.8.8, systemd-resolved stub)
//! so they never hit the UDP-drop privacy invariant.
//!
//! The endpoint owns an `Arc<DnsForwarder>` and runs each incoming UDP
//! datagram through `forward()` directly — no OS-loopback hop, no
//! `LocalDnsServer` detour. That's the point: the flow arrived via the
//! TUN, we resolve in-process, and we write the reply back into the same
//! flow.
//!
//! TCP is not served: DNS-over-TCP to external IPs bypasses this endpoint
//! — those flows take the normal proxy cascade. Serving TCP here would
//! complicate the router's cascade semantics (port 53 TCP isn't
//! necessarily DNS — it could be zone-transfer AXFR or any service
//! running on port 53) with no known user benefit.

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
        // TCP/53 is not intercepted here. If the router routes TCP to this
        // endpoint, that's a cascade bug — debug_assert + drop silently.
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
