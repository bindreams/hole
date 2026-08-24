//! `MockEndpoint` — an [`Endpoint`] that reports what it was asked to
//! carry instead of opening a socket.
//!
//! Both production served slots dial for real: `Socks5Endpoint` connects
//! to the SOCKS5 server and `InterfaceEndpoint` binds a raw socket to an
//! interface index. A test may therefore never let a flow reach one, and
//! before this double there was no way to observe which mechanism the
//! cascade picked, or — the assertion that matters for the UDP-drop
//! privacy invariant — that the bypass slot was reached by nothing.

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tun_engine::{TcpFlow, UdpFlow};

use super::Endpoint;

/// What a [`MockEndpoint`] was handed, and for which destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    Tcp(SocketAddr),
    Udp(SocketAddr),
}

pub struct MockEndpoint {
    label: &'static str,
    supports_udp: bool,
    supports_ipv6_dst: bool,
    plugin_name: Option<&'static str>,
    served: mpsc::UnboundedSender<Served>,
}

impl MockEndpoint {
    /// Build an endpoint with fixed capabilities and no plugin, plus the
    /// receiver for everything it is asked to serve.
    ///
    /// The channel is unbounded: a bounded one could park a `serve_*`
    /// call inside a router the test is still awaiting, turning a full
    /// queue into a hang.
    pub fn new(
        label: &'static str,
        supports_udp: bool,
        supports_ipv6_dst: bool,
    ) -> (Self, mpsc::UnboundedReceiver<Served>) {
        Self::build(label, supports_udp, supports_ipv6_dst, None)
    }

    /// Same, carrying a plugin name — what the cascade reads off the
    /// proxy slot for the `plugin` field of the UDP-proxy-unavailable
    /// drop record.
    pub fn with_plugin(
        label: &'static str,
        supports_udp: bool,
        supports_ipv6_dst: bool,
        plugin_name: &'static str,
    ) -> (Self, mpsc::UnboundedReceiver<Served>) {
        Self::build(label, supports_udp, supports_ipv6_dst, Some(plugin_name))
    }

    fn build(
        label: &'static str,
        supports_udp: bool,
        supports_ipv6_dst: bool,
        plugin_name: Option<&'static str>,
    ) -> (Self, mpsc::UnboundedReceiver<Served>) {
        let (served, rx) = mpsc::unbounded_channel();
        (
            Self {
                label,
                supports_udp,
                supports_ipv6_dst,
                plugin_name,
                served,
            },
            rx,
        )
    }
}

#[async_trait]
impl Endpoint for MockEndpoint {
    async fn serve_tcp(&self, _flow: &mut TcpFlow, dst: SocketAddr) -> io::Result<()> {
        // The report precedes the return, so a completed `serve_tcp` is a
        // happens-after edge for the receiver. Send errors mean the test
        // dropped its receiver, which is not this double's business.
        let _ = self.served.send(Served::Tcp(dst));
        Ok(())
    }

    async fn serve_udp(&self, _flow: UdpFlow, dst: SocketAddr) -> io::Result<()> {
        let _ = self.served.send(Served::Udp(dst));
        Ok(())
    }

    fn supports_udp(&self) -> bool {
        self.supports_udp
    }

    fn supports_ipv6_dst(&self) -> bool {
        self.supports_ipv6_dst
    }

    fn name(&self) -> &str {
        self.label
    }

    fn plugin_name(&self) -> Option<&str> {
        self.plugin_name
    }
}

#[cfg(test)]
#[path = "mock_tests.rs"]
mod mock_tests;
