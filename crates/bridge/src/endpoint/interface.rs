//! `InterfaceEndpoint` — carries flows out a specific OS network interface.
//!
//! L1/L2 mechanism (binds sockets to a specific interface index before
//! connect) satisfying the L3 [`Endpoint`] contract. Used for bypass
//! flows that egress to the real internet without going through the SS
//! tunnel.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::copy_bidirectional;
use tun_engine::helpers::{create_bypass_tcp, create_bypass_udp};
use tun_engine::{TcpFlow, UdpFlow, UdpSender};

use super::Endpoint;

pub struct InterfaceEndpoint {
    iface_index: u32,
    ipv6_available: bool,
    label: String,
}

impl InterfaceEndpoint {
    pub fn new(iface_index: u32, ipv6_available: bool) -> Self {
        Self {
            iface_index,
            ipv6_available,
            label: format!("interface(#{iface_index})"),
        }
    }

    pub fn iface_index(&self) -> u32 {
        self.iface_index
    }
}

#[async_trait]
impl Endpoint for InterfaceEndpoint {
    async fn serve_tcp(&self, flow: &mut TcpFlow, dst: SocketAddr) -> io::Result<()> {
        if dst.is_ipv6() && !self.ipv6_available {
            debug_assert!(false, "InterfaceEndpoint::serve_tcp IPv6 dst despite !ipv6_available");
            tracing::error!(%dst, "cascade invariant violated: InterfaceEndpoint::serve_tcp v6 on !v6; dropping");
            return Ok(());
        }

        let mut upstream = create_bypass_tcp(dst, self.iface_index).await?;
        copy_bidirectional(flow, &mut upstream).await?;
        Ok(())
    }

    async fn serve_udp(&self, mut flow: UdpFlow, dst: SocketAddr) -> io::Result<()> {
        if dst.is_ipv6() && !self.ipv6_available {
            debug_assert!(false, "InterfaceEndpoint::serve_udp IPv6 dst despite !ipv6_available");
            tracing::error!(%dst, "cascade invariant violated: InterfaceEndpoint::serve_udp v6 on !v6; dropping");
            return Ok(());
        }

        let socket = create_bypass_udp(self.iface_index, dst.is_ipv6()).await?;
        socket.connect(dst).await?;
        let socket = Arc::new(socket);

        let socket_rx = Arc::clone(&socket);
        let sender: UdpSender = flow.sender();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = socket_rx.recv(&mut buf).await {
                if sender.send(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });

        while let Some(payload) = flow.recv().await {
            if socket.send(&payload).await.is_err() {
                break;
            }
        }
        Ok(())
    }

    fn supports_udp(&self) -> bool {
        // A raw OS socket bound to an interface always supports UDP.
        true
    }

    fn supports_ipv6_dst(&self) -> bool {
        self.ipv6_available
    }

    fn name(&self) -> &str {
        &self.label
    }
}
