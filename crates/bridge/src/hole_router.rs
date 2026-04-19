//! `HoleRouter` — hole's [`tun_engine::Router`] impl.
//!
//! Wires the filter engine, SOCKS5 proxy, and bypass socket plumbing into
//! tun-engine's abstract `Router` shape. Owns:
//!
//! - Hot-swappable [`RuleSet`] (for filter reloads).
//! - Per-connection block-logging dedup.
//!
//! Per-connection dispatch: peek (TCP only) → filter decide → splice. For
//! TCP flows the sniffer at [`crate::filter::peek`] extracts TLS SNI or
//! HTTP Host from the first ≤ 2 KiB of payload, feeding the recovered name
//! into the filter. UDP flows have no peek equivalent and match on IP only
//! unless a future QUIC Initial parser is added.
//!
//! UDP-on-TCP-only-plugin is dropped, not bypassed. See
//! [`HoleRouter::dispatch_udp`] for the privacy invariant.

pub mod block_log;

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tracing::{debug, info, warn};
use tun_engine::helpers::{create_bypass_tcp, create_bypass_udp, socks5_connect, Socks5UdpRelay};
use tun_engine::{Router, TcpFlow, TcpMeta, UdpFlow, UdpMeta, UdpSender};

use self::block_log::BlockLog;
use crate::filter;
use crate::filter::engine::{decide, ConnInfo, L4Proto};
use crate::filter::rules::RuleSet;
use hole_common::config::FilterAction;

// Constants ===========================================================================================================

/// Maximum bytes to peek for the sniffer (TLS ClientHello + HTTP request line).
const PEEK_BUF_SIZE: usize = 2048;

/// Maximum time to wait for the first payload bytes (for sniffer).
const PEEK_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

// HoleRouter ==========================================================================================================

pub struct HoleRouter {
    /// SS SOCKS5 local port on 127.0.0.1.
    local_port: u16,
    /// Upstream interface index for bypass sockets.
    iface_index: u32,
    /// Whether the upstream interface has IPv6 connectivity.
    ipv6_available: bool,
    /// Whether the current proxy config supports UDP relay (no v2ray-plugin).
    udp_proxy_available: bool,

    /// Hot-swappable filter rules.
    rules: Arc<ArcSwap<RuleSet>>,

    /// Rate-limited block log. Uses `std::sync::Mutex` because the
    /// critical section is sub-microsecond and never held across .await.
    block_log: Mutex<BlockLog>,
    /// One-time flag: emitted when IPv6 bypass falls back to block.
    ipv6_bypass_warned: AtomicBool,
}

impl HoleRouter {
    pub fn new(
        local_port: u16,
        iface_index: u32,
        ipv6_available: bool,
        udp_proxy_available: bool,
        rules: RuleSet,
    ) -> Self {
        Self {
            local_port,
            iface_index,
            ipv6_available,
            udp_proxy_available,
            rules: Arc::new(ArcSwap::from_pointee(rules)),
            block_log: Mutex::new(BlockLog::new()),
            ipv6_bypass_warned: AtomicBool::new(false),
        }
    }

    /// Hot-swap the filter rules.
    pub fn swap_rules(&self, new_rules: RuleSet) {
        self.rules.store(Arc::new(new_rules));
    }

    /// Invalid (dropped) rules from the current ruleset.
    pub fn invalid_filters(&self) -> Vec<hole_common::protocol::InvalidFilter> {
        self.rules.load().dropped.clone()
    }
}

// Router impl =========================================================================================================

#[async_trait]
impl Router for HoleRouter {
    async fn route_tcp(&self, meta: TcpMeta, mut flow: TcpFlow) -> io::Result<()> {
        self.dispatch_tcp(&mut flow, meta.dst).await
    }

    async fn route_udp(&self, meta: UdpMeta, flow: UdpFlow) -> io::Result<()> {
        self.dispatch_udp(meta, flow).await
    }
}

// TCP dispatch ========================================================================================================

impl HoleRouter {
    async fn dispatch_tcp(&self, flow: &mut TcpFlow, dst: SocketAddr) -> io::Result<()> {
        let current_rules = self.rules.load();

        // Sniffer peek — only when domain rules exist. Recovers TLS SNI or
        // HTTP Host from the first ≤ 2 KiB of payload so domain-based rules
        // can match.
        let mut domain: Option<String> = None;
        if current_rules.has_domain_rules {
            // `flow.peek` handles the sniffer-concurrency cap internally
            // via the engine-owned semaphore. A timeout returns `Ok(&[])`
            // so the `if let Ok` only swallows a legitimate close-during-
            // shutdown error, which we treat as "no peek payload".
            if let Ok(peeked) = flow.peek(PEEK_BUF_SIZE, PEEK_TIMEOUT).await {
                if !peeked.is_empty() {
                    if let Some(sni) = filter::peek(peeked) {
                        domain = Some(sni);
                    }
                }
            }
        }

        let conn_info = ConnInfo {
            dst,
            domain: domain.clone(),
            proto: L4Proto::Tcp,
        };
        let decision = decide(&current_rules, &conn_info);
        drop(current_rules);

        match decision.action {
            FilterAction::Proxy => self.dispatch_tcp_proxy(flow, dst).await,
            FilterAction::Bypass => self.dispatch_tcp_bypass(flow, dst).await,
            FilterAction::Block => {
                let rule_index = decision.rule_index.unwrap_or(0) as u32;
                let should_log = self.block_log.lock().unwrap().should_log(rule_index, dst);
                if should_log {
                    match domain.as_deref() {
                        Some(d) => debug!("blocked {d} ({dst}) by rule #{rule_index}"),
                        None => debug!("blocked {dst} by rule #{rule_index}"),
                    }
                }
                // Drop the flow — smoltcp sends RST.
                Ok(())
            }
        }
    }

    async fn dispatch_tcp_proxy(&self, flow: &mut TcpFlow, dst: SocketAddr) -> io::Result<()> {
        let mut upstream = socks5_connect(self.local_port, dst).await?;
        // Peeked bytes are still buffered inside `flow` — copy_bidirectional
        // will include them naturally.
        tokio::io::copy_bidirectional(flow, &mut upstream).await?;
        Ok(())
    }

    async fn dispatch_tcp_bypass(&self, flow: &mut TcpFlow, dst: SocketAddr) -> io::Result<()> {
        if dst.is_ipv6() && !self.ipv6_available {
            if !self.ipv6_bypass_warned.swap(true, Ordering::Relaxed) {
                warn!("IPv6 bypass requested but upstream has no IPv6; falling back to block");
            }
            return Ok(());
        }

        let mut upstream = create_bypass_tcp(dst, self.iface_index).await?;
        tokio::io::copy_bidirectional(flow, &mut upstream).await?;
        Ok(())
    }
}

// UDP dispatch ========================================================================================================

impl HoleRouter {
    async fn dispatch_udp(&self, meta: UdpMeta, flow: UdpFlow) -> io::Result<()> {
        let dst = meta.dst;

        let conn_info = ConnInfo {
            dst,
            domain: None,
            proto: L4Proto::Udp,
        };
        let current_rules = self.rules.load();
        let decision = decide(&current_rules, &conn_info);
        drop(current_rules);

        let mut action = decision.action;

        // Privacy invariant: UDP that the filter said to proxy must not
        // leak out the unprotected bypass when the plugin can't carry
        // it. Drop instead. See the module doc.
        if action == FilterAction::Proxy && !self.udp_proxy_available {
            let mut log = self.block_log.lock().unwrap();
            if log.should_log(decision.rule_index.unwrap_or(0) as u32, dst) {
                warn!(%dst, "UDP proxy unavailable (v2ray-plugin), blocking");
            }
            action = FilterAction::Block;
        }

        if action == FilterAction::Bypass && dst.is_ipv6() && !self.ipv6_available {
            if !self.ipv6_bypass_warned.swap(true, Ordering::Relaxed) {
                warn!("IPv6 bypass unavailable for UDP, blocking");
            }
            action = FilterAction::Block;
        }

        match action {
            FilterAction::Proxy => splice_udp_proxy(flow, self.local_port, dst).await,
            FilterAction::Bypass => splice_udp_bypass(flow, dst, self.iface_index).await,
            FilterAction::Block => {
                let rule_index = decision.rule_index.unwrap_or(0) as u32;
                let mut log = self.block_log.lock().unwrap();
                if log.should_log(rule_index, dst) {
                    info!(%dst, "blocked UDP flow");
                }
                // Dropping the flow ends route_udp; any further datagrams
                // for the 5-tuple silently fail to enqueue until the
                // engine's idle sweep evicts the entry.
                Ok(())
            }
        }
    }
}

// UDP splice helpers ==================================================================================================

/// Relay a UdpFlow through the SS SOCKS5 UDP Associate channel.
async fn splice_udp_proxy(mut flow: UdpFlow, local_port: u16, dst: SocketAddr) -> io::Result<()> {
    let relay = Arc::new(Socks5UdpRelay::associate(local_port).await?);

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

/// Relay a UdpFlow through a bypass UDP socket bound to an upstream
/// interface.
async fn splice_udp_bypass(mut flow: UdpFlow, dst: SocketAddr, iface_index: u32) -> io::Result<()> {
    let socket = create_bypass_udp(iface_index, dst.is_ipv6()).await?;
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

#[cfg(test)]
#[path = "hole_router_tests.rs"]
mod hole_router_tests;
