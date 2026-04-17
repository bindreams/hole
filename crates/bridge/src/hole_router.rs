//! `HoleRouter` — hole's [`tun_engine::Router`] impl.
//!
//! Wires the filter engine, fake DNS, SOCKS5 proxy, and bypass socket
//! plumbing into tun-engine's abstract `Router` shape. Owns:
//!
//! - Hot-swappable [`RuleSet`] (for filter reloads).
//! - Optional [`FakeDns`] for synthetic-IP DNS hijacking + reverse lookup.
//! - Upstream DNS resolver (for bypass-path domain resolution).
//! - Per-connection block-logging dedup.
//!
//! Per-connection dispatch mirrors the old `dispatcher::tcp_handler` /
//! `dispatcher::udp_handler` sequences: peek → reverse lookup → filter
//! decide → splice.

pub mod block_log;
pub mod upstream_dns;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tracing::{debug, info, warn};
use tun_engine::helpers::{create_bypass_tcp, create_bypass_udp, socks5_connect, Socks5UdpRelay};
use tun_engine::{DnsInterceptor, Router, TcpFlow, TcpMeta, UdpFlow, UdpMeta, UdpSender};

use self::block_log::BlockLog;
use self::upstream_dns::UpstreamResolver;
use crate::filter::engine::{decide, ConnInfo, L4Proto};
use crate::filter::rules::RuleSet;
use crate::filter::{self, FakeDns};
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
    /// Synthetic-IP DNS hijack + reverse lookup. When set, also the
    /// engine's `DnsInterceptor`.
    fake_dns: Option<Arc<FakeDns>>,

    /// DNS resolver for the bypass path.
    upstream_resolver: UpstreamResolver,
    /// Rate-limited block log. Uses `std::sync::Mutex` because the
    /// critical section is sub-microsecond and never held across .await.
    block_log: Mutex<BlockLog>,
    /// One-time flag: emitted when IPv6 bypass falls back to block.
    ipv6_bypass_warned: AtomicBool,
}

impl HoleRouter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_port: u16,
        iface_index: u32,
        ipv6_available: bool,
        udp_proxy_available: bool,
        rules: RuleSet,
        fake_dns: Option<Arc<FakeDns>>,
        upstream_resolver: UpstreamResolver,
    ) -> Self {
        Self {
            local_port,
            iface_index,
            ipv6_available,
            udp_proxy_available,
            rules: Arc::new(ArcSwap::from_pointee(rules)),
            fake_dns,
            upstream_resolver,
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

    /// Clone the fake DNS handle so the caller can also pass it as the
    /// engine's `DnsInterceptor`.
    pub fn fake_dns(&self) -> Option<Arc<FakeDns>> {
        self.fake_dns.clone()
    }
}

// Router impl =========================================================================================================

#[async_trait]
impl Router for HoleRouter {
    async fn route_tcp(&self, meta: TcpMeta, mut flow: TcpFlow) -> io::Result<()> {
        let dst_ip = meta.dst.ip();
        let dst_port = meta.dst.port();

        // Step 1: Port 53 fast path — DNS over TCP.
        if dst_port == 53 {
            if let Some(ref dns) = self.fake_dns {
                return dns.handle_tcp(&mut flow).await;
            }
        }

        // Step 2: Fake DNS reverse lookup.
        let mut domain: Option<String> = None;
        let mut pinned = false;

        if let Some(ref dns) = self.fake_dns {
            if let Some(d) = dns.reverse_lookup(dst_ip) {
                domain = Some(d.to_string());
                dns.pin(dst_ip);
                pinned = true;
            }
        }

        let result = self.dispatch_tcp(&mut flow, dst_ip, dst_port, &mut domain).await;

        if pinned {
            if let Some(ref dns) = self.fake_dns {
                dns.unpin(dst_ip);
            }
        }

        result
    }

    async fn route_udp(&self, meta: UdpMeta, flow: UdpFlow) -> io::Result<()> {
        let dst_ip = meta.dst.ip();

        // Fake DNS reverse lookup + pin.
        let mut domain: Option<String> = None;
        let mut pinned = false;
        if let Some(ref dns) = self.fake_dns {
            if let Some(d) = dns.reverse_lookup(dst_ip) {
                domain = Some(d.to_string());
                dns.pin(dst_ip);
                pinned = true;
            }
        }

        let result = self.dispatch_udp(meta, flow, &domain).await;

        if pinned {
            if let Some(ref dns) = self.fake_dns {
                dns.unpin(dst_ip);
            }
        }

        result
    }
}

// FakeDns implements DnsInterceptor for port-53 UDP hijacking =========================================================

/// Wrapper so `Arc<FakeDns>` can be handed to the engine via
/// [`EngineConfig::dns_interceptor`] without adding a `DnsInterceptor`
/// impl inside the `filter` module (which should not depend on
/// `tun_engine`).
pub struct FakeDnsInterceptor(pub Arc<FakeDns>);

#[async_trait]
impl DnsInterceptor for FakeDnsInterceptor {
    async fn intercept(&self, request: &[u8]) -> Option<Vec<u8>> {
        let reply = self.0.handle_udp(request);
        if reply.is_empty() {
            None
        } else {
            Some(reply)
        }
    }
}

// TCP dispatch ========================================================================================================

impl HoleRouter {
    async fn dispatch_tcp(
        &self,
        flow: &mut TcpFlow,
        dst_ip: IpAddr,
        dst_port: u16,
        domain: &mut Option<String>,
    ) -> io::Result<()> {
        let current_rules = self.rules.load();

        // Sniffer peek — only when domain is unknown AND domain rules exist.
        if domain.is_none() && current_rules.has_domain_rules {
            // `flow.peek` handles the sniffer-concurrency cap internally
            // via the engine-owned semaphore. A timeout is not an error;
            // the slice returned is whatever arrived in the window.
            if let Ok(peeked) = flow.peek(PEEK_BUF_SIZE, PEEK_TIMEOUT).await {
                if !peeked.is_empty() {
                    if let Some(sni) = filter::peek(peeked) {
                        *domain = Some(sni);
                    }
                }
            }
        }

        let conn_info = ConnInfo {
            dst_ip,
            dst_port,
            domain: domain.clone(),
            proto: L4Proto::Tcp,
        };
        let decision = decide(&current_rules, &conn_info);
        drop(current_rules);

        match decision.action {
            FilterAction::Proxy => self.dispatch_tcp_proxy(flow, dst_ip, dst_port, domain).await,
            FilterAction::Bypass => self.dispatch_tcp_bypass(flow, dst_ip, dst_port, domain).await,
            FilterAction::Block => {
                let rule_index = decision.rule_index.unwrap_or(0) as u32;
                let should_log = self.block_log.lock().unwrap().should_log(rule_index, dst_ip, dst_port);
                if should_log {
                    match domain.as_deref() {
                        Some(d) => debug!("blocked {d} ({dst_ip}:{dst_port}) by rule #{rule_index}"),
                        None => debug!("blocked {dst_ip}:{dst_port} by rule #{rule_index}"),
                    }
                }
                // Drop the flow — smoltcp sends RST.
                Ok(())
            }
        }
    }

    async fn dispatch_tcp_proxy(
        &self,
        flow: &mut TcpFlow,
        dst_ip: IpAddr,
        dst_port: u16,
        domain: &Option<String>,
    ) -> io::Result<()> {
        let mut upstream = socks5_connect(self.local_port, dst_ip, dst_port, domain.as_deref()).await?;
        // Peeked bytes are still buffered inside `flow` — copy_bidirectional
        // will include them naturally.
        tokio::io::copy_bidirectional(flow, &mut upstream).await?;
        Ok(())
    }

    async fn dispatch_tcp_bypass(
        &self,
        flow: &mut TcpFlow,
        dst_ip: IpAddr,
        dst_port: u16,
        domain: &Option<String>,
    ) -> io::Result<()> {
        let real_ip = self.resolve_bypass_ip(dst_ip, domain.as_deref()).await?;

        if real_ip.is_ipv6() && !self.ipv6_available {
            if !self.ipv6_bypass_warned.swap(true, Ordering::Relaxed) {
                warn!("IPv6 bypass requested but upstream has no IPv6; falling back to block");
            }
            return Ok(());
        }

        let mut upstream = create_bypass_tcp(real_ip, dst_port, self.iface_index).await?;
        tokio::io::copy_bidirectional(flow, &mut upstream).await?;
        Ok(())
    }

    async fn resolve_bypass_ip(&self, dst_ip: IpAddr, domain: Option<&str>) -> io::Result<IpAddr> {
        let is_fake = self.fake_dns.as_ref().is_some_and(|dns| dns.is_fake_ip(dst_ip));
        if !is_fake {
            return Ok(dst_ip);
        }
        let domain =
            domain.ok_or_else(|| io::Error::other("bypass: dst_ip is in fake DNS pool but no domain available"))?;
        let addrs = self.upstream_resolver.resolve(domain).await?;
        addrs
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other(format!("bypass: no addresses resolved for {domain}")))
    }
}

// UDP dispatch ========================================================================================================

impl HoleRouter {
    async fn dispatch_udp(&self, meta: UdpMeta, flow: UdpFlow, domain: &Option<String>) -> io::Result<()> {
        let dst_ip = meta.dst.ip();
        let dst_port = meta.dst.port();

        let conn_info = ConnInfo {
            dst_ip,
            dst_port,
            domain: domain.clone(),
            proto: L4Proto::Udp,
        };
        let current_rules = self.rules.load();
        let decision = decide(&current_rules, &conn_info);
        drop(current_rules);

        let mut action = decision.action;

        if action == FilterAction::Proxy && !self.udp_proxy_available {
            let mut log = self.block_log.lock().unwrap();
            if log.should_log(decision.rule_index.unwrap_or(0) as u32, dst_ip, dst_port) {
                warn!(dst_ip = %dst_ip, dst_port, "UDP proxy unavailable (v2ray-plugin), blocking");
            }
            action = FilterAction::Block;
        }

        let real_ip = if action == FilterAction::Bypass {
            self.resolve_bypass_ip(dst_ip, domain.as_deref()).await?
        } else {
            dst_ip
        };

        if action == FilterAction::Bypass && real_ip.is_ipv6() && !self.ipv6_available {
            if !self.ipv6_bypass_warned.swap(true, Ordering::Relaxed) {
                warn!("IPv6 bypass unavailable for UDP, blocking");
            }
            action = FilterAction::Block;
        }

        match action {
            FilterAction::Proxy => splice_udp_proxy(flow, self.local_port, real_ip, dst_port, domain.clone()).await,
            FilterAction::Bypass => splice_udp_bypass(flow, real_ip, dst_port, self.iface_index).await,
            FilterAction::Block => {
                let rule_index = decision.rule_index.unwrap_or(0) as u32;
                let mut log = self.block_log.lock().unwrap();
                if log.should_log(rule_index, dst_ip, dst_port) {
                    info!(dst_ip = %dst_ip, dst_port, domain = ?domain, "blocked UDP flow");
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
async fn splice_udp_proxy(
    mut flow: UdpFlow,
    local_port: u16,
    real_ip: IpAddr,
    dst_port: u16,
    domain: Option<String>,
) -> io::Result<()> {
    let relay = Arc::new(Socks5UdpRelay::associate(local_port).await?);

    // Reader task: pull replies from the relay and inject back into the flow.
    let relay_rx = Arc::clone(&relay);
    let sender: UdpSender = flow.sender();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, _src_ip, _src_port)) = relay_rx.recv_from(&mut buf).await {
            if sender.send(&buf[..n]).await.is_err() {
                break;
            }
        }
    });

    // Forwarder: pull inbound datagrams from the flow, send via relay.
    while let Some(payload) = flow.recv().await {
        if relay
            .send_to(real_ip, dst_port, domain.as_deref(), &payload)
            .await
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

/// Relay a UdpFlow through a bypass UDP socket bound to an upstream
/// interface.
async fn splice_udp_bypass(mut flow: UdpFlow, real_ip: IpAddr, dst_port: u16, iface_index: u32) -> io::Result<()> {
    let socket = create_bypass_udp(iface_index, real_ip.is_ipv6()).await?;
    socket.connect(SocketAddr::new(real_ip, dst_port)).await?;
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
