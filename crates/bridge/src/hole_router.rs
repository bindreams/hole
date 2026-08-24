//! `HoleRouter` — hole's [`tun_engine::Router`] impl.
//!
//! Wires two [`Endpoint`](crate::endpoint::Endpoint) mechanisms plus a
//! [`DropSink`](crate::drop_sink::DropSink) into the filter engine and
//! TUN dispatch shape of `tun-engine`:
//!
//! - `proxy`: [`Socks5Endpoint`](crate::endpoint::Socks5Endpoint) —
//!   flows that should go through the SS tunnel.
//! - `bypass`: [`InterfaceEndpoint`](crate::endpoint::InterfaceEndpoint) —
//!   flows that should egress via the real upstream interface.
//! - `drops`: [`LoggingDropSink`](crate::drop_sink::LoggingDropSink) —
//!   records flows the cascade refused to carry. Nothing serves them.
//!
//! ## Role vs. mechanism
//!
//! Field names encode *role* (why we chose this endpoint for the flow —
//! the [`FilterAction`](hole_common::config::FilterAction) variant).
//! Field types encode *mechanism* (how the endpoint carries bytes). The
//! cascade in [`HoleRouter::resolve_endpoint`] maps role → mechanism.
//!
//! ## Per-flow dispatch
//!
//! 1. TCP only: peek ≤ 2 KiB and run the TLS SNI / HTTP Host sniffer to
//!    recover a domain (see [`crate::filter::sniffer`]). UDP has no peek
//!    equivalent and always matches on IP.
//! 2. Build a [`ConnInfo`] and run [`crate::filter::engine::decide`].
//! 3. Cascade the `FilterAction` + flow shape to a concrete endpoint via
//!    [`HoleRouter::resolve_endpoint`], recording any drop reason on the
//!    [`DropSink`](crate::drop_sink::DropSink).
//! 4. Call `endpoint.serve_tcp` or `endpoint.serve_udp`.
//!
//! ## UDP-drop privacy invariant
//!
//! `FilterAction::Proxy` + UDP + `!proxy.supports_udp()` resolves to a
//! drop, **not** to `&self.bypass`. This is deliberate: falling back to
//! the clear-text bypass would leak UDP outside the encrypted tunnel,
//! violating the user's VPN expectation. Users who need tunneled UDP
//! should configure a UDP-capable plugin (galoshes). The drop is
//! recorded on the [`DropSink`](crate::drop_sink::DropSink).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tun_engine::{Router, TcpFlow, TcpMeta, UdpFlow, UdpMeta};

use crate::drop_sink::{DropSink, LoggingDropSink};
use crate::endpoint::{Endpoint, InterfaceEndpoint, LocalDnsEndpoint, Socks5Endpoint};
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
    proxy: Box<dyn Endpoint>,
    bypass: Box<dyn Endpoint>,
    drops: Box<dyn DropSink>,
    /// Optional in-tunnel DNS interceptor. When `Some`, the cascade diverts
    /// UDP/53 flows to this endpoint instead of the proxy; `is_some()` is the
    /// sole gate. `None` disables interception (DNS disabled or SocksOnly mode).
    local_dns: Option<Box<dyn Endpoint>>,
    rules: Arc<ArcSwap<RuleSet>>,
}

impl HoleRouter {
    pub fn new(proxy: Socks5Endpoint, bypass: InterfaceEndpoint, drops: LoggingDropSink, rules: RuleSet) -> Self {
        Self::with_endpoints(Box::new(proxy), Box::new(bypass), Box::new(drops), None, rules)
    }

    /// Construct with an in-tunnel DNS interceptor attached. When
    /// `Some(_)`, the UDP/53 cascade diverts to `local_dns` before
    /// falling through to the proxy path. `None` disables interception.
    pub fn with_local_dns(
        proxy: Socks5Endpoint,
        bypass: InterfaceEndpoint,
        drops: LoggingDropSink,
        local_dns: Option<LocalDnsEndpoint>,
        rules: RuleSet,
    ) -> Self {
        Self::with_endpoints(
            Box::new(proxy),
            Box::new(bypass),
            Box::new(drops),
            local_dns.map(|e| Box::new(e) as Box<dyn Endpoint>),
            rules,
        )
    }

    /// Construct over the slots directly, so a caller can put any
    /// mechanism in any slot. The production constructors above are thin
    /// wrappers; this is the seam tests use to substitute doubles for
    /// `Socks5Endpoint` and `InterfaceEndpoint`, both of which dial real
    /// sockets, and for `LoggingDropSink`, whose only output is a log line.
    pub fn with_endpoints(
        proxy: Box<dyn Endpoint>,
        bypass: Box<dyn Endpoint>,
        drops: Box<dyn DropSink>,
        local_dns: Option<Box<dyn Endpoint>>,
        rules: RuleSet,
    ) -> Self {
        Self {
            proxy,
            bypass,
            drops,
            local_dns,
            rules: Arc::new(ArcSwap::from_pointee(rules)),
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

// Cascade =============================================================================================================

/// A flow whose cascade resolved to a drop, tagged with the reason so the
/// caller can pick the right log path before dropping.
#[derive(Debug, Clone, Copy)]
enum DropReason {
    /// The user's rule explicitly said `Block`.
    RuleBlock { rule_index: u32 },
    /// `FilterAction::Proxy` + UDP + the plugin cannot carry UDP.
    /// Privacy invariant — we refuse to leak UDP to the bypass.
    UdpProxyUnavailable { rule_index: u32 },
    /// `FilterAction::Bypass` + IPv6 destination + upstream has no IPv6.
    Ipv6BypassUnreachable { rule_index: u32 },
}

/// Cascade output: either a concrete endpoint to serve the flow, or a
/// drop reason for the router to log before dropping.
enum Dispatch<'a> {
    Endpoint(&'a dyn Endpoint),
    Drop(DropReason),
}

impl HoleRouter {
    /// Map a [`FilterAction`] + flow shape to a concrete endpoint, or to
    /// a drop reason when the cascade's privacy / reachability invariants
    /// preclude carrying the flow.
    fn resolve_endpoint(
        &self,
        action: FilterAction,
        l4: L4Proto,
        dst: SocketAddr,
        rule_index: Option<u32>,
    ) -> Dispatch<'_> {
        let rule_index = rule_index.unwrap_or(0);
        // Intercept UDP/53 *before* the action cascade — a LocalDnsEndpoint
        // takes precedence over any FilterAction decision. This ensures
        // the forwarder answers even for flows whose rule would otherwise
        // Block/Bypass/Proxy (e.g. a user rule `Block 8.8.8.8` still sends
        // Chrome's hardcoded-DoH DNS through the local forwarder).
        if l4 == L4Proto::Udp && dst.port() == 53 {
            if let Some(local) = self.local_dns.as_deref() {
                return Dispatch::Endpoint(local);
            }
        }
        match action {
            FilterAction::Proxy => {
                // Privacy invariant: if proxy can't carry this UDP flow,
                // drop it. Do NOT fall back to the clear-text bypass.
                if l4 == L4Proto::Udp && !self.proxy.supports_udp() {
                    return Dispatch::Drop(DropReason::UdpProxyUnavailable { rule_index });
                }
                Dispatch::Endpoint(self.proxy.as_ref())
            }
            FilterAction::Bypass => {
                if dst.is_ipv6() && !self.bypass.supports_ipv6_dst() {
                    return Dispatch::Drop(DropReason::Ipv6BypassUnreachable { rule_index });
                }
                Dispatch::Endpoint(self.bypass.as_ref())
            }
            FilterAction::Block => Dispatch::Drop(DropReason::RuleBlock { rule_index }),
        }
    }

    /// Record a drop reason before the flow is released. Uses per-reason
    /// methods on the [`DropSink`] so the sink can distinguish
    /// explicit-rule from privacy from reachability drops.
    fn log_drop(&self, reason: DropReason, dst: SocketAddr, domain: Option<&str>, l4: L4Proto) {
        match (reason, l4) {
            (DropReason::RuleBlock { rule_index }, L4Proto::Tcp) => {
                self.drops.rule_block_tcp(rule_index, dst, domain);
            }
            (DropReason::RuleBlock { rule_index }, L4Proto::Udp) => {
                self.drops.rule_block_udp(rule_index, dst);
            }
            (DropReason::UdpProxyUnavailable { rule_index }, L4Proto::Udp) => {
                self.drops
                    .udp_proxy_unavailable(rule_index, dst, self.proxy.plugin_name());
            }
            (DropReason::UdpProxyUnavailable { .. }, L4Proto::Tcp) => {
                // Unreachable: UdpProxyUnavailable is UDP-only. debug_assert
                // guards the contract.
                debug_assert!(false, "UdpProxyUnavailable produced for TCP flow");
            }
            (DropReason::Ipv6BypassUnreachable { rule_index }, l4) => {
                let l4_label = match l4 {
                    L4Proto::Tcp => "tcp",
                    L4Proto::Udp => "udp",
                };
                self.drops.ipv6_bypass_unreachable(rule_index, dst, l4_label);
            }
        }
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

        match self.resolve_endpoint(
            decision.action,
            L4Proto::Tcp,
            dst,
            decision.rule_index.map(|i| i as u32),
        ) {
            Dispatch::Endpoint(endpoint) => endpoint.serve_tcp(flow, dst).await,
            Dispatch::Drop(reason) => {
                self.log_drop(reason, dst, domain.as_deref(), L4Proto::Tcp);
                // Drop the flow — smoltcp sends RST.
                Ok(())
            }
        }
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

        match self.resolve_endpoint(
            decision.action,
            L4Proto::Udp,
            dst,
            decision.rule_index.map(|i| i as u32),
        ) {
            Dispatch::Endpoint(endpoint) => endpoint.serve_udp(flow, dst).await,
            Dispatch::Drop(reason) => {
                self.log_drop(reason, dst, None, L4Proto::Udp);
                // Dropping the flow ends route_udp; any further datagrams
                // for the 5-tuple silently fail to enqueue until the
                // engine's idle sweep evicts the entry.
                Ok(())
            }
        }
    }
}

#[cfg(test)]
#[path = "hole_router_tests.rs"]
mod hole_router_tests;
