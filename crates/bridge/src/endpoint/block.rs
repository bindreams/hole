//! `BlockEndpoint` — drops flows instead of carrying them.
//!
//! Terminal of the router's dispatch cascade for three distinct reasons:
//!
//! 1. `FilterAction::Block` — the user's rules explicitly asked to block.
//! 2. **Privacy invariant** — `FilterAction::Proxy` + UDP + the plugin
//!    cannot carry UDP. Falling back to the clear-text bypass would leak
//!    the flow outside the encrypted tunnel, violating the user's VPN
//!    guarantee. Do not 'fix' by cascading to [`InterfaceEndpoint`].
//! 3. **Reachability** — `FilterAction::Bypass` + IPv6 destination +
//!    upstream interface has no IPv6. This is just "we can't deliver it."
//!
//! The [`Endpoint`] impl drops the flow (smoltcp emits RST for TCP, the
//! UDP flow's idle sweep evicts for UDP). Diagnostic logging is exposed
//! via dedicated methods ([`BlockEndpoint::log_rule_block_tcp`],
//! [`BlockEndpoint::log_rule_block_udp`],
//! [`BlockEndpoint::log_udp_proxy_unavailable`],
//! [`BlockEndpoint::log_ipv6_bypass_unreachable`]) that the router calls
//! before `serve_*` so the log message can distinguish the three drop
//! reasons.

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};
use tun_engine::{TcpFlow, UdpFlow};

use super::Endpoint;
use crate::hole_router::block_log::BlockLog;

pub struct BlockEndpoint {
    /// Rate-limited warn/info dedup, keyed on (rule_index, dst). Uses
    /// `std::sync::Mutex` because the critical section is sub-microsecond
    /// and never held across an `.await`.
    block_log: Mutex<BlockLog>,
    /// One-time flag for the IPv6-unreachable warn — different cardinality
    /// from block_log (infrastructure-level, not per-flow).
    ipv6_unreachable_warned: AtomicBool,
}

impl BlockEndpoint {
    pub fn new() -> Self {
        Self {
            block_log: Mutex::new(BlockLog::new()),
            ipv6_unreachable_warned: AtomicBool::new(false),
        }
    }

    /// Log a rule-caused TCP block. Called from the router's dispatch
    /// loop before [`BlockEndpoint::serve_tcp`] drops the flow.
    pub fn log_rule_block_tcp(&self, rule_index: u32, dst: SocketAddr, domain: Option<&str>) {
        let should_log = self.block_log.lock().unwrap().should_log(rule_index, dst);
        if should_log {
            match domain {
                Some(d) => debug!("blocked {d} ({dst}) by rule #{rule_index}"),
                None => debug!("blocked {dst} by rule #{rule_index}"),
            }
        }
    }

    /// Log a rule-caused UDP block.
    pub fn log_rule_block_udp(&self, rule_index: u32, dst: SocketAddr) {
        let should_log = self.block_log.lock().unwrap().should_log(rule_index, dst);
        if should_log {
            info!(%dst, "blocked UDP flow");
        }
    }

    /// Log the UDP-proxy-unavailable privacy drop. `rule_index` is the
    /// rule that matched Proxy; `plugin` is the currently-configured
    /// plugin name (for diagnostic context). Rate-limited by `block_log`.
    pub fn log_udp_proxy_unavailable(&self, rule_index: u32, dst: SocketAddr, plugin: Option<&str>) {
        let should_log = self.block_log.lock().unwrap().should_log(rule_index, dst);
        if should_log {
            warn!(
                %dst,
                plugin = plugin.unwrap_or("<none>"),
                "UDP proxy unavailable (TCP-only plugin, dropping for privacy)"
            );
        }
    }

    /// Log the IPv6-unreachable-bypass drop. Emits two complementary
    /// signals, matching pre-refactor behavior:
    ///
    /// - A one-shot `warn!` via `ipv6_unreachable_warned` that describes
    ///   the infrastructure-level scenario (no upstream IPv6 connectivity).
    /// - A per-(rule_index, dst) rate-limited `info!` that records which
    ///   destinations the cascade dropped. This preserves the visibility
    ///   pre-refactor `dispatch_udp`/`dispatch_tcp_bypass` had when the
    ///   IPv6 check fell through to `FilterAction::Block`.
    pub fn log_ipv6_bypass_unreachable(&self, rule_index: u32, dst: SocketAddr, l4: &'static str) {
        if !self.ipv6_unreachable_warned.swap(true, Ordering::Relaxed) {
            warn!("IPv6 bypass unreachable; upstream interface has no IPv6 connectivity");
        }
        let should_log = self.block_log.lock().unwrap().should_log(rule_index, dst);
        if should_log {
            info!(%dst, l4, "bypass dropped: IPv6 destination without upstream IPv6");
        }
    }
}

impl Default for BlockEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Endpoint for BlockEndpoint {
    async fn serve_tcp(&self, _flow: &mut TcpFlow, _dst: SocketAddr) -> io::Result<()> {
        // Drop — smoltcp sends RST as `flow` goes out of scope up the
        // call chain. Logging happens on the router side via the
        // `log_*` methods above, because the router has the decision
        // context (rule_index, reason).
        Ok(())
    }

    async fn serve_udp(&self, _flow: UdpFlow, _dst: SocketAddr) -> io::Result<()> {
        // Drop — the UDP flow's idle sweep evicts the 5-tuple entry
        // from the engine once no more datagrams arrive.
        Ok(())
    }

    fn supports_udp(&self) -> bool {
        // Block doesn't care about the flow's protocol.
        true
    }

    fn supports_ipv6_dst(&self) -> bool {
        // Block doesn't care about reachability.
        true
    }

    fn name(&self) -> &str {
        "block"
    }
}
