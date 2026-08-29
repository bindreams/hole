//! `LoggingDropSink` — the production [`DropSink`], which records a drop
//! by logging it.
//!
//! Two rate limits, of different cardinality: a per-`(rule_index, dst)`
//! window from [`BlockLog`] covers all three reasons, and a one-shot flag
//! covers the IPv6-unreachable `warn!`, which describes the upstream
//! interface rather than any one flow.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tracing::{debug, info, warn};

use super::block_log::BlockLog;
use super::DropSink;

pub struct LoggingDropSink {
    /// Rate-limited warn/info dedup, keyed on (rule_index, dst). Uses
    /// `std::sync::Mutex` because the critical section is sub-microsecond
    /// and never held across an `.await`.
    block_log: Mutex<BlockLog>,
    /// One-time flag for the IPv6-unreachable warn — different cardinality
    /// from block_log (infrastructure-level, not per-flow).
    ipv6_unreachable_warned: AtomicBool,
}

impl LoggingDropSink {
    pub fn new() -> Self {
        Self {
            block_log: Mutex::new(BlockLog::new()),
            ipv6_unreachable_warned: AtomicBool::new(false),
        }
    }
}

impl Default for LoggingDropSink {
    fn default() -> Self {
        Self::new()
    }
}

impl DropSink for LoggingDropSink {
    fn rule_block_tcp(&self, rule_index: u32, dst: SocketAddr, domain: Option<&str>) {
        let should_log = self.block_log.lock().unwrap().should_log(rule_index, dst);
        if should_log {
            match domain {
                Some(d) => debug!("blocked {d} ({dst}) by rule #{rule_index}"),
                None => debug!("blocked {dst} by rule #{rule_index}"),
            }
        }
    }

    fn rule_block_udp(&self, rule_index: u32, dst: SocketAddr) {
        let should_log = self.block_log.lock().unwrap().should_log(rule_index, dst);
        if should_log {
            info!(%dst, "blocked UDP flow");
        }
    }

    fn udp_proxy_unavailable(&self, rule_index: u32, dst: SocketAddr, plugin: Option<&str>) {
        let should_log = self.block_log.lock().unwrap().should_log(rule_index, dst);
        if should_log {
            warn!(
                %dst,
                plugin = plugin.unwrap_or("<none>"),
                "UDP proxy unavailable (TCP-only plugin, dropping for privacy)"
            );
        }
    }

    fn ipv6_bypass_unreachable(&self, rule_index: u32, dst: SocketAddr, l4: &'static str) {
        if !self.ipv6_unreachable_warned.swap(true, Ordering::Relaxed) {
            warn!("IPv6 bypass unreachable; upstream interface has no IPv6 connectivity");
        }
        let should_log = self.block_log.lock().unwrap().should_log(rule_index, dst);
        if should_log {
            info!(%dst, l4, "bypass dropped: IPv6 destination without upstream IPv6");
        }
    }
}
