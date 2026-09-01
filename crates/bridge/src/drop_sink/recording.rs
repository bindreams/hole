//! `RecordingDropSink` — a [`DropSink`] that turns each drop into a value
//! on a channel.
//!
//! A dropped flow is served by nothing, so the sink is its only trace.
//! `LoggingDropSink` writes that trace to a log line, which no test can
//! assert on without capturing a subscriber; this one writes it to an
//! `mpsc`, which makes the reason, the destination and the plugin name
//! ordinary values. It is what gives the UDP-drop privacy invariant a
//! positive observable, and the completed `route_udp` call is the
//! happens-after edge that makes the matching negatives sound.

use std::net::SocketAddr;

use tokio::sync::mpsc;

use super::DropSink;

/// One recorded drop, with the fields the corresponding [`DropSink`]
/// method carried. Owned `String`s so a record outlives the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dropped {
    RuleBlockTcp {
        rule_index: u32,
        dst: SocketAddr,
        domain: Option<String>,
    },
    RuleBlockUdp {
        rule_index: u32,
        dst: SocketAddr,
    },
    UdpProxyUnavailable {
        rule_index: u32,
        dst: SocketAddr,
        plugin: Option<String>,
    },
    Ipv6BypassUnreachable {
        rule_index: u32,
        dst: SocketAddr,
        l4: &'static str,
    },
}

pub struct RecordingDropSink {
    records: mpsc::UnboundedSender<Dropped>,
}

impl RecordingDropSink {
    /// Build the sink and the receiver for its records. Unbounded: the
    /// `DropSink` methods are synchronous and cannot await capacity, so a
    /// bounded channel would have to drop records instead.
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Dropped>) {
        let (records, rx) = mpsc::unbounded_channel();
        (Self { records }, rx)
    }
}

impl DropSink for RecordingDropSink {
    fn rule_block_tcp(&self, rule_index: u32, dst: SocketAddr, domain: Option<&str>) {
        // Send errors mean the test dropped its receiver; recording is
        // best-effort from the router's side either way.
        let _ = self.records.send(Dropped::RuleBlockTcp {
            rule_index,
            dst,
            domain: domain.map(str::to_string),
        });
    }

    fn rule_block_udp(&self, rule_index: u32, dst: SocketAddr) {
        let _ = self.records.send(Dropped::RuleBlockUdp { rule_index, dst });
    }

    fn udp_proxy_unavailable(&self, rule_index: u32, dst: SocketAddr, plugin: Option<&str>) {
        let _ = self.records.send(Dropped::UdpProxyUnavailable {
            rule_index,
            dst,
            plugin: plugin.map(str::to_string),
        });
    }

    fn ipv6_bypass_unreachable(&self, rule_index: u32, dst: SocketAddr, l4: &'static str) {
        let _ = self
            .records
            .send(Dropped::Ipv6BypassUnreachable { rule_index, dst, l4 });
    }
}

#[cfg(test)]
#[path = "recording_tests.rs"]
mod recording_tests;
