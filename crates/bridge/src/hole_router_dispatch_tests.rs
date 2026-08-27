//! What the cascade's decision actually *does* to a flow.
//!
//! `hole_router_tests.rs` drives [`HoleRouter::resolve_endpoint`] over a
//! table and asserts which output it chose. That is the decision. This
//! file asserts the consequence: which mechanism received the flow, and
//! which reason was recorded when none did — the two questions the
//! UDP-drop privacy invariant is actually about.
//!
//! Every test wires [`MockEndpoint`]s into the served slots and a
//! [`RecordingDropSink`] into the drop slot via
//! [`HoleRouter::with_endpoints`], then calls `route_udp` or `route_tcp`
//! **to completion**. No real socket is opened, and nothing here needs an
//! engine, a TUN device or a packet.
//!
//! **Only wired slots are asserted on.** An unwired mock's sender dies
//! with `wire`, so its receiver reports `Disconnected` whatever the router
//! did — a negative that cannot fail. [`Wired`] therefore holds the
//! local-dns receiver only when that slot exists.
//!
//! **The ordering edge is the completed call.** Each `route_*` reports on
//! its slot before returning, so an awaited call orders every report
//! ahead of the reads below. That is what makes the negatives — "the
//! bypass received nothing" — evidence rather than a coin flip, and it is
//! why they use `try_recv` and fail instead of hanging.

use super::*;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Semaphore;
use tun_engine::engine::FlowKey;
use tun_engine::{Router, TcpFlow, TcpMeta, UdpMeta};

use crate::drop_sink::recording::{Dropped, RecordingDropSink};
use crate::endpoint::mock::{MockEndpoint, Served};
use crate::filter::rules::RuleSet;
use hole_common::config::{FilterAction, FilterRule, MatchType};

// Fixtures ============================================================================================================

fn v4(s: &str, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(s.parse::<Ipv4Addr>().unwrap()), port)
}

fn v6(s: &str, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(s.parse::<Ipv6Addr>().unwrap()), port)
}

fn rules(specs: &[(&str, MatchType, FilterAction)]) -> RuleSet {
    let user: Vec<FilterRule> = specs
        .iter()
        .map(|(address, matching, action)| FilterRule {
            address: (*address).to_string(),
            matching: *matching,
            action: *action,
        })
        .collect();
    let set = RuleSet::from_user_rules(&user);
    assert!(
        set.dropped.is_empty(),
        "fixture rules must all compile: {:?}",
        set.dropped
    );
    set
}

/// The router under test plus every wired double's receiver, so each test
/// reads all its slots rather than only the one it expects to fire.
struct Wired {
    router: HoleRouter,
    proxy: UnboundedReceiver<Served>,
    bypass: UnboundedReceiver<Served>,
    /// `Some` iff the router was given a local-dns slot.
    local_dns: Option<UnboundedReceiver<Served>>,
    drops: UnboundedReceiver<Dropped>,
}

struct Slots {
    proxy_supports_udp: bool,
    proxy_plugin: Option<&'static str>,
    bypass_supports_ipv6: bool,
    with_local_dns: bool,
}

impl Default for Slots {
    fn default() -> Self {
        Self {
            proxy_supports_udp: true,
            proxy_plugin: None,
            bypass_supports_ipv6: true,
            with_local_dns: false,
        }
    }
}

fn wire(slots: Slots, rules: RuleSet) -> Wired {
    let (proxy, proxy_rx) = match slots.proxy_plugin {
        Some(plugin) => MockEndpoint::with_plugin("proxy", slots.proxy_supports_udp, true, plugin),
        None => MockEndpoint::new("proxy", slots.proxy_supports_udp, true),
    };
    let (bypass, bypass_rx) = MockEndpoint::new("bypass", true, slots.bypass_supports_ipv6);
    let (drops, drops_rx) = RecordingDropSink::new();

    let (local_dns_slot, local_dns_rx) = if slots.with_local_dns {
        let (local_dns, rx) = MockEndpoint::new("local-dns", true, true);
        (Some(Box::new(local_dns) as Box<dyn Endpoint>), Some(rx))
    } else {
        (None, None)
    };
    let router = HoleRouter::with_endpoints(
        Box::new(proxy),
        Box::new(bypass),
        Box::new(drops),
        local_dns_slot,
        rules,
    );

    Wired {
        router,
        proxy: proxy_rx,
        bypass: bypass_rx,
        local_dns: local_dns_rx,
        drops: drops_rx,
    }
}

impl Wired {
    /// Every wired served-slot channel, in a fixed order, for the "no slot
    /// was served" assertions.
    fn endpoint_slots(&mut self) -> Vec<(&'static str, &mut UnboundedReceiver<Served>)> {
        let mut slots = vec![("proxy", &mut self.proxy), ("bypass", &mut self.bypass)];
        if let Some(local_dns) = self.local_dns.as_mut() {
            slots.push(("local-dns", local_dns));
        }
        slots
    }

    fn assert_no_slot_served(&mut self) {
        for (name, rx) in self.endpoint_slots() {
            assert!(
                rx.try_recv().is_err(),
                "{name} slot served a flow the cascade resolved to a drop"
            );
        }
    }

    fn drained_drops(&mut self) -> Vec<Dropped> {
        std::iter::from_fn(|| self.drops.try_recv().ok()).collect()
    }
}

/// A `UdpFlow` and its 5-tuple metadata. The peer end is returned so it
/// outlives the call — dropping it would close the flow underneath the
/// router.
fn udp_flow(src: SocketAddr, dst: SocketAddr) -> (UdpMeta, tun_engine::UdpFlow, tun_engine::sim::UdpFlowPeer) {
    let (flow, peer) = tun_engine::sim::udp_flow(FlowKey { src, dst });
    (UdpMeta { src, dst }, flow, peer)
}

// UDP-drop privacy invariant ==========================================================================================

#[skuld::test]
async fn udp_to_proxy_on_a_tcp_only_plugin_is_recorded_as_a_privacy_drop() {
    let dst = v4("8.8.8.8", 443);
    let mut w = wire(
        Slots {
            proxy_supports_udp: false,
            proxy_plugin: Some("v2ray-plugin"),
            ..Slots::default()
        },
        RuleSet::default(),
    );
    let (meta, flow, _peer) = udp_flow(v4("10.255.0.2", 51000), dst);

    w.router.route_udp(meta, flow).await.unwrap();

    assert_eq!(
        w.drained_drops(),
        vec![Dropped::UdpProxyUnavailable {
            rule_index: 0,
            dst,
            plugin: Some("v2ray-plugin".to_string()),
        }]
    );
}

#[skuld::test]
async fn udp_to_proxy_on_a_tcp_only_plugin_never_reaches_the_bypass() {
    // The leak this invariant exists to prevent: the flow egressing in
    // clear text through the bypass mechanism. The positive control is
    // `udp_to_proxy_on_a_udp_capable_plugin_is_served_by_the_proxy` —
    // without it, these empty channels would also be consistent with a
    // router that serves nothing at all.
    let mut w = wire(
        Slots {
            proxy_supports_udp: false,
            proxy_plugin: Some("v2ray-plugin"),
            ..Slots::default()
        },
        RuleSet::default(),
    );
    let (meta, flow, _peer) = udp_flow(v4("10.255.0.2", 51000), v4("8.8.8.8", 443));

    w.router.route_udp(meta, flow).await.unwrap();

    w.assert_no_slot_served();
}

#[skuld::test]
async fn udp_to_proxy_on_a_udp_capable_plugin_is_served_by_the_proxy() {
    let dst = v4("8.8.8.8", 443);
    let mut w = wire(
        Slots {
            proxy_supports_udp: true,
            proxy_plugin: Some("galoshes"),
            ..Slots::default()
        },
        RuleSet::default(),
    );
    let (meta, flow, _peer) = udp_flow(v4("10.255.0.2", 51000), dst);

    w.router.route_udp(meta, flow).await.unwrap();

    assert_eq!(w.proxy.try_recv(), Ok(Served::Udp(dst)));
    assert!(w.bypass.try_recv().is_err(), "bypass served a proxied flow");
    assert_eq!(w.drained_drops(), vec![]);
}

// UDP/53 divert =======================================================================================================

#[skuld::test]
async fn udp_53_is_served_by_the_local_dns_slot() {
    // A TCP-only plugin, so the divert has to precede the privacy drop
    // rather than merely coincide with a path that would have worked.
    let dst = v4("8.8.8.8", 53);
    let mut w = wire(
        Slots {
            proxy_supports_udp: false,
            proxy_plugin: Some("v2ray-plugin"),
            with_local_dns: true,
            ..Slots::default()
        },
        RuleSet::default(),
    );
    let (meta, flow, _peer) = udp_flow(v4("10.255.0.2", 51000), dst);

    w.router.route_udp(meta, flow).await.unwrap();

    assert_eq!(w.local_dns.as_mut().unwrap().try_recv(), Ok(Served::Udp(dst)));
    assert!(w.proxy.try_recv().is_err(), "proxy served a diverted DNS flow");
    assert_eq!(w.drained_drops(), vec![]);
}

#[skuld::test]
async fn udp_53_without_a_local_dns_slot_follows_the_cascade() {
    let dst = v4("8.8.8.8", 53);
    let mut w = wire(
        Slots {
            proxy_supports_udp: true,
            with_local_dns: false,
            ..Slots::default()
        },
        RuleSet::default(),
    );
    let (meta, flow, _peer) = udp_flow(v4("10.255.0.2", 51000), dst);

    w.router.route_udp(meta, flow).await.unwrap();

    assert_eq!(w.proxy.try_recv(), Ok(Served::Udp(dst)));
    assert!(w.bypass.try_recv().is_err(), "bypass served a proxied DNS flow");
    assert_eq!(w.drained_drops(), vec![]);
}

// The other two drop reasons ==========================================================================================

#[skuld::test]
async fn a_rule_block_is_recorded_and_no_slot_is_served() {
    let dst = v4("1.2.3.4", 443);
    let mut w = wire(
        Slots {
            with_local_dns: true,
            ..Slots::default()
        },
        rules(&[("1.2.3.4/32", MatchType::Subnet, FilterAction::Block)]),
    );
    let (meta, flow, _peer) = udp_flow(v4("10.255.0.2", 51000), dst);

    w.router.route_udp(meta, flow).await.unwrap();

    assert_eq!(w.drained_drops(), vec![Dropped::RuleBlockUdp { rule_index: 0, dst }]);
    w.assert_no_slot_served();
}

#[skuld::test]
async fn an_ipv6_bypass_without_upstream_ipv6_is_recorded_and_no_slot_is_served() {
    let dst = v6("2001:db8::1", 443);
    let mut w = wire(
        Slots {
            bypass_supports_ipv6: false,
            with_local_dns: true,
            ..Slots::default()
        },
        rules(&[("2001:db8::/32", MatchType::Subnet, FilterAction::Bypass)]),
    );
    let (meta, flow, _peer) = udp_flow(v6("fd00::ff00:2", 51000), dst);

    w.router.route_udp(meta, flow).await.unwrap();

    assert_eq!(
        w.drained_drops(),
        vec![Dropped::Ipv6BypassUnreachable {
            rule_index: 0,
            dst,
            l4: "udp",
        }]
    );
    w.assert_no_slot_served();
}

// TCP =================================================================================================================

#[skuld::test]
async fn a_tcp_rule_block_is_recorded_and_no_slot_is_served() {
    // A domain rule, so the sniffer path runs and the recovered name has
    // to survive all the way into the drop record.
    let dst = v4("93.184.216.34", 80);
    let src = v4("10.255.0.2", 51000);
    let mut w = wire(
        Slots {
            with_local_dns: true,
            ..Slots::default()
        },
        rules(&[("example.com", MatchType::Exactly, FilterAction::Block)]),
    );

    let (flow, to_handler, _from_handler) = TcpFlow::new(Arc::new(Semaphore::new(1)));
    to_handler
        .send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec())
        .await
        .unwrap();
    // Closing the write half ends the peek at EOF rather than at its
    // deadline: the sniffer has everything the client will ever send.
    drop(to_handler);

    w.router.route_tcp(TcpMeta { src, dst }, flow).await.unwrap();

    assert_eq!(
        w.drained_drops(),
        vec![Dropped::RuleBlockTcp {
            rule_index: 0,
            dst,
            domain: Some("example.com".to_string()),
        }]
    );
    w.assert_no_slot_served();
}
