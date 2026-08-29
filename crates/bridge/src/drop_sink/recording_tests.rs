//! Tests for [`RecordingDropSink`]. Every drop assertion in
//! `hole_router_dispatch_tests.rs` reads this sink, so a sink that
//! recorded nothing, or that lost a field on the way, would make those
//! proofs vacuous. Each reason is driven directly here, once, with
//! distinct field values so a crossed wire shows up as a mismatch rather
//! than as a coincidence.

use super::*;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn v4(s: &str, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(s.parse::<Ipv4Addr>().unwrap()), port)
}

fn v6(s: &str, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(s.parse::<Ipv6Addr>().unwrap()), port)
}

#[skuld::test]
fn a_recording_drop_sink_reports_each_reason_with_its_fields() {
    let (sink, mut records) = RecordingDropSink::new();

    let tcp_dst = v4("1.2.3.4", 443);
    let udp_dst = v4("5.6.7.8", 4433);
    let privacy_dst = v4("9.10.11.12", 51820);
    let v6_dst = v6("2001:db8::1", 80);

    sink.rule_block_tcp(1, tcp_dst, Some("example.com"));
    sink.rule_block_tcp(2, tcp_dst, None);
    sink.rule_block_udp(3, udp_dst);
    sink.udp_proxy_unavailable(4, privacy_dst, Some("v2ray-plugin"));
    sink.udp_proxy_unavailable(5, privacy_dst, None);
    sink.ipv6_bypass_unreachable(6, v6_dst, "tcp");

    // Rendezvous: each record was sent before its `sink.*` call returned,
    // so the six reads below are ordered after all six sends.
    let got: Vec<Dropped> = std::iter::from_fn(|| records.try_recv().ok()).collect();
    assert_eq!(
        got,
        vec![
            Dropped::RuleBlockTcp {
                rule_index: 1,
                dst: tcp_dst,
                domain: Some("example.com".to_string()),
            },
            Dropped::RuleBlockTcp {
                rule_index: 2,
                dst: tcp_dst,
                domain: None,
            },
            Dropped::RuleBlockUdp {
                rule_index: 3,
                dst: udp_dst,
            },
            Dropped::UdpProxyUnavailable {
                rule_index: 4,
                dst: privacy_dst,
                plugin: Some("v2ray-plugin".to_string()),
            },
            Dropped::UdpProxyUnavailable {
                rule_index: 5,
                dst: privacy_dst,
                plugin: None,
            },
            Dropped::Ipv6BypassUnreachable {
                rule_index: 6,
                dst: v6_dst,
                l4: "tcp",
            },
        ]
    );
}
