//! Tests for [`MockEndpoint`]. The double is load-bearing for the
//! cascade proofs in `hole_router_dispatch_tests.rs`, so its own
//! reporting and capability contract are pinned here: a mock that
//! silently reported nothing would make every negative assertion over
//! there pass vacuously.

use super::*;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::sync::Semaphore;

fn v4(s: &str, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(s.parse::<Ipv4Addr>().unwrap()), port)
}

/// The UDP arm is proved in `hole_router_dispatch_tests.rs`, which reaches
/// `serve_udp` through the cascade with a `UdpFlow` from `tun_engine::sim`
/// — a `UdpFlow` has no constructor reachable from here.
#[skuld::test]
async fn a_mock_endpoint_reports_what_it_served() {
    let (endpoint, mut served) = MockEndpoint::new("mock", true, true);
    let dst = v4("1.2.3.4", 443);
    let (mut flow, _to_handler, _from_handler) = TcpFlow::new(Arc::new(Semaphore::new(1)));

    endpoint.serve_tcp(&mut flow, dst).await.unwrap();

    // The report is sent before `serve_tcp` returns, so the completed
    // call orders it ahead of this read: `try_recv` is sound and, unlike
    // an await, a mock that reports nothing fails here instead of hanging.
    assert_eq!(served.try_recv(), Ok(Served::Tcp(dst)));
    assert!(served.try_recv().is_err(), "one serve_tcp, one report");
}

#[skuld::test]
fn mock_capability_flags_are_stable() {
    // The `Endpoint` doc requires the capability accessors to be pure and
    // stable for the endpoint's lifetime — the cascade's drop gates read
    // them once per flow and a varying answer would leak flows past.
    let (endpoint, _served) = MockEndpoint::new("tcp-only", false, true);
    assert!(!endpoint.supports_udp());
    assert!(endpoint.supports_ipv6_dst());
    assert!(!endpoint.supports_udp());
    assert!(endpoint.supports_ipv6_dst());
    assert_eq!(endpoint.name(), "tcp-only");
    assert_eq!(endpoint.plugin_name(), None);

    let (v6_less, _served) = MockEndpoint::with_plugin("bypass", true, false, "v2ray-plugin");
    assert!(v6_less.supports_udp());
    assert!(!v6_less.supports_ipv6_dst());
    assert_eq!(v6_less.plugin_name(), Some("v2ray-plugin"));
}
