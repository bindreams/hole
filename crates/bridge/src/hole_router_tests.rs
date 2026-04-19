//! Unit tests for [`HoleRouter`].
//!
//! The trait-based refactor makes dispatch unit-testable without a real
//! TUN device: the cascade's `resolve_endpoint` is driven directly over
//! a table of `(FilterAction, L4Proto, dst, proxy_udp, bypass_v6)` rows
//! and asserts which endpoint (or drop reason) the cascade chose. Real
//! socket plumbing is exercised indirectly by the ProxyManager e2e
//! tests.

use super::*;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use std::sync::Arc;

use crate::dns::connector::DirectConnector;
use crate::dns::forwarder::DnsForwarder;
use crate::endpoint::{BlockEndpoint, InterfaceEndpoint, LocalDnsEndpoint, Socks5Endpoint};
use crate::filter::rules::RuleSet;
use hole_common::config::{DnsConfig, DnsProtocol, FilterAction};

fn v4(s: &str, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(s.parse::<Ipv4Addr>().unwrap()), port)
}

fn v6(s: &str, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(s.parse::<Ipv6Addr>().unwrap()), port)
}

fn router_with(proxy_udp: bool, bypass_v6: bool) -> HoleRouter {
    let proxy = Socks5Endpoint::new(v4("127.0.0.1", 1080), Some("test-plugin".into()), proxy_udp);
    let bypass = InterfaceEndpoint::new(1, bypass_v6);
    let block = BlockEndpoint::new();
    HoleRouter::new(proxy, bypass, block, RuleSet::default())
}

// Lifecycle smoke =====================================================================================================

#[skuld::test]
fn swap_rules_updates_and_invalid_filters_reads() {
    let r = router_with(true, true);
    assert!(r.invalid_filters().is_empty());
    r.swap_rules(RuleSet::default());
    assert!(r.invalid_filters().is_empty());
}

// Capability flags on the real endpoint types =========================================================================

#[skuld::test]
fn socks5_endpoint_capabilities_reflect_constructor() {
    let with_udp = Socks5Endpoint::new(v4("127.0.0.1", 1080), Some("galoshes".into()), true);
    assert!(with_udp.supports_udp());
    assert!(with_udp.supports_ipv6_dst());
    assert_eq!(with_udp.name(), "socks5(galoshes)");
    assert_eq!(with_udp.plugin_name(), Some("galoshes"));

    let without_udp = Socks5Endpoint::new(v4("127.0.0.1", 1080), Some("v2ray-plugin".into()), false);
    assert!(!without_udp.supports_udp());
    assert!(without_udp.supports_ipv6_dst()); // SOCKS5 always supports v6 dst.
    assert_eq!(without_udp.name(), "socks5(v2ray-plugin)");

    let no_plugin = Socks5Endpoint::new(v4("127.0.0.1", 1080), None, true);
    assert_eq!(no_plugin.name(), "socks5");
    assert_eq!(no_plugin.plugin_name(), None);
}

#[skuld::test]
fn interface_endpoint_capabilities_reflect_constructor() {
    let with_v6 = InterfaceEndpoint::new(5, true);
    assert!(with_v6.supports_udp()); // Raw socket always supports UDP.
    assert!(with_v6.supports_ipv6_dst());
    assert_eq!(with_v6.iface_index(), 5);

    let without_v6 = InterfaceEndpoint::new(5, false);
    assert!(without_v6.supports_udp());
    assert!(!without_v6.supports_ipv6_dst());
}

#[skuld::test]
fn block_endpoint_has_uniform_capabilities() {
    let block = BlockEndpoint::new();
    // Block doesn't care about the flow's protocol or addressing; it drops.
    assert!(block.supports_udp());
    assert!(block.supports_ipv6_dst());
    assert_eq!(block.name(), "block");
}

// Cascade table =======================================================================================================
//
// Drives `HoleRouter::resolve_endpoint` directly (the private method is
// reachable here because `hole_router_tests` is nested under
// `hole_router`). Each row covers a `(FilterAction, l4, dst, proxy_udp,
// bypass_v6)` combination and asserts which cascade output we expect.
// This is the primary unit-level regression gate for the UDP-drop
// privacy invariant.

#[derive(Debug, PartialEq, Eq)]
enum ExpectedEndpoint {
    Proxy,
    Bypass,
    Drop { reason: &'static str },
}

#[derive(Debug, PartialEq, Eq)]
enum DnsExpectedEndpoint {
    Proxy,
    Bypass,
    LocalDns,
    Drop { reason: &'static str },
}

fn classify(d: Dispatch<'_>, router: &HoleRouter) -> ExpectedEndpoint {
    match d {
        Dispatch::Endpoint(e) => {
            if std::ptr::eq(e as *const _ as *const (), &router.proxy as *const _ as *const ()) {
                ExpectedEndpoint::Proxy
            } else if std::ptr::eq(e as *const _ as *const (), &router.bypass as *const _ as *const ()) {
                ExpectedEndpoint::Bypass
            } else {
                panic!("resolve_endpoint returned an unknown &dyn Endpoint")
            }
        }
        Dispatch::Drop(r) => {
            let reason = match r {
                DropReason::RuleBlock { .. } => "rule_block",
                DropReason::UdpProxyUnavailable { .. } => "udp_proxy_unavailable",
                DropReason::Ipv6BypassUnreachable { .. } => "ipv6_bypass_unreachable",
            };
            ExpectedEndpoint::Drop { reason }
        }
    }
}

fn classify_with_dns(d: Dispatch<'_>, router: &HoleRouter) -> DnsExpectedEndpoint {
    match d {
        Dispatch::Endpoint(e) => {
            if std::ptr::eq(e as *const _ as *const (), &router.proxy as *const _ as *const ()) {
                DnsExpectedEndpoint::Proxy
            } else if std::ptr::eq(e as *const _ as *const (), &router.bypass as *const _ as *const ()) {
                DnsExpectedEndpoint::Bypass
            } else {
                DnsExpectedEndpoint::LocalDns
            }
        }
        Dispatch::Drop(r) => {
            let reason = match r {
                DropReason::RuleBlock { .. } => "rule_block",
                DropReason::UdpProxyUnavailable { .. } => "udp_proxy_unavailable",
                DropReason::Ipv6BypassUnreachable { .. } => "ipv6_bypass_unreachable",
            };
            DnsExpectedEndpoint::Drop { reason }
        }
    }
}

fn sample_dns_cfg() -> DnsConfig {
    DnsConfig {
        enabled: true,
        servers: vec!["192.0.2.1".parse().unwrap()],
        protocol: DnsProtocol::PlainUdp,
        intercept_udp53: true,
    }
}

fn router_with_local_dns(proxy_udp: bool, bypass_v6: bool) -> HoleRouter {
    let proxy = Socks5Endpoint::new(v4("127.0.0.1", 1080), Some("test-plugin".into()), proxy_udp);
    let bypass = InterfaceEndpoint::new(1, bypass_v6);
    let block = BlockEndpoint::new();
    let fwd = Arc::new(DnsForwarder::new(sample_dns_cfg(), Arc::new(DirectConnector), true));
    let local_dns = LocalDnsEndpoint::new(fwd);
    HoleRouter::with_local_dns(proxy, bypass, block, Some(local_dns), RuleSet::default())
}

#[skuld::test]
fn cascade_table() {
    let ipv4 = v4("1.2.3.4", 443);
    let ipv6 = v6("2001:db8::1", 443);

    use ExpectedEndpoint as E;
    use FilterAction::{Block, Bypass, Proxy};
    use L4Proto::{Tcp, Udp};

    // (action, l4, dst, proxy_udp, bypass_v6, expected)
    let rows: &[(FilterAction, L4Proto, SocketAddr, bool, bool, ExpectedEndpoint)] = &[
        (Proxy, Tcp, ipv4, true, true, E::Proxy),
        (Proxy, Tcp, ipv6, true, true, E::Proxy),
        (Proxy, Tcp, ipv6, true, false, E::Proxy), // bypass_v6 doesn't gate proxy
        (Proxy, Udp, ipv4, true, true, E::Proxy),
        (
            Proxy,
            Udp,
            ipv4,
            false,
            true,
            E::Drop {
                reason: "udp_proxy_unavailable",
            },
        ), // privacy invariant
        (
            Proxy,
            Udp,
            ipv4,
            false,
            false,
            E::Drop {
                reason: "udp_proxy_unavailable",
            },
        ),
        (
            Proxy,
            Udp,
            ipv6,
            false,
            true,
            E::Drop {
                reason: "udp_proxy_unavailable",
            },
        ),
        (
            Proxy,
            Udp,
            ipv6,
            false,
            false,
            E::Drop {
                reason: "udp_proxy_unavailable",
            },
        ),
        (Bypass, Tcp, ipv4, true, true, E::Bypass),
        (
            Bypass,
            Tcp,
            ipv6,
            true,
            false,
            E::Drop {
                reason: "ipv6_bypass_unreachable",
            },
        ),
        (Bypass, Tcp, ipv6, true, true, E::Bypass),
        (Bypass, Udp, ipv4, true, true, E::Bypass),
        (Bypass, Udp, ipv6, true, true, E::Bypass),
        (
            Bypass,
            Udp,
            ipv6,
            true,
            false,
            E::Drop {
                reason: "ipv6_bypass_unreachable",
            },
        ),
        (Block, Tcp, ipv4, true, true, E::Drop { reason: "rule_block" }),
        (Block, Udp, ipv6, true, true, E::Drop { reason: "rule_block" }),
    ];

    for (action, l4, dst, proxy_udp, bypass_v6, expected) in rows {
        let router = router_with(*proxy_udp, *bypass_v6);
        let got = classify(router.resolve_endpoint(*action, *l4, *dst, Some(0)), &router);
        assert_eq!(
            got, *expected,
            "resolve_endpoint({action:?}, {l4:?}, {dst}, proxy_udp={proxy_udp}, bypass_v6={bypass_v6})"
        );
    }
}

// BlockEndpoint log-methods — rate-limit and one-shot behavior ========================================================

// LocalDns interception ===============================================================================================

#[skuld::test]
fn udp53_to_external_ip_intercepted_when_local_dns_present() {
    let r = router_with_local_dns(false, true);
    // UDP/53 to an external resolver — normally this would be dropped by
    // the UDP-proxy-unavailable invariant (proxy_udp=false), but the
    // LocalDnsEndpoint precedes the action cascade.
    let got = classify_with_dns(
        r.resolve_endpoint(FilterAction::Proxy, L4Proto::Udp, v4("8.8.8.8", 53), Some(0)),
        &r,
    );
    assert_eq!(got, DnsExpectedEndpoint::LocalDns);
}

#[skuld::test]
fn udp53_intercepted_even_when_rule_says_block() {
    // The hardcoded-DoH case: user has a rule `Block 1.1.1.1`, but Chrome
    // hits 1.1.1.1:53 for DoH. We still serve via local DNS.
    let r = router_with_local_dns(true, true);
    let got = classify_with_dns(
        r.resolve_endpoint(FilterAction::Block, L4Proto::Udp, v4("1.1.1.1", 53), Some(0)),
        &r,
    );
    assert_eq!(got, DnsExpectedEndpoint::LocalDns);
}

#[skuld::test]
fn udp53_intercepted_even_when_rule_says_bypass() {
    let r = router_with_local_dns(true, true);
    let got = classify_with_dns(
        r.resolve_endpoint(FilterAction::Bypass, L4Proto::Udp, v4("8.8.4.4", 53), Some(0)),
        &r,
    );
    assert_eq!(got, DnsExpectedEndpoint::LocalDns);
}

#[skuld::test]
fn tcp53_not_intercepted_even_with_local_dns() {
    // TCP/53 is out of scope for LocalDnsEndpoint (could be AXFR etc.).
    let r = router_with_local_dns(true, true);
    let got = classify_with_dns(
        r.resolve_endpoint(FilterAction::Proxy, L4Proto::Tcp, v4("1.1.1.1", 53), Some(0)),
        &r,
    );
    assert_eq!(got, DnsExpectedEndpoint::Proxy);
}

#[skuld::test]
fn udp53_v6_destination_also_intercepted() {
    let r = router_with_local_dns(false, false);
    let got = classify_with_dns(
        r.resolve_endpoint(
            FilterAction::Proxy,
            L4Proto::Udp,
            v6("2001:4860:4860::8888", 53),
            Some(0),
        ),
        &r,
    );
    assert_eq!(got, DnsExpectedEndpoint::LocalDns);
}

#[skuld::test]
fn udp53_without_local_dns_keeps_existing_behavior() {
    // When local_dns is None (intercept_udp53 disabled), the cascade
    // reverts to the pre-refactor behavior: Proxy + UDP + !proxy_udp
    // drops via the privacy invariant.
    let r = router_with(false, true);
    let got = classify(
        r.resolve_endpoint(FilterAction::Proxy, L4Proto::Udp, v4("8.8.8.8", 53), Some(0)),
        &r,
    );
    assert_eq!(
        got,
        ExpectedEndpoint::Drop {
            reason: "udp_proxy_unavailable"
        }
    );
}

#[skuld::test]
fn udp_non53_not_intercepted_by_local_dns() {
    // Non-53 UDP should not hit LocalDnsEndpoint even when it's present.
    let r = router_with_local_dns(true, true);
    let got = classify_with_dns(
        r.resolve_endpoint(FilterAction::Proxy, L4Proto::Udp, v4("8.8.8.8", 443), Some(0)),
        &r,
    );
    assert_eq!(got, DnsExpectedEndpoint::Proxy);
}

// BlockEndpoint log-methods — rate-limit and one-shot behavior ========================================================

#[skuld::test]
fn ipv6_bypass_unreachable_warn_is_one_shot() {
    // Simply smoke-check the one-shot flag — we can call twice and see
    // the AtomicBool transition, then the subsequent call finds it already
    // set. Logging is side-effect-free for the test (tracing is not
    // subscribed).
    let block = BlockEndpoint::new();
    let dst = v6("2001:db8::1", 443);
    block.log_ipv6_bypass_unreachable(0, dst, "tcp");
    block.log_ipv6_bypass_unreachable(0, dst, "tcp"); // second call — one-shot warn no-ops
}

#[skuld::test]
fn block_endpoint_rate_limits_rule_block_logs() {
    // Per-flow dedup: BlockLog's `should_log(rule_index, dst)` suppresses
    // duplicate calls within its TTL window.
    let block = BlockEndpoint::new();
    let dst = v4("1.2.3.4", 80);
    // First N calls for the same key cost nothing to emit (at most one log
    // line). This is a smoke check; tracing capture is not wired in the
    // test harness.
    for _ in 0..8 {
        block.log_rule_block_tcp(7, dst, Some("example.com"));
    }
    block.log_rule_block_udp(7, dst);
    block.log_udp_proxy_unavailable(7, dst, Some("v2ray-plugin"));
}
