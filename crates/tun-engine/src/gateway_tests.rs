use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

#[skuld::test]
#[ignore] // Requires network — run manually with `cargo test -- --ignored`
fn get_default_gateway_info_returns_valid_result() {
    let info = get_default_gateway_info().expect("should detect default gateway info");
    assert!(
        info.gateway_ip.is_ipv4(),
        "expected IPv4 gateway, got {}",
        info.gateway_ip
    );
    assert!(!info.interface_name.is_empty(), "interface name should not be empty");
    assert!(info.interface_index > 0, "interface index should be non-zero");
    // ipv6_available is informational — just ensure it doesn't panic.
    let _ = info.ipv6_available;
}

// tun_ipv6_available probes the TUN's OWN interface, not upstream =====================================================

#[skuld::test]
fn interface_index_by_name_errs_for_an_unknown_name() {
    let result = interface_index_by_name("definitely-not-a-real-adapter-xyz");
    assert!(
        result.is_err(),
        "expected an error for a nonexistent interface, got {result:?}"
    );
}

#[skuld::test]
fn tun_ipv6_available_is_false_when_the_adapter_cannot_be_resolved() {
    // No adapter of this name exists on this host, so resolution fails —
    // `false` is the safe default (tolerate the IPv6 route commands failing,
    // never skip issuing them; see `SetupCommand`).
    assert!(!tun_ipv6_available("definitely-not-a-real-adapter-xyz"));
}

#[skuld::test]
fn probe_ipv6_bound_is_false_for_an_interface_index_that_does_not_exist() {
    // No live NIC has this index — the IPV6_UNICAST_IF/IPV6_BOUND_IF scoping
    // call itself must fail, before any network I/O.
    assert!(!probe_ipv6_bound(u32::MAX));
}

// classify_hop ========================================================================================================
//
// These drive the refusal branches over FABRICATED hops. They are honest
// classification tests and prove nothing about detection — that the lookup can
// see a wintun adapter at all is `tests/gateway_privileged.rs`.

fn hop(next_hop: IpAddr) -> RouteHop {
    RouteHop {
        next_hop,
        interface_index: 42,
        interface_alias: "ProtonVPN TUN".into(),
    }
}

#[skuld::test]
fn classify_hop_maps_no_route_to_no_default_route() {
    let err = classify_hop(None, false).expect_err("no route must be an error");
    assert!(matches!(err, GatewayError::NoDefaultRoute), "got {err:?}");
}

/// An on-link default route is a route **form**, not a refusal — the
/// interface-scoped bypass (`routing.rs`) is what makes it usable. Run for
/// both families: reading the on-link marker with the wrong address family
/// would silently mis-handle a dual-stack host, which is exactly the cohort
/// this exists for.
#[skuld::test]
fn an_on_link_default_classifies_as_on_link_not_an_error() {
    let info = classify_hop(Some(hop(IpAddr::V4(Ipv4Addr::UNSPECIFIED))), false).expect("on-link must not be refused");
    assert_eq!(info.next_hop, NextHop::OnLink);
}

#[skuld::test]
fn an_on_link_ipv6_default_classifies_as_on_link() {
    let info = classify_hop(Some(hop(IpAddr::V6(Ipv6Addr::UNSPECIFIED))), false).expect("on-link must not be refused");
    assert_eq!(info.next_hop, NextHop::OnLink);
}

/// The regression guard that matters most: an ordinary gateway must keep
/// classifying as `Via`, never `OnLink` — this is the common case every VPN
/// user relies on.
#[skuld::test]
fn a_gateway_default_still_classifies_as_via() {
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
    let info = classify_hop(Some(hop(gateway)), false).expect("a real next hop is usable");
    assert_eq!(info.next_hop, NextHop::Via(gateway));
}

#[skuld::test]
fn a_gateway_ipv6_default_classifies_as_via() {
    let gateway: IpAddr = "2001:db8::1".parse().unwrap();
    let info = classify_hop(Some(hop(gateway)), false).expect("a real next hop is usable");
    assert_eq!(info.next_hop, NextHop::Via(gateway));
}

#[skuld::test]
fn classify_hop_maps_empty_alias_to_interface_name_unavailable() {
    let nameless = RouteHop {
        next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        interface_index: 7,
        interface_alias: String::new(),
    };
    let err = classify_hop(Some(nameless), false).expect_err("an unnamed adapter must be refused");
    assert!(
        matches!(err, GatewayError::InterfaceNameUnavailable { interface_index: 7, .. }),
        "got {err:?}"
    );
}

#[skuld::test]
fn classify_hop_accepts_a_real_next_hop() {
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
    let info = classify_hop(Some(hop(gateway)), true).expect("a real next hop is usable");
    assert_eq!(info.gateway_ip, gateway);
    assert_eq!(info.next_hop, NextHop::Via(gateway));
    assert_eq!(info.interface_name, "ProtonVPN TUN");
    assert_eq!(info.interface_index, 42);
    assert!(info.ipv6_available);
}

// macOS's on-link mapping =============================================================================================
//
// Pure and platform-independent, so it is testable on every host regardless
// of which platform's `get_default_gateway_info` calls it. macOS has no
// interface-scoped IPv4 bypass form (`routing.rs`), so on-link must stay a
// refusal there even though Windows now accepts it.

#[skuld::test]
fn reject_macos_on_link_refuses_on_link_as_no_default_route() {
    let info = classify_hop(Some(hop(IpAddr::V4(Ipv4Addr::UNSPECIFIED))), false).unwrap();
    let err = reject_macos_on_link(info).expect_err("macOS must still refuse on-link");
    assert!(matches!(err, GatewayError::NoDefaultRoute), "got {err:?}");
}

#[skuld::test]
fn reject_macos_on_link_passes_a_real_gateway_through_unchanged() {
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
    let info = classify_hop(Some(hop(gateway)), true).unwrap();
    let passed = reject_macos_on_link(info.clone()).expect("a real gateway must not be refused");
    assert_eq!(passed, info);
}

// macOS default-interface lookup ======================================================================================
//
// The macOS arm of `get_default_gateway_info` is two pure steps over what
// `default-net` and `if_nametoindex` return; these drive them on any host.

/// Capture `WARN`-and-above records for the duration of `body`.
fn captured(body: impl FnOnce()) -> String {
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    let writer = garter::test_utils::WaitableWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        body();
    }
    writer.snapshot()
}

/// `default-net` hands back a `String`; it is the only diagnostic there is, so
/// it must survive as the error's `source()`.
#[skuld::test]
fn a_default_net_failure_keeps_its_text_as_the_source() {
    let err = default_net_query_failed("no default interface from the routing socket".to_string());

    assert!(
        matches!(err, GatewayError::RouteQueryFailed { code: 0, .. }),
        "got {err:?}"
    );
    let source = std::error::Error::source(&err).expect("the default-net text must be the source");
    assert_eq!(source.to_string(), "no default interface from the routing socket");
    assert_eq!(
        err.to_string(),
        "Could not read the system routing table. See bridge.log for details.",
        "the toast sentence must not change"
    );
}

#[skuld::test]
fn an_unnameable_default_interface_is_logged_with_its_index() {
    let mut result = None;
    let log = captured(|| {
        result = Some(index_or_unavailable("en0", 17, |_| {
            Err(std::io::Error::other("if_nametoindex failed for 'en0'"))
        }));
    });

    let err = result.unwrap().expect_err("a failed lookup is an error");
    assert!(
        matches!(
            err,
            GatewayError::InterfaceNameUnavailable {
                interface_index: 17,
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(
        std::error::Error::source(&err)
            .expect("lookup error is the source")
            .to_string(),
        "if_nametoindex failed for 'en0'"
    );
    assert!(
        log.contains("interface_index=17"),
        "bridge.log must name the index: {log}"
    );
}

#[skuld::test]
fn a_nameable_default_interface_returns_the_os_index_not_the_default_net_one() {
    let log = captured(|| {
        assert_eq!(
            index_or_unavailable("en0", 17, |name| {
                assert_eq!(name, "en0");
                Ok(4)
            })
            .unwrap(),
            4
        );
    });
    assert!(log.is_empty(), "success must log nothing at WARN: {log}");
}
