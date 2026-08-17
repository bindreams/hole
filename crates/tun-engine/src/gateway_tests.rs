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

// classify_hop ========================================================================================================
//
// These drive the refusal branches over FABRICATED hops. They are honest
// classification tests and prove nothing about detection — that the lookup can
// see a wintun adapter at all is `gateway/windows_privileged_tests.rs`.

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

/// Run for both families: reading the on-link marker with the wrong address
/// family would silently turn "no gateway" into a working start pointed at
/// `0.0.0.0`.
#[skuld::test]
fn classify_hop_maps_unspecified_next_hop_to_no_usable_gateway() {
    for unspecified in [IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V6(Ipv6Addr::UNSPECIFIED)] {
        let err = classify_hop(Some(hop(unspecified)), false).expect_err("on-link must be refused");
        assert!(
            matches!(err, GatewayError::NoUsableGateway { .. }),
            "{unspecified} should be on-link, got {err:?}"
        );
    }
}

/// The refusal branch must not destroy the adapter its own copy tells the user
/// to look up. Without this the toast says "see bridge.log for the adapter
/// involved" and `bridge.log` names nothing.
#[skuld::test]
fn classify_hop_preserves_the_adapter_in_the_error() {
    let err = classify_hop(Some(hop(IpAddr::V4(Ipv4Addr::UNSPECIFIED))), false).expect_err("on-link is refused");
    let GatewayError::NoUsableGateway { detail } = &err else {
        panic!("expected NoUsableGateway, got {err:?}");
    };
    assert_eq!(detail.interface_alias, "ProtonVPN TUN");
    assert_eq!(detail.interface_index, 42);
    assert_eq!(detail.next_hop, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
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
    assert_eq!(info.interface_name, "ProtonVPN TUN");
    assert_eq!(info.interface_index, 42);
    assert!(info.ipv6_available);
}
