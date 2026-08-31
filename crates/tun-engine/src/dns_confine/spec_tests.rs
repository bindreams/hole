use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

const TUN_LUID: u64 = 0x1234_5678_9abc_def0;
const SERVER_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

#[skuld::test]
fn spec_permits_dns_only_on_the_named_interface() {
    let spec = build_spec(TUN_LUID, SERVER_V4);

    let on_interface_permits: Vec<&FilterSpec> = spec
        .filters
        .iter()
        .filter(|f| matches!(f.condition, Condition::OnInterface { .. }))
        .collect();

    // 2 families x 2 protocols.
    assert_eq!(on_interface_permits.len(), 4);
    for f in on_interface_permits {
        assert_eq!(f.action, Action::Permit);
        let Condition::OnInterface { luid, remote_port, .. } = f.condition else {
            unreachable!()
        };
        assert_eq!(luid, TUN_LUID);
        assert_eq!(remote_port, DNS_PORT);
    }
}

#[skuld::test]
fn spec_blocks_both_families_and_both_l4() {
    let spec = build_spec(TUN_LUID, SERVER_V4);

    let blocks: Vec<&FilterSpec> = spec.filters.iter().filter(|f| f.action == Action::Block).collect();
    assert_eq!(blocks.len(), 4, "expected exactly one block per (family, l4) pair");

    let mut seen: Vec<(Layer, L4)> = Vec::new();
    for f in &blocks {
        let Condition::AnyTo { l4, remote_port } = f.condition else {
            panic!("every Block filter must carry Condition::AnyTo, got {:?}", f.condition);
        };
        assert_eq!(remote_port, DNS_PORT);
        seen.push((f.layer, l4));
    }
    for layer in [Layer::ConnectV4, Layer::ConnectV6] {
        for l4 in [L4::Udp, L4::Tcp] {
            assert!(
                seen.contains(&(layer, l4)),
                "missing block for {layer:?}/{l4:?}; got {seen:?}"
            );
        }
    }
}

#[skuld::test]
fn spec_permits_outrank_blocks() {
    // A compile-time invariant, not a runtime comparison — clippy flags
    // asserting on two `const`s as dead weight; `const { }` makes the
    // check happen at compile time instead, which is what it actually is.
    const { assert!(PERMIT_WEIGHT > BLOCK_WEIGHT) };
}

#[skuld::test]
fn spec_blocks_only_port_53() {
    let spec = build_spec(TUN_LUID, SERVER_V4);
    for f in spec.filters.iter().filter(|f| f.action == Action::Block) {
        let Condition::AnyTo { remote_port, .. } = f.condition else {
            panic!("Block filter with non-AnyTo condition: {:?}", f.condition);
        };
        assert_eq!(remote_port, 53);
    }
}

#[skuld::test]
fn spec_permits_the_server_ip_on_any_port() {
    let spec = build_spec(TUN_LUID, SERVER_V4);
    let server_permits: Vec<&FilterSpec> = spec
        .filters
        .iter()
        .filter(|f| matches!(f.condition, Condition::ServerIp(_)))
        .collect();
    assert_eq!(server_permits.len(), 1);
    let f = server_permits[0];
    assert_eq!(f.action, Action::Permit);
    assert_eq!(f.weight, PERMIT_WEIGHT);
    assert_eq!(f.condition, Condition::ServerIp(SERVER_V4));
    assert_eq!(f.layer, Layer::ConnectV4);
}

#[skuld::test]
fn spec_permits_the_server_ip_v6_on_its_own_layer() {
    let server_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let spec = build_spec(TUN_LUID, server_v6);
    let server_permits: Vec<&FilterSpec> = spec
        .filters
        .iter()
        .filter(|f| matches!(f.condition, Condition::ServerIp(_)))
        .collect();
    assert_eq!(server_permits.len(), 1);
    assert_eq!(server_permits[0].layer, Layer::ConnectV6);
}

/// Every other `Condition` variant gets a structural test; this is
/// `LoopbackNet`'s: count, action, weight, port, and that the address
/// matches the family's loopback constant per layer.
#[skuld::test]
fn spec_permits_loopback_dns_per_family() {
    let spec = build_spec(TUN_LUID, SERVER_V4);
    let loopback_permits: Vec<&FilterSpec> = spec
        .filters
        .iter()
        .filter(|f| matches!(f.condition, Condition::LoopbackNet { .. }))
        .collect();

    // 2 families x 2 protocols.
    assert_eq!(loopback_permits.len(), 4);
    for f in &loopback_permits {
        assert_eq!(f.action, Action::Permit);
        assert_eq!(f.weight, PERMIT_WEIGHT);
        let Condition::LoopbackNet { addr, remote_port, .. } = f.condition else {
            unreachable!()
        };
        assert_eq!(remote_port, DNS_PORT);
        let expected_addr = match f.layer {
            Layer::ConnectV4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Layer::ConnectV6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        assert_eq!(
            addr, expected_addr,
            "loopback address must match its own layer's family"
        );
    }
    for layer in [Layer::ConnectV4, Layer::ConnectV6] {
        for l4 in [L4::Udp, L4::Tcp] {
            assert!(
                loopback_permits.iter().any(|f| f.layer == layer
                    && matches!(f.condition, Condition::LoopbackNet { l4: c_l4, .. } if c_l4 == l4)),
                "missing loopback permit for {layer:?}/{l4:?}"
            );
        }
    }
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn spec_guids_are_disjoint_from_the_cover_guids() {
    use crate::routing::failclosed::platform::{
        FILTER_GUIDS, LOCKDOWN_FILTER_GUIDS, PROVIDER_GUID as COVER_PROVIDER_GUID, SUBLAYER_GUID as COVER_SUBLAYER_GUID,
    };

    let provider = windows::core::GUID::from_u128(super::PROVIDER_GUID.0);
    let sublayer = windows::core::GUID::from_u128(super::SUBLAYER_GUID.0);

    let cover_provider_and_sublayer = [COVER_PROVIDER_GUID, COVER_SUBLAYER_GUID];
    for g in FILTER_GUIDS
        .iter()
        .chain(LOCKDOWN_FILTER_GUIDS.iter())
        .chain(cover_provider_and_sublayer.iter())
    {
        assert_ne!(
            *g, provider,
            "dns_confine PROVIDER_GUID collides with a cover filter/provider/sublayer GUID"
        );
        assert_ne!(
            *g, sublayer,
            "dns_confine SUBLAYER_GUID collides with a cover filter/provider/sublayer GUID"
        );
    }
}
