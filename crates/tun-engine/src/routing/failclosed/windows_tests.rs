use super::*;
use std::net::IpAddr;

fn v4() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}
fn v6() -> IpAddr {
    "2001:db8::1".parse().unwrap()
}

#[skuld::test]
fn spec_blocks_on_both_v4_and_v6_layers() {
    let s = build_cover_spec(v4());
    assert!(s
        .filters
        .iter()
        .any(|f| f.layer == Layer::ConnectV4 && f.action == Action::Block));
    assert!(s
        .filters
        .iter()
        .any(|f| f.layer == Layer::ConnectV6 && f.action == Action::Block));
}

#[skuld::test]
fn spec_permits_loopback_on_both_layers() {
    let s = build_cover_spec(v4());
    let loopback_permits = s
        .filters
        .iter()
        .filter(|f| f.action == Action::Permit && matches!(f.condition, Condition::Loopback))
        .count();
    assert_eq!(loopback_permits, 2, "loopback permit on V4 and V6");
}

#[skuld::test]
fn spec_permits_v4_server_on_v4_layer_only() {
    let s = build_cover_spec(v4());
    let server_permits: Vec<_> = s
        .filters
        .iter()
        .filter(|f| f.action == Action::Permit && matches!(f.condition, Condition::RemoteIp(_)))
        .collect();
    assert_eq!(server_permits.len(), 1);
    assert_eq!(server_permits[0].layer, Layer::ConnectV4);
    assert!(matches!(server_permits[0].condition, Condition::RemoteIp(ip) if ip == v4()));
}

#[skuld::test]
fn spec_permits_v6_server_on_v6_layer_only() {
    let s = build_cover_spec(v6());
    let server_permits: Vec<_> = s
        .filters
        .iter()
        .filter(|f| f.action == Action::Permit && matches!(f.condition, Condition::RemoteIp(_)))
        .collect();
    assert_eq!(server_permits.len(), 1);
    assert_eq!(server_permits[0].layer, Layer::ConnectV6);
}

#[skuld::test]
fn permit_filters_are_hard_and_outweigh_block() {
    let s = build_cover_spec(v4());
    for f in &s.filters {
        match f.action {
            Action::Permit => {
                assert!(
                    f.hard,
                    "permits must be hard (CLEAR_ACTION_RIGHT) so other firewalls can't veto"
                );
                assert_eq!(f.weight, PERMIT_WEIGHT);
                assert!(f.weight > BLOCK_WEIGHT, "permit must outweigh block in our sublayer");
            }
            Action::Block => {
                assert!(!f.hard);
                assert_eq!(f.weight, BLOCK_WEIGHT);
            }
        }
    }
}

#[skuld::test]
fn spec_uses_the_fixed_hole_guids() {
    let s = build_cover_spec(v4());
    assert_eq!(s.provider, PROVIDER_GUID);
    assert_eq!(s.sublayer, SUBLAYER_GUID);
}
