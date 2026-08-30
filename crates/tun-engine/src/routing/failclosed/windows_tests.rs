use super::*;
use std::net::IpAddr;

use crate::GLOBAL_NET_STATE;

fn v4() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}
fn v6() -> IpAddr {
    "2001:db8::1".parse().unwrap()
}
fn resolver_v4() -> IpAddr {
    "198.51.100.5".parse().unwrap()
}
fn resolver_v6() -> IpAddr {
    "2001:db8::abcd".parse().unwrap()
}

#[skuld::test]
fn spec_blocks_egress_only_on_both_v4_and_v6_layers() {
    // The block-all is an egress kill switch: CONNECT only. Blocking RECV_ACCEPT
    // would make it an inbound firewall (out of scope, and inconsistent with the
    // macOS `set skip on lo0` egress-only model).
    let s = build_cover_spec(v4(), None);
    assert!(s
        .filters
        .iter()
        .any(|f| f.layer == Layer::ConnectV4 && f.action == Action::Block));
    assert!(s
        .filters
        .iter()
        .any(|f| f.layer == Layer::ConnectV6 && f.action == Action::Block));
    assert!(
        !s.filters
            .iter()
            .any(|f| matches!(f.layer, Layer::RecvAcceptV4 | Layer::RecvAcceptV6) && f.action == Action::Block),
        "block-all must stay CONNECT-only (egress kill switch, not an inbound firewall)"
    );
}

#[skuld::test]
fn spec_permits_loopback_on_all_four_ale_layers() {
    // A loopback connect is authorized at CONNECT *and* RECV_ACCEPT (the inbound
    // accept side); a permit on CONNECT alone is denied at accept. Hole's data
    // plane runs app->hole-tun->loopback SOCKS5->ss-service, so the cover must
    // permit loopback on both ALE directions, V4 and V6. The deterministic
    // matcher is the address range (LoopbackNet) on ALL FOUR layers; the
    // IS_LOOPBACK flag isn't reliably set on CI's elevated lane.
    let s = build_cover_spec(v4(), None);
    for layer in [
        Layer::ConnectV4,
        Layer::ConnectV6,
        Layer::RecvAcceptV4,
        Layer::RecvAcceptV6,
    ] {
        assert!(
            s.filters.iter().any(|f| f.layer == layer
                && f.action == Action::Permit
                && matches!(f.condition, Condition::LoopbackNet(_))),
            "address-range loopback permit missing on {layer:?}"
        );
    }
}

#[skuld::test]
fn spec_permits_v4_server_on_v4_layer_only() {
    let s = build_cover_spec(v4(), None);
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
    let s = build_cover_spec(v6(), None);
    let server_permits: Vec<_> = s
        .filters
        .iter()
        .filter(|f| f.action == Action::Permit && matches!(f.condition, Condition::RemoteIp(_)))
        .collect();
    assert_eq!(server_permits.len(), 1);
    assert_eq!(server_permits[0].layer, Layer::ConnectV6);
}

// Arbitration within our single sublayer is pure weight (no CLEAR_ACTION_RIGHT on
// any filter): the permits must outweigh block-all, else block-all wins and the
// cover blocks everything. A compile-time invariant, not a runtime check.
const _: () = assert!(PERMIT_WEIGHT > BLOCK_WEIGHT);

#[skuld::test]
fn permit_filters_outweigh_block() {
    let s = build_cover_spec(v4(), None);
    for f in &s.filters {
        match f.action {
            Action::Permit => assert_eq!(f.weight, PERMIT_WEIGHT),
            Action::Block => assert_eq!(f.weight, BLOCK_WEIGHT),
        }
    }
}

#[skuld::test]
fn spec_uses_the_fixed_hole_guids() {
    let s = build_cover_spec(v4(), None);
    assert_eq!(s.provider, PROVIDER_GUID);
    assert_eq!(s.sublayer, SUBLAYER_GUID);
}

// resolver permit =====================================================================================================

#[skuld::test]
fn spec_permits_resolver_ip_on_its_own_family_layer_when_given() {
    let s = build_cover_spec(v4(), Some(resolver_v4()));
    let resolver_permits: Vec<_> = s
        .filters
        .iter()
        .filter(|f| {
            f.action == Action::Permit
                && matches!(f.condition, Condition::RemoteIpPortTcp(ip, _) if ip == resolver_v4())
        })
        .collect();
    assert_eq!(resolver_permits.len(), 1, "exactly one resolver permit");
    assert_eq!(resolver_permits[0].layer, Layer::ConnectV4);
}

#[skuld::test]
fn spec_permits_v6_resolver_on_v6_layer_only() {
    let s = build_cover_spec(v4(), Some(resolver_v6()));
    let resolver_permits: Vec<_> = s
        .filters
        .iter()
        .filter(|f| {
            f.action == Action::Permit
                && matches!(f.condition, Condition::RemoteIpPortTcp(ip, _) if ip == resolver_v6())
        })
        .collect();
    assert_eq!(resolver_permits.len(), 1);
    assert_eq!(resolver_permits[0].layer, Layer::ConnectV6);
}

#[skuld::test]
fn spec_omits_resolver_permit_when_none() {
    // Negative direction: no resolver_ip means no RemoteIpPortTcp permit
    // exists at all — proves the widening is opt-in, never automatic.
    let s = build_cover_spec(v4(), None);
    let resolver_permits: Vec<_> = s
        .filters
        .iter()
        .filter(|f| f.action == Action::Permit && matches!(f.condition, Condition::RemoteIpPortTcp(..)))
        .collect();
    assert_eq!(resolver_permits.len(), 0, "no resolver permit when resolver_ip is None");
}

#[skuld::test]
fn spec_resolver_permit_is_scoped_to_tcp_443_not_unrestricted() {
    // NOT the server permit's unrestricted shape: doh_url_for_ip
    // (crates/bridge/src/dns/ech.rs) never constructs a URL with a port
    // other than RESOLVER_PERMIT_PORT, so this is the one value the fetch
    // can need.
    let s = build_cover_spec(v4(), Some(resolver_v4()));
    let resolver_permit = s
        .filters
        .iter()
        .find(|f| matches!(f.condition, Condition::RemoteIpPortTcp(ip, _) if ip == resolver_v4()))
        .expect("resolver permit must exist");
    assert!(
        matches!(
            resolver_permit.condition,
            Condition::RemoteIpPortTcp(_, RESOLVER_PERMIT_PORT)
        ),
        "resolver permit must be scoped to RESOLVER_PERMIT_PORT, not unrestricted like the server permit: {:?}",
        resolver_permit.condition
    );
}

#[skuld::test]
fn resolver_permit_weight_outweighs_block() {
    let s = build_cover_spec(v4(), Some(resolver_v4()));
    for f in s
        .filters
        .iter()
        .filter(|f| matches!(f.condition, Condition::RemoteIpPortTcp(ip, _) if ip == resolver_v4()))
    {
        assert_eq!(f.weight, PERMIT_WEIGHT);
    }
}

#[skuld::test]
fn resolver_permit_guids_are_distinct_and_swept() {
    // Every filter a cover installs must be deletable by recovery (else a
    // crash leaks an unswept permit across restarts), and every GUID in one
    // spec must be unique (else the second FwpmFilterAdd0 silently clobbers
    // the first).
    let transient_swept: std::collections::HashSet<GUID> = swept_transient_guids().into_iter().collect();
    for resolver in [resolver_v4(), resolver_v6()] {
        let s = build_cover_spec(v4(), Some(resolver));
        for f in &s.filters {
            assert!(
                transient_swept.contains(&f.guid),
                "{:?} must be in the transient sweep set",
                f.guid
            );
        }
        let unique: std::collections::HashSet<GUID> = s.filters.iter().map(|f| f.guid).collect();
        assert_eq!(
            unique.len(),
            s.filters.len(),
            "every filter GUID in the spec must be distinct"
        );
    }
}

#[skuld::test]
fn resolver_permit_guid_matches_its_own_ip_family() {
    // The GUID a resolver permit uses is family-specific (`FILTER_GUIDS[10]`
    // for V4, `[11]` for V6, per `build_cover_spec`) — checked directly
    // here, not just inferred from set-membership/distinctness (which BOTH
    // families exercised in `resolver_permit_guids_are_distinct_and_swept`
    // would still pass under a swapped V4/V6 match arm, since both GUIDs are
    // in the swept set and distinct from each other either way).
    let v4_filter = build_cover_spec(v4(), Some(resolver_v4()))
        .filters
        .into_iter()
        .find(|f| matches!(f.condition, Condition::RemoteIpPortTcp(ip, _) if ip == resolver_v4()))
        .expect("a V4 resolver permit filter");
    assert_eq!(v4_filter.guid, FILTER_GUIDS[10]);

    let v6_filter = build_cover_spec(v4(), Some(resolver_v6()))
        .filters
        .into_iter()
        .find(|f| matches!(f.condition, Condition::RemoteIpPortTcp(ip, _) if ip == resolver_v6()))
        .expect("a V6 resolver permit filter");
    assert_eq!(v6_filter.guid, FILTER_GUIDS[11]);
}

// build_lockdown_spec =================================================================================================

fn luid() -> u64 {
    0x0000_0006_0000_0000 // a representative NET_LUID value
}
fn plugin_path() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\Program Files\Hole\ex-ray.exe")
}
fn bridge_path() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\Program Files\Hole\hole.exe")
}

#[skuld::test]
fn lockdown_spec_permits_loopback_tun_appids_and_server_then_blocks() {
    let s = build_lockdown_spec(v4(), luid(), &[plugin_path(), bridge_path()]);
    // loopback on all four ALE layers (CONNECT + RECV_ACCEPT) by the deterministic
    // address-range matcher — see spec_permits_loopback_on_all_four_ale_layers for
    // why the accept side matters and why the flag is unreliable.
    for layer in [
        Layer::ConnectV4,
        Layer::ConnectV6,
        Layer::RecvAcceptV4,
        Layer::RecvAcceptV6,
    ] {
        assert!(
            s.filters.iter().any(|f| f.layer == layer
                && f.action == Action::Permit
                && matches!(f.condition, Condition::LoopbackNet(_))),
            "address-range loopback permit missing on {layer:?}"
        );
    }
    // local-interface (TUN LUID) permit on both layers
    let tun = s
        .filters
        .iter()
        .filter(|f| f.action == Action::Permit && matches!(f.condition, Condition::LocalInterface(l) if l == luid()))
        .count();
    assert_eq!(tun, 2, "TUN LUID permit on V4 and V6");
    // one AppId permit per binary, on both layers
    let appids = s
        .filters
        .iter()
        .filter(|f| f.action == Action::Permit && matches!(f.condition, Condition::AppId(_)))
        .count();
    assert_eq!(appids, 4, "two binaries x V4+V6");
    // server permit, on the v4 layer only
    let server: Vec<_> = s
        .filters
        .iter()
        .filter(|f| f.action == Action::Permit && matches!(f.condition, Condition::RemoteIp(_)))
        .collect();
    assert_eq!(server.len(), 1);
    assert_eq!(server[0].layer, Layer::ConnectV4);
    // block-all on both CONNECT layers; never on RECV_ACCEPT (egress-only kill switch)
    assert!(s
        .filters
        .iter()
        .any(|f| f.layer == Layer::ConnectV4 && f.action == Action::Block));
    assert!(s
        .filters
        .iter()
        .any(|f| f.layer == Layer::ConnectV6 && f.action == Action::Block));
    assert!(
        !s.filters
            .iter()
            .any(|f| matches!(f.layer, Layer::RecvAcceptV4 | Layer::RecvAcceptV6) && f.action == Action::Block),
        "lockdown block-all must stay CONNECT-only (egress kill switch)"
    );
}

#[skuld::test]
fn lockdown_spec_permits_outweigh_block() {
    // Weight-only arbitration in one sublayer (see the const assert above).
    let s = build_lockdown_spec(v6(), luid(), &[plugin_path()]);
    for f in &s.filters {
        match f.action {
            Action::Permit => assert_eq!(f.weight, PERMIT_WEIGHT),
            Action::Block => assert_eq!(f.weight, BLOCK_WEIGHT),
        }
    }
}

#[skuld::test]
fn lockdown_spec_uses_distinct_guids_from_transient_cover() {
    let lock = build_lockdown_spec(v4(), luid(), &[plugin_path()]);
    let cover = build_cover_spec(v4(), Some(resolver_v4()));
    let lock_guids: std::collections::HashSet<_> = lock.filters.iter().map(|f| f.guid).collect();
    let cover_guids: std::collections::HashSet<_> = cover.filters.iter().map(|f| f.guid).collect();
    assert!(
        lock_guids.is_disjoint(&cover_guids),
        "lockdown and transient covers must use disjoint filter GUIDs so recovery sweeps both unconditionally"
    );
    // shared provider + sublayer (one Hole sublayer)
    assert_eq!(lock.provider, PROVIDER_GUID);
    assert_eq!(lock.sublayer, SUBLAYER_GUID);
}

#[skuld::test]
fn lockdown_spec_v6_server_lands_on_v6_layer() {
    let s = build_lockdown_spec(v6(), luid(), &[plugin_path()]);
    let server: Vec<_> = s
        .filters
        .iter()
        .filter(|f| f.action == Action::Permit && matches!(f.condition, Condition::RemoteIp(_)))
        .collect();
    assert_eq!(server.len(), 1);
    assert_eq!(server[0].layer, Layer::ConnectV6);
}

// lockdown sweep / Adopt GUID sets ====================================================================================

#[skuld::test]
fn all_swept_guids_cover_both_covers() {
    // The lockdown sweep must iterate every fixed lockdown GUID plus the
    // per-binary App-ID GUIDs so an intent-OFF leftover is fully cleaned.
    let swept = swept_lockdown_guids();
    for g in LOCKDOWN_FILTER_GUIDS {
        assert!(swept.contains(&g), "lockdown GUID {g:?} must be swept");
    }
    for i in 0..MAX_APPID_BINARIES {
        assert!(swept.contains(&appid_filter_guid(i, false)));
        assert!(swept.contains(&appid_filter_guid(i, true)));
    }
}

#[skuld::test]
fn all_swept_guids_are_mutually_distinct() {
    // Every transient + lockdown + App-ID-derived GUID must be pairwise
    // distinct: two filters sharing a key means the second add
    // silently clobbers the first (FwpmFilterAdd0 keys on filterKey). GUID
    // derives Hash + Eq, so collect directly (no to_u128 — it doesn't exist).
    let mut all: Vec<GUID> = swept_transient_guids(); // fixed transient GUIDs
    all.extend(swept_lockdown_guids());
    let unique: std::collections::HashSet<GUID> = all.iter().copied().collect();
    assert_eq!(
        unique.len(),
        all.len(),
        "every filter GUID (transient + lockdown + App-ID) must be distinct"
    );
}

#[skuld::test]
fn adopt_deletes_volatile_permits() {
    // Adopt keeps the host fail-closed but drops the VOLATILE permits — the
    // TUN-LUID pair (LUID dead after teardown) AND the server-IP pair (the
    // server changes between connects). Both are re-added fresh by the next
    // connect's engage with current values. The fail-closed floor (block-all,
    // loopback, App-ID) stays in force.
    let adopt = adopt_delete_guids();
    assert_eq!(adopt.len(), 4, "TUN V4/V6 + server V4/V6");
    for &i in &LOCKDOWN_TUN_GUID_INDICES {
        assert!(
            adopt.contains(&LOCKDOWN_FILTER_GUIDS[i]),
            "Adopt must delete the TUN permit at index {i}"
        );
    }
    for &i in &LOCKDOWN_SERVER_GUID_INDICES {
        assert!(
            adopt.contains(&LOCKDOWN_FILTER_GUIDS[i]),
            "Adopt must delete the server permit at index {i}"
        );
    }
    // It must NOT delete the fail-closed floor: block-all or loopback.
    assert!(
        !adopt.contains(&LOCKDOWN_FILTER_GUIDS[6]),
        "Adopt must NOT delete block-all V4"
    );
    assert!(
        !adopt.contains(&LOCKDOWN_FILTER_GUIDS[7]),
        "Adopt must NOT delete block-all V6"
    );
    assert!(
        !adopt.contains(&LOCKDOWN_FILTER_GUIDS[0]),
        "Adopt must NOT delete loopback CONNECT V4"
    );
    assert!(
        !adopt.contains(&LOCKDOWN_FILTER_GUIDS[1]),
        "Adopt must NOT delete loopback CONNECT V6"
    );
    assert!(
        !adopt.contains(&LOCKDOWN_FILTER_GUIDS[8]),
        "Adopt must NOT delete loopback RECV_ACCEPT V4 (fail-closed floor)"
    );
    assert!(
        !adopt.contains(&LOCKDOWN_FILTER_GUIDS[9]),
        "Adopt must NOT delete loopback RECV_ACCEPT V6 (fail-closed floor)"
    );
}

#[skuld::test]
fn adopt_drops_server_permit_so_reengage_can_update_it() {
    // Regression: keeping the fixed-GUID server permit across an Adopt left a
    // stale IP permitted — the next engage to a different server hits
    // FWP_E_ALREADY_EXISTS (treated as success) and never updates the address.
    // Adopt must drop the server GUIDs (so engage re-adds fresh) while keeping
    // the floor (block-all + loopback + App-ID), which must survive untouched.
    let adopt: std::collections::HashSet<GUID> = adopt_delete_guids().into_iter().collect();

    // Server permits MUST be in the Adopt-delete set.
    assert!(adopt.contains(&LOCKDOWN_FILTER_GUIDS[4]), "server V4 must be dropped");
    assert!(adopt.contains(&LOCKDOWN_FILTER_GUIDS[5]), "server V6 must be dropped");

    // The fail-closed floor MUST NOT be in the Adopt-delete set.
    assert!(!adopt.contains(&LOCKDOWN_FILTER_GUIDS[6]), "block-all V4 stays");
    assert!(!adopt.contains(&LOCKDOWN_FILTER_GUIDS[7]), "block-all V6 stays");
    assert!(!adopt.contains(&LOCKDOWN_FILTER_GUIDS[0]), "loopback CONNECT V4 stays");
    assert!(!adopt.contains(&LOCKDOWN_FILTER_GUIDS[1]), "loopback CONNECT V6 stays");
    assert!(
        !adopt.contains(&LOCKDOWN_FILTER_GUIDS[8]),
        "loopback RECV_ACCEPT V4 stays"
    );
    assert!(
        !adopt.contains(&LOCKDOWN_FILTER_GUIDS[9]),
        "loopback RECV_ACCEPT V6 stays"
    );
    for i in 0..MAX_APPID_BINARIES {
        assert!(
            !adopt.contains(&appid_filter_guid(i, false)),
            "App-ID floor stays (V4 #{i})"
        );
        assert!(
            !adopt.contains(&appid_filter_guid(i, true)),
            "App-ID floor stays (V6 #{i})"
        );
    }
}

#[skuld::test]
fn both_specs_permit_loopback_recv_accept_by_address_range() {
    // The accept-side permits must land on the RECV_ACCEPT layers (not a second
    // CONNECT permit) AND match by the deterministic address range, not the
    // IS_LOOPBACK flag: on CI's elevated lane the flag doesn't match at
    // RECV_ACCEPT, so a flag-only permit leaves the loopback accept dropped. At
    // RECV_ACCEPT IP_REMOTE_ADDRESS is the peer (127.0.0.1 for a loopback accept),
    // so the 127.0.0.0/8 or ::1/128 range matches. The matching family per layer:
    // V4 range on RecvAcceptV4, V6 range on RecvAcceptV6.
    for s in [
        build_cover_spec(v4(), None),
        build_lockdown_spec(v4(), luid(), &[plugin_path()]),
    ] {
        assert!(
            s.filters.iter().any(|f| f.layer == Layer::RecvAcceptV4
                && f.action == Action::Permit
                && f.weight == PERMIT_WEIGHT
                && f.condition == Condition::LoopbackNet(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))),
            "address-range loopback permit (127.0.0.0/8) missing on RECV_ACCEPT V4"
        );
        assert!(
            s.filters.iter().any(|f| f.layer == Layer::RecvAcceptV6
                && f.action == Action::Permit
                && f.weight == PERMIT_WEIGHT
                && f.condition == Condition::LoopbackNet(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))),
            "address-range loopback permit (::1/128) missing on RECV_ACCEPT V6"
        );
    }
}

#[skuld::test]
fn loopback_recv_accept_permits_are_in_both_sweep_floors() {
    // The accept-side loopback permits are part of the fail-closed FLOOR: the
    // transient sweep (delete_all iterates FILTER_GUIDS) and the lockdown sweep
    // (swept_lockdown_guids) must both delete them, but Adopt must keep them.
    // The transient cover wires its RECV_ACCEPT loopback GUIDs from FILTER_GUIDS,
    // so iterating the array sweeps them; assert they actually appear in the spec.
    let cover = build_cover_spec(v4(), None);
    let cover_guids: std::collections::HashSet<GUID> = cover.filters.iter().map(|f| f.guid).collect();
    assert!(
        cover_guids.contains(&FILTER_GUIDS[6]),
        "transient RECV_ACCEPT V4 in spec"
    );
    assert!(
        cover_guids.contains(&FILTER_GUIDS[7]),
        "transient RECV_ACCEPT V6 in spec"
    );

    let swept = swept_lockdown_guids();
    assert!(
        swept.contains(&LOCKDOWN_FILTER_GUIDS[8]),
        "lockdown RECV_ACCEPT V4 swept"
    );
    assert!(
        swept.contains(&LOCKDOWN_FILTER_GUIDS[9]),
        "lockdown RECV_ACCEPT V6 swept"
    );
}

#[skuld::test]
fn every_emitted_filter_guid_is_in_its_sweep_set() {
    // Structural fail-closed invariant: any filter a cover installs must be
    // deletable by recovery, else a crash leaks an unswept block across restarts.
    // Transient -> delete_all iterates swept_transient_guids (the fixed GUIDs);
    // lockdown -> swept_lockdown_guids. The transient side ALSO carries a
    // resolver permit here so the new GUIDs' sweep membership is exercised.
    let transient_swept: std::collections::HashSet<GUID> = swept_transient_guids().into_iter().collect();
    for ip in [v4(), v6()] {
        let cover = build_cover_spec(ip, Some(resolver_v4()));
        for f in &cover.filters {
            assert!(
                transient_swept.contains(&f.guid),
                "transient filter {:?} ({:?}) is not in swept_transient_guids",
                f.guid,
                f.layer
            );
        }
        let swept: std::collections::HashSet<GUID> = swept_lockdown_guids().into_iter().collect();
        let lock = build_lockdown_spec(ip, luid(), &[plugin_path(), bridge_path()]);
        for f in &lock.filters {
            assert!(
                swept.contains(&f.guid),
                "lockdown filter {:?} ({:?}) is not in swept_lockdown_guids",
                f.guid,
                f.layer
            );
        }
    }
}

// address-range loopback permits at CONNECT ===========================================================================

#[skuld::test]
fn both_specs_permit_loopback_by_address_range_at_connect() {
    // The IS_LOOPBACK flag is not reliably set at ALE_AUTH_CONNECT in CI's
    // elevated lane, so the flag permit alone leaves loopback connects denied by
    // block-all. An address-range permit keyed on the connect's DESTINATION
    // matches deterministically: 127.0.0.0/8 on CONNECT V4, ::1/128 on CONNECT V6.
    for s in [
        build_cover_spec(v4(), None),
        build_lockdown_spec(v4(), luid(), &[plugin_path()]),
    ] {
        let v4_net = s.filters.iter().any(|f| {
            f.layer == Layer::ConnectV4
                && f.action == Action::Permit
                && f.weight == PERMIT_WEIGHT
                && f.condition == Condition::LoopbackNet(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        });
        assert!(
            v4_net,
            "address-range loopback permit (127.0.0.0/8) missing on CONNECT V4"
        );
        let v6_net = s.filters.iter().any(|f| {
            f.layer == Layer::ConnectV6
                && f.action == Action::Permit
                && f.weight == PERMIT_WEIGHT
                && f.condition == Condition::LoopbackNet(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
        });
        assert!(v6_net, "address-range loopback permit (::1/128) missing on CONNECT V6");
    }
}

#[skuld::test]
fn flag_loopback_permits_are_kept_only_on_connect() {
    // At CONNECT the flag permits stay as harmless belt-and-suspenders alongside
    // the address-range ones (don't churn them). At RECV_ACCEPT the flag is
    // dropped in favor of the deterministic address-range permit, because the
    // flag doesn't match there on CI's elevated lane.
    let s = build_cover_spec(v4(), None);
    let flag_permits: Vec<_> = s
        .filters
        .iter()
        .filter(|f| f.action == Action::Permit && matches!(f.condition, Condition::Loopback))
        .collect();
    assert_eq!(
        flag_permits.len(),
        2,
        "flag loopback permits kept on CONNECT V4+V6 only"
    );
    for f in &flag_permits {
        assert!(
            matches!(f.layer, Layer::ConnectV4 | Layer::ConnectV6),
            "flag loopback permit must be CONNECT-only, found on {:?}",
            f.layer
        );
    }
}

#[skuld::test]
fn new_loopbacknet_guids_are_in_their_sweep_floors_and_distinct() {
    // The new address-range loopback GUIDs are part of the fail-closed FLOOR:
    // the transient sweep (delete_all iterates FILTER_GUIDS) and the lockdown
    // sweep (swept_lockdown_guids) must both delete them. They must also be
    // distinct from every prior GUID (a shared key silently clobbers).
    let cover = build_cover_spec(v4(), None);
    for f in cover
        .filters
        .iter()
        .filter(|f| matches!(f.condition, Condition::LoopbackNet(_)))
    {
        assert!(
            FILTER_GUIDS.contains(&f.guid),
            "transient LoopbackNet GUID {:?} must be in FILTER_GUIDS (transient sweep)",
            f.guid
        );
    }
    let swept: std::collections::HashSet<GUID> = swept_lockdown_guids().into_iter().collect();
    let lock = build_lockdown_spec(v4(), luid(), &[plugin_path()]);
    for f in lock
        .filters
        .iter()
        .filter(|f| matches!(f.condition, Condition::LoopbackNet(_)))
    {
        assert!(
            swept.contains(&f.guid),
            "lockdown LoopbackNet GUID {:?} must be swept",
            f.guid
        );
    }
}

// release_all =========================================================================================================

// Not a privileged real-engage test — a bare mocked unit test that the
// `.config/nextest.toml` `global_net_state` filter's `release_all_` name
// substring incidentally sweeps in (Option B, bindreams/hole#894): labeled to
// preserve its existing group membership exactly, not because it mutates
// real OS state.
#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_first_delete_failure_reports_the_first_real_error_and_inspects_every_code() {
    // Not-found is benign (a clean host or an already-swept filter); the fold
    // must skip it and report the FIRST genuine failure, not stop at it —
    // every code in the slice must have been issued already by the caller.
    let codes = [
        ("a", ERROR_SUCCESS.0),
        ("b", FWP_E_FILTER_NOT_FOUND_DWORD),
        ("c", 0x1234_5678),
        ("d", 0x9abc_def0),
    ];
    let err = first_delete_failure(&codes).expect("a genuine failure must be reported");
    let msg = err.to_string();
    assert!(
        msg.contains("0x12345678"),
        "must name the FIRST genuine failure's code: {msg}"
    );
    assert!(
        !msg.contains("0x9abcdef0"),
        "must not report the second failure's code: {msg}"
    );

    let clean = [("a", ERROR_SUCCESS.0), ("b", FWP_E_FILTER_NOT_FOUND_DWORD)];
    assert!(
        first_delete_failure(&clean).is_none(),
        "success and not-found must never be treated as an error"
    );
}

#[skuld::test]
fn adopt_does_not_delete_the_address_range_loopback_floor() {
    // The address-range loopback permits are floor, not volatile: Adopt must keep
    // them (only the TUN-LUID + server-IP pairs are dropped). adopt_delete_guids
    // is keyed on the [2,3] / [4,5] indices, which the appended GUIDs do not touch.
    let adopt: std::collections::HashSet<GUID> = adopt_delete_guids().into_iter().collect();
    let lock = build_lockdown_spec(v4(), luid(), &[plugin_path()]);
    for f in lock
        .filters
        .iter()
        .filter(|f| matches!(f.condition, Condition::LoopbackNet(_)))
    {
        assert!(
            !adopt.contains(&f.guid),
            "Adopt must NOT delete the address-range loopback floor {:?}",
            f.guid
        );
    }
    // Adopt still drops exactly the four volatile permits — unchanged by this fix.
    assert_eq!(adopt.len(), 4, "adopt_delete_guids unchanged: TUN V4/V6 + server V4/V6");
}

// Cover presence ======================================================================================================

use crate::routing::CoverPresence;

/// `ERROR_ACCESS_DENIED` as the Win32 DWORD a DACL-denied FWPM read returns.
const ERROR_ACCESS_DENIED_DWORD: u32 = 5;

#[skuld::test]
fn classify_presence_is_closed_over_its_inputs() {
    let nf = FWP_E_FILTER_NOT_FOUND_DWORD;
    let ok = ERROR_SUCCESS.0;
    let cases: [(bool, &[u32], CoverPresence); 6] = [
        (false, &[], CoverPresence::Unreachable),
        (false, &[ok], CoverPresence::Unreachable),
        (true, &[nf, nf, nf], CoverPresence::Absent),
        (true, &[nf, ok, nf], CoverPresence::Live),
        (true, &[nf, 0x8032_0001, nf], CoverPresence::Indeterminate),
        (true, &[0x8032_0001, ok], CoverPresence::Live),
    ];
    for (opened, codes, expected) in cases {
        assert_eq!(
            classify_presence(opened, codes),
            expected,
            "engine_opened={opened} codes={codes:x?} must classify as {expected:?}"
        );
    }
    assert_eq!(
        classify_presence(true, &[]),
        CoverPresence::Absent,
        "an open engine with nothing to report found no cover"
    );
}

#[skuld::test]
fn an_access_denied_code_is_never_absent() {
    // The structural guarantee that makes the unelevated-read question a
    // documentation matter, not a correctness dependency: ONLY the literal
    // FWP_E_FILTER_NOT_FOUND produces `Absent`, so a denied read can never be
    // mistaken for a clean host.
    let nf = FWP_E_FILTER_NOT_FOUND_DWORD;
    assert_eq!(
        classify_presence(true, &[nf, ERROR_ACCESS_DENIED_DWORD, nf]),
        CoverPresence::Indeterminate,
        "a DACL-denied read must be Indeterminate, never Absent"
    );
}

#[skuld::test]
fn an_interrupted_sweep_still_reads_as_live() {
    // The sweeps loop delete-by-key with every return code discarded, so a
    // sweep killed part-way (say after index 6, leaving block-all V6) survives
    // a reboot as a PARTIAL cover. One found GUID is enough to report Live —
    // otherwise that partial cover would answer Absent forever.
    let nf = FWP_E_FILTER_NOT_FOUND_DWORD;
    let mut codes = vec![nf; swept_lockdown_guids().len()];
    for i in 0..codes.len() {
        let mut one = codes.clone();
        one[i] = ERROR_SUCCESS.0;
        assert_eq!(
            classify_presence(true, &one),
            CoverPresence::Live,
            "a single surviving filter at index {i} must read as Live"
        );
    }
    codes[0] = ERROR_SUCCESS.0;
    assert_eq!(classify_presence(true, &codes), CoverPresence::Live);
}

#[skuld::test]
fn presence_probes_every_swept_lockdown_guid() {
    // `lockdown_cover_presence` iterates exactly `swept_lockdown_guids()` — the
    // same set the sweeps delete — so no residue the sweep would remove can
    // hide from the probe.
    let probed = swept_lockdown_guids();
    assert_eq!(
        probed.len(),
        LOCKDOWN_FILTER_GUIDS.len() + MAX_APPID_BINARIES * 2,
        "the probe must cover the fixed lockdown GUIDs plus every App-ID slot"
    );
    assert!(
        probed.contains(&LOCKDOWN_FILTER_GUIDS[6]),
        "block-all V4 must be probed"
    );
    assert!(
        probed.contains(&LOCKDOWN_FILTER_GUIDS[7]),
        "block-all V6 must be probed"
    );
    for i in 0..MAX_APPID_BINARIES {
        assert!(probed.contains(&appid_filter_guid(i, false)), "App-ID slot {i} V4");
        assert!(probed.contains(&appid_filter_guid(i, true)), "App-ID slot {i} V6");
    }
}

// engage-time volatile-permit refresh =================================================================================

#[skuld::test]
fn engage_lockdown_refreshes_the_volatile_permits() {
    // The refresh lives at ENGAGE, not at recovery: `ok_or_exists` treats a
    // re-add of a fixed-key filter as success, so without a delete first the
    // stale TUN LUID and the previous server IP would survive a reconnect.
    let spec = build_lockdown_spec(v4(), luid(), &[plugin_path(), bridge_path()]);
    assert_eq!(
        spec.pre_delete,
        adopt_delete_guids(),
        "engage must drop exactly the volatile permits — the TUN pair and BOTH server-family \
         permits — before adding anything"
    );

    // Every deleted key is either re-added with this attempt's fresh values
    // (the TUN pair, and the server permit for THIS family) or deliberately
    // left deleted (the other family's stale server permit).
    let added: std::collections::HashSet<GUID> = spec.filters.iter().map(|f| f.guid).collect();
    for &i in &LOCKDOWN_TUN_GUID_INDICES {
        assert!(
            added.contains(&LOCKDOWN_FILTER_GUIDS[i]),
            "the TUN permit at index {i} must be re-added fresh after the delete"
        );
    }
    assert!(
        added.contains(&LOCKDOWN_FILTER_GUIDS[4]),
        "a v4 server must have its v4 permit re-added"
    );
    assert!(
        !added.contains(&LOCKDOWN_FILTER_GUIDS[5]),
        "the other family's server permit stays deleted, not re-added stale"
    );

    // The fail-closed floor is never dropped by an engage either.
    for guid in [
        LOCKDOWN_FILTER_GUIDS[6],
        LOCKDOWN_FILTER_GUIDS[7],
        LOCKDOWN_FILTER_GUIDS[0],
        LOCKDOWN_FILTER_GUIDS[1],
        LOCKDOWN_FILTER_GUIDS[8],
        LOCKDOWN_FILTER_GUIDS[9],
    ] {
        assert!(
            !spec.pre_delete.contains(&guid),
            "engage must not delete the fail-closed floor {guid:?}"
        );
    }
    for i in 0..MAX_APPID_BINARIES {
        assert!(!spec.pre_delete.contains(&appid_filter_guid(i, false)));
        assert!(!spec.pre_delete.contains(&appid_filter_guid(i, true)));
    }
}

#[skuld::test]
fn the_transient_cover_deletes_nothing_at_engage() {
    // Only the lockdown cover has fixed-key volatile permits to refresh; the
    // transient cover is engaged once per attempt over a swept host.
    assert!(build_cover_spec(v4(), None).pre_delete.is_empty());
    assert!(build_cover_spec(v6(), Some(resolver_v4())).pre_delete.is_empty());
}

// Recovery-time TUN-permit reclaim ====================================================================================

#[skuld::test]
fn should_reclaim_tun_permit_only_when_unresolved() {
    // A resolving hole-tun means some bridge may be relying on the permit —
    // never reclaim it. Only a provably-gone name is safe to delete.
    assert!(
        !should_reclaim_tun_permit(true),
        "a resolving hole-tun must never be reclaimed"
    );
    assert!(
        should_reclaim_tun_permit(false),
        "an unresolvable hole-tun must be reclaimed"
    );
}

struct StubResolver {
    result: std::sync::Mutex<Option<Result<u64, RoutingError>>>,
    called_with: std::sync::Mutex<Option<String>>,
}

impl crate::routing::failclosed::LuidResolver for StubResolver {
    fn resolve(&self, alias: &str) -> Result<u64, RoutingError> {
        *self.called_with.lock().unwrap() = Some(alias.to_owned());
        self.result
            .lock()
            .unwrap()
            .take()
            .expect("resolve called more than once in this test")
    }
}

#[skuld::test]
fn reclaim_stale_tun_permit_resolves_the_given_name() {
    // Reintroduction proof for a hardcoded-alias regression: the resolver
    // must see the SAME name the caller passed, not a literal baked into this
    // function.
    let resolver = StubResolver {
        result: std::sync::Mutex::new(Some(Ok(0x1234))),
        called_with: std::sync::Mutex::new(None),
    };
    reclaim_stale_tun_permit(&resolver, "some-other-tun");
    assert_eq!(
        resolver.called_with.into_inner().unwrap().as_deref(),
        Some("some-other-tun"),
        "reclaim must resolve the exact alias it was given"
    );
}

#[skuld::test]
fn first_delete_failure_treats_access_denied_as_a_genuine_failure() {
    // Mirrors `an_access_denied_code_is_never_absent`: the code class Finding
    // 4 (#898 rework) is about — a DACL-denied delete must never be folded
    // away as though the reclaim succeeded.
    let codes = [("TUN-LUID permit", ERROR_ACCESS_DENIED_DWORD)];
    let err = first_delete_failure(&codes).expect("an access-denied delete must be a genuine failure");
    assert!(
        err.to_string().contains("TUN-LUID permit"),
        "must name what failed: {err}"
    );
}

#[skuld::test]
fn reclaim_stale_tun_permit_does_not_discard_delete_codes() {
    // Structural guard, not a proof (mirrors
    // `route_recovery::recover_routes_has_exactly_one_bridge_caller` in the
    // bridge crate): Finding 4 (#898 rework) was
    // `let _ = FwpmFilterDeleteByKey0(...)`, silently discarding the exact
    // return code that means a filter is STILL blocking egress. Assert the
    // source routes the TUN-permit deletes through the same
    // `first_delete_failure` fold `Cover::drop`'s Lockdown arm and
    // `delete_all` use, rather than re-running the real FWPM call under an
    // access-denied DACL to observe it (this file has no such fixture).
    let src = include_str!("windows.rs");
    let start = src
        .find("pub fn reclaim_stale_tun_permit(")
        .expect("reclaim_stale_tun_permit must exist in windows.rs");
    let after = &src[start..];
    let next_pub_fn = after[1..].find("\npub fn ").map(|i| i + 1);
    let next_pub_crate_fn = after[1..].find("\npub(crate) fn ").map(|i| i + 1);
    let end = [next_pub_fn, next_pub_crate_fn]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(after.len());
    let body = &after[..end];

    assert!(
        !body.contains("let _ = FwpmFilterDeleteByKey0"),
        "reclaim_stale_tun_permit must not discard a TUN-permit delete's return code:\n{body}"
    );
    assert!(
        body.contains("first_delete_failure"),
        "reclaim_stale_tun_permit must fold its delete codes through first_delete_failure:\n{body}"
    );
}
