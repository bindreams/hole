use super::*;
use std::net::IpAddr;

fn v4() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}
fn v6() -> IpAddr {
    "2001:db8::1".parse().unwrap()
}

#[skuld::test]
fn spec_blocks_egress_only_on_both_v4_and_v6_layers() {
    // The block-all is an egress kill switch: CONNECT only. Blocking RECV_ACCEPT
    // would make it an inbound firewall (out of scope, and inconsistent with the
    // macOS `set skip on lo0` egress-only model).
    let s = build_cover_spec(v4());
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
    let s = build_cover_spec(v4());
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
fn lockdown_spec_permits_are_hard_and_outweigh_block() {
    let s = build_lockdown_spec(v6(), luid(), &[plugin_path()]);
    for f in &s.filters {
        match f.action {
            Action::Permit => {
                assert!(f.hard, "lockdown permits must be hard (CLEAR_ACTION_RIGHT)");
                assert_eq!(f.weight, PERMIT_WEIGHT);
            }
            Action::Block => {
                assert!(!f.hard);
                assert_eq!(f.weight, BLOCK_WEIGHT);
            }
        }
    }
}

#[skuld::test]
fn lockdown_spec_uses_distinct_guids_from_transient_cover() {
    let lock = build_lockdown_spec(v4(), luid(), &[plugin_path()]);
    let cover = build_cover_spec(v4());
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
    let mut all: Vec<GUID> = FILTER_GUIDS.to_vec();
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
        build_cover_spec(v4()),
        build_lockdown_spec(v4(), luid(), &[plugin_path()]),
    ] {
        assert!(
            s.filters.iter().any(|f| f.layer == Layer::RecvAcceptV4
                && f.action == Action::Permit
                && f.hard
                && f.condition == Condition::LoopbackNet(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))),
            "address-range loopback permit (127.0.0.0/8) missing on RECV_ACCEPT V4"
        );
        assert!(
            s.filters.iter().any(|f| f.layer == Layer::RecvAcceptV6
                && f.action == Action::Permit
                && f.hard
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
    let cover = build_cover_spec(v4());
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
    // Transient -> delete_all iterates FILTER_GUIDS; lockdown -> swept_lockdown_guids.
    for ip in [v4(), v6()] {
        let cover = build_cover_spec(ip);
        for f in &cover.filters {
            assert!(
                FILTER_GUIDS.contains(&f.guid),
                "transient filter {:?} ({:?}) is not in FILTER_GUIDS",
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
        build_cover_spec(v4()),
        build_lockdown_spec(v4(), luid(), &[plugin_path()]),
    ] {
        let v4_net = s.filters.iter().any(|f| {
            f.layer == Layer::ConnectV4
                && f.action == Action::Permit
                && f.hard
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
                && f.hard
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
    let s = build_cover_spec(v4());
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
    let cover = build_cover_spec(v4());
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
