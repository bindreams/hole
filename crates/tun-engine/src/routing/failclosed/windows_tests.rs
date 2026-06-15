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
    // loopback on both layers
    let loopback = s
        .filters
        .iter()
        .filter(|f| f.action == Action::Permit && matches!(f.condition, Condition::Loopback))
        .count();
    assert_eq!(loopback, 2, "loopback permit on V4 and V6");
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
    // block-all on both layers
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
    // Transient six + lockdown eight + every App-ID-derived GUID must be
    // pairwise distinct: two filters sharing a key means the second add
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
        "Adopt must NOT delete loopback V4"
    );
    assert!(
        !adopt.contains(&LOCKDOWN_FILTER_GUIDS[1]),
        "Adopt must NOT delete loopback V6"
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
    assert!(!adopt.contains(&LOCKDOWN_FILTER_GUIDS[0]), "loopback V4 stays");
    assert!(!adopt.contains(&LOCKDOWN_FILTER_GUIDS[1]), "loopback V6 stays");
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
