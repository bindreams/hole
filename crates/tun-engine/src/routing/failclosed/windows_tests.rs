use super::*;
use std::net::IpAddr;

use crate::GLOBAL_NET_STATE;

// GUID-only views of the swept key lists. The production lists carry each
// key's `KeyLifetime` (see `SweptKey`); the tests below are about GUID set
// membership and disjointness, which the lifetime does not bear on.
fn swept_lockdown_guids() -> Vec<GUID> {
    swept_lockdown_keys().into_iter().map(|k| k.guid).collect()
}
fn swept_transient_guids() -> Vec<GUID> {
    swept_transient_keys().into_iter().map(|k| k.guid).collect()
}

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

// Boot-time lifetime (#998) ===========================================================================================

#[skuld::test]
fn transient_spec_is_never_boottime() {
    // The transient cover (bounded-window RAII guard held only while the
    // bridge process is already running) has no boot window to cover, so
    // none of its filters may be `Boottime` — #998's scope decision is that
    // only the standing lockdown's block-all floor gets a twin.
    let s = build_cover_spec(v4(), Some(resolver_v4()));
    for f in &s.filters {
        assert_eq!(
            f.lifetime,
            FilterLifetime::PERSISTENT,
            "transient cover filter {:?} must be Persistent, never Boottime",
            f.guid
        );
    }
}

#[skuld::test]
fn a_lifetime_hands_out_its_wfp_flag_and_its_key_class_from_one_value() {
    // The #1010 coupling, at its two ends. `filter_flags` is the crate's only
    // producer of the `FWPM_FILTER0::flags` bits and `key_lifetime` is what a
    // sweep records; both read the SAME private `KeyLifetime`, so a filter
    // installed boot-time cannot have its key swept as persistent. Before
    // this there were two enums and two hand-written match arms, and nothing
    // said they had to agree.
    assert_eq!(
        FilterLifetime::PERSISTENT.filter_flags().0,
        FWPM_FILTER_FLAG_PERSISTENT.0
    );
    assert_eq!(FilterLifetime::PERSISTENT.key_lifetime(), KeyLifetime::Persistent);
    assert_eq!(FilterLifetime::BOOT_TIME.filter_flags().0, FWPM_FILTER_FLAG_BOOTTIME.0);
    assert_eq!(FilterLifetime::BOOT_TIME.key_lifetime(), KeyLifetime::BootTime);
}

// That `add_filter` really carries a spec's lifetime through to the live WFP
// object — the literal bug #998 reports, a block-all hardcoded to PERSISTENT
// regardless of its spec — is proven against the real firewall by
// `boottime_privileged_tests`, which adds a `Boottime` spec through THIS
// `add_filter` and reads `FWPM_FILTER_FLAG_BOOTTIME` (and not PERSISTENT) back
// off the filter WFP stored. Nothing here can prove that: the mapping is
// FFI-side, and a source-text guard over `windows.rs` asserts the shape of the
// code rather than its effect.

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

#[skuld::test]
fn lockdown_spec_blockall_has_boottime_twins() {
    // #998: the block-all floor must be enforced from boot, before BFE starts
    // re-adding the Persistent pair — so each of ConnectV4/ConnectV6 needs
    // both a Persistent AND a Boottime block, the latter keyed on the fixed
    // LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS pair (see the module doc's "Boot-time
    // coverage" section).
    let s = build_lockdown_spec(v4(), luid(), &[plugin_path()]);
    let blocks: Vec<_> = s.filters.iter().filter(|f| f.action == Action::Block).collect();

    for (layer, boottime_guid) in [
        (Layer::ConnectV4, LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[0]),
        (Layer::ConnectV6, LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[1]),
    ] {
        assert!(
            blocks
                .iter()
                .any(|f| f.layer == layer && f.lifetime == FilterLifetime::PERSISTENT),
            "expected a Persistent block on {layer:?}"
        );
        let boottime = blocks
            .iter()
            .find(|f| f.layer == layer && f.lifetime == FilterLifetime::BOOT_TIME)
            .unwrap_or_else(|| panic!("expected a Boottime block on {layer:?}"));
        assert_eq!(boottime.guid, boottime_guid);
    }
}

#[skuld::test]
fn every_lockdown_filter_is_swept_under_the_lifetime_it_is_installed_with() {
    // The #1003 invariant, stated over the two lists that used to be able to
    // disagree. `build_lockdown_spec` stamps a WFP lifetime flag on an object;
    // `swept_lockdown_keys` records what a delete of that object's key PROVES.
    // A filter added `FWPM_FILTER_FLAG_BOOTTIME` whose key is swept as
    // `Persistent` makes `release_all` report a proof of removal it never
    // observed, and the MSI deletes `hole.exe` on the strength of it.
    //
    // #1010 made that unrepresentable for the twins (one
    // `LOCKDOWN_BOOTTIME_TWINS` entry feeds both sites) — this asserts it for
    // EVERY lockdown filter, including the App-ID ones, whose two lists are
    // still built independently.
    let spec = build_lockdown_spec(v4(), luid(), &[plugin_path()]);
    let swept: std::collections::HashMap<GUID, FilterLifetime> = swept_lockdown_keys()
        .into_iter()
        .map(|k| (k.guid, k.lifetime))
        .collect();
    for f in &spec.filters {
        let sweep_lifetime = swept
            .get(&f.guid)
            .unwrap_or_else(|| panic!("lockdown filter {:?} is installed but never swept", f.guid));
        assert_eq!(
            *sweep_lifetime, f.lifetime,
            "filter {:?} is installed {:?} but its key is swept as {:?}",
            f.guid, f.lifetime, sweep_lifetime
        );
    }
}

#[skuld::test]
fn every_transient_filter_is_swept_under_the_lifetime_it_is_installed_with() {
    // Same invariant for the transient cover. It has no boot-time half today,
    // which is exactly why it needs the guard: nothing else would notice one
    // arriving on only one of the two lists.
    let spec = build_cover_spec(v4(), Some(resolver_v4()));
    let swept: std::collections::HashMap<GUID, FilterLifetime> = swept_transient_keys()
        .into_iter()
        .map(|k| (k.guid, k.lifetime))
        .collect();
    for f in &spec.filters {
        let sweep_lifetime = swept
            .get(&f.guid)
            .unwrap_or_else(|| panic!("transient filter {:?} is installed but never swept", f.guid));
        assert_eq!(
            *sweep_lifetime, f.lifetime,
            "filter {:?} is installed {:?} but its key is swept as {:?}",
            f.guid, f.lifetime, sweep_lifetime
        );
    }
}

#[skuld::test]
fn lockdown_spec_permits_are_never_boottime() {
    // Only the block-all floor gets a boot-time twin (#998's scope decision:
    // TUN-LUID/server-IP permits carry runtime-discovered values that would
    // be stale pre-BFE, and a boot-time loopback/App-ID permit has no
    // hand-off to its persistent counterpart). See the module doc's
    // "Boot-time coverage" section.
    let s = build_lockdown_spec(v4(), luid(), &[plugin_path()]);
    for f in s.filters.iter().filter(|f| f.action == Action::Permit) {
        assert_eq!(
            f.lifetime,
            FilterLifetime::PERSISTENT,
            "lockdown permit {:?} on {:?} must be Persistent, never Boottime",
            f.guid,
            f.layer
        );
    }
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
    for g in LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS {
        assert!(swept.contains(&g), "boot-time block-all GUID {g:?} must be swept");
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
    // The boot-time probe's GUID belongs in the same set. Its disjointness from
    // every cover GUID is what keeps the probe a probe: a collision would make
    // it install a real cover filter under a cover key — a boot-time PERMIT
    // sitting where a swept object is expected — and its documented "no sweep
    // can reach it" would be false in the worst possible direction.
    all.push(crate::routing::failclosed::boottime_privileged_tests::PROBE_GUID);
    let unique: std::collections::HashSet<GUID> = all.iter().copied().collect();
    assert_eq!(
        unique.len(),
        all.len(),
        "every filter GUID (transient + lockdown + App-ID + the boot-time probe) must be distinct"
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

// Clearance wiring ----------------------------------------------------------------------------------------------------

fn key(label: &'static str, lifetime: FilterLifetime) -> SweptKey {
    SweptKey {
        guid: GUID::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0001),
        label,
        lifetime,
    }
}

#[skuld::test]
fn a_code_that_is_neither_success_nor_not_found_is_a_failure_not_a_removal() {
    // The #1003/F4 anti-pattern, at the one place a raw DWORD becomes a
    // verdict. `ERROR_ACCESS_DENIED` (5) is the live example: an unelevated
    // sweep, an object still installed, and — under a "not NotFound therefore
    // Removed" mapping — a `KeyOutcome::Removed` that proves the key empty.
    assert_eq!(classify_delete_code(5), KeyOutcome::Failed);
    assert_eq!(classify_delete_code(0xDEAD_BEEF), KeyOutcome::Failed);
    assert_eq!(classify_delete_code(ERROR_SUCCESS.0), KeyOutcome::Removed);
    assert_eq!(classify_delete_code(FWP_E_FILTER_NOT_FOUND_DWORD), KeyOutcome::NotFound);

    // ...and that failure can never reach the gate as proof, whatever the
    // key's lifetime.
    let swept = [
        (key("persistent", FilterLifetime::PERSISTENT), 5u32),
        (key("boot-time", FilterLifetime::BOOT_TIME), 5u32),
    ];
    let clearance = Clearance::from_observations(&observations(&swept));
    assert!(!clearance.is_proven());
    assert_eq!(clearance.unproven_keys(), ["persistent", "boot-time"]);
}

// `disengage_lockdown`'s fail-loud verdict ----------------------------------------------------------------------------
//
// `hole bridge unlock` flips the persisted kill-switch intent off ONLY on this
// function's success (`cutover::unlock_with`). An `Ok` over a host it did not
// unlock leaves the cover engaged with the intent reading "off" — egress
// blocked and nothing left that will reconcile it.

#[skuld::test]
fn a_refused_delete_fails_the_disengage_instead_of_reporting_success() {
    // ERROR_ACCESS_DENIED: the unelevated run. FWPM opens the engine without
    // elevation but refuses the write, so this is the reachable case, not an
    // exotic one. The previous body discarded every code and returned Ok.
    let err = disengage_verdict(None, &[("lockdown block-all V4", 5)]).expect_err("a refused delete must fail loud");
    assert!(
        format!("{err}").contains("lockdown block-all V4"),
        "the failing key must be named: {err}"
    );
}

#[skuld::test]
fn an_unreachable_firewall_and_a_refused_delete_are_distinct_failures() {
    let unreachable = disengage_verdict(Some(0x8032_0001), &[]).expect_err("engine open failure");
    assert!(
        format!("{unreachable}").contains("could not be reached"),
        "{unreachable}"
    );
    let refused = disengage_verdict(None, &[("k", 5)]).expect_err("refused delete");
    assert_ne!(
        format!("{unreachable}"),
        format!("{refused}"),
        "the two causes must not collapse into one message"
    );
}

#[skuld::test]
fn a_clean_or_already_swept_host_disengages_successfully() {
    // Idempotency: a host that never engaged answers not-found on every key,
    // and that must stay an unqualified success — the escape hatch is meant to
    // be runnable at any time.
    assert!(disengage_verdict(
        None,
        &[
            ("a", ERROR_SUCCESS.0),
            ("b", FWP_E_FILTER_NOT_FOUND_DWORD),
            ("c", FWP_E_FILTER_NOT_FOUND_DWORD),
        ]
    )
    .is_ok());
    assert!(disengage_verdict(None, &[]).is_ok());
}

#[skuld::test]
fn the_failure_verdict_and_the_clearance_read_the_same_classifier() {
    // Two folds, one classifier: a code `first_delete_failure` calls a genuine
    // failure is exactly a code `observations` refuses to call a removal. Were
    // they independent, a code added to one and not the other would fail the
    // release while the clearance still reported it proven — or, worse, the
    // reverse.
    for code in [ERROR_SUCCESS.0, FWP_E_FILTER_NOT_FOUND_DWORD, 5, 0x8032_0009] {
        let fails = first_delete_failure(&[("k", code)]).is_some();
        let observed_failed = classify_delete_code(code) == KeyOutcome::Failed;
        assert_eq!(fails, observed_failed, "code 0x{code:08x}");
    }
}

#[skuld::test]
fn observations_map_not_found_apart_from_a_real_removal() {
    // The FWPM half of the gate: `FWP_E_FILTER_NOT_FOUND` is the only code
    // that means "the key answered empty", and `ERROR_SUCCESS` the only one
    // that means "an object was removed".
    let swept = [
        (key("persistent", FilterLifetime::PERSISTENT), ERROR_SUCCESS.0),
        (
            key("persistent", FilterLifetime::PERSISTENT),
            FWP_E_FILTER_NOT_FOUND_DWORD,
        ),
        (key("boot-time", FilterLifetime::BOOT_TIME), ERROR_SUCCESS.0),
        (
            key("boot-time", FilterLifetime::BOOT_TIME),
            FWP_E_FILTER_NOT_FOUND_DWORD,
        ),
    ];
    let obs = observations(&swept);
    assert_eq!(
        obs.iter().map(|o| o.outcome).collect::<Vec<_>>(),
        [
            KeyOutcome::Removed,
            KeyOutcome::NotFound,
            KeyOutcome::Removed,
            KeyOutcome::NotFound
        ]
    );
    // ...and the lifetime rides through untouched, so the fold sees the class
    // the sweep list declared rather than one re-derived here.
    assert_eq!(
        obs.iter().map(|o| o.lifetime).collect::<Vec<_>>(),
        [
            KeyLifetime::Persistent,
            KeyLifetime::Persistent,
            KeyLifetime::BootTime,
            KeyLifetime::BootTime
        ]
    );
}

#[skuld::test]
fn a_not_found_sweep_proves_every_key_but_the_boot_time_twins() {
    // End-to-end over the REAL sweep lists with the "clean host" answer
    // (`FWP_E_FILTER_NOT_FOUND` everywhere). This is what stopped being an
    // unqualified clearance the moment #998's boot-time keys joined the
    // sweep, and the inversion is the point: a persistent key's by-key delete
    // addresses its only record, so empty proves empty; a boot-time key's
    // runtime object exists only between kernel start and BFE start, so on
    // every boot where `release_all` actually runs it answers empty whether
    // or not a policy record survives behind it. Reporting that as proof is
    // what lets `RemoveFiles` delete `hole.exe` over a live boot-window block
    // (bindreams/hole#1003).
    let swept: Vec<(SweptKey, u32)> = swept_lockdown_keys()
        .into_iter()
        .chain(swept_transient_keys())
        .map(|k| (k, FWP_E_FILTER_NOT_FOUND_DWORD))
        .collect();
    let clearance = Clearance::from_observations(&observations(&swept));
    assert_eq!(
        clearance.unproven_keys(),
        ["lockdown boot-time block-all V4", "lockdown boot-time block-all V6"],
        "exactly the boot-time twins go unproven on a not-found sweep — no persistent key may \
         join them, and neither twin may drop out"
    );
}

#[skuld::test]
fn a_sweep_that_watched_the_twins_go_proves_them_empty() {
    // The other half, and the reason `proves_empty` keys on the OUTCOME and
    // not on the lifetime alone: `ERROR_SUCCESS` is a removal somebody
    // watched happen, which is proof for a boot-time key exactly as it is for
    // a persistent one (`boottime_privileged_tests` measures that a live
    // twin's by-key delete returns it and that the filter leaves the
    // BOOTTIME_ONLY view). An uninstall on the boot that engaged is therefore
    // still an unqualified clearance; it is only the boot where no twin is
    // live that cannot be proven.
    let swept: Vec<(SweptKey, u32)> = swept_lockdown_keys()
        .into_iter()
        .chain(swept_transient_keys())
        .map(|k| (k, ERROR_SUCCESS.0))
        .collect();
    let clearance = Clearance::from_observations(&observations(&swept));
    assert!(
        clearance.is_proven(),
        "a removal that was watched happen proves the key empty whatever its lifetime: {:?}",
        clearance.unproven_keys()
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
        LOCKDOWN_FILTER_GUIDS.len() + LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS.len() + MAX_APPID_BINARIES * 2,
        "the probe must cover the fixed lockdown GUIDs, the boot-time block-all pair (#998), \
         and every App-ID slot"
    );
    assert!(
        probed.contains(&LOCKDOWN_FILTER_GUIDS[6]),
        "block-all V4 must be probed"
    );
    assert!(
        probed.contains(&LOCKDOWN_FILTER_GUIDS[7]),
        "block-all V6 must be probed"
    );
    assert!(
        probed.contains(&LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[0]),
        "boot-time block-all V4 must be probed"
    );
    assert!(
        probed.contains(&LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[1]),
        "boot-time block-all V6 must be probed"
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
    // Pinned as LITERALS, not as `lockdown_pre_delete_guids()`: comparing the
    // spec against the same expression `build_lockdown_spec` used to build it
    // is a tautology that cannot fail, and it would silently bless any future
    // edit to that helper.
    assert_eq!(
        spec.pre_delete,
        vec![
            LOCKDOWN_FILTER_GUIDS[2], // TUN V4
            LOCKDOWN_FILTER_GUIDS[3], // TUN V6
            LOCKDOWN_FILTER_GUIDS[4], // server V4
            LOCKDOWN_FILTER_GUIDS[5], // server V6
            appid_filter_guid(0, false),
            appid_filter_guid(0, true),
            appid_filter_guid(1, false),
            appid_filter_guid(1, true),
            appid_filter_guid(2, false),
            appid_filter_guid(2, true),
            appid_filter_guid(3, false),
            appid_filter_guid(3, true),
            LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[0],
            LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[1],
        ],
        "engage must drop exactly the runtime-valued permits — the TUN pair, BOTH server-family \
         permits and EVERY App-ID slot — plus the boot-time twins, before adding anything"
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
    // The App-ID slots are the opposite case, and the reason is the same one
    // that puts the TUN and server permits here: the key is derived from the
    // SLOT INDEX, the value is a process image path, and an update-cutover
    // reuses a slot's key with a new path. Leaving that to `ok_or_exists` kept
    // the pre-update `hole.exe` permitted and blocked the running one, under a
    // cover reporting success (bindreams/hole#1010, finding F2). Every slot is
    // dropped, including the ones this engage will not re-add — a config that
    // loses its plugin shortens `app_ids`, and the vacated slot's permit would
    // otherwise stand for a binary this bridge no longer runs.
    for i in 0..MAX_APPID_BINARIES {
        assert!(
            spec.pre_delete.contains(&appid_filter_guid(i, false)),
            "App-ID slot {i} V4 must be dropped before the adds"
        );
        assert!(
            spec.pre_delete.contains(&appid_filter_guid(i, true)),
            "App-ID slot {i} V6 must be dropped before the adds"
        );
    }
    assert!(
        added.contains(&appid_filter_guid(0, false)) && added.contains(&appid_filter_guid(1, false)),
        "the slots in use must be re-added with this engage's paths"
    );
    assert!(
        !added.contains(&appid_filter_guid(2, false)),
        "an unused slot stays deleted, not re-added stale"
    );
}

#[skuld::test]
fn engage_lockdown_rearms_the_boottime_twins_rather_than_leaving_them_to_ok_or_exists() {
    // The twins carry FIXED keys, like the volatile permits and unlike nothing
    // else in the floor — but a boot-time filter is SPENT by the boot it
    // covered, and Microsoft's pages disagree on what "spent" leaves behind.
    // Under the "removed" reading (`FwpmFilterAdd0`, "Object Management") a
    // plain add is enough. Under the "disabled" reading ("Basic Operation",
    // twice) the object survives with its key occupied, so the add returns
    // FWP_E_ALREADY_EXISTS, `ok_or_exists` reports Ok, and every engage after
    // the first re-arms nothing: the kill switch would cover one boot and then
    // silently stop. This PR refuses to adjudicate that disagreement, so it has
    // to be right under both — which means the keys must be pre-deleted.
    let spec = build_lockdown_spec(v4(), luid(), &[plugin_path(), bridge_path()]);
    for g in LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS {
        assert!(
            spec.pre_delete.contains(&g),
            "the boot-time twin {g:?} must be deleted before it is re-added, or a second engage \
             in one boot short-circuits on FWP_E_ALREADY_EXISTS and re-arms nothing"
        );
    }

    // A pre-delete only helps if the same engage adds the key back — otherwise
    // it is a disarm, not a re-arm.
    let added: std::collections::HashSet<GUID> = spec.filters.iter().map(|f| f.guid).collect();
    for g in LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS {
        assert!(
            added.contains(&g),
            "the boot-time twin {g:?} must be re-added by the same engage that deletes it"
        );
    }

    // The PERSISTENT block-all is live and enforcing right now; a refresh must
    // never drop the floor, not even inside a transaction.
    for guid in [LOCKDOWN_FILTER_GUIDS[6], LOCKDOWN_FILTER_GUIDS[7]] {
        assert!(
            !spec.pre_delete.contains(&guid),
            "the persistent block-all {guid:?} stays in force across a refresh"
        );
    }
}

#[skuld::test]
fn the_transient_cover_refreshes_its_runtime_valued_permits_too() {
    // It is normally engaged over a swept host, which is why this used to
    // delete nothing. "Normally" is not "always": `ok_or_exists`'s own
    // disclosed residual was a repair (release, then re-engage with a
    // corrected server) landing on a key whose release delete had failed, so
    // the re-add reported success and the OLD address stayed permitted
    // (bindreams/hole#1010, finding F2). Both families of both permits, for
    // the same reason the lockdown spec drops both: a V4->V6 server switch
    // must not leave the V4 permit standing.
    for spec in [
        build_cover_spec(v4(), None),
        build_cover_spec(v6(), Some(resolver_v4())),
    ] {
        assert_eq!(
            spec.pre_delete,
            vec![
                FILTER_GUIDS[2],  // server V4
                FILTER_GUIDS[3],  // server V6
                FILTER_GUIDS[10], // resolver V4
                FILTER_GUIDS[11], // resolver V6
            ]
        );
        // The floor is never dropped — deleting a BLOCK is the one thing that
        // could open the host mid-refresh.
        for guid in [
            FILTER_GUIDS[4],
            FILTER_GUIDS[5],
            FILTER_GUIDS[0],
            FILTER_GUIDS[1],
            FILTER_GUIDS[6],
            FILTER_GUIDS[7],
            FILTER_GUIDS[8],
            FILTER_GUIDS[9],
        ] {
            assert!(
                !spec.pre_delete.contains(&guid),
                "engage must not delete the transient fail-closed floor {guid:?}"
            );
        }
    }
}

#[skuld::test]
fn a_condition_carrying_a_runtime_value_is_told_apart_from_one_that_merely_holds_data() {
    // The predicate that decides whether `FWP_E_ALREADY_EXISTS` is benign.
    // `LoopbackNet` is the trap: it CARRIES an `IpAddr` and is still fixed,
    // because only the address family is read and the family is a property of
    // the key's layer. Grouping by "holds data" instead of by "can the data
    // differ between two engages of the same key" would put it on the wrong
    // side and make every re-engage over an unswept cover fail.
    for fixed in [
        Condition::Loopback,
        Condition::LoopbackNet(v4()),
        Condition::LoopbackNet(v6()),
        Condition::Any,
    ] {
        assert!(!fixed.carries_runtime_value(), "{fixed:?} is fixed by its key");
    }
    for runtime in [
        Condition::RemoteIp(v4()),
        Condition::RemoteIpPortTcp(resolver_v4(), RESOLVER_PERMIT_PORT),
        Condition::LocalInterface(luid()),
        Condition::AppId(plugin_path()),
    ] {
        assert!(
            runtime.carries_runtime_value(),
            "{runtime:?} can differ between two engages of the same key"
        );
    }
}

#[skuld::test]
fn a_boot_time_twin_needs_a_fresh_add_though_its_condition_carries_nothing() {
    // The gap a condition-only predicate had. A twin's condition is
    // `Condition::Any` — it carries no value at all — so
    // `carries_runtime_value` is false and the duplicate-add backstop skipped
    // exactly the two keys #998 exists to add. Under the "disabled" reading of
    // BFE startup, a twin dropping out of the pre-delete list would then give
    // a silent `Ok` over a kill switch that armed once and stopped.
    let twin = build_lockdown_spec(v4(), luid(), &[plugin_path()])
        .filters
        .into_iter()
        .find(|f| f.guid == LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[0])
        .expect("the V4 boot-time twin");
    assert_eq!(twin.condition, Condition::Any);
    assert!(!twin.condition.carries_runtime_value());
    assert!(
        twin.requires_fresh_add(),
        "a boot-time twin is spent by the boot it covered, so its key must be empty when the \
         re-arm adds it"
    );

    // The PERSISTENT block-all beside it is the control: fixed by its key, so
    // a re-add over an unswept cover stays idempotent — which is what lets an
    // adopted cover be re-engaged at all.
    let floor = build_lockdown_spec(v4(), luid(), &[plugin_path()])
        .filters
        .into_iter()
        .find(|f| f.guid == LOCKDOWN_FILTER_GUIDS[6])
        .expect("the V4 persistent block-all");
    assert!(!floor.requires_fresh_add());
}

#[skuld::test]
fn the_stale_key_policy_follows_what_the_caller_does_with_a_failed_engage() {
    // Not a property of which cover it is — a property of its caller, which is
    // why the two answers differ and why neither is safe for the other.
    //
    // `install_lockdown` is fail-fatal in `ProxyManager`: an aborted engage
    // rolls the transaction back and leaves whatever cover was in force still
    // in force, so failing costs a connection and never a cover.
    assert_eq!(
        build_lockdown_spec(v4(), luid(), &[plugin_path()]).stale_key,
        StaleKeyPolicy::Fail
    );
    // The transient cover's caller logs "host NOT blocked, proceeding open"
    // and runs UNCOVERED when this engage returns `Err` — and on the repair
    // path it has ALREADY released the cover it held, so there is nothing for
    // a rollback to preserve. Failing there would trade "covered, one stale
    // address permitted" for "no cover at all" on the exact path #1010's
    // finding F2 is about.
    assert_eq!(build_cover_spec(v4(), None).stale_key, StaleKeyPolicy::Degrade);
    assert_eq!(
        build_cover_spec(v6(), Some(resolver_v6())).stale_key,
        StaleKeyPolicy::Degrade
    );
}

#[skuld::test]
fn a_refused_pre_delete_fails_a_lockdown_engage_and_degrades_a_transient_one() {
    // The decision itself, on the `(label, code)` shape `issue_pre_deletes`
    // builds. `ERROR_ACCESS_DENIED` is the reachable case: FWPM opens the
    // engine unelevated but refuses the write.
    let refused = [("server-IP permit V4", ERROR_ACCESS_DENIED_DWORD)];
    let err = pre_delete_verdict(StaleKeyPolicy::Fail, &refused)
        .expect_err("a refused pre-delete must abort a kill-switch-armed start");
    assert!(
        err.to_string().contains("server-IP permit V4"),
        "the abort must name which key failed: {err}"
    );
    assert!(
        pre_delete_verdict(StaleKeyPolicy::Degrade, &refused).is_ok(),
        "the transient engage must keep the stale filter rather than lose the cover entirely"
    );

    // Benign for BOTH: every ordinary engage pre-deletes keys that are not
    // there. If not-found failed under `Fail`, the kill switch could never arm.
    let absent = [
        ("TUN-LUID permit V4", FWP_E_FILTER_NOT_FOUND_DWORD),
        ("lockdown boot-time block-all V4", FWP_E_FILTER_NOT_FOUND_DWORD),
    ];
    assert!(pre_delete_verdict(StaleKeyPolicy::Fail, &absent).is_ok());
    assert!(pre_delete_verdict(StaleKeyPolicy::Degrade, &absent).is_ok());
    // A removal that happened is benign too, and an empty list is a no-op.
    assert!(pre_delete_verdict(StaleKeyPolicy::Fail, &[("k", ERROR_SUCCESS.0)]).is_ok());
    assert!(pre_delete_verdict(StaleKeyPolicy::Fail, &[]).is_ok());
}

#[skuld::test]
fn no_spec_leaves_a_filter_that_needs_a_fresh_add_to_ok_or_exists() {
    // The F2 invariant over both covers, keyed on `requires_fresh_add` and NOT
    // on `carries_runtime_value`: every filter whose content can differ from
    // what is already stored under its key is pre-deleted in the same
    // transaction. That is two causes — a runtime-discovered value, and a
    // boot-time twin spent by the boot it covered — and the condition-only
    // predicate saw only the first, so it skipped exactly the keys #998
    // exists to add.
    let specs = [
        build_lockdown_spec(v4(), luid(), &[plugin_path(), bridge_path()]),
        build_lockdown_spec(v6(), luid(), &[plugin_path()]),
        build_cover_spec(v4(), Some(resolver_v4())),
        build_cover_spec(v6(), None),
    ];
    for spec in &specs {
        for f in spec.filters.iter().filter(|f| f.requires_fresh_add()) {
            assert!(
                spec.pre_delete.contains(&f.guid),
                "{:?}/{:?} needs an empty key but is not pre-deleted, so a re-engage would keep \
                 whatever the previous one stored",
                f.condition,
                f.lifetime
            );
        }
    }
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
fn a_not_found_pre_delete_is_benign_but_any_other_code_aborts_the_engage() {
    // The VERDICT function `engage_lockdown` folds its pre-delete codes
    // through, exercised on the exact `(label, code)` shape it builds. This
    // pins the decision, not the FFI wiring — that the real codes reach this
    // fold at all is `neither_engage_discards_its_pre_delete_codes`.
    // Two directions matter and they pull opposite ways:
    //
    // BENIGN — every ordinary engage pre-deletes keys that are not there. The
    // first engage on a clean host finds none of the six; the "removed" reading
    // of BFE startup means a spent twin is gone too. If not-found were fatal,
    // the kill switch could never arm at all.
    let every_key: Vec<GUID> = lockdown_pre_delete_guids()
        .into_iter()
        .chain(transient_pre_delete_guids())
        .collect();
    let all_absent: Vec<(&'static str, u32)> = every_key
        .iter()
        .map(|g| (pre_delete_label(g), FWP_E_FILTER_NOT_FOUND_DWORD))
        .collect();
    assert!(
        first_delete_failure(&all_absent).is_none(),
        "a first engage on a clean host pre-deletes every key and finds none of them; that must \
         not abort the start"
    );

    // FATAL — anything else means the key is still occupied, so the add that
    // follows returns FWP_E_ALREADY_EXISTS, `ok_or_exists` reports success, and
    // the engage hands back a cover that was never actually refreshed. That is
    // the silent failure the pre-delete exists to prevent.
    for (i, guid) in every_key.iter().enumerate() {
        let mut codes = all_absent.clone();
        codes[i] = (pre_delete_label(guid), ERROR_ACCESS_DENIED_DWORD);
        let err = first_delete_failure(&codes)
            .unwrap_or_else(|| panic!("an access-denied pre-delete of {guid:?} must abort the engage"));
        assert!(
            err.to_string().contains(pre_delete_label(guid)),
            "the abort must name which key failed, not just that one did: {err}"
        );
    }
}

#[skuld::test]
fn every_pre_delete_guid_has_its_own_label() {
    // A failing pre-delete now ABORTS a kill-switch-armed start, and
    // `first_delete_failure`'s `"{what} delete failed"` string is the whole
    // diagnostic — it carries no GUID. So the label must identify the key on
    // its own, down to the address family: a V6-only failure has ordinary
    // causes (a host with no IPv6 binding) that a V4 one does not.
    let guids: Vec<GUID> = lockdown_pre_delete_guids()
        .into_iter()
        .chain(transient_pre_delete_guids())
        .collect();
    let labels: Vec<&'static str> = guids.iter().map(pre_delete_label).collect();
    assert!(
        !labels.contains(&"unnamed pre-delete key"),
        "every pre-delete key must be named for the operator who sees the abort: {labels:?}"
    );
    // One name per key across every diagnostic: the pre-delete abort reads
    // the same `LOCKDOWN_BOOTTIME_TWINS` label `bridge release-covers` prints
    // for an unproven key, so an operator handed one string can find the
    // other.
    assert_eq!(
        pre_delete_label(&LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[0]),
        "lockdown boot-time block-all V4"
    );
    assert_eq!(
        pre_delete_label(&LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[1]),
        "lockdown boot-time block-all V6"
    );
    assert_eq!(pre_delete_label(&LOCKDOWN_FILTER_GUIDS[2]), "TUN-LUID permit V4");
    assert_eq!(pre_delete_label(&LOCKDOWN_FILTER_GUIDS[5]), "server-IP permit V6");
    assert_eq!(pre_delete_label(&appid_filter_guid(1, true)), "App-ID permit slot 1 V6");
    // The two covers are separate objects with separate GUIDs, so their
    // same-role keys are named apart: an operator reading which delete failed
    // needs to know which engage aborted.
    assert_eq!(pre_delete_label(&FILTER_GUIDS[3]), "transient server-IP permit V6");
    assert_eq!(pre_delete_label(&FILTER_GUIDS[10]), "transient resolver permit V4");
    // One label per key — no two pre-delete failures read alike.
    let distinct: std::collections::HashSet<&'static str> = labels.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        guids.len(),
        "each pre-delete key needs its own label, including per family: {labels:?}"
    );
}

/// The text of the item starting at `head`, bounded by its own column-0
/// closing brace, so a guard cannot drift onto a neighbour or read its own
/// prose.
fn item_body<'a>(src: &'a str, head: &str) -> &'a str {
    let start = src
        .find(head)
        .unwrap_or_else(|| panic!("{head} must exist in windows.rs"));
    let after = &src[start..];
    let end = after.find("\n}\n").map(|i| i + 2).unwrap_or(after.len());
    &after[..end]
}

#[skuld::test]
fn neither_engage_discards_its_pre_delete_codes() {
    // A pre-delete is the ONLY thing standing between a re-engage and a filter
    // that was never replaced. Unlike a sweep, where a failed delete is warned
    // and life goes on, a failed pre-delete must abort: the add that follows
    // finds the key still occupied, and for a runtime-valued filter
    // `add_filter` then fails with a bare FWPM code naming nothing.
    //
    // Structural guard, same technique and same reason as
    // `reclaim_stale_tun_permit_does_not_discard_delete_codes` below: there is
    // no fixture in this file that can make a real FwpmFilterDeleteByKey0 fail
    // with an access-denied DACL. Both engages are covered because both now
    // pre-delete — the transient one gained its own list with #1010's finding
    // F2, and a guard scoped to `engage_lockdown` alone would have gone on
    // passing while the new path discarded everything.
    let src = include_str!("windows.rs");

    let fold = item_body(src, "unsafe fn issue_pre_deletes(");
    // Counted, not pattern-matched for a discard: `let _ = f(..)`,
    // `let _rc = f(..)` and a bare `f(..);` statement all discard a `u32`
    // without a warning, so a guard that only rejected the first spelling
    // read as coverage it did not have. Exactly one call, and the assertion
    // below pins that it is the one feeding `codes`.
    assert_eq!(
        fold.matches("FwpmFilterDeleteByKey0").count(),
        1,
        "issue_pre_deletes must issue its deletes in exactly one place, the labelled map whose \
         codes are folded:\n{fold}"
    );
    assert!(
        fold.contains("first_delete_failure(&codes)"),
        "issue_pre_deletes must fold its codes through first_delete_failure, so a not-found stays \
         benign and anything else aborts the transaction:\n{fold}"
    );
    // The label mapping is only worth testing if production actually uses it;
    // a hardcoded string here would leave `pre_delete_label` dead and every
    // abort message identical.
    assert!(
        fold.contains("pre_delete_label(g)"),
        "issue_pre_deletes must label each pre-delete via pre_delete_label, or the abort cannot \
         say which key failed:\n{fold}"
    );

    for head in ["pub fn engage(", "pub fn engage_lockdown("] {
        let body = item_body(src, head);
        assert!(
            body.contains("issue_pre_deletes(engine, &spec.pre_delete, spec.stale_key)"),
            "{head} must issue its spec's pre-deletes through the shared fold:\n{body}"
        );
        assert_eq!(
            body.matches("FwpmFilterDeleteByKey0").count(),
            0,
            "{head} must reach its pre-deletes only through issue_pre_deletes, where the codes \
             are folded — a call of its own could discard one:\n{body}"
        );
    }
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
