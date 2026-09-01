use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

fn sample_ipv4() -> RouteState {
    let server_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
    RouteState {
        version: SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip,
        interface_name: "en0".into(),
        original_gateway: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        route_form: RouteForm::Via,
        installed: planned_routes(server_ip),
        stale: Vec::new(),
    }
}

fn sample_ipv6() -> RouteState {
    let server_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    RouteState {
        version: SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip,
        interface_name: "Wi-Fi".into(),
        original_gateway: None,
        route_form: RouteForm::Via,
        installed: vec![RouteId::SplitV6Low],
        stale: Vec::new(),
    }
}

/// A record carrying a stale group from an earlier, still-unswept session —
/// the schema-3 shape [`load_v1_migrates_to_the_full_planned_set`] and
/// friends never exercise.
fn sample_ipv4_with_stale() -> RouteState {
    let stale_server_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
    RouteState {
        stale: vec![StaleRecord {
            tun_name: "hole-tun".into(),
            server_ip: stale_server_ip,
            interface_name: "en1".into(),
            original_gateway: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 1))),
            route_form: RouteForm::Via,
            installed: vec![RouteId::ServerBypass],
        }],
        ..sample_ipv4()
    }
}

#[skuld::test]
fn save_then_load_roundtrip_ipv4() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_ipv4();
    save(dir.path(), &state, None).unwrap();
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn save_then_load_roundtrip_ipv6() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_ipv6();
    save(dir.path(), &state, None).unwrap();
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn save_then_load_roundtrip_with_stale_groups() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_ipv4_with_stale();
    save(dir.path(), &state, None).unwrap();
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn load_missing_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_corrupted_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(STATE_FILE_NAME), b"not valid json { .").unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_wrong_version_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 99,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_unknown_field_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": SCHEMA_VERSION,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
        "original_gateway": null,
        "installed": ["split-v4-low"],
        "stale": [],
        "extra_field": "should be rejected",
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn clear_missing_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    clear(dir.path()).unwrap();
}

#[skuld::test]
fn clear_existing_removes_file() {
    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &sample_ipv4(), None).unwrap();
    assert!(dir.path().join(STATE_FILE_NAME).exists());
    clear(dir.path()).unwrap();
    assert!(!dir.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn save_creates_missing_dir() {
    let parent = tempfile::tempdir().unwrap();
    let nested = parent.path().join("a").join("b").join("c");
    save(&nested, &sample_ipv4(), None).unwrap();
    assert!(nested.join(STATE_FILE_NAME).exists());
}

// Schema migration ====================================================================================================
//
// A schema bump must not silently turn recovery into a no-op: the state file
// is the only record of what a crashed run leaked, so a rejected file leaves
// the host on split routes pointing at a TUN that no longer exists.

#[skuld::test]
fn load_v1_migrates_to_the_full_planned_set() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 1,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();

    let loaded = load(dir.path()).expect("a v1 file must still drive recovery, not be discarded");
    assert_eq!(loaded.version, SCHEMA_VERSION);
    assert_eq!(loaded.tun_name, "hole-tun");
    assert_eq!(loaded.interface_name, "en0");
    assert_eq!(
        loaded.installed,
        planned_routes(loaded.server_ip),
        "v1 had no provenance and deleted every planned route; the migration must delete the same set"
    );
    assert_eq!(loaded.original_gateway, None, "v1 never persisted a gateway");
    assert_eq!(loaded.stale, Vec::new(), "v1 had no stale-group concept");
}

#[skuld::test]
fn load_v2_migrates_preserving_installed_and_leaving_gateway_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 2,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
        "installed": ["split-v4-low", "server-bypass"],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();

    let loaded = load(dir.path()).expect("a v2 file must still drive recovery, not be discarded");
    assert_eq!(loaded.version, SCHEMA_VERSION);
    assert_eq!(loaded.tun_name, "hole-tun");
    assert_eq!(loaded.interface_name, "en0");
    assert_eq!(
        loaded.installed,
        vec![RouteId::SplitV4Low, RouteId::ServerBypass],
        "v2 DID have provenance — unlike v1, the migration must preserve it exactly, not widen to the full planned set"
    );
    assert_eq!(
        loaded.original_gateway, None,
        "v2 never persisted a gateway — the migrated record falls back to an unscoped delete"
    );
    assert_eq!(loaded.stale, Vec::new(), "v2 had no stale-group concept");
}

/// A record without a `route_form` field predates on-link support entirely,
/// so every route it names was installed through a real gateway — teardown
/// must pick the gateway delete form, never default to (or panic on) the
/// interface-scoped form it never used.
#[skuld::test]
fn a_record_without_a_form_field_migrates_to_via() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 3,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
        "original_gateway": "203.0.113.254",
        "installed": ["server-bypass"],
        "stale": [],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();

    let loaded = load(dir.path()).expect("a v3 file must still drive recovery, not be discarded");
    assert_eq!(loaded.version, SCHEMA_VERSION);
    assert_eq!(
        loaded.route_form,
        RouteForm::Via,
        "a v3 record never had an on-link bypass"
    );
    assert_eq!(loaded.original_gateway, Some("203.0.113.254".parse().unwrap()));
}

/// The same migration, exercised on a carried-forward `stale` group nested
/// inside the v3 record — `StaleRecordV3` must migrate too, not just the
/// top-level fields.
#[skuld::test]
fn a_stale_group_without_a_form_field_migrates_to_via() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 3,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
        "original_gateway": null,
        "installed": [],
        "stale": [{
            "tun_name": "hole-tun",
            "server_ip": "9.9.9.9",
            "interface_name": "en1",
            "original_gateway": "9.9.9.1",
            "installed": ["server-bypass"],
        }],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();

    let loaded = load(dir.path()).expect("a v3 file must still drive recovery, not be discarded");
    assert_eq!(loaded.stale.len(), 1);
    assert_eq!(loaded.stale[0].route_form, RouteForm::Via);
}

#[skuld::test]
fn load_v2_with_unknown_field_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 2,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
        "installed": ["split-v4-low"],
        "extra_field": "should be rejected",
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_v1_loopback_migrates_without_the_bypass() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 1,
        "tun_name": "hole-tun",
        "server_ip": "127.0.0.1",
        "interface_name": "en0",
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();

    let loaded = load(dir.path()).unwrap();
    assert!(
        !loaded.installed.contains(&RouteId::ServerBypass),
        "a loopback server never installs a bypass, got {:?}",
        loaded.installed
    );
}

#[skuld::test]
fn load_v1_with_unknown_field_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 1,
        "tun_name": "hole-tun",
        "server_ip": "203.0.113.1",
        "interface_name": "en0",
        "extra_field": "should be rejected",
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

// Canonical form ======================================================================================================
//
// `coalesce` is the shared primitive every group-consuming path (sweep,
// crash recovery) must route through: groups sharing an identity — the
// tuple that determines the teardown argv they'd each emit — merge into one,
// each survivor is sanitized against `planned_routes(server_ip)`, and an
// empty survivor is dropped. See CONTRIBUTING's Route ownership section.

fn group(server_ip: IpAddr, installed: Vec<RouteId>) -> StaleRecord {
    StaleRecord {
        tun_name: "hole-tun".into(),
        server_ip,
        interface_name: "en0".into(),
        original_gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        route_form: RouteForm::Via,
        installed,
    }
}

#[skuld::test]
fn coalesce_merges_two_groups_with_identical_identity() {
    let server_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
    let a = group(server_ip, vec![RouteId::SplitV4Low]);
    let b = group(server_ip, vec![RouteId::SplitV4High]);

    let merged = coalesce(vec![a, b]);

    assert_eq!(merged.len(), 1, "identical-identity groups must become one: {merged:?}");
    assert_eq!(merged[0].installed, vec![RouteId::SplitV4Low, RouteId::SplitV4High]);
}

#[skuld::test]
fn coalesce_merges_more_than_two_duplicate_entries() {
    // Simulates N consecutive failed install attempts to the same server,
    // each leaving its own unconfirmed leftover — they must fold into one
    // retried entry, not accumulate one per attempt.
    let server_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
    let groups = vec![
        group(server_ip, vec![RouteId::ServerBypass]),
        group(server_ip, vec![RouteId::ServerBypass]),
        group(server_ip, vec![RouteId::ServerBypass]),
    ];

    let merged = coalesce(groups);

    assert_eq!(
        merged.len(),
        1,
        "repeated failed attempts must not each grow the stale list: {merged:?}"
    );
    assert_eq!(merged[0].installed, vec![RouteId::ServerBypass]);
}

#[skuld::test]
fn coalesce_keeps_distinct_identities_separate() {
    let a = group(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), vec![RouteId::SplitV4Low]);
    let b = group(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), vec![RouteId::SplitV4Low]);

    let merged = coalesce(vec![a.clone(), b.clone()]);

    assert_eq!(
        merged.len(),
        2,
        "different server_ip means different identity: {merged:?}"
    );
    assert!(merged.contains(&a));
    assert!(merged.contains(&b));
}

#[skuld::test]
fn coalesce_drops_an_id_with_no_possible_teardown_command() {
    let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // ServerBypass against a loopback server_ip can never produce a
    // teardown command (see `platform_bypass_teardown_command`), so it can
    // never drain from `still_installed` — must be sanitized away here,
    // the same defense `recover_routes_with` already applies to its own
    // two record kinds.
    let unplannable = group(loopback, vec![RouteId::ServerBypass]);

    let merged = coalesce(vec![unplannable]);

    assert!(
        merged.is_empty(),
        "an unplannable-only group must be dropped, not pin stale open forever: {merged:?}"
    );
}

#[skuld::test]
fn coalesce_sanitizes_a_plannable_id_alongside_an_unplannable_one() {
    let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let mixed = group(loopback, vec![RouteId::SplitV4Low, RouteId::ServerBypass]);

    let merged = coalesce(vec![mixed]);

    assert_eq!(merged.len(), 1);
    assert_eq!(
        merged[0].installed,
        vec![RouteId::SplitV4Low],
        "the plannable id must survive even though its sibling was dropped"
    );
}

/// Pin `installed`'s wire names: they are the persisted schema-2 format a
/// newer binary must read back from an older run's crash-leftover file, so
/// renaming a `RouteId` variant is a schema break needing a `SCHEMA_VERSION`
/// bump and a migration arm, same as the v1 migration below.
#[skuld::test]
fn installed_routes_serialize_as_kebab_case() {
    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &sample_ipv4(), None).unwrap();
    let raw = std::fs::read_to_string(dir.path().join(STATE_FILE_NAME)).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        parsed["installed"],
        serde_json::json!([
            "split-v4-low",
            "split-v4-high",
            "split-v6-low",
            "split-v6-high",
            "server-bypass"
        ]),
        "in:\n{raw}"
    );
}
