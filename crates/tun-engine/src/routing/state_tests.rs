use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

fn sample_ipv4() -> RouteState {
    let server_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
    RouteState {
        version: SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip,
        interface_name: "en0".into(),
        installed: planned_routes(server_ip),
    }
}

fn sample_ipv6() -> RouteState {
    let server_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    RouteState {
        version: SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip,
        interface_name: "Wi-Fi".into(),
        installed: vec![RouteId::SplitV6Low],
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
        "installed": ["split-v4-low"],
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
