use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

fn sample_ipv4() -> RouteState {
    RouteState {
        version: SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)),
        interface_name: "en0".into(),
    }
}

fn sample_ipv6() -> RouteState {
    RouteState {
        version: SCHEMA_VERSION,
        tun_name: "hole-tun".into(),
        server_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        interface_name: "Wi-Fi".into(),
    }
}

#[skuld::test]
fn save_then_load_roundtrip_ipv4() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_ipv4();
    save(dir.path(), &state).unwrap();
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn save_then_load_roundtrip_ipv6() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_ipv6();
    save(dir.path(), &state).unwrap();
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
    save(dir.path(), &sample_ipv4()).unwrap();
    assert!(dir.path().join(STATE_FILE_NAME).exists());
    clear(dir.path()).unwrap();
    assert!(!dir.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn save_creates_missing_dir() {
    let parent = tempfile::tempdir().unwrap();
    let nested = parent.path().join("a").join("b").join("c");
    save(&nested, &sample_ipv4()).unwrap();
    assert!(nested.join(STATE_FILE_NAME).exists());
}
