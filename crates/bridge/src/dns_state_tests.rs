use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::*;

fn sample_windows_state() -> DnsState {
    DnsState {
        version: SCHEMA_VERSION,
        chosen_loopback: SocketAddr::from(([127, 0, 0, 1], 53)),
        adapters: vec![
            DnsPriorAdapter {
                id: AdapterId::WindowsLuid {
                    value: 0x0001_0000_0000_0001,
                },
                name_at_capture: "Ethernet".into(),
                v4: DnsPrior::Static {
                    servers: vec![
                        IpAddr::V4(Ipv4Addr::new(89, 216, 1, 40)),
                        IpAddr::V4(Ipv4Addr::new(89, 216, 1, 50)),
                    ],
                },
                v6: DnsPrior::None,
            },
            DnsPriorAdapter {
                id: AdapterId::WindowsLuid {
                    value: 0x0002_0000_0000_0002,
                },
                name_at_capture: "hole-tun".into(),
                v4: DnsPrior::Dhcp,
                v6: DnsPrior::Static {
                    servers: vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888))],
                },
            },
        ],
    }
}

fn sample_macos_state() -> DnsState {
    DnsState {
        version: SCHEMA_VERSION,
        chosen_loopback: SocketAddr::from(([127, 53, 0, 1], 53)),
        adapters: vec![DnsPriorAdapter {
            id: AdapterId::MacosServiceId {
                value: "BE3F4D41-1234-5678-ABCD-0123456789AB".into(),
            },
            name_at_capture: "Wi-Fi".into(),
            v4: DnsPrior::Dhcp,
            v6: DnsPrior::None,
        }],
    }
}

#[skuld::test]
fn save_then_load_roundtrip_windows() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_windows_state();
    save(dir.path(), &state).unwrap();
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn save_then_load_roundtrip_macos() {
    let dir = tempfile::tempdir().unwrap();
    let state = sample_macos_state();
    save(dir.path(), &state).unwrap();
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn save_then_load_roundtrip_fallback_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let state = DnsState {
        version: SCHEMA_VERSION,
        chosen_loopback: SocketAddr::from(([127, 53, 0, 254], 53)),
        adapters: vec![],
    };
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
        "chosen_loopback": "127.0.0.1:53",
        "adapters": [],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_unknown_top_level_field_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": SCHEMA_VERSION,
        "chosen_loopback": "127.0.0.1:53",
        "adapters": [],
        "extra_field": "should be rejected",
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_unknown_adapter_field_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": SCHEMA_VERSION,
        "chosen_loopback": "127.0.0.1:53",
        "adapters": [{
            "id": { "kind": "windows_luid", "value": 42 },
            "name_at_capture": "Ethernet",
            "v4": { "kind": "none" },
            "v6": { "kind": "none" },
            "surprise": true,
        }],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_unknown_dns_prior_variant_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": SCHEMA_VERSION,
        "chosen_loopback": "127.0.0.1:53",
        "adapters": [{
            "id": { "kind": "windows_luid", "value": 42 },
            "name_at_capture": "Ethernet",
            "v4": { "kind": "mystery_mode" },
            "v6": { "kind": "none" },
        }],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn dns_prior_variants_serialize_snake_case() {
    let none_json = serde_json::to_value(DnsPrior::None).unwrap();
    assert_eq!(none_json, serde_json::json!({ "kind": "none" }));

    let dhcp_json = serde_json::to_value(DnsPrior::Dhcp).unwrap();
    assert_eq!(dhcp_json, serde_json::json!({ "kind": "dhcp" }));

    let static_json = serde_json::to_value(DnsPrior::Static {
        servers: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
    })
    .unwrap();
    assert_eq!(
        static_json,
        serde_json::json!({ "kind": "static", "servers": ["1.1.1.1"] })
    );
}

#[skuld::test]
fn adapter_id_variants_serialize_snake_case() {
    let win = serde_json::to_value(AdapterId::WindowsLuid { value: 42 }).unwrap();
    assert_eq!(win, serde_json::json!({ "kind": "windows_luid", "value": 42 }));

    let mac = serde_json::to_value(AdapterId::MacosServiceId { value: "abc".into() }).unwrap();
    assert_eq!(mac, serde_json::json!({ "kind": "macos_service_id", "value": "abc" }));
}

#[skuld::test]
fn load_rejects_unknown_field_in_static_variant() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": SCHEMA_VERSION,
        "chosen_loopback": "127.0.0.1:53",
        "adapters": [{
            "id": { "kind": "windows_luid", "value": 42 },
            "name_at_capture": "Ethernet",
            "v4": { "kind": "static", "servers": ["1.1.1.1"], "mystery": true },
            "v6": { "kind": "none" },
        }],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_rejects_unknown_field_in_macos_service_id() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": SCHEMA_VERSION,
        "chosen_loopback": "127.0.0.1:53",
        "adapters": [{
            "id": { "kind": "macos_service_id", "value": "abc", "extra": 1 },
            "name_at_capture": "Wi-Fi",
            "v4": { "kind": "none" },
            "v6": { "kind": "none" },
        }],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_rejects_missing_required_field() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": SCHEMA_VERSION,
        // chosen_loopback missing
        "adapters": [],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn save_then_load_roundtrip_ipv6_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let state = DnsState {
        version: SCHEMA_VERSION,
        chosen_loopback: SocketAddr::from((Ipv6Addr::LOCALHOST, 53)),
        adapters: vec![],
    };
    save(dir.path(), &state).unwrap();
    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, state);
}

#[skuld::test]
fn save_overwrites_prior_file() {
    let dir = tempfile::tempdir().unwrap();
    let first = sample_windows_state();
    save(dir.path(), &first).unwrap();

    let second = sample_macos_state();
    save(dir.path(), &second).unwrap();

    let loaded = load(dir.path()).unwrap();
    assert_eq!(loaded, second);
}

#[skuld::test]
fn save_leaves_no_stray_temp_files() {
    // Guards against a future refactor that replaces `NamedTempFile` with
    // a manual write+rename that leaks `.tmpXXX` siblings.
    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &sample_windows_state()).unwrap();
    save(dir.path(), &sample_macos_state()).unwrap();
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from(STATE_FILE_NAME)]);
}

#[skuld::test]
fn clear_missing_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    clear(dir.path()).unwrap();
}

#[skuld::test]
fn clear_existing_removes_file() {
    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &sample_windows_state()).unwrap();
    assert!(dir.path().join(STATE_FILE_NAME).exists());
    clear(dir.path()).unwrap();
    assert!(!dir.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn save_creates_missing_dir() {
    let parent = tempfile::tempdir().unwrap();
    let nested = parent.path().join("a").join("b").join("c");
    save(&nested, &sample_windows_state()).unwrap();
    assert!(nested.join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn state_file_name_is_bridge_dns_json() {
    assert_eq!(STATE_FILE_NAME, "bridge-dns.json");
}
