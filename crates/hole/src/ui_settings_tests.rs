use super::*;
use hole_common::config::{AppConfig, ServerEntry, ValidationState};
use hole_common::protocol::ServerTestOutcome;
use time::OffsetDateTime;

fn entry(id: &str) -> ServerEntry {
    ServerEntry {
        id: id.into(),
        name: format!("Server {id}"),
        server: "1.2.3.4".into(),
        server_port: 8388,
        method: "aes-256-gcm".into(),
        password: "pw".into(),
        plugin: None,
        plugin_opts: None,
        validation: None,
    }
}

fn validated(id: &str) -> ServerEntry {
    ServerEntry {
        validation: Some(ValidationState {
            tested_at: OffsetDateTime::UNIX_EPOCH,
            outcome: ServerTestOutcome::Reachable { latency_ms: 42 },
        }),
        ..entry(id)
    }
}

fn ui_entry(id: &str) -> UiServerEntry {
    serde_json::from_value(serde_json::json!({
        "id": id, "name": format!("Server {id}"), "server": "1.2.3.4",
        "server_port": 8388, "method": "aes-256-gcm", "password": "pw",
    }))
    .unwrap()
}

fn default_settings_json() -> serde_json::Value {
    serde_json::json!({
        "servers": [], "selected_server": null, "local_port": 4073,
        "filters": [], "start_on_login": false, "on_startup": "restore_last_state",
        "theme": "dark", "proxy_server_enabled": true, "proxy_socks5": true,
        "proxy_http": false, "dns": AppConfig::default().dns, "local_port_http": 4074,
        "diagnostic_plugin_tap": false
    })
}

// The defect-1 regression (#462): backend-owned fields are unrepresentable
// on the wire — a frontend that sends them must fail loudly, not be
// silently merged or ignored.
#[skuld::test]
fn deserialize_rejects_enabled_key() {
    let mut json = default_settings_json();
    json["enabled"] = serde_json::json!(true);
    let err = serde_json::from_value::<UiSettings>(json).unwrap_err();
    assert!(err.to_string().contains("enabled"), "got: {err}");
}

#[skuld::test]
fn deserialize_rejects_elevation_prompt_shown_key() {
    let mut json = default_settings_json();
    json["elevation_prompt_shown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<UiSettings>(json).is_err());
}

// Relies on UiServerEntry's OWN deny_unknown_fields — the attribute does
// not recurse from UiSettings. Dropping it there would make `validation`
// silently *ignored* instead of rejected, and this test would catch that.
#[skuld::test]
fn deserialize_rejects_server_validation_key() {
    let mut json = default_settings_json();
    json["servers"] = serde_json::json!([{
        "id": "a", "name": "A", "server": "1.2.3.4", "server_port": 8388,
        "method": "aes-256-gcm", "password": "pw",
        "validation": {
            "tested_at": "2026-01-01T00:00:00Z",
            "outcome": { "kind": "reachable", "latency_ms": 1 }
        }
    }]);
    assert!(serde_json::from_value::<UiSettings>(json).is_err());
}

#[skuld::test]
fn apply_preserves_backend_owned_fields() {
    let mut current = AppConfig {
        enabled: true,
        elevation_prompt_shown: true,
        ..Default::default()
    };
    let settings: UiSettings = serde_json::from_value(default_settings_json()).unwrap();
    settings.apply(&mut current);
    assert!(current.enabled, "stale UI save must not clobber backend-owned enabled");
    assert!(current.elevation_prompt_shown);
}

// Membership is backend-owned (#504): apply merges UI-owned fields by id and
// can neither add nor drop members.

#[skuld::test]
fn apply_keeps_servers_absent_from_payload() {
    // Backend imported "c" after the webview took its snapshot; the stale
    // save payload only knows "a" and "b". "c" must survive (#504).
    let mut current = AppConfig {
        servers: vec![entry("a"), entry("b"), entry("c")],
        selected_server: Some("a".into()),
        ..Default::default()
    };
    let mut settings: UiSettings = serde_json::from_value(default_settings_json()).unwrap();
    settings.servers = vec![ui_entry("a"), ui_entry("b")];
    settings.apply(&mut current);
    assert_eq!(
        current.servers.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["a", "b", "c"],
        "a server absent from the stale payload must not be dropped; order preserved"
    );
}

#[skuld::test]
fn apply_ignores_payload_ids_absent_from_current() {
    // The UI cannot mint server ids; a payload entry the backend never had
    // (e.g. a server deleted concurrently) must not be resurrected.
    let mut current = AppConfig {
        servers: vec![entry("a")],
        ..Default::default()
    };
    let mut settings: UiSettings = serde_json::from_value(default_settings_json()).unwrap();
    settings.servers = vec![ui_entry("a"), ui_entry("ghost")];
    settings.apply(&mut current);
    assert_eq!(
        current.servers.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["a"],
        "unknown payload id must be ignored"
    );
}

#[skuld::test]
fn apply_updates_ui_fields_by_id_keeping_validation() {
    let mut current = AppConfig {
        servers: vec![validated("a")],
        ..Default::default()
    };
    let mut settings: UiSettings = serde_json::from_value(default_settings_json()).unwrap();
    settings.servers = vec![UiServerEntry {
        name: "Renamed".into(),
        ..ui_entry("a")
    }];
    settings.apply(&mut current);
    assert_eq!(current.servers.len(), 1);
    assert_eq!(current.servers[0].name, "Renamed", "UI-owned field updated by id");
    assert!(
        current.servers[0].validation.is_some(),
        "backend-owned validation preserved"
    );
}

#[skuld::test]
fn apply_duplicate_incoming_ids_update_single_member() {
    // The UI should never send duplicate ids, but if it does, membership still
    // comes from `current` (one member) and the first payload occurrence wins
    // for its fields.
    let mut current = AppConfig {
        servers: vec![validated("a")],
        ..Default::default()
    };
    let mut settings: UiSettings = serde_json::from_value(default_settings_json()).unwrap();
    settings.servers = vec![ui_entry("a"), ui_entry("a")];
    settings.apply(&mut current);
    assert_eq!(
        current.servers.len(),
        1,
        "membership comes from current, not the payload"
    );
    assert!(current.servers[0].validation.is_some(), "validation preserved");
}

#[skuld::test]
fn apply_keeps_current_order_ignoring_payload_order() {
    // `current` order is authoritative; iterating the payload (as the old
    // wholesale-replace did) would let a reordered snapshot reorder the list.
    let mut current = AppConfig {
        servers: vec![entry("a"), entry("b")],
        ..Default::default()
    };
    let mut settings: UiSettings = serde_json::from_value(default_settings_json()).unwrap();
    settings.servers = vec![ui_entry("b"), ui_entry("a")]; // reversed
    settings.apply(&mut current);
    assert_eq!(
        current.servers.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["a", "b"],
        "payload order must not reorder the authoritative list"
    );
}

#[skuld::test]
fn apply_replaces_ui_owned_fields() {
    let mut current = AppConfig::default();
    let mut json = default_settings_json();
    json["local_port"] = serde_json::json!(5555);
    let settings: UiSettings = serde_json::from_value(json).unwrap();
    settings.apply(&mut current);
    assert_eq!(current.local_port, 5555);
}
