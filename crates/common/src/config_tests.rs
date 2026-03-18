use super::*;
use skuld::temp_dir;
use std::path::Path;

#[skuld::test]
fn load_nonexistent_returns_defaults(#[fixture(temp_dir)] dir: &Path) {
    let config = AppConfig::load(&dir.join("nonexistent.json")).unwrap();
    assert_eq!(config.local_port, 4073);
    assert!(config.servers.is_empty());
    assert!(!config.enabled);
    assert_eq!(config.selected_server, None);
}

#[skuld::test]
fn load_valid_json_roundtrips(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let original = AppConfig {
        servers: vec![ServerEntry {
            id: "abc-123".to_string(),
            name: "Test".to_string(),
            server: "1.2.3.4".to_string(),
            server_port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "secret".to_string(),
            plugin: None,
            plugin_opts: None,
        }],
        selected_server: Some("abc-123".to_string()),
        local_port: 5555,
        enabled: true,
    };
    original.save(&path).unwrap();
    let loaded = AppConfig::load(&path).unwrap();
    assert_eq!(original, loaded);
}

#[skuld::test]
fn load_corrupt_json_returns_error(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("bad.json");
    std::fs::write(&path, "not json at all {{{").unwrap();
    let err = AppConfig::load(&path).unwrap_err();
    assert!(err.to_string().contains("parse"));
}

#[skuld::test]
fn save_creates_parent_dirs(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("nested").join("deep").join("config.json");
    AppConfig::default().save(&path).unwrap();
    assert!(path.exists());
}

#[skuld::test]
fn save_then_load_is_identity(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let config = AppConfig::default();
    config.save(&path).unwrap();
    let loaded = AppConfig::load(&path).unwrap();
    assert_eq!(config, loaded);
}

#[skuld::test]
fn default_selected_server_is_none() {
    assert_eq!(AppConfig::default().selected_server, None);
}

#[skuld::test]
fn selected_entry_with_unknown_uuid_returns_none() {
    let config = AppConfig {
        selected_server: Some("nonexistent-uuid".to_string()),
        servers: vec![ServerEntry {
            id: "abc".to_string(),
            name: "S".to_string(),
            server: "1.2.3.4".to_string(),
            server_port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "pw".to_string(),
            plugin: None,
            plugin_opts: None,
        }],
        ..Default::default()
    };
    assert!(config.selected_entry().is_none());
}

#[skuld::test]
fn selected_entry_with_valid_uuid_returns_correct_entry() {
    let config = AppConfig {
        selected_server: Some("target-id".to_string()),
        servers: vec![
            ServerEntry {
                id: "other-id".to_string(),
                name: "Other".to_string(),
                server: "1.1.1.1".to_string(),
                server_port: 1111,
                method: "aes-256-gcm".to_string(),
                password: "pw1".to_string(),
                plugin: None,
                plugin_opts: None,
            },
            ServerEntry {
                id: "target-id".to_string(),
                name: "Target".to_string(),
                server: "2.2.2.2".to_string(),
                server_port: 2222,
                method: "chacha20-ietf-poly1305".to_string(),
                password: "pw2".to_string(),
                plugin: None,
                plugin_opts: None,
            },
        ],
        ..Default::default()
    };
    let entry = config.selected_entry().unwrap();
    assert_eq!(entry.name, "Target");
    assert_eq!(entry.server, "2.2.2.2");
}

#[skuld::test]
fn deserialize_with_missing_fields_uses_defaults() {
    let json = r#"{"servers": []}"#;
    let config: AppConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.local_port, 4073);
    assert!(!config.enabled);
    assert_eq!(config.selected_server, None);
}

#[skuld::test]
fn deserialize_with_extra_unknown_fields_succeeds() {
    let json = r#"{"servers": [], "future_field": 42, "another": "hi"}"#;
    let config: AppConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.local_port, 4073);
}
