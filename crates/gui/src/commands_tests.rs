use super::*;
use hole_common::config::{AppConfig, ServerEntry};

fn test_entry(id: &str) -> ServerEntry {
    ServerEntry {
        id: id.to_string(),
        name: format!("Server {id}"),
        server: "1.2.3.4".to_string(),
        server_port: 8388,
        method: "aes-256-gcm".to_string(),
        password: "pw".to_string(),
        plugin: None,
        plugin_opts: None,
    }
}

#[skuld::test]
fn build_proxy_config_with_selected_server() {
    let config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: Some("b".to_string()),
        local_port: 4073,
        enabled: false,
    };

    let pc = build_proxy_config(&config).expect("should return Some");
    assert_eq!(pc.server.id, "b");
    assert_eq!(pc.local_port, 4073);
    assert!(pc.plugin_path.is_none());
}

#[skuld::test]
fn build_proxy_config_no_selection() {
    let config = AppConfig {
        servers: vec![test_entry("a")],
        selected_server: None,
        local_port: 4073,
        enabled: false,
    };

    assert!(build_proxy_config(&config).is_none());
}

#[skuld::test]
fn build_proxy_config_invalid_selection() {
    let config = AppConfig {
        servers: vec![test_entry("a")],
        selected_server: Some("nonexistent".to_string()),
        local_port: 4073,
        enabled: false,
    };

    assert!(build_proxy_config(&config).is_none());
}
