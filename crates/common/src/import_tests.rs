use super::*;

#[skuld::test]
fn parse_single_server_minimal() {
    let json = r#"{
        "server": "1.2.3.4",
        "server_port": 8388,
        "password": "pw",
        "method": "aes-256-gcm"
    }"#;
    let servers = import_servers(json).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].server, "1.2.3.4");
    assert_eq!(servers[0].server_port, 8388);
    assert_eq!(servers[0].method, "aes-256-gcm");
    assert_eq!(servers[0].password, "pw");
    assert_eq!(servers[0].name, "1.2.3.4:8388"); // fallback name
    assert!(servers[0].plugin.is_none());
    assert!(!servers[0].id.is_empty()); // UUID assigned
}

#[skuld::test]
fn parse_single_server_with_plugin() {
    let json = r#"{
        "server": "1.2.3.4",
        "server_port": 443,
        "password": "pw",
        "method": "aes-256-gcm",
        "plugin": "v2ray-plugin",
        "plugin_opts": "tls;host=example.com",
        "remarks": "V2Ray Server"
    }"#;
    let servers = import_servers(json).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].name, "V2Ray Server");
    assert_eq!(servers[0].plugin.as_deref(), Some("v2ray-plugin"));
    assert_eq!(servers[0].plugin_opts.as_deref(), Some("tls;host=example.com"));
}

#[skuld::test]
fn parse_multi_server_configs_array() {
    let json = r#"{
        "configs": [
            {"server": "10.0.0.1", "server_port": 8388, "password": "pw1", "method": "aes-256-gcm", "remarks": "S1"},
            {"server": "10.0.0.2", "server_port": 8389, "password": "pw2", "method": "chacha20-ietf-poly1305", "remarks": "S2"}
        ]
    }"#;
    let servers = import_servers(json).unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].name, "S1");
    assert_eq!(servers[0].server, "10.0.0.1");
    assert_eq!(servers[1].name, "S2");
    assert_eq!(servers[1].server, "10.0.0.2");
    // Each should have a unique UUID
    assert_ne!(servers[0].id, servers[1].id);
}

#[skuld::test]
fn missing_remarks_falls_back_to_host_port() {
    let json = r#"{
        "server": "5.6.7.8",
        "server_port": 9999,
        "password": "pw",
        "method": "aes-256-gcm"
    }"#;
    let servers = import_servers(json).unwrap();
    assert_eq!(servers[0].name, "5.6.7.8:9999");
}

#[skuld::test]
fn missing_plugin_fields_produce_none() {
    let json = r#"{
        "server": "1.2.3.4",
        "server_port": 8388,
        "password": "pw",
        "method": "aes-256-gcm"
    }"#;
    let servers = import_servers(json).unwrap();
    assert!(servers[0].plugin.is_none());
    assert!(servers[0].plugin_opts.is_none());
}

#[skuld::test]
fn invalid_json_returns_error() {
    let result = import_servers("not json {{{");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("parse"));
}

#[skuld::test]
fn empty_configs_array_returns_empty_vec() {
    let json = r#"{"configs": []}"#;
    let servers = import_servers(json).unwrap();
    assert!(servers.is_empty());
}

#[skuld::test]
fn extra_unknown_fields_are_ignored() {
    let json = r#"{
        "server": "1.2.3.4",
        "server_port": 8388,
        "password": "pw",
        "method": "aes-256-gcm",
        "unknown_field": "whatever",
        "another": 42
    }"#;
    let servers = import_servers(json).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].server, "1.2.3.4");
}

#[skuld::test]
fn wrong_types_for_fields_returns_error() {
    let json = r#"{
        "server": 123,
        "server_port": "not a number",
        "password": "pw",
        "method": "aes-256-gcm"
    }"#;
    let result = import_servers(json);
    assert!(result.is_err());
}

#[skuld::test]
fn empty_object_without_required_fields_returns_error() {
    let json = r#"{}"#;
    let result = import_servers(json);
    assert!(result.is_err());
}

#[skuld::test]
fn import_rejects_plugin_with_path_separators() {
    let json = r#"{
        "server": "1.2.3.4",
        "server_port": 8388,
        "password": "pw",
        "method": "aes-256-gcm",
        "plugin": "/usr/bin/evil"
    }"#;
    let err = import_servers(json).unwrap_err();
    assert!(err.to_string().contains("plugin name"));
}
