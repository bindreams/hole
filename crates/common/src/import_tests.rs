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

/// PII boundary: the "invalid plugin name" error must NOT echo the
/// rejected name itself into the message. A user might mistype a
/// password into the `plugin` field; `is_valid_plugin_name` rejects
/// anything outside `[A-Za-z0-9._-]`, and shell metacharacters /
/// passwords readily fail that check — but the bytes must not flow
/// through to the user-visible message.
#[skuld::test]
fn invalid_plugin_name_does_not_leak_input() {
    // Plug a "password-shaped" string into the plugin field. The shape
    // check fails (whitespace), and the resulting error must not echo
    // the bytes.
    let json = r#"{
        "server": "1.2.3.4",
        "server_port": 8388,
        "password": "pw",
        "method": "aes-256-gcm",
        "plugin": "secret password 123"
    }"#;
    let err = import_servers(json).unwrap_err();
    let msg = err.to_string();
    assert!(
        !msg.contains("secret password 123"),
        "error message leaked the rejected plugin field bytes: {msg}"
    );
    assert!(!msg.contains("secret"), "leaked partial: {msg}");
}

// shadowsocks-rust v2 schema (top-level `servers` array, `address`/`port` aliases) ====================================
// Triggered by bindreams/hole#385: real user file used this format and was rejected.

/// User-reported `test.json` shape: `servers` array + `address`/`port`/
/// `plugin`/`plugin_opts`/`local_port`/`local_address`. Reduced to the
/// load-bearing fields here.
#[skuld::test]
fn parse_servers_array_with_address_port_aliases() {
    let json = r#"{
        "servers": [
            {
                "address": "host.example.com",
                "port": 443,
                "password": "pw",
                "method": "chacha20-ietf-poly1305",
                "plugin": "galoshes",
                "plugin_opts": "tls;path=/x;host=host.example.com"
            }
        ],
        "local_port": 1080,
        "local_address": "127.0.0.1"
    }"#;
    let servers = import_servers(json).expect("schema should be recognized");
    assert_eq!(servers.len(), 1);
    let entry = &servers[0];
    assert_eq!(entry.server, "host.example.com");
    assert_eq!(entry.server_port, 443);
    assert_eq!(entry.password, "pw");
    assert_eq!(entry.method, "chacha20-ietf-poly1305");
    assert_eq!(entry.plugin.as_deref(), Some("galoshes"));
    assert_eq!(entry.plugin_opts.as_deref(), Some("tls;path=/x;host=host.example.com"));
    // Fallback name uses (server, server_port) regardless of the input field names.
    assert_eq!(entry.name, "host.example.com:443");
}

/// Multi-entry `servers` array.
#[skuld::test]
fn parse_servers_array_multi() {
    let json = r#"{
        "servers": [
            {"address": "10.0.0.1", "port": 8388, "password": "p1", "method": "aes-256-gcm"},
            {"address": "10.0.0.2", "port": 8389, "password": "p2", "method": "chacha20-ietf-poly1305"}
        ]
    }"#;
    let servers = import_servers(json).unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].server, "10.0.0.1");
    assert_eq!(servers[0].server_port, 8388);
    assert_eq!(servers[1].server, "10.0.0.2");
    assert_eq!(servers[1].server_port, 8389);
}

/// `servers` array with the legacy `server`/`server_port` field names
/// (some clients use the array shape but the legacy field names).
#[skuld::test]
fn parse_servers_array_with_legacy_field_names() {
    let json = r#"{
        "servers": [
            {"server": "1.2.3.4", "server_port": 8388, "password": "pw", "method": "aes-256-gcm"}
        ]
    }"#;
    let servers = import_servers(json).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].server, "1.2.3.4");
    assert_eq!(servers[0].server_port, 8388);
}

/// `configs` array with `address`/`port` field names (mixed shape).
/// Hole accepts the cross product; field aliasing is per-entry.
#[skuld::test]
fn parse_configs_array_with_address_port_aliases() {
    let json = r#"{
        "configs": [
            {"address": "1.2.3.4", "port": 8388, "password": "pw", "method": "aes-256-gcm"}
        ]
    }"#;
    let servers = import_servers(json).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].server, "1.2.3.4");
}

/// `configs` array takes precedence over `servers` if both are present.
/// (Highly unusual input, but the order needs to be deterministic.)
#[skuld::test]
fn configs_array_takes_precedence_over_servers() {
    let json = r#"{
        "configs": [
            {"server": "from-configs", "server_port": 1111, "password": "p", "method": "aes-256-gcm"}
        ],
        "servers": [
            {"server": "from-servers", "server_port": 2222, "password": "p", "method": "aes-256-gcm"}
        ]
    }"#;
    let servers = import_servers(json).unwrap();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].server, "from-configs");
}

/// Empty `servers` array, like the empty `configs` array case.
#[skuld::test]
fn empty_servers_array_returns_empty_vec() {
    let json = r#"{"servers": []}"#;
    let servers = import_servers(json).unwrap();
    assert!(servers.is_empty());
}

/// Missing both `server` and `address` returns a single, informative error
/// that names both alternatives.
#[skuld::test]
fn missing_server_and_address_names_both_alternatives() {
    let json = r#"{
        "server_port": 8388,
        "password": "pw",
        "method": "aes-256-gcm"
    }"#;
    let err = import_servers(json).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("server"), "error should name 'server': {msg}");
    assert!(msg.contains("address"), "error should also name 'address': {msg}");
}

/// Same for missing both `server_port` and `port`.
#[skuld::test]
fn missing_server_port_and_port_names_both_alternatives() {
    let json = r#"{
        "server": "1.2.3.4",
        "password": "pw",
        "method": "aes-256-gcm"
    }"#;
    let err = import_servers(json).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("server_port"), "error should name 'server_port': {msg}");
    assert!(msg.contains("port"), "error should also name 'port': {msg}");
}

// Plugin-shipped validation (bindreams/hole#385 Phase 2) ==============================================================
// Hole ships only v2ray-plugin and galoshes. Importing a config that
// references any other plugin name fails at parse time so the user
// gets an immediate, actionable error instead of a runtime failure
// later (when the proxy tries to exec the missing plugin).

#[skuld::test]
fn import_accepts_known_plugin_galoshes() {
    let json = r#"{
        "server": "1.2.3.4",
        "server_port": 8388,
        "password": "pw",
        "method": "aes-256-gcm",
        "plugin": "galoshes"
    }"#;
    let servers = import_servers(json).expect("galoshes is a shipped plugin");
    assert_eq!(servers[0].plugin.as_deref(), Some("galoshes"));
}

#[skuld::test]
fn import_accepts_known_plugin_v2ray() {
    let json = r#"{
        "server": "1.2.3.4",
        "server_port": 8388,
        "password": "pw",
        "method": "aes-256-gcm",
        "plugin": "v2ray-plugin"
    }"#;
    let servers = import_servers(json).expect("v2ray-plugin is a shipped plugin");
    assert_eq!(servers[0].plugin.as_deref(), Some("v2ray-plugin"));
}

#[skuld::test]
fn import_rejects_unknown_plugin_with_actionable_error() {
    let json = r#"{
        "server": "1.2.3.4",
        "server_port": 8388,
        "password": "pw",
        "method": "aes-256-gcm",
        "plugin": "kcptun"
    }"#;
    let err = import_servers(json).unwrap_err();
    let msg = err.to_string();
    // Names the offending plugin so the user knows which entry is the
    // problem in a multi-entry file.
    assert!(msg.contains("kcptun"), "error should name the unknown plugin: {msg}");
    // Names at least one of the supported plugins so the user knows what
    // IS shipped.
    assert!(
        msg.contains("galoshes") || msg.contains("v2ray-plugin"),
        "error should list shipped plugins: {msg}"
    );
}

/// No-plugin entries (direct shadowsocks) stay accepted — the
/// known-plugin check fires only when a plugin is specified.
#[skuld::test]
fn import_accepts_entry_with_no_plugin() {
    let json = r#"{
        "server": "1.2.3.4",
        "server_port": 8388,
        "password": "pw",
        "method": "aes-256-gcm"
    }"#;
    let servers = import_servers(json).unwrap();
    assert!(servers[0].plugin.is_none());
}
