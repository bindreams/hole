use super::*;
use crate::bridge_client::ClientError;
use hole_common::config::{AppConfig, ServerEntry};
use skuld::temp_dir;
use std::path::Path;

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
        validation: None,
    }
}

#[skuld::test]
fn build_proxy_config_with_selected_server() {
    let config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: Some("b".to_string()),
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    let pc = build_proxy_config(&config).expect("should return Some");
    assert_eq!(pc.server.id, "b");
    assert_eq!(pc.local_port, 4073);
}

#[skuld::test]
fn build_proxy_config_no_selection() {
    let config = AppConfig {
        servers: vec![test_entry("a")],
        selected_server: None,
        local_port: 4073,
        enabled: false,
        ..Default::default()
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
        ..Default::default()
    };

    assert!(build_proxy_config(&config).is_none());
}

#[skuld::test]
fn build_proxy_config_master_toggle_off_disables_listeners() {
    let config = AppConfig {
        servers: vec![test_entry("a")],
        selected_server: Some("a".to_string()),
        proxy_server_enabled: false,
        proxy_socks5: true,
        proxy_http: true,
        ..Default::default()
    };

    let pc = build_proxy_config(&config).expect("should return Some");
    assert!(!pc.proxy_socks5, "master toggle off must disable the SOCKS5 listener");
    assert!(!pc.proxy_http, "master toggle off must disable the HTTP listener");
}

#[skuld::test]
fn build_proxy_config_master_toggle_on_passes_listener_flags() {
    let config = AppConfig {
        servers: vec![test_entry("a")],
        selected_server: Some("a".to_string()),
        proxy_server_enabled: true,
        proxy_socks5: true,
        proxy_http: true,
        ..Default::default()
    };

    let pc = build_proxy_config(&config).expect("should return Some");
    assert!(pc.proxy_socks5);
    assert!(pc.proxy_http);
}

// save_config preservation tests ======================================================================================

// Backend-owned-field preservation across a save lives in
// `ui_settings_tests.rs` (`apply_preserves_backend_owned_fields`): the
// wire type makes those fields unrepresentable and `UiSettings::apply`
// carries the preservation.

// auto_select_first_server tests ======================================================================================

#[skuld::test]
fn auto_select_first_server_when_none_selected() {
    let mut config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: None,
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    auto_select_first_server(&mut config);
    assert_eq!(config.selected_server.as_deref(), Some("a"));
}

#[skuld::test]
fn auto_select_preserves_existing_selection() {
    let mut config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: Some("b".to_string()),
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    auto_select_first_server(&mut config);
    assert_eq!(config.selected_server.as_deref(), Some("b"));
}

#[skuld::test]
fn auto_select_fixes_stale_selection() {
    let mut config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: Some("deleted-id".to_string()),
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    auto_select_first_server(&mut config);
    assert_eq!(config.selected_server.as_deref(), Some("a"));
}

#[skuld::test]
fn auto_select_noop_on_empty_servers() {
    let mut config = AppConfig {
        servers: vec![],
        selected_server: None,
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    auto_select_first_server(&mut config);
    assert!(config.selected_server.is_none());
}

// remove_server tests =================================================================================================

#[skuld::test]
fn remove_server_removes_by_id() {
    let mut config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b"), test_entry("c")],
        selected_server: Some("b".to_string()),
        ..Default::default()
    };
    let removed = remove_server(&mut config, "b");
    assert!(removed);
    assert_eq!(
        config.servers.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["a", "c"]
    );
}

#[skuld::test]
fn remove_server_heals_selection_when_selected_removed() {
    let mut config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: Some("a".to_string()),
        ..Default::default()
    };
    remove_server(&mut config, "a");
    assert_eq!(
        config.selected_server.as_deref(),
        Some("b"),
        "selection heals to the first remaining server"
    );
}

#[skuld::test]
fn remove_server_keeps_selection_when_other_removed() {
    let mut config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: Some("b".to_string()),
        ..Default::default()
    };
    remove_server(&mut config, "a");
    assert_eq!(config.selected_server.as_deref(), Some("b"));
}

#[skuld::test]
fn remove_server_clears_selection_when_last_removed() {
    let mut config = AppConfig {
        servers: vec![test_entry("a")],
        selected_server: Some("a".to_string()),
        ..Default::default()
    };
    remove_server(&mut config, "a");
    assert!(config.servers.is_empty());
    assert!(config.selected_server.is_none());
}

#[skuld::test]
fn remove_server_missing_id_is_noop() {
    let mut config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: Some("a".to_string()),
        ..Default::default()
    };
    let removed = remove_server(&mut config, "nonexistent");
    assert!(!removed);
    assert_eq!(config.servers.len(), 2);
    assert_eq!(config.selected_server.as_deref(), Some("a"));
}

// apply_ui_settings composition: merge by id + selection heal =========================================================

fn ui_server_entry(id: &str) -> crate::ui_settings::UiServerEntry {
    serde_json::from_value(serde_json::json!({
        "id": id, "name": format!("Server {id}"), "server": "1.2.3.4",
        "server_port": 8388, "method": "aes-256-gcm", "password": "pw",
    }))
    .unwrap()
}

fn default_ui_settings() -> crate::ui_settings::UiSettings {
    serde_json::from_value(serde_json::json!({
        "servers": [], "selected_server": null, "local_port": 4073,
        "filters": [], "start_on_login": false, "on_startup": "restore_last_state",
        "theme": "dark", "proxy_server_enabled": true, "proxy_socks5": true,
        "proxy_http": false, "dns": AppConfig::default().dns, "local_port_http": 4074,
        "diagnostic_plugin_tap": false
    }))
    .unwrap()
}

#[skuld::test]
fn apply_ui_settings_drops_stale_selection_and_ignores_unknown() {
    // Backend truth after a concurrent delete of "a": only "b" remains.
    let mut current = AppConfig {
        servers: vec![test_entry("b")],
        selected_server: Some("b".to_string()),
        ..Default::default()
    };
    // Stale webview snapshot still believes "a" exists and is selected.
    let mut settings = default_ui_settings();
    settings.servers = vec![ui_server_entry("a"), ui_server_entry("b")];
    settings.selected_server = Some("a".to_string());

    apply_ui_settings(&mut current, settings);

    assert_eq!(
        current.servers.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["b"],
        "the unknown stale id 'a' must not be resurrected"
    );
    assert_eq!(
        current.selected_server.as_deref(),
        Some("b"),
        "a selection naming the concurrently-deleted server is healed"
    );
}

// get_metrics / get_diagnostics response mapping + public-IP parsing tests ============================================

/// Verify that a Metrics BridgeResponse maps to the expected JSON.
#[skuld::test]
fn get_metrics_returns_json() {
    let resp = BridgeResponse::Metrics {
        bytes_in: 1024,
        bytes_out: 512,
        speed_in_bps: 2048,
        speed_out_bps: 1024,
        uptime_secs: 120,
        filter: None,
    };
    let json = map_metrics_response(Ok(resp));
    assert_eq!(json["bytes_in"], 1024);
    assert_eq!(json["bytes_out"], 512);
    assert_eq!(json["speed_in_bps"], 2048);
    assert_eq!(json["speed_out_bps"], 1024);
    assert_eq!(json["uptime_secs"], 120);
    assert!(json["filter"].is_null());
}

/// Verify that a failed metrics request returns zero defaults.
#[skuld::test]
fn get_metrics_fallback_on_error() {
    let err = ClientError::Connection(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "bridge unreachable",
    ));
    let json = map_metrics_response(Err(err));
    assert_eq!(json["bytes_in"], 0);
    assert_eq!(json["bytes_out"], 0);
    assert_eq!(json["speed_in_bps"], 0);
    assert_eq!(json["speed_out_bps"], 0);
    assert_eq!(json["uptime_secs"], 0);
}

/// Verify that an unexpected response type falls back to zero defaults.
#[skuld::test]
fn get_metrics_unexpected_response_falls_back() {
    let json = map_metrics_response(Ok(BridgeResponse::Ack));
    assert_eq!(json["bytes_in"], 0);
    assert_eq!(json["uptime_secs"], 0);
}

/// Verify that a Diagnostics BridgeResponse maps to the expected JSON.
#[skuld::test]
fn get_diagnostics_returns_json() {
    let resp = BridgeResponse::Diagnostics {
        app: "ok".into(),
        bridge: "ok".into(),
        network: "degraded".into(),
        vpn_server: "ok".into(),
        internet: "ok".into(),
    };
    let json = map_diagnostics_response(Ok(resp));
    assert_eq!(json["app"], "ok");
    assert_eq!(json["bridge"], "ok");
    assert_eq!(json["network"], "degraded");
    assert_eq!(json["vpn_server"], "ok");
    assert_eq!(json["internet"], "ok");
}

/// Verify that a failed diagnostics request returns unknown defaults.
#[skuld::test]
fn get_diagnostics_fallback_on_error() {
    let err = ClientError::Connection(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "bridge unreachable",
    ));
    let json = map_diagnostics_response(Err(err));
    assert_eq!(json["app"], "ok");
    assert_eq!(json["bridge"], "unknown");
    assert_eq!(json["network"], "unknown");
    assert_eq!(json["vpn_server"], "unknown");
    assert_eq!(json["internet"], "unknown");
}

/// Verify that an unexpected response type falls back to unknown defaults.
#[skuld::test]
fn get_diagnostics_unexpected_response_falls_back() {
    let json = map_diagnostics_response(Ok(BridgeResponse::Ack));
    assert_eq!(json["app"], "ok");
    assert_eq!(json["bridge"], "unknown");
}

// map_status_response (#470) ==========================================================================================

fn status_snap(seq: u64, running: bool, error: Option<&str>) -> crate::state::ProxySnapshot {
    crate::state::ProxySnapshot {
        seq,
        running,
        error: error.map(Into::into),
        lockdown_enabled: false,
        lockdown_active: false,
    }
}

/// All seven keys are present on the Status-Ok arm; cosmetics come from the
/// response, running/state_seq from the snapshot.
#[skuld::test]
fn map_status_emits_full_shape_on_status_ok() {
    let resp = Ok(BridgeResponse::Status {
        running: true,
        uptime_secs: 42,
        error: None,
        invalid_filters: vec![hole_common::protocol::InvalidFilter {
            index: 2,
            error: "bad".into(),
        }],
        udp_proxy_available: false,
        ipv6_bypass_available: true,
        lockdown_enabled: false,
        lockdown_active: false,
    });
    let j = map_status_response(resp, status_snap(7, true, None));
    for k in [
        "running",
        "state_seq",
        "error",
        "uptime_secs",
        "invalid_filters",
        "udp_proxy_available",
        "ipv6_bypass_available",
    ] {
        assert!(j.get(k).is_some(), "missing key {k}");
    }
    assert_eq!(j["running"], true);
    assert_eq!(j["state_seq"], 7);
    assert_eq!(j["uptime_secs"], 42);
    assert_eq!(j["udp_proxy_available"], false);
    assert_eq!(j["ipv6_bypass_available"], true);
    assert_eq!(j["invalid_filters"][0]["index"], 2);
    assert_eq!(j["invalid_filters"][0]["error"], "bad");
}

/// running/state_seq/error come from the SNAPSHOT, not the response — distinct
/// values prove the snapshot wins.
#[skuld::test]
fn map_status_sources_running_seq_error_from_snap() {
    let resp = Ok(BridgeResponse::Status {
        running: true, // response disagrees with the committed snapshot
        uptime_secs: 0,
        error: Some("RESPONSE-ERROR".into()),
        invalid_filters: vec![],
        udp_proxy_available: true,
        ipv6_bypass_available: true,
        lockdown_enabled: false,
        lockdown_active: false,
    });
    let j = map_status_response(resp, status_snap(9, false, Some("proxy task exited unexpectedly")));
    assert_eq!(j["running"], false, "running from snap");
    assert_eq!(j["state_seq"], 9, "state_seq from snap");
    assert_eq!(
        j["error"], "proxy task exited unexpectedly",
        "error from snap, not the response"
    );
}

/// Error arm: caps null (unknown), error from snap, running stale from snap.
#[skuld::test]
fn map_status_error_arm_caps_null_error_from_snap() {
    let j = map_status_response(
        Ok(BridgeResponse::Error { message: "boom".into() }),
        status_snap(3, true, None),
    );
    assert!(j["udp_proxy_available"].is_null(), "caps unknown on non-Status arm");
    assert!(j["ipv6_bypass_available"].is_null());
    assert!(j["error"].is_null(), "error from snap (None), not the response message");
    assert_eq!(j["running"], true, "running from snap (stale truth)");
    assert!(
        j["invalid_filters"].is_null(),
        "invalid_filters unknown on non-Status arm"
    );
    assert_eq!(j["uptime_secs"], 0);
}

/// Transport error: caps null, running/seq/error from snap.
#[skuld::test]
fn map_status_transport_error_caps_null() {
    let err = ClientError::Connection(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "x"));
    let j = map_status_response(Err(err), status_snap(1, false, None));
    assert!(j["udp_proxy_available"].is_null());
    assert!(j["ipv6_bypass_available"].is_null());
    assert_eq!(j["running"], false);
    assert_eq!(j["state_seq"], 1);
    assert!(j["error"].is_null());
}

/// PII guard: on a death the mapper emits the snapshot's path-free sentinel,
/// never the response's (possibly PII) error.
#[skuld::test]
fn map_status_death_error_is_the_sentinel_only() {
    let resp = Ok(BridgeResponse::Status {
        running: false,
        uptime_secs: 0,
        error: Some("/home/user/secret/path failed".into()), // would-be PII on the wire
        invalid_filters: vec![],
        udp_proxy_available: true,
        ipv6_bypass_available: true,
        lockdown_enabled: false,
        lockdown_active: false,
    });
    let j = map_status_response(resp, status_snap(4, false, Some("proxy task exited unexpectedly")));
    assert_eq!(j["error"], "proxy task exited unexpectedly");
    assert!(
        !j["error"].as_str().unwrap().contains('/'),
        "the snapshot error (path-free sentinel) is used, never the response's"
    );
}

/// `parse_cf_trace` pulls `ip=` / `loc=` out of Cloudflare's trace body.
#[skuld::test]
fn parse_cf_trace_extracts_ip_and_country() {
    let body = "fl=123abc\nh=cloudflare.com\nip=203.0.113.42\nts=1700000000.1\nvisit_scheme=https\nloc=DE\ncolo=FRA\n";
    let out = parse_cf_trace(body);
    assert_eq!(out["ip"], "203.0.113.42");
    assert_eq!(out["country_code"], "DE");
}

/// Absent fields fall back to the display placeholders.
#[skuld::test]
fn parse_cf_trace_falls_back_when_fields_absent() {
    let out = parse_cf_trace("fl=123abc\nh=cloudflare.com\ncolo=FRA\n");
    assert_eq!(out["ip"], "unknown");
    assert_eq!(out["country_code"], "??");
}

/// CRLF line endings: `str::lines()` strips the trailing `\r`.
#[skuld::test]
fn parse_cf_trace_handles_crlf() {
    let out = parse_cf_trace("ip=203.0.113.42\r\nloc=DE\r\n");
    assert_eq!(out["ip"], "203.0.113.42");
    assert_eq!(out["country_code"], "DE");
}

/// Present-but-empty fields stay empty; the UI renders its own placeholder.
#[skuld::test]
fn parse_cf_trace_present_but_empty_fields() {
    let out = parse_cf_trace("ip=\nloc=\n");
    assert_eq!(out["ip"], "");
    assert_eq!(out["country_code"], "");
}

// validate_and_read_import tests ======================================================================================

const VALID_SERVER_JSON: &str = r#"{"server":"1.2.3.4","server_port":8388,"password":"pw","method":"aes-256-gcm"}"#;

#[skuld::test]
fn import_rejects_non_json_extension(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("data.txt");
    std::fs::write(&file, VALID_SERVER_JSON).unwrap();
    let err = validate_and_read_import(&file).unwrap_err();
    match err {
        ImportFailure::FileError { detail } => assert!(detail.contains("only .json"), "{detail}"),
        other => panic!("expected FileError, got {other:?}"),
    }
}

#[skuld::test]
fn import_rejects_no_extension(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("shadow");
    std::fs::write(&file, "root:x:0:0:root").unwrap();
    let err = validate_and_read_import(&file).unwrap_err();
    match err {
        ImportFailure::FileError { detail } => assert!(detail.contains("only .json"), "{detail}"),
        other => panic!("expected FileError, got {other:?}"),
    }
}

#[skuld::test]
fn import_rejects_directory(#[fixture(temp_dir)] dir: &Path) {
    let subdir = dir.join("not-a-file.json");
    std::fs::create_dir(&subdir).unwrap();
    let err = validate_and_read_import(&subdir).unwrap_err();
    match err {
        ImportFailure::FileError { detail } => {
            // On Windows, File::open on a directory fails before the is_file() check.
            assert!(
                detail.contains("not a regular file") || detail.contains("not found or not accessible"),
                "unexpected detail: {detail}"
            );
        }
        other => panic!("expected FileError, got {other:?}"),
    }
}

#[skuld::test]
fn import_rejects_nonexistent_path() {
    let err = validate_and_read_import(Path::new("/nonexistent/path.json")).unwrap_err();
    match err {
        ImportFailure::FileError { detail } => assert!(detail.contains("not found"), "{detail}"),
        other => panic!("expected FileError, got {other:?}"),
    }
}

#[skuld::test]
fn import_rejects_oversized_file(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("huge.json");
    let data = vec![b' '; 11 * 1024 * 1024]; // 11 MB
    std::fs::write(&file, &data).unwrap();
    let err = validate_and_read_import(&file).unwrap_err();
    match err {
        ImportFailure::FileError { detail } => assert!(detail.contains("too large"), "{detail}"),
        other => panic!("expected FileError, got {other:?}"),
    }
}

#[skuld::test]
fn import_accepts_valid_json_file(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("servers.json");
    std::fs::write(&file, VALID_SERVER_JSON).unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

#[skuld::test]
fn import_accepts_uppercase_json_extension(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("servers.JSON");
    std::fs::write(&file, VALID_SERVER_JSON).unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_ok());
}

/// Corrupted JSON must produce `ImportFailure::CorruptedJson` with NO
/// detail field — `serde_json::Error`'s Display includes a fragment of
/// the input near the parse error, which can include credentials.
#[skuld::test]
fn corrupted_json_does_not_leak_content(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("bad.json");
    std::fs::write(&file, "SUPER_SECRET_CONTENT_HERE").unwrap();
    let err = validate_and_read_import(&file).unwrap_err();
    match err {
        ImportFailure::CorruptedJson => {} // good — no detail to leak
        other => panic!("expected CorruptedJson, got {other:?}"),
    }
    let json = serde_json::to_string(&err).unwrap();
    assert!(!json.contains("SUPER_SECRET"), "wire form leaked file content: {json}");
}

/// `InvalidValue` is allowed to surface a port number — it's
/// information the user needs to fix their config and not PII. Sensitive
/// fragments (raw passwords, server hostnames) are NOT in the
/// `InvalidValue` detail because they don't trigger this variant.
#[skuld::test]
fn invalid_value_keeps_port_for_diagnosis(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("bad-port.json");
    std::fs::write(
        &file,
        r#"{"server":"1.2.3.4","server_port":99999,"password":"pw","method":"aes-256-gcm"}"#,
    )
    .unwrap();
    let err = validate_and_read_import(&file).unwrap_err();
    match err {
        ImportFailure::InvalidValue { detail } => {
            assert!(detail.contains("99999"), "user needs to see which value: {detail}");
            assert!(!detail.contains("pw"), "must not leak password: {detail}");
            assert!(!detail.contains("1.2.3.4"), "must not leak server: {detail}");
        }
        other => panic!("expected InvalidValue, got {other:?}"),
    }
}

// apply_import tests ==================================================================================================

use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct VecWriter {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Build a `ServerEntry` from individual fields. The default `test_entry`
/// fixture at the top of this file always uses 1.2.3.4:8388 which makes
/// dedup tests harder to read.
fn entry(id: &str, server: &str, port: u16) -> ServerEntry {
    ServerEntry {
        id: id.to_string(),
        name: format!("Server {id}"),
        server: server.to_string(),
        server_port: port,
        method: "aes-256-gcm".to_string(),
        password: "pw".to_string(),
        plugin: None,
        plugin_opts: None,
        validation: None,
    }
}

#[skuld::test]
fn apply_import_empty_parsed_appends_nothing() {
    let mut config = AppConfig::default();
    let (appended, deduped) = apply_import(&mut config, vec![]);
    assert!(appended.is_empty());
    assert_eq!(deduped, 0);
    assert!(config.servers.is_empty());
    assert!(config.selected_server.is_none());
}

/// Stronger non-mutation property: an empty parsed list must not touch
/// the existing servers list, the selection, or any other field of
/// `AppConfig`. Compares the whole config before and after.
#[skuld::test]
fn apply_import_empty_parsed_does_not_mutate_populated_config() {
    let before = AppConfig {
        servers: vec![entry("a", "10.0.0.1", 8388), entry("b", "10.0.0.2", 8388)],
        selected_server: Some("b".to_string()),
        local_port: 4073,
        enabled: true,
        ..Default::default()
    };
    let mut after = before.clone();
    let (appended, deduped) = apply_import(&mut after, vec![]);
    assert!(appended.is_empty());
    assert_eq!(deduped, 0);
    // Compare relevant fields explicitly (PartialEq on AppConfig may not
    // exist; field-by-field is robust either way).
    assert_eq!(after.servers, before.servers);
    assert_eq!(after.selected_server, before.selected_server);
    assert_eq!(after.local_port, before.local_port);
    assert_eq!(after.enabled, before.enabled);
}

#[skuld::test]
fn apply_import_appends_all_unique_entries() {
    let mut config = AppConfig::default();
    let parsed = vec![
        entry("new-1", "10.0.0.1", 8388),
        entry("new-2", "10.0.0.2", 8388),
        entry("new-3", "10.0.0.3", 8388),
    ];
    let (appended, deduped) = apply_import(&mut config, parsed);
    assert_eq!(appended.len(), 3);
    assert_eq!(deduped, 0);
    assert_eq!(config.servers.len(), 3);
}

#[skuld::test]
fn apply_import_deduplicates_against_existing() {
    let mut config = AppConfig {
        servers: vec![entry("existing", "10.0.0.1", 8388)],
        ..Default::default()
    };
    let parsed = vec![
        entry("dup", "10.0.0.1", 8388), // same as existing — should be skipped
        entry("fresh", "10.0.0.2", 8388),
    ];
    let (appended, deduped) = apply_import(&mut config, parsed);
    assert_eq!(appended.len(), 1);
    assert_eq!(appended[0].server, "10.0.0.2");
    assert_eq!(deduped, 1);
    assert_eq!(config.servers.len(), 2);
}

#[skuld::test]
fn apply_import_auto_selects_first_when_previously_none() {
    let mut config = AppConfig {
        selected_server: None,
        ..Default::default()
    };
    let parsed = vec![entry("a", "10.0.0.1", 8388), entry("b", "10.0.0.2", 8388)];
    let (appended, _) = apply_import(&mut config, parsed);
    assert_eq!(appended.len(), 2);
    assert_eq!(
        config.selected_server.as_deref(),
        Some("a"),
        "selected_server should auto-set to the first appended entry"
    );
}

#[skuld::test]
fn apply_import_preserves_existing_selection() {
    let mut config = AppConfig {
        servers: vec![entry("first", "10.0.0.0", 8388)],
        selected_server: Some("first".to_string()),
        ..Default::default()
    };
    let parsed = vec![entry("new", "10.0.0.1", 8388)];
    let (appended, _) = apply_import(&mut config, parsed);
    assert_eq!(appended.len(), 1);
    assert_eq!(
        config.selected_server.as_deref(),
        Some("first"),
        "existing selection must not be clobbered by an import"
    );
}

/// All entries already exist — appended is empty but the call is still a
/// "success." The frontend uses this to show a "no new servers" info toast
/// instead of leaving the user with silent no-op.
#[skuld::test]
fn apply_import_all_duplicates_returns_empty_with_dedup_count() {
    let mut config = AppConfig {
        servers: vec![entry("a", "10.0.0.1", 8388), entry("b", "10.0.0.2", 8388)],
        ..Default::default()
    };
    let parsed = vec![entry("dup1", "10.0.0.1", 8388), entry("dup2", "10.0.0.2", 8388)];
    let (appended, deduped) = apply_import(&mut config, parsed);
    assert!(appended.is_empty());
    assert_eq!(deduped, 2);
    assert_eq!(config.servers.len(), 2);
}

#[skuld::test]
fn apply_import_emits_summary_event() {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = VecWriter { inner: buf.clone() };
    let subscriber = tracing_subscriber::fmt().with_writer(writer).with_ansi(false).finish();
    let _g = garter::tracing_test::set_default_in_current_thread(subscriber);

    let mut config = AppConfig::default();
    let parsed = vec![entry("a", "10.0.0.1", 8388), entry("b", "10.0.0.2", 8388)];
    apply_import(&mut config, parsed);

    let captured = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(
        captured.contains("import_servers_from_file: apply summary"),
        "expected apply summary event in captured output:\n{captured}"
    );
    assert!(
        captured.contains("parsed=2"),
        "expected parsed=2 field in summary:\n{captured}"
    );
    assert!(
        captured.contains("appended=2"),
        "expected appended=2 field in summary:\n{captured}"
    );
    assert!(
        captured.contains("deduped=0"),
        "expected deduped=0 field in summary:\n{captured}"
    );
}

// ImportFailure sanitization ==========================================================================================
// `to_import_failure` converts the file-I/O + parse error surface into
// the tagged enum the frontend deserializes. The conversion is the only
// place where (a) `serde_json::Error`'s parse-error message (which echoes
// file content) is scrubbed and (b) the per-variant categorization is
// made — so the frontend can show the right blocking dialog without any
// string parsing.

#[skuld::test]
fn to_import_failure_parse_error_becomes_corrupted_json() {
    let err =
        hole_common::import::ImportError::Parse(serde_json::from_str::<serde_json::Value>("not-json").unwrap_err());
    let failure = to_import_failure(err);
    assert!(matches!(failure, ImportFailure::CorruptedJson), "got {failure:?}");
}

#[skuld::test]
fn to_import_failure_missing_field_becomes_unrecognized_format() {
    let err = hole_common::import::ImportError::MissingField("server (or 'address')");
    let failure = to_import_failure(err);
    match failure {
        ImportFailure::UnrecognizedFormat { missing_field } => {
            assert_eq!(missing_field, "server (or 'address')");
        }
        other => panic!("expected UnrecognizedFormat, got {other:?}"),
    }
}

#[skuld::test]
fn to_import_failure_unsupported_plugin_carries_name_and_list() {
    let err = hole_common::import::ImportError::UnsupportedPlugin {
        name: "kcptun".to_string(),
    };
    let failure = to_import_failure(err);
    match failure {
        ImportFailure::UnsupportedPlugin { plugin, supported } => {
            assert_eq!(plugin, "kcptun");
            // `supported` is derived from the single source of truth
            // (`KNOWN_PLUGINS`), so this assertion stays correct
            // automatically when new plugins are added.
            assert!(supported.contains(&"v2ray-plugin".to_string()), "got {supported:?}");
            assert!(supported.contains(&"galoshes".to_string()), "got {supported:?}");
        }
        other => panic!("expected UnsupportedPlugin, got {other:?}"),
    }
}

#[skuld::test]
fn to_import_failure_invalid_value_keeps_safe_detail() {
    let err = hole_common::import::ImportError::InvalidValue("server_port 99999 out of range".to_string());
    let failure = to_import_failure(err);
    match failure {
        ImportFailure::InvalidValue { detail } => {
            // Port detail is safe to show (numeric, not file content).
            assert!(detail.contains("99999"), "port detail should survive: {detail}");
        }
        other => panic!("expected InvalidValue, got {other:?}"),
    }
}

/// `ImportFailure` must serialize as a `serde`-tagged enum so the JS
/// `{ kind }` discriminator works.
#[skuld::test]
fn import_failure_serializes_with_kind_tag() {
    let f = ImportFailure::CorruptedJson;
    let json = serde_json::to_string(&f).unwrap();
    assert_eq!(json, r#"{"kind":"corrupted_json"}"#);

    let f = ImportFailure::UnrecognizedFormat {
        missing_field: "method".to_string(),
    };
    let json = serde_json::to_string(&f).unwrap();
    assert_eq!(json, r#"{"kind":"unrecognized_format","missing_field":"method"}"#);

    let f = ImportFailure::UnsupportedPlugin {
        plugin: "kcptun".to_string(),
        supported: vec!["v2ray-plugin".to_string(), "galoshes".to_string()],
    };
    let json = serde_json::to_string(&f).unwrap();
    assert!(json.contains(r#""kind":"unsupported_plugin""#));
    assert!(json.contains(r#""plugin":"kcptun""#));
    assert!(json.contains(r#""supported":["v2ray-plugin","galoshes"]"#));

    let f = ImportFailure::FileError {
        detail: "file not found or not accessible".to_string(),
    };
    let json = serde_json::to_string(&f).unwrap();
    assert_eq!(
        json,
        r#"{"kind":"file_error","detail":"file not found or not accessible"}"#
    );

    let f = ImportFailure::SaveFailed;
    let json = serde_json::to_string(&f).unwrap();
    assert_eq!(json, r#"{"kind":"save_failed"}"#);
}

#[skuld::test]
fn apply_import_summary_records_dedup_counts() {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = VecWriter { inner: buf.clone() };
    let subscriber = tracing_subscriber::fmt().with_writer(writer).with_ansi(false).finish();
    let _g = garter::tracing_test::set_default_in_current_thread(subscriber);

    let mut config = AppConfig {
        servers: vec![entry("existing", "10.0.0.1", 8388)],
        ..Default::default()
    };
    let parsed = vec![
        entry("dup", "10.0.0.1", 8388),
        entry("dup2", "10.0.0.1", 8388),
        entry("new", "10.0.0.2", 8388),
    ];
    apply_import(&mut config, parsed);

    let captured = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(
        captured.contains("parsed=3"),
        "expected parsed=3 in summary:\n{captured}"
    );
    assert!(
        captured.contains("appended=1"),
        "expected appended=1 in summary:\n{captured}"
    );
    assert!(
        captured.contains("deduped=2"),
        "expected deduped=2 in summary:\n{captured}"
    );
}
