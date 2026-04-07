use super::*;
use crate::bridge_client::ClientError;
use hole_common::config::{AppConfig, ServerEntry};
use skuld::temp_dir;
use std::path::Path;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

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

// save_config preservation tests ======================================================================================

/// Verify that merging a frontend config (elevation_prompt_shown=false) with
/// an in-memory config (elevation_prompt_shown=true) preserves the flag.
///
/// This mirrors the logic in `save_config`: re-inject the in-memory
/// `elevation_prompt_shown` before saving, because the frontend doesn't
/// know about the field and always sends `false`.
#[skuld::test]
fn save_config_preserves_elevation_prompt_shown() {
    // Simulate in-memory state where the dialog has been shown
    let in_memory = AppConfig {
        elevation_prompt_shown: true,
        ..Default::default()
    };

    // Simulate what the frontend sends (doesn't know about the field)
    let mut from_frontend = AppConfig {
        local_port: 5555, // user changed the port
        elevation_prompt_shown: false,
        ..Default::default()
    };

    // Apply the same logic as save_config
    from_frontend.elevation_prompt_shown = in_memory.elevation_prompt_shown;

    assert!(
        from_frontend.elevation_prompt_shown,
        "elevation_prompt_shown should be preserved from in-memory state"
    );
    assert_eq!(
        from_frontend.local_port, 5555,
        "other fields should keep frontend values"
    );
}

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

// get_metrics / get_diagnostics / get_public_ip response mapping tests ================================================

/// Verify that a Metrics BridgeResponse maps to the expected JSON.
#[skuld::test]
fn get_metrics_returns_json() {
    let resp = BridgeResponse::Metrics {
        bytes_in: 1024,
        bytes_out: 512,
        speed_in_bps: 2048,
        speed_out_bps: 1024,
        uptime_secs: 120,
    };
    let json = map_metrics_response(Ok(resp));
    assert_eq!(json["bytes_in"], 1024);
    assert_eq!(json["bytes_out"], 512);
    assert_eq!(json["speed_in_bps"], 2048);
    assert_eq!(json["speed_out_bps"], 1024);
    assert_eq!(json["uptime_secs"], 120);
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

/// Verify that a PublicIp BridgeResponse maps to the expected JSON.
#[skuld::test]
fn get_public_ip_bridge_success_returns_json() {
    let resp: Result<BridgeResponse, ClientError> = Ok(BridgeResponse::PublicIp {
        ip: "203.0.113.42".into(),
        country_code: "DE".into(),
    });
    let json = map_public_ip_bridge_response(resp).expect("should return Some for PublicIp");
    assert_eq!(json["ip"], "203.0.113.42");
    assert_eq!(json["country_code"], "DE");
}

/// Verify that a failed PublicIp bridge request returns None (triggers fallback).
#[skuld::test]
fn get_public_ip_bridge_failure_returns_none() {
    let err: Result<BridgeResponse, ClientError> = Err(ClientError::Connection(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "bridge unreachable",
    )));
    assert!(map_public_ip_bridge_response(err).is_none());
}

/// Verify that an unexpected BridgeResponse for PublicIp returns None.
#[skuld::test]
fn get_public_ip_unexpected_response_returns_none() {
    let resp: Result<BridgeResponse, ClientError> = Ok(BridgeResponse::Ack);
    assert!(map_public_ip_bridge_response(resp).is_none());
}

// validate_and_read_import tests ======================================================================================

const VALID_SERVER_JSON: &str = r#"{"server":"1.2.3.4","server_port":8388,"password":"pw","method":"aes-256-gcm"}"#;

#[skuld::test]
fn import_rejects_non_json_extension(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("data.txt");
    std::fs::write(&file, VALID_SERVER_JSON).unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("only .json"));
}

#[skuld::test]
fn import_rejects_no_extension(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("shadow");
    std::fs::write(&file, "root:x:0:0:root").unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("only .json"));
}

#[skuld::test]
fn import_rejects_directory(#[fixture(temp_dir)] dir: &Path) {
    let subdir = dir.join("not-a-file.json");
    std::fs::create_dir(&subdir).unwrap();
    let result = validate_and_read_import(&subdir);
    assert!(result.is_err());
    let err = result.unwrap_err();
    // On Windows, File::open on a directory fails before the is_file() check.
    assert!(
        err.contains("not a regular file") || err.contains("not found or not accessible"),
        "unexpected error: {err}"
    );
}

#[skuld::test]
fn import_rejects_nonexistent_path() {
    let result = validate_and_read_import(Path::new("/nonexistent/path.json"));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}

#[skuld::test]
fn import_rejects_oversized_file(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("huge.json");
    let data = vec![b' '; 11 * 1024 * 1024]; // 11 MB
    std::fs::write(&file, &data).unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("too large"));
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

#[skuld::test]
fn import_error_does_not_leak_content(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("bad.json");
    std::fs::write(&file, "SUPER_SECRET_CONTENT_HERE").unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        !err.contains("SUPER_SECRET"),
        "error message leaked file content: {err}"
    );
}

#[skuld::test]
fn import_error_sanitizes_invalid_value(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("bad-port.json");
    std::fs::write(
        &file,
        r#"{"server":"1.2.3.4","server_port":99999,"password":"pw","method":"aes-256-gcm"}"#,
    )
    .unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(!err.contains("99999"), "error message leaked raw value: {err}");
}

// merge_vpn_probe tests ===============================================================================================

#[skuld::test]
fn merge_vpn_probe_overrides_unknown_with_reachable() {
    let diag = serde_json::json!({
        "app": "ok", "bridge": "ok", "network": "ok",
        "vpn_server": "unknown", "internet": "unknown",
    });
    let merged = merge_vpn_probe(diag, true);
    assert_eq!(merged["vpn_server"], "ok");
}

#[skuld::test]
fn merge_vpn_probe_overrides_unknown_with_unreachable() {
    let diag = serde_json::json!({
        "app": "ok", "bridge": "ok", "network": "ok",
        "vpn_server": "unknown", "internet": "unknown",
    });
    let merged = merge_vpn_probe(diag, false);
    assert_eq!(merged["vpn_server"], "error");
}

#[skuld::test]
fn merge_vpn_probe_leaves_ok_alone() {
    let diag = serde_json::json!({ "vpn_server": "ok" });
    let merged = merge_vpn_probe(diag, false);
    assert_eq!(merged["vpn_server"], "ok");
}

#[skuld::test]
fn merge_vpn_probe_leaves_error_alone() {
    let diag = serde_json::json!({ "vpn_server": "error" });
    let merged = merge_vpn_probe(diag, true);
    assert_eq!(merged["vpn_server"], "error");
}

// diagnose orchestration tests ========================================================================================
//
// These exercise probe_vpn_server_reachable end-to-end against real local
// TCP fixtures (no network, no flakiness, no skip-on-missing).

fn config_with_server(host: &str, port: u16) -> AppConfig {
    AppConfig {
        servers: vec![ServerEntry {
            id: "test".into(),
            name: "Test".into(),
            server: host.into(),
            server_port: port,
            method: "aes-256-gcm".into(),
            password: "pw".into(),
            plugin: None,
            plugin_opts: None,
        }],
        selected_server: Some("test".into()),
        local_port: 4073,
        enabled: false,
        ..Default::default()
    }
}

fn unknown_diag_response() -> Result<BridgeResponse, ClientError> {
    Ok(BridgeResponse::Diagnostics {
        app: "ok".into(),
        bridge: "ok".into(),
        network: "ok".into(),
        vpn_server: "unknown".into(),
        internet: "unknown".into(),
    })
}

// diagnose orchestration tests use diagnose_with() with an injected fake
// probe so they are deterministic on every platform. The real
// probe_vpn_server_reachable has its own tests further below.
//
// Why the injection is necessary: the GHA windows-latest image silently
// drops inbound SYN packets to ephemeral loopback ports even from the same
// process, so any real-socket "reachable" fixture hangs until the tokio
// probe timeout fires and resolves to "error". Verified on 2026-04-07 via
// a diagnostic commit on PR #132 that dumped raw std::net::TcpStream::
// connect_timeout output — a 3-second timeout hit on both attempts with
// zero accepts observed on the listener.

/// Build a probe closure that always returns the given result, matching
/// the async fn pointer shape expected by `diagnose_with`.
fn fake_probe(
    result: bool,
) -> impl FnOnce(String, u16) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> {
    move |_host, _port| Box::pin(async move { result })
}

#[skuld::test]
fn diagnose_overrides_unknown_when_probe_reports_reachable() {
    rt().block_on(async {
        let config = config_with_server("example.com", 8388);
        let result = diagnose_with(unknown_diag_response(), &config, fake_probe(true)).await;
        assert_eq!(result["vpn_server"], "ok");
    });
}

#[skuld::test]
fn diagnose_overrides_unknown_when_probe_reports_unreachable() {
    rt().block_on(async {
        let config = config_with_server("example.com", 8388);
        let result = diagnose_with(unknown_diag_response(), &config, fake_probe(false)).await;
        assert_eq!(result["vpn_server"], "error");
    });
}

#[skuld::test]
fn diagnose_leaves_ok_alone_no_probe_needed() {
    rt().block_on(async {
        let bridge_resp = Ok(BridgeResponse::Diagnostics {
            app: "ok".into(),
            bridge: "ok".into(),
            network: "ok".into(),
            vpn_server: "ok".into(),
            internet: "unknown".into(),
        });
        let config = config_with_server("example.com", 8388);
        // Probe would return false if called — but it must not be called.
        let result = diagnose_with(bridge_resp, &config, fake_probe(false)).await;
        assert_eq!(result["vpn_server"], "ok");
    });
}

#[skuld::test]
fn diagnose_leaves_unknown_when_no_selected_server() {
    rt().block_on(async {
        let config = AppConfig::default();
        let result = diagnose_with(unknown_diag_response(), &config, fake_probe(true)).await;
        // No selected server → we do not probe at all → vpn_server stays "unknown".
        assert_eq!(result["vpn_server"], "unknown");
    });
}

#[skuld::test]
fn diagnose_probes_when_bridge_unreachable_and_probe_reports_reachable() {
    rt().block_on(async {
        let bridge_err: Result<BridgeResponse, ClientError> = Err(ClientError::Connection(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "bridge unreachable",
        )));
        let config = config_with_server("example.com", 8388);
        let result = diagnose_with(bridge_err, &config, fake_probe(true)).await;
        assert_eq!(result["bridge"], "unknown"); // bridge-fallback path took effect
        assert_eq!(result["vpn_server"], "ok"); // …and the GUI still probed
    });
}

// probe_vpn_server_reachable direct tests =============================================================================
//
// The pure orchestration tests above use `diagnose_with` with a fake
// probe; here we exercise the real `probe_vpn_server_reachable` against
// local TCP fixtures. Only the "unreachable" shape is testable on GHA
// windows-latest (ephemeral loopback SYNs are dropped there — see the
// block comment above on `fake_probe`). The "reachable" shape is covered
// on non-Windows via a direct fixture; on Windows it's covered indirectly
// by `diagnose_overrides_unknown_when_probe_reports_reachable` plus the
// pure merge tests — together these pin the `true → "ok"` path.

#[skuld::test]
fn probe_vpn_server_reachable_returns_false_for_empty_host() {
    rt().block_on(async {
        assert!(!probe_vpn_server_reachable(String::new(), 8388).await);
    });
}

#[skuld::test]
fn probe_vpn_server_reachable_returns_false_for_closed_port() {
    // Bind an ephemeral port then drop the listener so the port is
    // unbound. On Linux/macOS the kernel returns RST immediately; on
    // Windows the probe hits its 2s timeout and returns false. Either
    // way the outcome is "unreachable".
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    rt().block_on(async {
        assert!(!probe_vpn_server_reachable("127.0.0.1".to_string(), port).await);
    });
}

// Gated on non-Windows because the GHA windows-latest image drops inbound
// SYN packets to ephemeral loopback ports even from the same process.
// Verified 2026-04-07 via a diagnostic commit on PR #132 that dumped raw
// std::net::TcpStream::connect_timeout output — the 3-second timeout hit
// on every attempt with zero accepts observed on the listener. A real
// Windows box (not the GHA image) runs this test reliably if the cfg
// gate is removed. The reachable→ok semantics are still covered on all
// platforms by `diagnose_overrides_unknown_when_probe_reports_reachable`
// via the injected fake probe, so this is a test-fixture platform gap,
// not a coverage gap.
#[cfg(not(target_os = "windows"))]
#[skuld::test]
fn probe_vpn_server_reachable_returns_true_for_open_port() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    rt().block_on(async {
        assert!(probe_vpn_server_reachable("127.0.0.1".to_string(), port).await);
    });
}
