use super::*;
use crate::config::ServerEntry;

fn sample_server() -> ServerEntry {
    ServerEntry {
        id: "test-id".to_string(),
        name: "Test".to_string(),
        server: "1.2.3.4".to_string(),
        server_port: 8388,
        method: "aes-256-gcm".to_string(),
        password: "pw".to_string(),
        plugin: None,
        plugin_opts: None,
    }
}

fn sample_config() -> ProxyConfig {
    ProxyConfig {
        server: sample_server(),
        local_port: 4073,
        plugin_path: None,
    }
}

// DaemonRequest/DaemonResponse JSON serialization (used by elevation flow) -----

#[skuld::test]
fn daemon_request_start_json_roundtrip() {
    let req = DaemonRequest::Start {
        config: sample_config(),
    };
    let json = serde_json::to_vec(&req).unwrap();
    let decoded: DaemonRequest = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn daemon_request_stop_json_roundtrip() {
    let req = DaemonRequest::Stop;
    let json = serde_json::to_vec(&req).unwrap();
    let decoded: DaemonRequest = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn daemon_request_status_json_roundtrip() {
    let req = DaemonRequest::Status;
    let json = serde_json::to_vec(&req).unwrap();
    let decoded: DaemonRequest = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn daemon_request_reload_json_roundtrip() {
    let req = DaemonRequest::Reload {
        config: sample_config(),
    };
    let json = serde_json::to_vec(&req).unwrap();
    let decoded: DaemonRequest = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn daemon_response_ack_json_roundtrip() {
    let resp = DaemonResponse::Ack;
    let json = serde_json::to_vec(&resp).unwrap();
    let decoded: DaemonResponse = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, resp);
}

#[skuld::test]
fn daemon_response_status_json_roundtrip() {
    let resp = DaemonResponse::Status {
        running: true,
        uptime_secs: 3600,
        error: Some("minor issue".to_string()),
    };
    let json = serde_json::to_vec(&resp).unwrap();
    let decoded: DaemonResponse = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, resp);
}

#[skuld::test]
fn daemon_response_error_json_roundtrip() {
    let resp = DaemonResponse::Error {
        message: "port in use".to_string(),
    };
    let json = serde_json::to_vec(&resp).unwrap();
    let decoded: DaemonResponse = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, resp);
}

#[skuld::test]
fn proxy_config_with_plugin_path_json_roundtrip() {
    let config = ProxyConfig {
        server: sample_server(),
        local_port: 4073,
        plugin_path: Some("/usr/bin/v2ray-plugin".into()),
    };
    let json = serde_json::to_vec(&config).unwrap();
    let decoded: ProxyConfig = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, config);
}

// Generated type tests -----

#[skuld::test]
fn status_response_json_roundtrip() {
    let resp = StatusResponse {
        running: true,
        uptime_secs: 3600,
        error: Some("minor issue".to_string()),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let decoded: StatusResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, resp);
}

#[skuld::test]
fn status_response_without_error() {
    let resp = StatusResponse {
        running: false,
        uptime_secs: 0,
        error: None,
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(!json.contains("error"), "None error should be skipped in serialization");
    let decoded: StatusResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, resp);
}

#[skuld::test]
fn error_response_json_roundtrip() {
    let resp = ErrorResponse {
        message: "port in use".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let decoded: ErrorResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, resp);
}

#[skuld::test]
fn empty_response_serializes_to_empty_object() {
    let resp = EmptyResponse {};
    let json = serde_json::to_string(&resp).unwrap();
    assert_eq!(json, "{}");
}

#[skuld::test]
fn status_response_explicit_null_error() {
    let json = r#"{"running": false, "uptime_secs": 0, "error": null}"#;
    let decoded: StatusResponse = serde_json::from_str(json).unwrap();
    assert_eq!(decoded.error, None);
}

#[skuld::test]
fn route_constants_are_correct() {
    assert_eq!(ROUTE_STATUS, "/v1/status");
    assert_eq!(ROUTE_START, "/v1/start");
    assert_eq!(ROUTE_STOP, "/v1/stop");
    assert_eq!(ROUTE_RELOAD, "/v1/reload");
}
