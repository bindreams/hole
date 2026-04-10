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
        validation: None,
    }
}

fn sample_config() -> ProxyConfig {
    ProxyConfig {
        server: sample_server(),
        local_port: 4073,
        tunnel_mode: TunnelMode::Full,
        filters: Vec::new(),
    }
}

// BridgeRequest/BridgeResponse JSON serialization (used by elevation flow) --------------------------------------------

#[skuld::test]
fn bridge_request_start_json_roundtrip() {
    let req = BridgeRequest::Start {
        config: sample_config(),
    };
    let json = serde_json::to_vec(&req).unwrap();
    let decoded: BridgeRequest = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn bridge_request_stop_json_roundtrip() {
    let req = BridgeRequest::Stop;
    let json = serde_json::to_vec(&req).unwrap();
    let decoded: BridgeRequest = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn bridge_request_status_json_roundtrip() {
    let req = BridgeRequest::Status;
    let json = serde_json::to_vec(&req).unwrap();
    let decoded: BridgeRequest = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn bridge_request_reload_json_roundtrip() {
    let req = BridgeRequest::Reload {
        config: sample_config(),
    };
    let json = serde_json::to_vec(&req).unwrap();
    let decoded: BridgeRequest = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn bridge_request_cancel_json_roundtrip() {
    let req = BridgeRequest::Cancel;
    let json = serde_json::to_vec(&req).unwrap();
    let decoded: BridgeRequest = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn cancelled_message_constant_is_stable() {
    // The bridge writes this exact string into ErrorResponse when a Start is
    // cancelled; the client matches against it. Changing it is a breaking
    // change to the client/bridge contract.
    assert_eq!(CANCELLED_MESSAGE, "cancelled");
}

#[skuld::test]
fn bridge_response_ack_json_roundtrip() {
    let resp = BridgeResponse::Ack;
    let json = serde_json::to_vec(&resp).unwrap();
    let decoded: BridgeResponse = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, resp);
}

#[skuld::test]
fn bridge_response_status_json_roundtrip() {
    let resp = BridgeResponse::Status {
        running: true,
        uptime_secs: 3600,
        error: Some("minor issue".to_string()),
        invalid_filters: vec![InvalidFilter {
            index: 2,
            error: "bad pattern".to_string(),
        }],
        udp_proxy_available: true,
        ipv6_bypass_available: false,
    };
    let json = serde_json::to_vec(&resp).unwrap();
    let decoded: BridgeResponse = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, resp);
}

#[skuld::test]
fn bridge_response_error_json_roundtrip() {
    let resp = BridgeResponse::Error {
        message: "port in use".to_string(),
    };
    let json = serde_json::to_vec(&resp).unwrap();
    let decoded: BridgeResponse = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, resp);
}

/// Ensure old clients that still send `plugin_path` in JSON don't break deserialization.
/// Guards against a future `deny_unknown_fields` accidentally breaking backward compatibility.
#[skuld::test]
fn proxy_config_ignores_unknown_plugin_path_field() {
    let json = r#"{
        "server": {
            "id": "test-id", "name": "Test", "server": "1.2.3.4",
            "server_port": 8388, "method": "aes-256-gcm", "password": "pw"
        },
        "local_port": 4073,
        "plugin_path": "/usr/bin/evil"
    }"#;
    let config: ProxyConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.local_port, 4073);
}

// Generated type tests ------------------------------------------------------------------------------------------------

#[skuld::test]
fn status_response_json_roundtrip() {
    let resp = StatusResponse {
        running: true,
        uptime_secs: 3600,
        error: Some("minor issue".to_string()),
        invalid_filters: vec![InvalidFilter {
            index: 1,
            error: "bad pattern".to_string(),
        }],
        udp_proxy_available: false,
        ipv6_bypass_available: true,
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
        invalid_filters: Vec::new(),
        udp_proxy_available: true,
        ipv6_bypass_available: true,
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
    // Default values should be applied for missing fields
    assert!(decoded.invalid_filters.is_empty());
    assert!(decoded.udp_proxy_available);
    assert!(decoded.ipv6_bypass_available);
}

#[skuld::test]
fn route_constants_are_correct() {
    assert_eq!(ROUTE_STATUS, "/v1/status");
    assert_eq!(ROUTE_START, "/v1/start");
    assert_eq!(ROUTE_STOP, "/v1/stop");
    assert_eq!(ROUTE_CANCEL, "/v1/cancel");
    assert_eq!(ROUTE_RELOAD, "/v1/reload");
}

// New response types --------------------------------------------------------------------------------------------------

#[skuld::test]
fn metrics_response_roundtrips() {
    let resp = MetricsResponse {
        bytes_in: 1_000_000,
        bytes_out: 500_000,
        speed_in_bps: 1_048_576,
        speed_out_bps: 524_288,
        uptime_secs: 3600,
        filter: Some(FilterMetrics::default()),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: MetricsResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}

#[skuld::test]
fn diagnostics_response_roundtrips() {
    let resp = DiagnosticsResponse {
        app: "ok".to_string(),
        bridge: "ok".to_string(),
        network: "ok".to_string(),
        vpn_server: "ok".to_string(),
        internet: "unknown".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: DiagnosticsResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}

#[skuld::test]
fn public_ip_response_roundtrips() {
    let resp = PublicIpResponse {
        ip: "185.0.0.42".to_string(),
        country_code: "DE".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: PublicIpResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}

#[skuld::test]
fn route_constants_for_new_endpoints_exist() {
    assert_eq!(ROUTE_METRICS, "/v1/metrics");
    assert_eq!(ROUTE_DIAGNOSTICS, "/v1/diagnostics");
    assert_eq!(ROUTE_PUBLIC_IP, "/v1/public-ip");
}

// Protocol variant roundtrips -----------------------------------------------------------------------------------------

#[skuld::test]
fn bridge_request_metrics_roundtrips() {
    let req = BridgeRequest::Metrics;
    let json = serde_json::to_string(&req).unwrap();
    let parsed: BridgeRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, parsed);
}

#[skuld::test]
fn bridge_request_diagnostics_roundtrips() {
    let req = BridgeRequest::Diagnostics;
    let json = serde_json::to_string(&req).unwrap();
    let parsed: BridgeRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, parsed);
}

#[skuld::test]
fn bridge_request_public_ip_roundtrips() {
    let req = BridgeRequest::PublicIp;
    let json = serde_json::to_string(&req).unwrap();
    let parsed: BridgeRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, parsed);
}

#[skuld::test]
fn bridge_response_metrics_roundtrips() {
    let resp = BridgeResponse::Metrics {
        bytes_in: 100,
        bytes_out: 50,
        speed_in_bps: 1024,
        speed_out_bps: 512,
        uptime_secs: 60,
        filter: Some(FilterMetrics::default()),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: BridgeResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}

#[skuld::test]
fn bridge_response_diagnostics_roundtrips() {
    let resp = BridgeResponse::Diagnostics {
        app: "ok".to_string(),
        bridge: "ok".to_string(),
        network: "error".to_string(),
        vpn_server: "unknown".to_string(),
        internet: "unknown".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: BridgeResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}

#[skuld::test]
fn bridge_response_public_ip_roundtrips() {
    let resp = BridgeResponse::PublicIp {
        ip: "1.2.3.4".to_string(),
        country_code: "US".to_string(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let parsed: BridgeResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, parsed);
}

// TunnelMode wire compatibility =======================================================================================

#[skuld::test]
fn tunnel_mode_default_is_full() {
    // Explicit assertion — TunnelMode::default() MUST be Full because
    // older clients that omit the field rely on this to preserve
    // pre-existing behavior (TUN + routing).
    assert_eq!(TunnelMode::default(), TunnelMode::Full);
}

#[skuld::test]
fn tunnel_mode_serializes_as_snake_case() {
    // snake_case is the project-wide serialization convention and is
    // load-bearing for the OpenAPI spec's enum values.
    assert_eq!(serde_json::to_string(&TunnelMode::Full).unwrap(), r#""full""#);
    assert_eq!(
        serde_json::to_string(&TunnelMode::SocksOnly).unwrap(),
        r#""socks_only""#,
    );
}

#[skuld::test]
fn proxy_config_parses_without_tunnel_mode_field() {
    // Wire compat: the existing GUI does not send `tunnel_mode`. Parsing
    // must succeed and yield the default (Full). This is the test that
    // prevents an accidental #[serde(default)] removal from silently
    // breaking every deployed GUI the next time the bridge is updated.
    let json = r#"{
        "server": {
            "id": "x",
            "name": "x",
            "server": "1.2.3.4",
            "server_port": 8388,
            "method": "aes-256-gcm",
            "password": "pw"
        },
        "local_port": 4073
    }"#;
    let cfg: ProxyConfig = serde_json::from_str(json).expect("legacy payload must parse");
    assert_eq!(cfg.tunnel_mode, TunnelMode::Full);
    assert_eq!(cfg.local_port, 4073);
}

#[skuld::test]
fn proxy_config_parses_with_socks_only_tunnel_mode() {
    let json = r#"{
        "server": {
            "id": "x",
            "name": "x",
            "server": "1.2.3.4",
            "server_port": 8388,
            "method": "aes-256-gcm",
            "password": "pw"
        },
        "local_port": 4073,
        "tunnel_mode": "socks_only"
    }"#;
    let cfg: ProxyConfig = serde_json::from_str(json).expect("socks_only payload must parse");
    assert_eq!(cfg.tunnel_mode, TunnelMode::SocksOnly);
}

#[skuld::test]
fn proxy_config_tunnel_mode_full_roundtrips() {
    let cfg = ProxyConfig {
        server: sample_server(),
        local_port: 4073,
        tunnel_mode: TunnelMode::Full,
        filters: Vec::new(),
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: ProxyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, cfg);
}

#[skuld::test]
fn proxy_config_tunnel_mode_socks_only_roundtrips() {
    let cfg = ProxyConfig {
        server: sample_server(),
        local_port: 4073,
        tunnel_mode: TunnelMode::SocksOnly,
        filters: Vec::new(),
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let decoded: ProxyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, cfg);
}
