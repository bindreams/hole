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

// Round-trip tests -----

#[skuld::test]
fn roundtrip_start_request() {
    let req = DaemonRequest::Start {
        config: sample_config(),
    };
    let bytes = encode(&req).unwrap();
    let (decoded, consumed): (DaemonRequest, _) = decode(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(decoded, req);
}

#[skuld::test]
fn roundtrip_stop_request() {
    let req = DaemonRequest::Stop;
    let bytes = encode(&req).unwrap();
    let (decoded, _): (DaemonRequest, _) = decode(&bytes).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn roundtrip_status_request() {
    let req = DaemonRequest::Status;
    let bytes = encode(&req).unwrap();
    let (decoded, _): (DaemonRequest, _) = decode(&bytes).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn roundtrip_reload_request() {
    let req = DaemonRequest::Reload {
        config: sample_config(),
    };
    let bytes = encode(&req).unwrap();
    let (decoded, _): (DaemonRequest, _) = decode(&bytes).unwrap();
    assert_eq!(decoded, req);
}

#[skuld::test]
fn roundtrip_ack_response() {
    let resp = DaemonResponse::Ack;
    let bytes = encode(&resp).unwrap();
    let (decoded, _): (DaemonResponse, _) = decode(&bytes).unwrap();
    assert_eq!(decoded, resp);
}

#[skuld::test]
fn roundtrip_status_response() {
    let resp = DaemonResponse::Status {
        running: true,
        uptime_secs: 3600,
        error: Some("minor issue".to_string()),
    };
    let bytes = encode(&resp).unwrap();
    let (decoded, _): (DaemonResponse, _) = decode(&bytes).unwrap();
    assert_eq!(decoded, resp);
}

#[skuld::test]
fn roundtrip_error_response() {
    let resp = DaemonResponse::Error {
        message: "port in use".to_string(),
    };
    let bytes = encode(&resp).unwrap();
    let (decoded, _): (DaemonResponse, _) = decode(&bytes).unwrap();
    assert_eq!(decoded, resp);
}

// Wire format tests -----

#[skuld::test]
fn encode_produces_4_byte_length_prefix() {
    let req = DaemonRequest::Stop;
    let bytes = encode(&req).unwrap();
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(len as usize, bytes.len() - 4);
}

#[skuld::test]
fn decode_truncated_length_returns_error() {
    let data = [0u8, 0]; // only 2 bytes, need 4
    let result: Result<(DaemonRequest, usize), _> = decode(&data);
    assert!(result.is_err());
}

#[skuld::test]
fn decode_truncated_body_returns_error() {
    let mut data = vec![0u8, 0, 0, 100]; // claims 100 bytes
    data.extend_from_slice(b"{}"); // only 2 bytes of body
    let result: Result<(DaemonRequest, usize), _> = decode(&data);
    assert!(result.is_err());
}

#[skuld::test]
fn decode_invalid_json_returns_error() {
    let garbage = b"not json!!!";
    let len = (garbage.len() as u32).to_be_bytes();
    let mut data = Vec::new();
    data.extend_from_slice(&len);
    data.extend_from_slice(garbage);
    let result: Result<(DaemonRequest, usize), _> = decode(&data);
    assert!(result.is_err());
}

#[skuld::test]
fn proxy_config_with_plugin_path_roundtrips() {
    let req = DaemonRequest::Start {
        config: ProxyConfig {
            server: sample_server(),
            local_port: 4073,
            plugin_path: Some("/usr/bin/v2ray-plugin".into()),
        },
    };
    let bytes = encode(&req).unwrap();
    let (decoded, _): (DaemonRequest, _) = decode(&bytes).unwrap();
    assert_eq!(decoded, req);
}
