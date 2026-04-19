use hole_common::config::ServerEntry;
use hole_common::protocol::{BridgeRequest, ProxyConfig, TunnelMode};

#[skuld::test]
fn encode_request_roundtrips() {
    use base64::Engine;

    let request = BridgeRequest::Start {
        config: ProxyConfig {
            server: ServerEntry {
                id: "test".into(),
                name: "Test".into(),
                server: "1.2.3.4".into(),
                server_port: 8388,
                method: "aes-256-gcm".into(),
                password: "pw".into(),
                plugin: None,
                plugin_opts: None,
                validation: None,
            },
            local_port: 4073,
            tunnel_mode: TunnelMode::Full,
            filters: Vec::new(),
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
        },
    };

    let b64 = super::encode_request(&request);
    let decoded_bytes = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
    let decoded: BridgeRequest = serde_json::from_slice(&decoded_bytes).unwrap();
    assert_eq!(decoded, request);
}

#[skuld::test]
fn encode_stop_request() {
    use base64::Engine;

    let b64 = super::encode_request(&BridgeRequest::Stop);
    let decoded_bytes = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
    let decoded: BridgeRequest = serde_json::from_slice(&decoded_bytes).unwrap();
    assert_eq!(decoded, BridgeRequest::Stop);
}

#[skuld::test]
fn encode_status_request() {
    use base64::Engine;

    let b64 = super::encode_request(&BridgeRequest::Status);
    let decoded_bytes = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
    let decoded: BridgeRequest = serde_json::from_slice(&decoded_bytes).unwrap();
    assert_eq!(decoded, BridgeRequest::Status);
}

#[skuld::test]
fn write_request_file_roundtrip() {
    let request = BridgeRequest::Start {
        config: ProxyConfig {
            server: ServerEntry {
                id: "test".into(),
                name: "Test".into(),
                server: "1.2.3.4".into(),
                server_port: 8388,
                method: "aes-256-gcm".into(),
                password: "secret-password".into(),
                plugin: None,
                plugin_opts: None,
                validation: None,
            },
            local_port: 4073,
            tunnel_mode: TunnelMode::Full,
            filters: Vec::new(),
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
        },
    };

    let temp_path = super::write_request_file(&request).unwrap();
    let parsed: BridgeRequest = serde_json::from_str(&std::fs::read_to_string(&temp_path).unwrap()).unwrap();
    assert_eq!(parsed, request);
}

#[skuld::test]
fn request_file_is_deleted_on_drop() {
    let temp_path = super::write_request_file(&BridgeRequest::Stop).unwrap();
    let path_copy = temp_path.to_path_buf();
    assert!(path_copy.exists());
    drop(temp_path);
    assert!(!path_copy.exists());
}

#[skuld::test]
fn read_request_file_roundtrip() {
    let request = BridgeRequest::Start {
        config: ProxyConfig {
            server: ServerEntry {
                id: "test".into(),
                name: "Test".into(),
                server: "1.2.3.4".into(),
                server_port: 8388,
                method: "aes-256-gcm".into(),
                password: "secret-password".into(),
                plugin: None,
                plugin_opts: None,
                validation: None,
            },
            local_port: 4073,
            tunnel_mode: TunnelMode::Full,
            filters: Vec::new(),
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
        },
    };

    let temp_path = super::write_request_file(&request).unwrap();
    let path = temp_path.to_path_buf();
    // Prevent TempPath from deleting so read_request_file can find it
    temp_path.keep().unwrap();

    let parsed = super::read_request_file(&path).unwrap();
    assert_eq!(parsed, request);
}

#[skuld::test]
fn read_request_file_deletes_after_reading() {
    let temp_path = super::write_request_file(&BridgeRequest::Stop).unwrap();
    let path = temp_path.to_path_buf();
    temp_path.keep().unwrap();
    assert!(path.exists());

    let _ = super::read_request_file(&path).unwrap();
    assert!(!path.exists());
}

#[skuld::test]
fn read_request_file_missing_file_returns_error() {
    let path = std::path::Path::new("/tmp/claude/nonexistent-request-file");
    let result = super::read_request_file(path);
    assert!(result.is_err());
}
