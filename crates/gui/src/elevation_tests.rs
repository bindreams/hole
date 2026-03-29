use hole_common::config::ServerEntry;
use hole_common::protocol::{DaemonRequest, ProxyConfig};

#[skuld::test]
fn encode_request_roundtrips() {
    use base64::Engine;

    let request = DaemonRequest::Start {
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
            },
            local_port: 4073,
        },
    };

    let b64 = super::encode_request(&request);
    let decoded_bytes = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
    let decoded: DaemonRequest = serde_json::from_slice(&decoded_bytes).unwrap();
    assert_eq!(decoded, request);
}

#[skuld::test]
fn encode_stop_request() {
    use base64::Engine;

    let b64 = super::encode_request(&DaemonRequest::Stop);
    let decoded_bytes = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
    let decoded: DaemonRequest = serde_json::from_slice(&decoded_bytes).unwrap();
    assert_eq!(decoded, DaemonRequest::Stop);
}

#[skuld::test]
fn encode_status_request() {
    use base64::Engine;

    let b64 = super::encode_request(&DaemonRequest::Status);
    let decoded_bytes = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
    let decoded: DaemonRequest = serde_json::from_slice(&decoded_bytes).unwrap();
    assert_eq!(decoded, DaemonRequest::Status);
}
