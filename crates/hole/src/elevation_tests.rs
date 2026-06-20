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
            dns: hole_common::config::DnsConfig {
                enabled: false,
                ..hole_common::config::DnsConfig::default()
            },
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
            diagnostic_plugin_tap: false,
        },
        attempt_id: "elev-test".into(),
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
            dns: hole_common::config::DnsConfig {
                enabled: false,
                ..hole_common::config::DnsConfig::default()
            },
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
            diagnostic_plugin_tap: false,
        },
        attempt_id: "elev-test".into(),
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
            dns: hole_common::config::DnsConfig {
                enabled: false,
                ..hole_common::config::DnsConfig::default()
            },
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
            diagnostic_plugin_tap: false,
        },
        attempt_id: "elev-test".into(),
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

#[skuld::test]
fn start_attempt_id_survives_request_file_roundtrip() {
    // The attempt id is a STRUCT FIELD, so it round-trips through the elevation
    // re-serialization path (write/read_request_file). A header minted only in
    // bridge_client would be dropped on the elevated replay — then an elevated
    // Start could never match a pre-arm (#465).
    let request = BridgeRequest::Start {
        config: ProxyConfig::default(),
        attempt_id: "elev-attempt-42".into(),
    };
    let temp_path = super::write_request_file(&request).unwrap();
    let path = temp_path.to_path_buf();
    temp_path.keep().unwrap();
    let parsed = super::read_request_file(&path).unwrap();
    match parsed {
        BridgeRequest::Start { attempt_id, .. } => assert_eq!(attempt_id, "elev-attempt-42"),
        other => panic!("expected Start, got {other:?}"),
    }
}

// Result-file channel =================================================================================================

use super::{read_result_file, write_result_file, ElevatedOutcome};

/// An empty result-file target with its handle closed, mirroring the parent's
/// `write_result_file_target`; the child then writes to it.
fn result_target() -> tempfile::TempPath {
    tempfile::NamedTempFile::new().unwrap().into_temp_path()
}

fn outcome_samples() -> Vec<ElevatedOutcome> {
    vec![
        ElevatedOutcome::Success,
        ElevatedOutcome::BridgeError {
            message: "invalid cipher method: aes-999".into(),
        },
        ElevatedOutcome::Transport {
            detail: "refused".into(),
        },
    ]
}

#[skuld::test]
fn result_file_roundtrips_each_variant() {
    for outcome in outcome_samples() {
        let target = result_target();
        let path = target.to_path_buf();
        target.keep().unwrap(); // keep so read (which deletes) can find it
        write_result_file(&path, &outcome).unwrap();
        let parsed = read_result_file(&path).unwrap();
        assert_eq!(parsed, outcome);
    }
}

#[skuld::test]
fn read_result_file_deletes_after_read() {
    let target = result_target();
    let path = target.to_path_buf();
    target.keep().unwrap();
    write_result_file(&path, &ElevatedOutcome::Success).unwrap();
    assert!(path.exists());
    let _ = read_result_file(&path).unwrap();
    assert!(!path.exists(), "result file must be deleted after read");
}

#[skuld::test]
fn read_result_file_missing_is_err() {
    assert!(read_result_file(std::path::Path::new("/tmp/claude/nonexistent-result-file")).is_err());
}

#[skuld::test]
fn read_result_file_empty_is_err() {
    // A created-but-unwritten file must not parse as a valid outcome.
    let target = result_target();
    let path = target.to_path_buf();
    target.keep().unwrap();
    assert!(read_result_file(&path).is_err());
}

#[skuld::test]
fn read_result_file_garbage_is_err() {
    // A partial/garbage write (child killed mid fs::write) must not parse — the
    // parent then falls back to the SetupError axis, never to "denied".
    let target = result_target();
    let path = target.to_path_buf();
    target.keep().unwrap();
    std::fs::write(&path, b"{\"kind\":\"bri").unwrap();
    assert!(read_result_file(&path).is_err());
}

// classify_elevated_send ==============================================================================================

use super::classify_elevated_send;
use hole_common::protocol::{BridgeResponse, CANCELLED_MESSAGE};

#[skuld::test]
fn classify_ack_is_success() {
    assert_eq!(
        classify_elevated_send(&Ok(BridgeResponse::Ack)),
        ElevatedOutcome::Success
    );
}

#[skuld::test]
fn classify_bridge_error_carries_raw_message() {
    let r = Ok(BridgeResponse::Error {
        message: "invalid cipher method: aes-999".into(),
    });
    assert_eq!(
        classify_elevated_send(&r),
        ElevatedOutcome::BridgeError {
            message: "invalid cipher method: aes-999".into()
        }
    );
}

#[skuld::test]
fn classify_bridge_cancel_is_success_not_error() {
    // The no-relabel guard: a bridge-side cancel must never become a BridgeError
    // (and thus never a "denied" toast).
    let r = Ok(BridgeResponse::Error {
        message: CANCELLED_MESSAGE.into(),
    });
    assert_eq!(classify_elevated_send(&r), ElevatedOutcome::Success);
}

#[skuld::test]
fn classify_already_running_is_success() {
    let r = Ok(BridgeResponse::Error {
        message: "proxy already running".into(),
    });
    assert_eq!(classify_elevated_send(&r), ElevatedOutcome::Success);
}

#[skuld::test]
fn classify_stop_error_is_bridge_error() {
    // elevate_and_confirm is reachable from a Stop too; a generic Stop error is a
    // real bridge error (the Other arm), surfaced to the user.
    let r = Ok(BridgeResponse::Error {
        message: "teardown failed".into(),
    });
    assert_eq!(
        classify_elevated_send(&r),
        ElevatedOutcome::BridgeError {
            message: "teardown failed".into()
        }
    );
}

#[skuld::test]
fn classify_transport_err_is_transport() {
    let r: Result<BridgeResponse, String> = Err("failed to connect to bridge: refused".into());
    assert_eq!(
        classify_elevated_send(&r),
        ElevatedOutcome::Transport {
            detail: "failed to connect to bridge: refused".into()
        }
    );
}

// elevation_result_from ===============================================================================================

use super::{elevation_result_from, ElevationResult};
use crate::setup::SetupError;

fn exit_code_err() -> SetupError {
    SetupError::ExitCode {
        code: 1,
        output: String::new(),
        log_path: None,
    }
}

#[skuld::test]
fn elevation_result_cancelled_from_setup_cancelled() {
    assert_eq!(
        elevation_result_from(Err(&SetupError::Cancelled), None),
        ElevationResult::Cancelled
    );
}

#[skuld::test]
fn elevation_result_launch_failure_on_exitcode_without_file() {
    assert_eq!(
        elevation_result_from(Err(&exit_code_err()), None),
        ElevationResult::LaunchFailure
    );
}

#[skuld::test]
fn elevation_result_bridge_error_overrides_exit_code() {
    // THE BUG: child exited 1 but the file says why — the file wins.
    let file = Some(ElevatedOutcome::BridgeError {
        message: "bad config".into(),
    });
    assert_eq!(
        elevation_result_from(Err(&exit_code_err()), file),
        ElevationResult::BridgeError("bad config".into())
    );
}

#[skuld::test]
fn elevation_result_transport_overrides_exit_code() {
    let file = Some(ElevatedOutcome::Transport {
        detail: "refused".into(),
    });
    assert_eq!(
        elevation_result_from(Err(&exit_code_err()), file),
        ElevationResult::Transport("refused".into())
    );
}

#[skuld::test]
fn elevation_result_success_from_ok_and_file() {
    assert_eq!(
        elevation_result_from(Ok(()), Some(ElevatedOutcome::Success)),
        ElevationResult::Success
    );
}

#[skuld::test]
fn elevation_result_success_from_ok_without_file() {
    // Exit 0 means the send succeeded even if the file is unreadable.
    assert_eq!(elevation_result_from(Ok(()), None), ElevationResult::Success);
}

#[skuld::test]
fn elevation_result_launch_failure_on_io_error() {
    let e = SetupError::Io(std::io::Error::other("spawn failed"));
    assert_eq!(elevation_result_from(Err(&e), None), ElevationResult::LaunchFailure);
}
