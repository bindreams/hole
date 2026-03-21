use super::*;
use hole_common::protocol::{DaemonRequest, DaemonResponse};

// Helpers =====

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

/// Generate a test socket name. On macOS, returns a temp file path.
#[cfg(target_os = "windows")]
fn test_socket_name(suffix: &str) -> String {
    format!("hole-gui-test-{suffix}")
}

#[cfg(target_os = "macos")]
fn test_socket_name(suffix: &str) -> String {
    format!("/tmp/hole-gui-test-{suffix}.sock")
}

/// Spawn a mock daemon that responds to one connection with canned responses.
async fn spawn_mock_daemon(name: &str) -> tokio::task::JoinHandle<()> {
    use interprocess::local_socket::{traits::tokio::Listener as ListenerTrait, ListenerOptions};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = {
        #[cfg(target_os = "windows")]
        {
            use interprocess::local_socket::{GenericNamespaced, ToNsName};
            let ns_name = name.to_ns_name::<GenericNamespaced>().unwrap();
            ListenerOptions::new().name(ns_name).create_tokio().unwrap()
        }
        #[cfg(target_os = "macos")]
        {
            use interprocess::local_socket::{GenericFilePath, ToFsName};
            let _ = std::fs::remove_file(name);
            let fs_name = name.to_fs_name::<GenericFilePath>().unwrap();
            ListenerOptions::new().name(fs_name).create_tokio().unwrap()
        }
    };

    tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        loop {
            // Read length prefix
            let mut len_buf = [0u8; 4];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(_) => return, // client disconnected
            }
            let msg_len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; msg_len];
            stream.read_exact(&mut body).await.unwrap();

            let req: DaemonRequest = serde_json::from_slice(&body).unwrap();
            let resp = match req {
                DaemonRequest::Status => DaemonResponse::Status {
                    running: false,
                    uptime_secs: 0,
                    error: None,
                },
                DaemonRequest::Start { .. } => DaemonResponse::Ack,
                DaemonRequest::Stop => DaemonResponse::Ack,
                DaemonRequest::Reload { .. } => DaemonResponse::Ack,
            };

            let resp_json = serde_json::to_vec(&resp).unwrap();
            let resp_len = (resp_json.len() as u32).to_be_bytes();
            stream.write_all(&resp_len).await.unwrap();
            stream.write_all(&resp_json).await.unwrap();
        }
    })
}

// Tests =====

#[skuld::test]
fn send_status_request_receives_response() {
    rt().block_on(async {
        let name = &test_socket_name("status");
        let _mock = spawn_mock_daemon(name).await;

        let mut client = DaemonClient::connect(name).await.unwrap();
        let resp = client.send(DaemonRequest::Status).await.unwrap();

        assert_eq!(
            resp,
            DaemonResponse::Status {
                running: false,
                uptime_secs: 0,
                error: None,
            }
        );
    });
}

#[skuld::test]
fn send_start_receives_ack() {
    rt().block_on(async {
        let name = &test_socket_name("start");
        let _mock = spawn_mock_daemon(name).await;

        let mut client = DaemonClient::connect(name).await.unwrap();
        let resp = client
            .send(DaemonRequest::Start {
                config: hole_common::protocol::ProxyConfig {
                    server: hole_common::config::ServerEntry {
                        id: "id".into(),
                        name: "S".into(),
                        server: "1.2.3.4".into(),
                        server_port: 8388,
                        method: "aes-256-gcm".into(),
                        password: "pw".into(),
                        plugin: None,
                        plugin_opts: None,
                    },
                    local_port: 4073,
                    plugin_path: None,
                },
            })
            .await
            .unwrap();
        assert_eq!(resp, DaemonResponse::Ack);
    });
}

#[skuld::test]
fn multiple_requests_on_same_client() {
    rt().block_on(async {
        let name = &test_socket_name("multi");
        let _mock = spawn_mock_daemon(name).await;

        let mut client = DaemonClient::connect(name).await.unwrap();

        let r1 = client.send(DaemonRequest::Status).await.unwrap();
        assert!(matches!(r1, DaemonResponse::Status { .. }));

        let r2 = client.send(DaemonRequest::Stop).await.unwrap();
        assert_eq!(r2, DaemonResponse::Ack);
    });
}

#[skuld::test]
fn connect_to_nonexistent_returns_error() {
    rt().block_on(async {
        let result = DaemonClient::connect(&test_socket_name("nonexistent")).await;
        assert!(result.is_err());
    });
}

#[skuld::test]
fn permission_denied_maps_to_variant() {
    // Verify that map_connect_error correctly maps PermissionDenied
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
    let client_err = super::map_connect_error(io_err);
    assert!(
        matches!(client_err, ClientError::PermissionDenied),
        "expected PermissionDenied, got: {client_err:?}"
    );
}

#[skuld::test]
fn other_io_error_maps_to_connection() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    let client_err = super::map_connect_error(io_err);
    assert!(
        matches!(client_err, ClientError::Connection(_)),
        "expected Connection, got: {client_err:?}"
    );
}
