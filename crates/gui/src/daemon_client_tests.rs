use super::*;
use axum::Json;
use hole_common::protocol::{DaemonRequest, DaemonResponse, EmptyResponse, StatusResponse};
use hyper::body::Incoming;

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

/// Spawn a mock HTTP daemon that responds to requests with canned responses.
async fn spawn_mock_daemon(name: &str) -> tokio::task::JoinHandle<()> {
    use interprocess::local_socket::{traits::tokio::Listener as ListenerTrait, ListenerOptions};

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

    let router = axum::Router::new()
        .route(
            hole_common::protocol::ROUTE_STATUS,
            axum::routing::get(|| async {
                Json(StatusResponse {
                    running: false,
                    uptime_secs: 0,
                    error: None,
                })
            }),
        )
        .route(
            hole_common::protocol::ROUTE_START,
            axum::routing::post(|| async { Json(EmptyResponse {}) }),
        )
        .route(
            hole_common::protocol::ROUTE_STOP,
            axum::routing::post(|| async { Json(EmptyResponse {}) }),
        )
        .route(
            hole_common::protocol::ROUTE_RELOAD,
            axum::routing::post(|| async { Json(EmptyResponse {}) }),
        );

    tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let io = hyper_util::rt::TokioIo::new(stream);
        let service = hyper::service::service_fn(move |req: http::Request<Incoming>| {
            let router = router.clone();
            async move {
                use tower::ServiceExt;
                let resp = router.oneshot(req.map(axum::body::Body::new)).await.unwrap();
                Ok::<_, std::convert::Infallible>(resp)
            }
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await;
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
