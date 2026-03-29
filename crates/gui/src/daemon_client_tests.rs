use super::*;
use axum::Json;
use hole_common::protocol::{DaemonRequest, DaemonResponse, EmptyResponse, StatusResponse};
use hyper::body::Incoming;
use std::path::PathBuf;

// Helpers =============================================================================================================

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

fn test_socket_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hole-gui-test-{}-{suffix}.sock", std::process::id()))
}

/// Spawn a mock HTTP daemon that responds to requests with canned responses.
async fn spawn_mock_daemon(path: &std::path::Path) -> tokio::task::JoinHandle<()> {
    let listener = hole_daemon::socket::LocalListener::bind(path).unwrap();

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

// Tests ===============================================================================================================

#[skuld::test]
fn send_status_request_receives_response() {
    rt().block_on(async {
        let path = test_socket_path("status");
        let _mock = spawn_mock_daemon(&path).await;

        let mut client = DaemonClient::connect(&path).await.unwrap();
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
        let path = test_socket_path("start");
        let _mock = spawn_mock_daemon(&path).await;

        let mut client = DaemonClient::connect(&path).await.unwrap();
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
        let path = test_socket_path("multi");
        let _mock = spawn_mock_daemon(&path).await;

        let mut client = DaemonClient::connect(&path).await.unwrap();

        let r1 = client.send(DaemonRequest::Status).await.unwrap();
        assert!(matches!(r1, DaemonResponse::Status { .. }));

        let r2 = client.send(DaemonRequest::Stop).await.unwrap();
        assert_eq!(r2, DaemonResponse::Ack);
    });
}

#[skuld::test]
fn connect_to_nonexistent_returns_error() {
    rt().block_on(async {
        let path = test_socket_path("nonexistent");
        let _ = std::fs::remove_file(&path);
        let result = DaemonClient::connect(&path).await;
        assert!(result.is_err());
    });
}

#[skuld::test]
fn permission_denied_maps_to_variant() {
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

#[skuld::test]
fn send_reload_receives_ack() {
    rt().block_on(async {
        let path = test_socket_path("reload");
        let _mock = spawn_mock_daemon(&path).await;

        let mut client = DaemonClient::connect(&path).await.unwrap();
        let resp = client
            .send(DaemonRequest::Reload {
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
                },
            })
            .await
            .unwrap();
        assert_eq!(resp, DaemonResponse::Ack);
    });
}

/// Spawn a mock daemon that returns 500 with an ErrorResponse for POST /start.
async fn spawn_error_daemon(path: &std::path::Path) -> tokio::task::JoinHandle<()> {
    use hole_common::protocol::ErrorResponse;

    let listener = hole_daemon::socket::LocalListener::bind(path).unwrap();

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
            axum::routing::post(|| async {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        message: "mock start failure".to_string(),
                    }),
                )
            }),
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

#[skuld::test]
fn server_error_maps_to_daemon_response_error() {
    rt().block_on(async {
        let path = test_socket_path("err500");
        let _mock = spawn_error_daemon(&path).await;

        let mut client = DaemonClient::connect(&path).await.unwrap();
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
                },
            })
            .await
            .unwrap();
        match resp {
            DaemonResponse::Error { message } => {
                assert!(
                    message.contains("mock start failure"),
                    "expected error message, got: {message}"
                );
            }
            other => panic!("expected Error response, got {other:?}"),
        }
    });
}
