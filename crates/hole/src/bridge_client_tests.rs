use super::*;
use axum::Json;
use hole_common::protocol::{
    BridgeRequest, BridgeResponse, DiagnosticsResponse, EmptyResponse, MetricsResponse, StatusResponse,
};
use hyper::body::Incoming;
use std::path::PathBuf;

// Helpers =============================================================================================================

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

fn test_socket_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hole-test-{}-{suffix}.sock", std::process::id()))
}

/// Spawn a mock HTTP bridge that responds to requests with canned responses.
async fn spawn_mock_bridge(path: &std::path::Path) -> tokio::task::JoinHandle<()> {
    let listener = hole_bridge::socket::LocalListener::bind(path).unwrap();

    let router = axum::Router::new()
        .route(
            hole_common::protocol::ROUTE_STATUS,
            axum::routing::get(|| async {
                Json(StatusResponse {
                    running: false,
                    uptime_secs: 0,
                    error: None,
                    invalid_filters: Vec::new(),
                    udp_proxy_available: true,
                    ipv6_bypass_available: true,
                    lockdown_enabled: false,
                    lockdown_active: false,
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
            hole_common::protocol::ROUTE_CANCEL,
            axum::routing::post(|| async { Json(EmptyResponse {}) }),
        )
        .route(
            hole_common::protocol::ROUTE_RELOAD,
            axum::routing::post(|| async { Json(EmptyResponse {}) }),
        )
        .route(
            hole_common::protocol::ROUTE_METRICS,
            axum::routing::get(|| async {
                Json(MetricsResponse {
                    bytes_in: 1024,
                    bytes_out: 512,
                    speed_in_bps: 2048,
                    speed_out_bps: 1024,
                    uptime_secs: 120,
                    filter: None,
                })
            }),
        )
        .route(
            hole_common::protocol::ROUTE_DIAGNOSTICS,
            axum::routing::get(|| async {
                Json(DiagnosticsResponse {
                    app: "ok".to_string(),
                    bridge: "ok".to_string(),
                    network: "ok".to_string(),
                    vpn_server: "ok".to_string(),
                    internet: "ok".to_string(),
                })
            }),
        )
        .layer(axum::middleware::map_response(
            |mut resp: axum::response::Response| async move {
                resp.headers_mut().insert(
                    "x-hole-bridge-version",
                    axum::http::HeaderValue::from_static(hole::version::VERSION),
                );
                resp
            },
        ));

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
        let _mock = spawn_mock_bridge(&path).await;

        let mut client = BridgeClient::connect(&path).await.unwrap();
        let resp = client.send(BridgeRequest::Status).await.unwrap();

        assert_eq!(
            resp,
            BridgeResponse::Status {
                running: false,
                uptime_secs: 0,
                error: None,
                invalid_filters: Vec::new(),
                udp_proxy_available: true,
                ipv6_bypass_available: true,
                lockdown_enabled: false,
                lockdown_active: false,
            }
        );
    });
}

#[skuld::test]
fn send_start_receives_ack() {
    rt().block_on(async {
        let path = test_socket_path("start");
        let _mock = spawn_mock_bridge(&path).await;

        let mut client = BridgeClient::connect(&path).await.unwrap();
        let resp = client
            .send(BridgeRequest::Start {
                attempt_id: "id-123".into(),
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
                        validation: None,
                    },
                    local_port: 4073,
                    tunnel_mode: hole_common::protocol::TunnelMode::Full,
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
            })
            .await
            .unwrap();
        assert_eq!(resp, BridgeResponse::Ack);
    });
}

#[skuld::test]
fn multiple_requests_on_same_client() {
    rt().block_on(async {
        let path = test_socket_path("multi");
        let _mock = spawn_mock_bridge(&path).await;

        let mut client = BridgeClient::connect(&path).await.unwrap();

        let r1 = client.send(BridgeRequest::Status).await.unwrap();
        assert!(matches!(r1, BridgeResponse::Status { .. }));

        let r2 = client.send(BridgeRequest::Stop).await.unwrap();
        assert_eq!(r2, BridgeResponse::Ack);
    });
}

#[skuld::test]
fn connect_to_nonexistent_returns_error() {
    rt().block_on(async {
        let path = test_socket_path("nonexistent");
        let _ = std::fs::remove_file(&path);
        let result = BridgeClient::connect(&path).await;
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
fn send_cancel_receives_ack() {
    rt().block_on(async {
        let path = test_socket_path("cancel");
        let _mock = spawn_mock_bridge(&path).await;

        let mut client = BridgeClient::connect(&path).await.unwrap();
        let resp = client
            .send(BridgeRequest::Cancel {
                attempt_id: "cancel-1".into(),
            })
            .await
            .unwrap();
        assert_eq!(resp, BridgeResponse::Ack);
    });
}

#[skuld::test]
fn start_and_cancel_send_attempt_id_header() {
    // Start and Cancel must put their attempt_id on the X-Hole-Attempt-Id
    // request header — the bridge keys start-cancellation on it (#465). A
    // capturing server records the header the BridgeClient actually sent.
    rt().block_on(async {
        let path = test_socket_path("attempt-id-header");
        let listener = hole_bridge::socket::LocalListener::bind(&path).unwrap();
        let captured: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let mk = |route: &'static str, cap: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>| {
            axum::routing::post(move |headers: axum::http::HeaderMap| {
                let cap = cap.clone();
                async move {
                    let id = headers
                        .get("x-hole-attempt-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("<missing>")
                        .to_owned();
                    cap.lock().unwrap().push((route.to_owned(), id));
                    Json(EmptyResponse {})
                }
            })
        };
        let router = axum::Router::new()
            .route(hole_common::protocol::ROUTE_START, mk("start", captured.clone()))
            .route(hole_common::protocol::ROUTE_CANCEL, mk("cancel", captured.clone()))
            .layer(axum::middleware::map_response(
                |mut resp: axum::response::Response| async move {
                    resp.headers_mut().insert(
                        "x-hole-bridge-version",
                        axum::http::HeaderValue::from_static(hole::version::VERSION),
                    );
                    resp
                },
            ));

        // One pooled BridgeClient connection serves both requests (keep-alive).
        let server = tokio::spawn(async move {
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
        });

        let mut client = BridgeClient::connect(&path).await.unwrap();
        client
            .send(BridgeRequest::Start {
                config: hole_common::protocol::ProxyConfig::default(),
                attempt_id: "id-123".into(),
            })
            .await
            .unwrap();
        client
            .send(BridgeRequest::Cancel {
                attempt_id: "id-123".into(),
            })
            .await
            .unwrap();

        drop(client);
        let _ = server.await;
        let got = captured.lock().unwrap().clone();
        assert_eq!(
            got,
            vec![
                ("start".to_owned(), "id-123".to_owned()),
                ("cancel".to_owned(), "id-123".to_owned()),
            ]
        );
    });
}

#[skuld::test]
fn send_reload_receives_ack() {
    rt().block_on(async {
        let path = test_socket_path("reload");
        let _mock = spawn_mock_bridge(&path).await;

        let mut client = BridgeClient::connect(&path).await.unwrap();
        let resp = client
            .send(BridgeRequest::Reload {
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
                        validation: None,
                    },
                    local_port: 4073,
                    tunnel_mode: hole_common::protocol::TunnelMode::Full,
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
            })
            .await
            .unwrap();
        assert_eq!(resp, BridgeResponse::Ack);
    });
}

/// Spawn a mock bridge that returns 500 with an ErrorResponse for POST /start.
async fn spawn_error_bridge(path: &std::path::Path) -> tokio::task::JoinHandle<()> {
    use hole_common::protocol::ErrorResponse;

    let listener = hole_bridge::socket::LocalListener::bind(path).unwrap();

    let router = axum::Router::new()
        .route(
            hole_common::protocol::ROUTE_STATUS,
            axum::routing::get(|| async {
                Json(StatusResponse {
                    running: false,
                    uptime_secs: 0,
                    error: None,
                    invalid_filters: Vec::new(),
                    udp_proxy_available: true,
                    ipv6_bypass_available: true,
                    lockdown_enabled: false,
                    lockdown_active: false,
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
        )
        .layer(axum::middleware::map_response(
            |mut resp: axum::response::Response| async move {
                resp.headers_mut().insert(
                    "x-hole-bridge-version",
                    axum::http::HeaderValue::from_static(hole::version::VERSION),
                );
                resp
            },
        ));

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
fn server_error_maps_to_bridge_response_error() {
    rt().block_on(async {
        let path = test_socket_path("err500");
        let _mock = spawn_error_bridge(&path).await;

        let mut client = BridgeClient::connect(&path).await.unwrap();
        let resp = client
            .send(BridgeRequest::Start {
                attempt_id: "id-123".into(),
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
                        validation: None,
                    },
                    local_port: 4073,
                    tunnel_mode: hole_common::protocol::TunnelMode::Full,
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
            })
            .await
            .unwrap();
        match resp {
            BridgeResponse::Error { message } => {
                assert!(
                    message.contains("mock start failure"),
                    "expected error message, got: {message}"
                );
            }
            other => panic!("expected Error response, got {other:?}"),
        }
    });
}

#[skuld::test]
fn send_metrics_returns_response() {
    rt().block_on(async {
        let path = test_socket_path("metrics");
        let _mock = spawn_mock_bridge(&path).await;

        let mut client = BridgeClient::connect(&path).await.unwrap();
        let resp = client.send(BridgeRequest::Metrics).await.unwrap();

        assert_eq!(
            resp,
            BridgeResponse::Metrics {
                bytes_in: 1024,
                bytes_out: 512,
                speed_in_bps: 2048,
                speed_out_bps: 1024,
                uptime_secs: 120,
                filter: None,
            }
        );
    });
}

// Version lockstep ====================================================================================================

/// Accept one connection and serve the given router on it.
fn serve_one(listener: hole_bridge::socket::LocalListener, router: axum::Router) -> tokio::task::JoinHandle<()> {
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

/// Mock serving GET /v1/status. When `version` is `Some`, stamps it on every
/// response via `X-Hole-Bridge-Version`; when `None`, sends no such header
/// (an old bridge predating the stamp). Has no /v1/version route (→ 404).
async fn spawn_status_mock(path: &std::path::Path, version: Option<&'static str>) -> tokio::task::JoinHandle<()> {
    let listener = hole_bridge::socket::LocalListener::bind(path).unwrap();
    let mut router = axum::Router::new().route(
        hole_common::protocol::ROUTE_STATUS,
        axum::routing::get(|| async {
            Json(StatusResponse {
                running: false,
                uptime_secs: 0,
                error: None,
                invalid_filters: Vec::new(),
                udp_proxy_available: true,
                ipv6_bypass_available: true,
                lockdown_enabled: false,
                lockdown_active: false,
            })
        }),
    );
    if let Some(v) = version {
        router = router.layer(axum::middleware::map_response(
            move |mut resp: axum::response::Response| async move {
                resp.headers_mut()
                    .insert("x-hole-bridge-version", axum::http::HeaderValue::from_static(v));
                resp
            },
        ));
    }
    serve_one(listener, router)
}

#[skuld::test]
fn matching_version_is_ok() {
    rt().block_on(async {
        let path = test_socket_path("ver-match");
        let _m = spawn_status_mock(&path, Some("7.0.0")).await;
        let mut c = BridgeClient::connect_with_version(&path, "7.0.0").await.unwrap();
        assert!(matches!(
            c.send(BridgeRequest::Status).await,
            Ok(BridgeResponse::Status { .. })
        ));
    });
}

#[skuld::test]
fn mismatching_version_is_version_mismatch() {
    rt().block_on(async {
        let path = test_socket_path("ver-mismatch");
        let _m = spawn_status_mock(&path, Some("6.0.0")).await;
        let mut c = BridgeClient::connect_with_version(&path, "7.0.0").await.unwrap();
        assert!(matches!(
            c.send(BridgeRequest::Status).await,
            Err(ClientError::VersionMismatch { .. })
        ));
    });
}

#[skuld::test]
fn absent_version_header_is_version_mismatch() {
    rt().block_on(async {
        let path = test_socket_path("ver-absent");
        let _m = spawn_status_mock(&path, None).await; // old bridge: no header
        let mut c = BridgeClient::connect_with_version(&path, "7.0.0").await.unwrap();
        assert!(matches!(
            c.send(BridgeRequest::Status).await,
            Err(ClientError::VersionMismatch { .. })
        ));
    });
}

#[skuld::test]
fn send_diagnostics_returns_response() {
    rt().block_on(async {
        let path = test_socket_path("diagnostics");
        let _mock = spawn_mock_bridge(&path).await;

        let mut client = BridgeClient::connect(&path).await.unwrap();
        let resp = client.send(BridgeRequest::Diagnostics).await.unwrap();

        assert_eq!(
            resp,
            BridgeResponse::Diagnostics {
                app: "ok".to_string(),
                bridge: "ok".to_string(),
                network: "ok".to_string(),
                vpn_server: "ok".to_string(),
                internet: "ok".to_string(),
            }
        );
    });
}
