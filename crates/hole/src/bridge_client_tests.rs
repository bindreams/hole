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

/// Spawn a mock bridge that returns a 500 typed `StartError` for POST /start.
async fn spawn_error_bridge(path: &std::path::Path) -> tokio::task::JoinHandle<()> {
    use hole_common::protocol::StartError;

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
                    Json(StartError::Failed {
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
fn start_500_maps_to_typed_start_failed() {
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
            BridgeResponse::StartFailed(hole_common::protocol::StartError::Failed { message }) => {
                assert!(
                    message.contains("mock start failure"),
                    "expected error message, got: {message}"
                );
            }
            other => panic!("expected StartFailed(Failed), got {other:?}"),
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

// Typed 4xx client errors =============================================================================================

/// Stamp the bridge version header on every response (so `check_version` passes).
fn stamp_version(router: axum::Router) -> axum::Router {
    router.layer(axum::middleware::map_response(
        |mut resp: axum::response::Response| async move {
            resp.headers_mut().insert(
                "x-hole-bridge-version",
                axum::http::HeaderValue::from_static(hole::version::VERSION),
            );
            resp
        },
    ))
}

/// Mock serving `route` (POST) with a fixed status + `ErrorResponse` body.
async fn spawn_route_error_bridge(
    path: &std::path::Path,
    route: &'static str,
    status: axum::http::StatusCode,
    message: &'static str,
) -> tokio::task::JoinHandle<()> {
    use hole_common::protocol::ErrorResponse;
    let listener = hole_bridge::socket::LocalListener::bind(path).unwrap();
    let router = stamp_version(axum::Router::new().route(
        route,
        axum::routing::post(move || async move {
            (
                status,
                Json(ErrorResponse {
                    message: message.to_string(),
                }),
            )
        }),
    ));
    serve_one(listener, router)
}

/// Drive POST /v1/update-apply against a mock — the update route owns the typed
/// 4xx `ClientError` mappings (`parse_update_error`).
async fn update_against_status(
    path: &std::path::Path,
    status: axum::http::StatusCode,
    message: &'static str,
) -> Result<BridgeResponse, ClientError> {
    let _mock = spawn_route_error_bridge(path, hole_common::protocol::ROUTE_UPDATE_APPLY, status, message).await;
    let mut client = BridgeClient::connect(path).await.unwrap();
    client
        .send(BridgeRequest::ApplyUpdate {
            payload_path: "/tmp/x.msi".into(),
            target_version: "9.9.9".into(),
            consent: true,
            sha256sums: "sums".into(),
            sha256sums_minisig: "sig".into(),
            asset_name: "x.msi".into(),
            app_dest: None,
        })
        .await
}

/// Drive POST /v1/stop against a mock — a generic non-Start, non-update route
/// (`parse_generic_error`).
async fn stop_against_status(
    path: &std::path::Path,
    status: axum::http::StatusCode,
    message: &'static str,
) -> Result<BridgeResponse, ClientError> {
    let _mock = spawn_route_error_bridge(path, hole_common::protocol::ROUTE_STOP, status, message).await;
    let mut client = BridgeClient::connect(path).await.unwrap();
    client.send(BridgeRequest::Stop).await
}

#[skuld::test]
fn forbidden_maps_to_consent_required() {
    rt().block_on(async {
        let result = update_against_status(
            &test_socket_path("err403"),
            axum::http::StatusCode::FORBIDDEN,
            "consent is required",
        )
        .await;
        match result {
            Err(ClientError::ConsentRequired { message }) => {
                assert!(message.contains("consent"), "expected consent message, got: {message}");
            }
            other => panic!("expected ConsentRequired, got {other:?}"),
        }
    });
}

#[skuld::test]
fn conflict_maps_to_cutover_in_progress() {
    rt().block_on(async {
        let result = update_against_status(
            &test_socket_path("err409"),
            axum::http::StatusCode::CONFLICT,
            "a cutover is in progress",
        )
        .await;
        match result {
            Err(ClientError::CutoverInProgress { message }) => {
                assert!(message.contains("cutover"), "expected cutover message, got: {message}");
            }
            other => panic!("expected CutoverInProgress, got {other:?}"),
        }
    });
}

#[skuld::test]
fn unprocessable_maps_to_payload_verification_failed() {
    rt().block_on(async {
        let result = update_against_status(
            &test_socket_path("err422"),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "hash mismatch on payload",
        )
        .await;
        match result {
            Err(ClientError::PayloadVerificationFailed { message }) => {
                assert!(message.contains("mismatch"), "expected verify message, got: {message}");
            }
            other => panic!("expected PayloadVerificationFailed, got {other:?}"),
        }
    });
}

#[skuld::test]
fn bad_request_maps_to_invalid_update_destination() {
    rt().block_on(async {
        let result = update_against_status(
            &test_socket_path("err400"),
            axum::http::StatusCode::BAD_REQUEST,
            "the update install destination is invalid",
        )
        .await;
        match result {
            Err(ClientError::InvalidUpdateDestination { message }) => {
                assert!(
                    message.contains("destination"),
                    "expected destination message, got: {message}"
                );
            }
            other => panic!("expected InvalidUpdateDestination, got {other:?}"),
        }
    });
}

#[skuld::test]
fn update_other_4xx_maps_to_protocol() {
    rt().block_on(async {
        let result =
            update_against_status(&test_socket_path("err404"), axum::http::StatusCode::NOT_FOUND, "nope").await;
        assert!(matches!(result, Err(ClientError::Protocol(_))), "got {result:?}");
    });
}

#[skuld::test]
fn generic_route_5xx_maps_to_error() {
    rt().block_on(async {
        let result = stop_against_status(
            &test_socket_path("stop500"),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "stop boom",
        )
        .await
        .unwrap();
        match result {
            BridgeResponse::Error { message } => assert!(message.contains("stop boom"), "got {message}"),
            other => panic!("expected Error, got {other:?}"),
        }
    });
}

#[skuld::test]
fn generic_route_4xx_maps_to_protocol() {
    rt().block_on(async {
        // A non-Start, non-update route must NOT inherit the update 4xx mappings.
        let result = stop_against_status(&test_socket_path("stop409"), axum::http::StatusCode::CONFLICT, "nope").await;
        assert!(matches!(result, Err(ClientError::Protocol(_))), "got {result:?}");
    });
}

// Typed Start error path ==============================================================================================

/// Mock serving POST /start with a raw (status, body) pair.
async fn spawn_start_raw(
    path: &std::path::Path,
    status: axum::http::StatusCode,
    body: String,
) -> tokio::task::JoinHandle<()> {
    let listener = hole_bridge::socket::LocalListener::bind(path).unwrap();
    let router = stamp_version(axum::Router::new().route(
        hole_common::protocol::ROUTE_START,
        axum::routing::post(move || async move { (status, body) }),
    ));
    serve_one(listener, router)
}

async fn start_raw(
    path: &std::path::Path,
    status: axum::http::StatusCode,
    body: &str,
) -> Result<BridgeResponse, ClientError> {
    let _m = spawn_start_raw(path, status, body.to_string()).await;
    let mut c = BridgeClient::connect(path).await.unwrap();
    c.send(BridgeRequest::Start {
        config: hole_common::protocol::ProxyConfig::default(),
        attempt_id: "a".into(),
    })
    .await
}

#[skuld::test]
fn start_409_maps_to_concurrent_start() {
    rt().block_on(async {
        let r = start_raw(
            &test_socket_path("s409"),
            axum::http::StatusCode::CONFLICT,
            r#"{"message":"start already in progress"}"#,
        )
        .await;
        assert!(matches!(r, Err(ClientError::ConcurrentStart)), "got {r:?}");
    });
}

#[skuld::test]
fn start_500_typed_body_parses() {
    rt().block_on(async {
        let r = start_raw(
            &test_socket_path("s500t"),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"kind":"network_blocked"}"#,
        )
        .await
        .unwrap();
        assert_eq!(
            r,
            BridgeResponse::StartFailed(hole_common::protocol::StartError::NetworkBlocked)
        );
    });
}

#[skuld::test]
fn start_500_unparseable_body_falls_back() {
    rt().block_on(async {
        let r = start_raw(
            &test_socket_path("s500j"),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "not json",
        )
        .await
        .unwrap();
        assert_eq!(
            r,
            BridgeResponse::StartFailed(hole_common::protocol::StartError::Failed {
                message: "unknown error".into()
            })
        );
    });
}

#[skuld::test]
fn start_500_oversized_body_is_read_failure() {
    rt().block_on(async {
        let r = start_raw(
            &test_socket_path("s500big"),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            &"x".repeat(2 * 1024 * 1024),
        )
        .await
        .unwrap();
        assert_eq!(
            r,
            BridgeResponse::StartFailed(hole_common::protocol::StartError::Failed {
                message: "failed to read error response".into()
            })
        );
    });
}

#[skuld::test]
fn start_unexpected_status_is_protocol_error() {
    rt().block_on(async {
        // A framework status (e.g. a body-limit 413) is NOT a typed StartError.
        let r = start_raw(
            &test_socket_path("s413"),
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "length limit exceeded",
        )
        .await;
        assert!(matches!(r, Err(ClientError::Protocol(_))), "got {r:?}");
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
