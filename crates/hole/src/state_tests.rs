use super::*;
use crate::bridge_client::ClientError;
use hole_common::protocol::{BridgeResponse, CANCELLED_MESSAGE};

// ProxyStateCell ======================================================================================================

#[skuld::test]
fn cell_bumps_seq_only_on_change() {
    let cell = ProxyStateCell::new();
    assert_eq!(cell.snapshot(), ProxySnapshot { seq: 0, running: false });
    cell.commit(false);
    assert_eq!(cell.snapshot().seq, 0, "no-change commit must not bump seq");
    cell.commit(true);
    assert_eq!(cell.snapshot(), ProxySnapshot { seq: 1, running: true });
    cell.commit(false);
    assert_eq!(cell.snapshot(), ProxySnapshot { seq: 2, running: false });
}

#[skuld::test]
async fn cell_wakes_watchers_only_on_change() {
    let cell = ProxyStateCell::new();
    let mut rx = cell.subscribe();
    cell.commit(false); // no change
    assert!(!rx.has_changed().unwrap());
    cell.commit(true);
    assert!(rx.has_changed().unwrap());
    assert_eq!(*rx.borrow_and_update(), ProxySnapshot { seq: 1, running: true });
}

// observed_running ====================================================================================================

fn status_resp(running: bool) -> BridgeResponse {
    BridgeResponse::Status {
        running,
        uptime_secs: 0,
        error: None,
        invalid_filters: vec![],
        udp_proxy_available: true,
        ipv6_bypass_available: true,
    }
}

fn err_resp(msg: &str) -> BridgeResponse {
    BridgeResponse::Error { message: msg.into() }
}

fn transport_err() -> ClientError {
    ClientError::Connection(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused"))
}

#[skuld::test]
fn observed_running_rules() {
    use ReqKind::*;
    // (kind, result, expected) — owned Results, only ever borrowed:
    // BridgeResponse/ClientError are not Clone.
    let table: Vec<(ReqKind, Result<BridgeResponse, ClientError>, Option<bool>)> = vec![
        (Status, Ok(status_resp(true)), Some(true)),
        (Status, Ok(status_resp(false)), Some(false)),
        (Start, Ok(BridgeResponse::Ack), Some(true)),
        (Start, Ok(err_resp(CANCELLED_MESSAGE)), Some(false)),
        (Start, Ok(err_resp("proxy already running")), Some(true)),
        (Start, Ok(err_resp("plugin failed")), Some(false)),
        (Stop, Ok(BridgeResponse::Ack), Some(false)),
        (Stop, Ok(err_resp("teardown failed")), None),
        (Start, Err(ClientError::PermissionDenied), None),
        (Stop, Err(ClientError::PermissionDenied), None),
        (Status, Err(transport_err()), Some(false)),
        (Start, Err(transport_err()), Some(false)),
        (Stop, Err(transport_err()), Some(false)),
        (Other, Ok(BridgeResponse::Ack), None),
        (Other, Err(transport_err()), None),
    ];
    for (kind, result, expected) in &table {
        assert_eq!(observed_running(*kind, result), *expected, "{kind:?} / {result:?}");
    }
}

#[skuld::test]
fn start_error_classification() {
    assert_eq!(classify_start_error(CANCELLED_MESSAGE), StartErrorKind::Cancelled);
    assert_eq!(
        classify_start_error("proxy already running"),
        StartErrorKind::AlreadyRunning
    );
    assert_eq!(classify_start_error("plugin failed"), StartErrorKind::Other);
}

// BridgeLink ==========================================================================================================

use axum::routing::{get, post};
use axum::Json;
use hole_common::protocol::{EmptyResponse, StatusResponse, ROUTE_RELOAD, ROUTE_START, ROUTE_STATUS};
use hyper::body::Incoming;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn test_socket_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hole-link-test-{}-{suffix}.sock", std::process::id()))
}

fn test_proxy_config() -> hole_common::protocol::ProxyConfig {
    hole_common::protocol::ProxyConfig {
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
    }
}

fn status_response(running: bool) -> StatusResponse {
    StatusResponse {
        running,
        uptime_secs: 0,
        error: None,
        invalid_filters: Vec::new(),
        udp_proxy_available: true,
        ipv6_bypass_available: true,
    }
}

/// Serve `router` on `path`, accepting connections in a loop (BridgeLink
/// reconnects after transport errors, and `send_oneshot` always dials
/// fresh). Each connection is served on its own task so a parked handler
/// cannot block later accepts.
async fn serve_router(path: &std::path::Path, router: axum::Router) -> tokio::task::JoinHandle<()> {
    let listener = hole_bridge::socket::LocalListener::bind(path).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok(stream) = listener.accept().await else { return };
            let io = hyper_util::rt::TokioIo::new(stream);
            let router = router.clone();
            let service = hyper::service::service_fn(move |req: http::Request<Incoming>| {
                let router = router.clone();
                async move {
                    use tower::ServiceExt;
                    let resp = router.oneshot(req.map(axum::body::Body::new)).await.unwrap();
                    Ok::<_, std::convert::Infallible>(resp)
                }
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    })
}

#[skuld::test]
async fn start_ack_commits_true() {
    let path = test_socket_path("start-ack");
    let router = axum::Router::new().route(ROUTE_START, post(|| async { Json(EmptyResponse {}) }));
    let _mock = serve_router(&path, router).await;

    let link = BridgeLink::new(path);
    assert!(!link.cell().snapshot().running);
    let resp = link
        .send(BridgeRequest::Start {
            config: test_proxy_config(),
        })
        .await
        .unwrap();
    assert!(matches!(resp, BridgeResponse::Ack));
    assert_eq!(link.cell().snapshot(), ProxySnapshot { seq: 1, running: true });
}

#[skuld::test]
async fn transport_error_commits_false() {
    let path = test_socket_path("dead");
    let _ = std::fs::remove_file(&path);
    let link = BridgeLink::new(path);
    link.cell().commit(true); // pretend we believed it was running
    let _ = link.send(BridgeRequest::Status).await.unwrap_err();
    assert_eq!(link.cell().snapshot(), ProxySnapshot { seq: 2, running: false });
}

#[skuld::test]
async fn oneshot_never_commits() {
    let path = test_socket_path("oneshot");
    let router = axum::Router::new().route(
        hole_common::protocol::ROUTE_CANCEL,
        post(|| async { Json(EmptyResponse {}) }),
    );
    let _mock = serve_router(&path, router).await;

    let link = BridgeLink::new(path);
    link.cell().commit(true);
    link.send_oneshot(BridgeRequest::Cancel).await.unwrap();
    assert_eq!(link.cell().snapshot(), ProxySnapshot { seq: 1, running: true });
}

#[skuld::test]
async fn untracked_requests_never_commit() {
    let path = test_socket_path("untracked");
    let router = axum::Router::new().route(
        hole_common::protocol::ROUTE_METRICS,
        get(|| async {
            Json(hole_common::protocol::MetricsResponse {
                bytes_in: 0,
                bytes_out: 0,
                speed_in_bps: 0,
                speed_out_bps: 0,
                uptime_secs: 0,
                filter: None,
            })
        }),
    );
    let _mock = serve_router(&path, router).await;

    let link = BridgeLink::new(path);
    link.send(BridgeRequest::Metrics).await.unwrap();
    assert_eq!(link.cell().snapshot(), ProxySnapshot { seq: 0, running: false });
}

/// The ordering guarantee under test is the CLIENT-LOCK serialization:
/// there is exactly one pooled connection; task B waits on the
/// tokio::sync::Mutex around the client, not on a second connection.
#[skuld::test]
async fn concurrent_requests_commit_in_bridge_order() {
    let path = test_socket_path("order");
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (entered2, release2) = (entered.clone(), release.clone());
    let router = axum::Router::new()
        .route(
            ROUTE_START,
            post(move || {
                let (entered, release) = (entered2.clone(), release2.clone());
                async move {
                    entered.notify_one();
                    release.notified().await;
                    Json(EmptyResponse {})
                }
            }),
        )
        .route(ROUTE_STATUS, get(|| async { Json(status_response(true)) }));
    let _mock = serve_router(&path, router).await;

    let link = Arc::new(BridgeLink::new(path));
    let a = tokio::spawn({
        let link = link.clone();
        async move {
            link.send(BridgeRequest::Start {
                config: test_proxy_config(),
            })
            .await
        }
    });
    // Rendezvous: A's Start has reached the mock, so A holds the client
    // lock before B is spawned.
    entered.notified().await;
    let b = tokio::spawn({
        let link = link.clone();
        async move { link.send(BridgeRequest::Status).await }
    });
    release.notify_one();

    let a = a.await.unwrap().unwrap();
    let b = b.await.unwrap().unwrap();
    assert!(matches!(a, BridgeResponse::Ack));
    assert!(matches!(b, BridgeResponse::Status { running: true, .. }));
    // Start committed true (seq 1); the queued Status confirmed true (no bump).
    assert_eq!(link.cell().snapshot(), ProxySnapshot { seq: 1, running: true });
}

#[skuld::test]
async fn reload_if_running_skips_when_stopped() {
    let path = test_socket_path("reload-stopped");
    let reloads = Arc::new(AtomicUsize::new(0));
    let reloads2 = reloads.clone();
    let router = axum::Router::new()
        .route(ROUTE_STATUS, get(|| async { Json(status_response(false)) }))
        .route(
            ROUTE_RELOAD,
            post(move || {
                let reloads = reloads2.clone();
                async move {
                    reloads.fetch_add(1, Ordering::SeqCst);
                    Json(EmptyResponse {})
                }
            }),
        );
    let _mock = serve_router(&path, router).await;

    let link = BridgeLink::new(path);
    let reloaded = link.reload_if_running(test_proxy_config()).await.unwrap();
    assert!(!reloaded);
    // The resurrection guard: bridge-side `reload` on a stopped proxy
    // STARTS it, so the Reload must never have been sent.
    assert_eq!(reloads.load(Ordering::SeqCst), 0);
}

#[skuld::test]
async fn reload_if_running_reloads_when_running() {
    let path = test_socket_path("reload-running");
    let reloads = Arc::new(AtomicUsize::new(0));
    let reloads2 = reloads.clone();
    let router = axum::Router::new()
        .route(ROUTE_STATUS, get(|| async { Json(status_response(true)) }))
        .route(
            ROUTE_RELOAD,
            post(move || {
                let reloads = reloads2.clone();
                async move {
                    reloads.fetch_add(1, Ordering::SeqCst);
                    Json(EmptyResponse {})
                }
            }),
        );
    let _mock = serve_router(&path, router).await;

    let link = BridgeLink::new(path);
    let reloaded = link.reload_if_running(test_proxy_config()).await.unwrap();
    assert!(reloaded);
    assert_eq!(reloads.load(Ordering::SeqCst), 1);
    // The Status leg committed the observation.
    assert_eq!(link.cell().snapshot(), ProxySnapshot { seq: 1, running: true });
}
