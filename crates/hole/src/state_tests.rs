use super::*;
use crate::bridge_client::ClientError;
use hole_common::protocol::{BridgeResponse, StartError};

// ProxyStateCell ======================================================================================================

#[skuld::test]
fn cell_bumps_seq_only_on_change() {
    let cell = ProxyStateCell::new();
    assert_eq!(
        cell.snapshot(),
        ProxySnapshot {
            seq: 0,
            running: false,
            error: None,
            lockdown_enabled: false,
            lockdown_active: false
        }
    );
    cell.commit(false);
    assert_eq!(cell.snapshot().seq, 0, "no-change commit must not bump seq");
    cell.commit(true);
    assert_eq!(
        cell.snapshot(),
        ProxySnapshot {
            seq: 1,
            running: true,
            error: None,
            lockdown_enabled: false,
            lockdown_active: false
        }
    );
    cell.commit(false);
    assert_eq!(
        cell.snapshot(),
        ProxySnapshot {
            seq: 2,
            running: false,
            error: None,
            lockdown_enabled: false,
            lockdown_active: false
        }
    );
}

#[skuld::test]
async fn cell_wakes_watchers_only_on_change() {
    let cell = ProxyStateCell::new();
    let mut rx = cell.subscribe();
    cell.commit(false); // no change
    assert!(!rx.has_changed().unwrap());
    cell.commit(true);
    assert!(rx.has_changed().unwrap());
    assert_eq!(
        rx.borrow_and_update().clone(),
        ProxySnapshot {
            seq: 1,
            running: true,
            error: None,
            lockdown_enabled: false,
            lockdown_active: false,
        }
    );
}

#[skuld::test]
fn commit_status_carries_lockdown_fields() {
    let cell = ProxyStateCell::new();
    // Initial snapshot defaults the lockdown fields to false.
    let s0 = cell.snapshot();
    assert!(!s0.lockdown_enabled && !s0.lockdown_active);
    // A Status commit threads both lockdown bools alongside `running`.
    cell.commit_status(true, None, true, false);
    let s1 = cell.snapshot();
    assert!(s1.running && s1.lockdown_enabled && !s1.lockdown_active);
    assert_eq!(s1.seq, 1, "seq bumped on change");
}

#[skuld::test]
fn commit_preserves_lockdown_fields() {
    // Every Start/Stop/reconciler exchange goes through `commit` (not
    // `commit_status`); its `..*snap` must NOT clobber the lockdown warning state
    // a prior Status established (`enabled && !active` is the tray warning state).
    let cell = ProxyStateCell::new();
    cell.commit_status(true, None, true, false); // running + lockdown enabled, not active
    let before = cell.snapshot();
    assert!(before.lockdown_enabled && !before.lockdown_active);

    cell.commit(false); // a Stop/transport observation knows only `running`
    let after = cell.snapshot();
    assert!(!after.running, "running flipped to false");
    assert!(
        after.lockdown_enabled && !after.lockdown_active,
        "commit must preserve the lockdown fields, got {after:?}"
    );
    assert_eq!(after.seq, before.seq + 1, "running change bumps seq");
}

// error field (#470) ==================================================================================================

#[skuld::test]
fn commit_status_carries_error_on_death() {
    let cell = ProxyStateCell::new();
    cell.commit(true); // connected
    cell.commit_status(false, Some("proxy task exited unexpectedly".into()), false, false);
    let snap = cell.snapshot();
    assert!(!snap.running);
    assert_eq!(snap.error.as_deref(), Some("proxy task exited unexpectedly"));
    assert_eq!(snap.seq, 2, "running change bumps seq");
}

#[skuld::test]
fn commit_clears_error_on_non_status_running_change() {
    // A non-Status running edge (Start/Stop/Cancel) is user-initiated and
    // carries no death reason — `commit` must clear any prior error.
    let cell = ProxyStateCell::new();
    cell.commit_status(true, Some("synthetic".into()), false, false); // running -> true with an error
    assert_eq!(cell.snapshot().error.as_deref(), Some("synthetic"));
    cell.commit(false); // clean stop via the non-Status path
    assert_eq!(cell.snapshot().error, None, "non-Status commit must clear error");
}

#[skuld::test]
fn reconnect_clears_death_error() {
    let cell = ProxyStateCell::new();
    cell.commit(true);
    cell.commit_status(false, Some("proxy task exited unexpectedly".into()), false, false);
    cell.commit(true); // reconnect via a Start Ack
    assert_eq!(cell.snapshot().error, None);
}

#[skuld::test]
fn proxy_snapshot_serializes_error() {
    // The proxy-state-changed event emits the snapshot; the webview reads
    // `event.payload.error`. Some -> string, None -> null (no skip).
    let some = serde_json::to_value(ProxySnapshot {
        seq: 1,
        running: false,
        error: Some("boom".into()),
        lockdown_enabled: false,
        lockdown_active: false,
    })
    .unwrap();
    assert_eq!(some["error"], "boom");
    let none = serde_json::to_value(ProxySnapshot {
        seq: 0,
        running: false,
        error: None,
        lockdown_enabled: false,
        lockdown_active: false,
    })
    .unwrap();
    assert!(
        none["error"].is_null(),
        "None error serializes as null for the TS payload"
    );
}

#[skuld::test]
fn observed_error_only_from_status_ok() {
    let status = Ok(BridgeResponse::Status {
        running: false,
        uptime_secs: 0,
        error: Some("proxy task exited unexpectedly".into()),
        invalid_filters: vec![],
        udp_proxy_available: true,
        ipv6_bypass_available: true,
        lockdown_enabled: false,
        lockdown_active: false,
    });
    assert_eq!(
        observed_error(&status).as_deref(),
        Some("proxy task exited unexpectedly")
    );
    assert_eq!(observed_error(&Ok(BridgeResponse::Ack)), None);
    assert_eq!(observed_error(&Err(ClientError::PermissionDenied)), None);
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
        lockdown_enabled: false,
        lockdown_active: false,
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
        (
            Start,
            Ok(BridgeResponse::StartFailed(StartError::Cancelled)),
            Some(false),
        ),
        (
            Start,
            Ok(BridgeResponse::StartFailed(StartError::AlreadyRunning)),
            Some(true),
        ),
        (
            Start,
            Ok(BridgeResponse::StartFailed(StartError::NetworkBlocked)),
            Some(false),
        ),
        (
            Start,
            Ok(BridgeResponse::StartFailed(StartError::Failed {
                message: "plugin failed".into(),
            })),
            Some(false),
        ),
        (Start, Err(ClientError::ConcurrentStart), None),
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
        assert_eq!(
            observed_running(*kind, result, false),
            *expected,
            "{kind:?} / {result:?}"
        );
    }
}

#[skuld::test]
fn observed_running_update_in_progress_holds_snapshot() {
    let transport_err: Result<BridgeResponse, ClientError> = Err(ClientError::Protocol("boom".into()));

    // Marker SET: a transport error commits None (hold last snapshot), not Some(false).
    for kind in [ReqKind::Status, ReqKind::Start, ReqKind::Stop] {
        assert_eq!(
            observed_running(kind, &transport_err, true),
            None,
            "{kind:?} marker-set"
        );
    }
    // Marker CLEAR: the existing pessimistic flip stands.
    for kind in [ReqKind::Status, ReqKind::Start, ReqKind::Stop] {
        assert_eq!(
            observed_running(kind, &transport_err, false),
            Some(false),
            "{kind:?} no-marker"
        );
    }
    // VersionMismatch precedence unchanged (None regardless of the marker).
    let vm: Result<BridgeResponse, ClientError> = Err(ClientError::VersionMismatch {
        bridge: Some("9.9.9".into()),
    });
    assert_eq!(observed_running(ReqKind::Status, &vm, false), None);
    assert_eq!(observed_running(ReqKind::Status, &vm, true), None);
    // A successful Status still reports truth (marker irrelevant on Ok).
    let ok: Result<BridgeResponse, ClientError> = Ok(status_resp(true));
    assert_eq!(observed_running(ReqKind::Status, &ok, true), Some(true));
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
        lockdown_enabled: false,
        lockdown_active: false,
    }
}

/// A no-op self-heal hook for `BridgeLink` tests that don't exercise a
/// version mismatch.
fn noop_hook() -> SelfHealHook {
    std::sync::Arc::new(|_| {})
}

/// Build a `BridgeLink` whose update-marker dir is a unique, never-created temp
/// path. `BridgeLink::new` would otherwise read the real system service log dir,
/// where a stray cutover marker would make `update_in_progress()` hold the
/// snapshot and break these transport-error assertions. A non-existent dir reads
/// as "no marker" (the `read` ENOENT path), keeping every test hermetic.
fn test_link(socket_path: PathBuf, self_heal: SelfHealHook) -> BridgeLink {
    let marker_dir = std::env::temp_dir().join(format!(
        "hole-link-marker-{}-{}",
        std::process::id(),
        socket_path.file_name().and_then(|s| s.to_str()).unwrap_or("x")
    ));
    BridgeLink::with_service_log_dir(socket_path, marker_dir, self_heal)
}

/// Serve `router` on `path`, accepting connections in a loop (BridgeLink
/// reconnects after transport errors, and `send_oneshot` always dials
/// fresh). Each connection is served on its own task so a parked handler
/// cannot block later accepts.
async fn serve_router(path: &std::path::Path, router: axum::Router) -> tokio::task::JoinHandle<()> {
    let listener = hole_bridge::socket::LocalListener::bind(path).unwrap();
    // Stamp the matching version unless the test already set one (mismatch
    // tests do) — otherwise the client's per-response check rejects every reply.
    let router = router.layer(axum::middleware::map_response(
        |mut resp: axum::response::Response| async move {
            if !resp.headers().contains_key("x-hole-bridge-version") {
                resp.headers_mut().insert(
                    "x-hole-bridge-version",
                    axum::http::HeaderValue::from_static(hole::version::VERSION),
                );
            }
            resp
        },
    ));
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

    let link = test_link(path, noop_hook());
    assert!(!link.cell().snapshot().running);
    let resp = link
        .send(BridgeRequest::Start {
            attempt_id: "x".into(),
            config: test_proxy_config(),
        })
        .await
        .unwrap();
    assert!(matches!(resp, BridgeResponse::Ack));
    assert_eq!(
        link.cell().snapshot(),
        ProxySnapshot {
            seq: 1,
            running: true,
            error: None,
            lockdown_enabled: false,
            lockdown_active: false
        }
    );
}

#[skuld::test]
async fn version_mismatch_fires_hook_and_does_not_flip_running() {
    let path = test_socket_path("ver-mismatch-link");
    // Mock stamps a mismatching version (overrides serve_router's default).
    let router = axum::Router::new()
        .route(ROUTE_STATUS, get(|| async { Json(status_response(true)) }))
        .layer(axum::middleware::map_response(
            |mut resp: axum::response::Response| async move {
                resp.headers_mut().insert(
                    "x-hole-bridge-version",
                    axum::http::HeaderValue::from_static("0.0.0-mismatch"),
                );
                resp
            },
        ));
    let _mock = serve_router(&path, router).await;

    let fired = Arc::new(AtomicUsize::new(0));
    let fired2 = fired.clone();
    let link = test_link(
        path,
        Arc::new(move |_| {
            fired2.fetch_add(1, Ordering::SeqCst);
        }),
    );

    let before = link.cell().snapshot();
    let result = link.send(BridgeRequest::Status).await;
    assert!(matches!(result, Err(ClientError::VersionMismatch { .. })));
    assert_eq!(fired.load(Ordering::SeqCst), 1, "self-heal hook fires once");
    assert_eq!(link.cell().snapshot(), before, "running must not flip during self-heal");
}

#[skuld::test]
async fn transport_error_commits_false() {
    let path = test_socket_path("dead");
    let _ = std::fs::remove_file(&path);
    let link = test_link(path, noop_hook());
    link.cell().commit(true); // pretend we believed it was running
    let _ = link.send(BridgeRequest::Status).await.unwrap_err();
    assert_eq!(
        link.cell().snapshot(),
        ProxySnapshot {
            seq: 2,
            running: false,
            error: None,
            lockdown_enabled: false,
            lockdown_active: false
        }
    );
}

#[skuld::test]
async fn transport_error_holds_snapshot_while_marker_present() {
    // End-to-end wiring: a cutover marker in the link's service log dir must make
    // a transport error hold the last snapshot (no surprise Disconnected),
    // unlike `transport_error_commits_false` above.
    let path = test_socket_path("dead-marker");
    let _ = std::fs::remove_file(&path);
    let marker_dir = tempfile::tempdir().unwrap();
    hole_common::update_marker::write(
        marker_dir.path(),
        &hole_common::update_marker::MarkerInfo {
            version: hole_common::update_marker::MARKER_VERSION,
            from_version: "0.2.0".into(),
            to_version: "0.3.0".into(),
            pid: std::process::id(),
            started_at_unix: 0,
        },
        None,
    )
    .unwrap();
    let link = BridgeLink::with_service_log_dir(path, marker_dir.path().to_path_buf(), noop_hook());
    link.cell().commit(true); // believed running before the cutover gap
    let _ = link.send(BridgeRequest::Status).await.unwrap_err();
    assert_eq!(
        link.cell().snapshot(),
        ProxySnapshot {
            seq: 1,
            running: true,
            error: None,
            lockdown_enabled: false,
            lockdown_active: false
        },
        "marker present => transport error holds the last snapshot"
    );
}

#[skuld::test]
async fn cutover_marker_suppresses_then_resumes_disconnected_flash() {
    // End-to-end: while the cutover marker is present, a failing Status (the
    // expected restart gap) must NOT flip the cell to Disconnected — no seq bump.
    // Once the new bridge clears the marker, the same failing Status commits
    // Disconnected. Proves the marker read flows through `observed_running`,
    // opening and closing the no-flash window with the marker.
    let path = test_socket_path("cutover-flash");
    let _ = std::fs::remove_file(&path); // dead socket: every send is a transport error
    let marker_dir = tempfile::tempdir().unwrap();
    let link = BridgeLink::with_service_log_dir(path, marker_dir.path().to_path_buf(), noop_hook());
    link.cell().commit(true); // believed Connected before the cutover
    let seq_connected = link.cell().snapshot().seq;

    // Marker SET: the failing Status must hold the Connected snapshot.
    hole_common::update_marker::write(
        marker_dir.path(),
        &hole_common::update_marker::MarkerInfo {
            version: hole_common::update_marker::MARKER_VERSION,
            from_version: "0.2.0".into(),
            to_version: "0.3.0".into(),
            pid: std::process::id(),
            started_at_unix: 0,
        },
        None,
    )
    .unwrap();
    let _ = link.send(BridgeRequest::Status).await.unwrap_err();
    assert_eq!(
        link.cell().snapshot().seq,
        seq_connected,
        "no Disconnected flash while the marker is set"
    );
    assert!(
        link.cell().snapshot().running,
        "snapshot still Connected during the gap"
    );

    // Marker CLEAR: the same failing Status now commits Disconnected.
    hole_common::update_marker::clear(marker_dir.path()).unwrap();
    let _ = link.send(BridgeRequest::Status).await.unwrap_err();
    assert!(
        !link.cell().snapshot().running,
        "Disconnected commits once the marker is gone"
    );
}

#[skuld::test]
async fn oneshot_never_commits() {
    let path = test_socket_path("oneshot");
    let router = axum::Router::new().route(
        hole_common::protocol::ROUTE_CANCEL,
        post(|| async { Json(EmptyResponse {}) }),
    );
    let _mock = serve_router(&path, router).await;

    let link = test_link(path, noop_hook());
    link.cell().commit(true);
    link.send_oneshot(BridgeRequest::Cancel { attempt_id: "x".into() })
        .await
        .unwrap();
    assert_eq!(
        link.cell().snapshot(),
        ProxySnapshot {
            seq: 1,
            running: true,
            error: None,
            lockdown_enabled: false,
            lockdown_active: false
        }
    );
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

    let link = test_link(path, noop_hook());
    link.send(BridgeRequest::Metrics).await.unwrap();
    assert_eq!(
        link.cell().snapshot(),
        ProxySnapshot {
            seq: 0,
            running: false,
            error: None,
            lockdown_enabled: false,
            lockdown_active: false
        }
    );
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

    let link = Arc::new(test_link(path, noop_hook()));
    let a = tokio::spawn({
        let link = link.clone();
        async move {
            link.send(BridgeRequest::Start {
                attempt_id: "x".into(),
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
    assert_eq!(
        link.cell().snapshot(),
        ProxySnapshot {
            seq: 1,
            running: true,
            error: None,
            lockdown_enabled: false,
            lockdown_active: false
        }
    );
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

    let link = test_link(path, noop_hook());
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

    let link = test_link(path, noop_hook());
    let reloaded = link.reload_if_running(test_proxy_config()).await.unwrap();
    assert!(reloaded);
    assert_eq!(reloads.load(Ordering::SeqCst), 1);
    // The Status leg committed the observation.
    assert_eq!(
        link.cell().snapshot(),
        ProxySnapshot {
            seq: 1,
            running: true,
            error: None,
            lockdown_enabled: false,
            lockdown_active: false
        }
    );
}

// resolve_bridge_socket ===============================================================================================

#[skuld::test]
fn resolve_bridge_socket_override_is_external() {
    let custom = std::path::PathBuf::from("/tmp/hole-dev.sock");
    let (path, external) = resolve_bridge_socket(Some(custom.clone()));
    assert_eq!(path, custom);
    assert!(external, "an explicit HOLE_BRIDGE_SOCKET ⇒ externally supervised");
}

#[skuld::test]
fn resolve_bridge_socket_default_is_not_external() {
    let (path, external) = resolve_bridge_socket(None);
    assert_eq!(path, hole_common::protocol::default_bridge_socket_path());
    assert!(!external, "the platform default ⇒ GUI owns the bridge lifecycle");
}

#[skuld::test]
fn resolve_bridge_socket_empty_override_is_not_external() {
    // An empty HOLE_BRIDGE_SOCKET= is malformed; treat it as unset (production
    // default, GUI owns the bridge) rather than an external "" socket — otherwise
    // an empty env var would wrongly skip the install gate.
    let (path, external) = resolve_bridge_socket(Some(std::path::PathBuf::from("")));
    assert_eq!(path, hole_common::protocol::default_bridge_socket_path());
    assert!(!external, "an empty override ⇒ not externally supervised");
}
