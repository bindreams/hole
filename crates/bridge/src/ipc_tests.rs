use super::*;
use crate::proxy::{Proxy, ProxyError, RunningProxy, TrafficTotals};
use crate::proxy_manager::ProxyManager;
use crate::socket::LocalStream;
use bytes::Bytes;
use hole_common::config::ServerEntry;
use hole_common::protocol::{DiagnosticsResponse, MetricsResponse, ProxyConfig};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tun_engine::gateway::GatewayInfo;
use tun_engine::routing::{state as route_state, Routing};
use tun_engine::RoutingError;

// MockProxy ===========================================================================================================

/// Cumulative traffic counters shared between `MockProxy` and the
/// `MockRunning` handles it issues. Tests clone the `Arc` out before
/// handing the mock to `ProxyManager::new` and `fetch_add` to simulate
/// tunnel traffic. Zeroed on every successful `start`, mirroring the
/// fresh `FlowStat` a new shadowsocks `Server` creates.
#[derive(Default)]
struct MockTraffic {
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

struct MockProxy {
    fail_start: AtomicBool,
    traffic: Arc<MockTraffic>,
    /// If Some, `start` awaits this gate before returning. Used to
    /// simulate a slow start so tests can race `POST /v1/cancel` against
    /// an in-flight `POST /v1/start`.
    start_gate: Option<Arc<tokio::sync::Notify>>,
    /// If Some, `start` fires this sender on entry — before awaiting
    /// `start_gate`. Lets tests park until the proxy is *known* to be
    /// inside `start()` instead of sleeping a guess-duration. One-shot
    /// per MockProxy (subsequent entries do nothing); the test pattern
    /// is "spawn task A; await entered; act on the parked state."
    /// See bindreams/hole#383.
    start_entered: std::sync::Mutex<Option<oneshot::Sender<()>>>,
}

impl MockProxy {
    fn new() -> Self {
        Self {
            fail_start: AtomicBool::new(false),
            traffic: Arc::new(MockTraffic::default()),
            start_gate: None,
            start_entered: std::sync::Mutex::new(None),
        }
    }

    fn failing() -> Self {
        Self {
            fail_start: AtomicBool::new(true),
            ..Self::new()
        }
    }

    fn gated(gate: Arc<tokio::sync::Notify>) -> Self {
        Self {
            start_gate: Some(gate),
            ..Self::new()
        }
    }

    fn with_entered_signal(mut self, tx: oneshot::Sender<()>) -> Self {
        self.start_entered = std::sync::Mutex::new(Some(tx));
        self
    }
}

impl Proxy for MockProxy {
    type Running = MockRunning;

    async fn start(&self, _config: shadowsocks_service::config::Config) -> Result<MockRunning, ProxyError> {
        // Fire the entered signal BEFORE awaiting the gate so the test
        // can sequence subsequent operations on the parked state.
        if let Some(tx) = self.start_entered.lock().unwrap().take() {
            let _ = tx.send(());
        }
        if let Some(gate) = self.start_gate.as_ref() {
            gate.notified().await;
        }
        if self.fail_start.load(Ordering::SeqCst) {
            return Err(ProxyError::Runtime(io::Error::other("mock failure")));
        }
        // Fresh session ⇒ fresh counters (production: a new Server
        // creates a new FlowStat).
        self.traffic.bytes_in.store(0, Ordering::SeqCst);
        self.traffic.bytes_out.store(0, Ordering::SeqCst);
        let handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            Ok(())
        });
        Ok(MockRunning {
            handle: Some(handle),
            traffic: Arc::clone(&self.traffic),
        })
    }
}

struct MockRunning {
    handle: Option<JoinHandle<io::Result<()>>>,
    traffic: Arc<MockTraffic>,
}

impl RunningProxy for MockRunning {
    fn is_alive(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }
    async fn stop(mut self) -> Result<(), ProxyError> {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
        Ok(())
    }
    fn traffic_totals(&self) -> TrafficTotals {
        TrafficTotals {
            bytes_in: self.traffic.bytes_in.load(Ordering::SeqCst),
            bytes_out: self.traffic.bytes_out.load(Ordering::SeqCst),
        }
    }
}

impl Drop for MockRunning {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

// MockRouting =========================================================================================================

struct MockRouting {
    state_dir: PathBuf,
    fail_gateway: AtomicBool,
}

impl MockRouting {
    fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            fail_gateway: AtomicBool::new(false),
        }
    }

    fn failing_gateway(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            fail_gateway: AtomicBool::new(true),
        }
    }
}

impl Routing for MockRouting {
    type Installed = MockRoutes;

    fn install(
        &self,
        tun_name: &str,
        server_ip: IpAddr,
        _gateway: IpAddr,
        interface_name: &str,
    ) -> Result<MockRoutes, RoutingError> {
        // Match SystemRouting ordering: write the state file BEFORE
        // any mutation, so tests that assert on `bridge-routes.json`
        // see the same write-then-clear lifecycle as production.
        let persisted = route_state::RouteState {
            version: route_state::SCHEMA_VERSION,
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
        };
        route_state::save(&self.state_dir, &persisted, None)
            .map_err(|e| RoutingError::RouteSetup(format!("mock persist failed: {e}")))?;
        Ok(MockRoutes {
            state_dir: self.state_dir.clone(),
        })
    }

    fn default_gateway(&self) -> Result<GatewayInfo, RoutingError> {
        if self.fail_gateway.load(Ordering::SeqCst) {
            return Err(RoutingError::Gateway("mock gateway failure".into()));
        }
        Ok(GatewayInfo {
            gateway_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            interface_name: "MockEthernet".into(),
            interface_index: 1,
            ipv6_available: false,
        })
    }

    type Cover = MockCover;

    fn install_failclosed_cover(
        &self,
        _server_ip: IpAddr,
        _resolver_ips: &[IpAddr],
    ) -> Result<MockCover, RoutingError> {
        Ok(MockCover)
    }

    fn install_lockdown(
        &self,
        _server_ip: IpAddr,
        _tun_name: &str,
        _app_ids: &[PathBuf],
    ) -> Result<MockCover, RoutingError> {
        Ok(MockCover)
    }
}

struct MockCover;

impl Drop for MockCover {
    fn drop(&mut self) {}
}

impl tun_engine::routing::CoverGuard for MockCover {
    fn disarm(self) {}
}

struct MockRoutes {
    state_dir: PathBuf,
}

impl Drop for MockRoutes {
    fn drop(&mut self) {
        let _ = route_state::clear(&self.state_dir);
    }
}

// Helpers =============================================================================================================

use crate::test_support::rt;

/// Build a mock proxy manager backed by a throw-away state dir. Uses
/// `tempfile::tempdir().keep()` so the directory is created but its
/// auto-cleanup Drop is suppressed — the directory lives until the
/// process exits, which is fine for unit tests.
fn mock_proxy() -> Arc<Mutex<ProxyManager<MockProxy, MockRouting>>> {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let routing = MockRouting::new(state_dir);
    Arc::new(Mutex::new(ProxyManager::new(MockProxy::new(), routing)))
}

/// `mock_proxy` variant whose manager has a persisted state_dir, so
/// `set_lockdown_intent` can write `bridge-lockdown.json`. The TempDir is
/// `.keep()`-ed (created, auto-cleanup suppressed) like the other helpers.
fn mock_proxy_with_state_dir() -> Arc<Mutex<ProxyManager<MockProxy, MockRouting>>> {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let routing = MockRouting::new(state_dir.clone());
    let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(state_dir);
    Arc::new(Mutex::new(pm))
}

/// `mock_proxy` variant that also hands back the mock's traffic counters
/// so tests can simulate tunnel bytes.
fn mock_proxy_with_traffic() -> (Arc<Mutex<ProxyManager<MockProxy, MockRouting>>>, Arc<MockTraffic>) {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let routing = MockRouting::new(state_dir);
    let mock = MockProxy::new();
    let traffic = Arc::clone(&mock.traffic);
    (Arc::new(Mutex::new(ProxyManager::new(mock, routing))), traffic)
}

fn failing_proxy() -> Arc<Mutex<ProxyManager<MockProxy, MockRouting>>> {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let routing = MockRouting::new(state_dir);
    Arc::new(Mutex::new(ProxyManager::new(MockProxy::failing(), routing)))
}

fn gateway_failing_proxy() -> Arc<Mutex<ProxyManager<MockProxy, MockRouting>>> {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let routing = MockRouting::failing_gateway(state_dir);
    Arc::new(Mutex::new(ProxyManager::new(MockProxy::new(), routing)))
}

fn gated_proxy(
    gate: Arc<tokio::sync::Notify>,
    entered: oneshot::Sender<()>,
) -> Arc<Mutex<ProxyManager<MockProxy, MockRouting>>> {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let routing = MockRouting::new(state_dir);
    let mock = MockProxy::gated(gate).with_entered_signal(entered);
    Arc::new(Mutex::new(ProxyManager::new(mock, routing)))
}

fn sample_config() -> ProxyConfig {
    ProxyConfig {
        server: ServerEntry {
            id: "test-id".to_string(),
            name: "Test".to_string(),
            server: "127.0.0.1".to_string(),
            server_port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "pw".to_string(),
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

fn test_socket_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hole-ipc-test-{}-{suffix}.sock", std::process::id()))
}

/// Test HTTP client that enforces the tower::Service `ready()` contract.
struct TestClient {
    sender: http1::SendRequest<Full<Bytes>>,
    _conn: tokio::task::JoinHandle<()>,
}

impl TestClient {
    /// Connect to a test IPC server and perform HTTP/1.1 handshake.
    async fn connect(path: &Path) -> Self {
        let stream = LocalStream::connect(path).await.unwrap();
        let io = TokioIo::new(stream);
        let (sender, conn) = http1::handshake(io).await.unwrap();
        let _conn = tokio::spawn(async move {
            let _ = conn.await;
        });
        Self { sender, _conn }
    }

    async fn send(&mut self, req: http::Request<Full<Bytes>>) -> http::Response<hyper::body::Incoming> {
        self.sender.ready().await.unwrap();
        #[allow(clippy::disallowed_methods)] // ready() called above
        self.sender.send_request(req).await.unwrap()
    }
}

async fn get_status(client: &mut TestClient) -> StatusResponse {
    let req = http::Request::builder()
        .method("GET")
        .uri(ROUTE_STATUS)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.send(req).await;
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

/// Consume the response body and return the status code (required before next request on keep-alive).
async fn consume(resp: http::Response<hyper::body::Incoming>) -> u16 {
    let status = resp.status().as_u16();
    let _ = resp.into_body().collect().await;
    status
}

/// `X-Hole-Attempt-Id`: the per-attempt idempotency key the GUI mints and sends
/// on both Start and Cancel; the bridge scopes start-cancellation to it (#465).
const ATTEMPT_ID_HEADER: &str = "x-hole-attempt-id";

async fn post_start(
    client: &mut TestClient,
    config: &ProxyConfig,
    attempt_id: &str,
) -> http::Response<hyper::body::Incoming> {
    let body_bytes = serde_json::to_vec(config).unwrap();
    let req = http::Request::builder()
        .method("POST")
        .uri(ROUTE_START)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header(ATTEMPT_ID_HEADER, attempt_id)
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap();
    client.send(req).await
}

async fn post_stop(client: &mut TestClient) -> http::Response<hyper::body::Incoming> {
    let req = http::Request::builder()
        .method("POST")
        .uri(ROUTE_STOP)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    client.send(req).await
}

async fn post_cancel(client: &mut TestClient, attempt_id: &str) -> http::Response<hyper::body::Incoming> {
    let req = http::Request::builder()
        .method("POST")
        .uri(ROUTE_CANCEL)
        .header("host", "localhost")
        .header(ATTEMPT_ID_HEADER, attempt_id)
        .body(Full::new(Bytes::new()))
        .unwrap();
    client.send(req).await
}

async fn post_lockdown(client: &mut TestClient, enabled: bool) -> http::Response<hyper::body::Incoming> {
    let body = serde_json::to_vec(&hole_common::protocol::LockdownRequest { enabled }).unwrap();
    let req = http::Request::builder()
        .method("POST")
        .uri(ROUTE_LOCKDOWN)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    client.send(req).await
}

async fn post_reload(client: &mut TestClient, config: &ProxyConfig) -> http::Response<hyper::body::Incoming> {
    let body_bytes = serde_json::to_vec(config).unwrap();
    let req = http::Request::builder()
        .method("POST")
        .uri(ROUTE_RELOAD)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap();
    client.send(req).await
}

async fn post_update_apply(
    client: &mut TestClient,
    payload_path: &str,
    consent: bool,
) -> http::Response<hyper::body::Incoming> {
    // Manifest/sig/asset_name are placeholders: the consent (403) and
    // single-occupancy (409) gates fire BEFORE re-verification, so these tests
    // never reach the verify step. The 422 path has its own dedicated test.
    post_update_apply_full(client, payload_path, consent, "x  hole.msi\n", "sig", "hole.msi", None).await
}

async fn post_update_apply_full(
    client: &mut TestClient,
    payload_path: &str,
    consent: bool,
    sha256sums: &str,
    sha256sums_minisig: &str,
    asset_name: &str,
    app_dest: Option<&str>,
) -> http::Response<hyper::body::Incoming> {
    let body = serde_json::to_vec(&hole_common::protocol::UpdateApplyRequest {
        payload_path: payload_path.into(),
        target_version: "0.3.0".into(),
        consent,
        sha256sums: sha256sums.into(),
        sha256sums_minisig: sha256sums_minisig.into(),
        asset_name: asset_name.into(),
        app_dest: app_dest.map(|s| s.to_string()),
    })
    .unwrap();
    let req = http::Request::builder()
        .method("POST")
        .uri(hole_common::protocol::ROUTE_UPDATE_APPLY)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    client.send(req).await
}

// Tests ===============================================================================================================

#[skuld::test]
fn server_accepts_connection() {
    rt().block_on(async {
        let path = test_socket_path("accept");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });
        let stream = LocalStream::connect(&path).await.unwrap();
        drop(stream);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn every_response_carries_bridge_version_header() {
    rt().block_on(async {
        let path = test_socket_path("ver-header");
        let server = IpcServer::bind(&path, mock_proxy(), "9.9.9").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });
        let mut client = TestClient::connect(&path).await;
        let req = http::Request::builder()
            .method("GET")
            .uri(ROUTE_STATUS)
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.send(req).await;
        assert_eq!(resp.headers().get("x-hole-bridge-version").unwrap(), "9.9.9");
        let _ = resp.into_body().collect().await;
        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn error_response_carries_bridge_version_header() {
    rt().block_on(async {
        let path = test_socket_path("ver-err-header");
        let server = IpcServer::bind(&path, failing_proxy(), "9.9.9").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });
        let mut client = TestClient::connect(&path).await;
        let resp = post_start(&mut client, &sample_config(), "t").await;
        assert_eq!(resp.status(), 500);
        assert_eq!(resp.headers().get("x-hole-bridge-version").unwrap(), "9.9.9");
        let _ = resp.into_body().collect().await;
        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn version_route_returns_injected_version() {
    rt().block_on(async {
        let path = test_socket_path("ver-route");
        let server = IpcServer::bind(&path, mock_proxy(), "9.9.9").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });
        let mut client = TestClient::connect(&path).await;
        let req = http::Request::builder()
            .method("GET")
            .uri(ROUTE_VERSION)
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.send(req).await;
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: hole_common::protocol::VersionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(v.version, "9.9.9");
        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn status_when_not_running_returns_false() {
    rt().block_on(async {
        let path = test_socket_path("status");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let status = get_status(&mut client).await;

        assert_eq!(
            status,
            StatusResponse {
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
        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn multiple_requests_on_same_connection() {
    rt().block_on(async {
        let path = test_socket_path("multi");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let s1 = get_status(&mut client).await;
        assert!(!s1.running);

        let s2 = get_status(&mut client).await;
        assert!(!s2.running);

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn lockdown_post_sets_intent_and_status_reflects_it() {
    rt().block_on(async {
        let path = test_socket_path("lockdown-post");
        let server = IpcServer::bind(&path, mock_proxy_with_state_dir(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // POST /v1/lockdown { enabled: true }
        let resp = post_lockdown(&mut client, true).await;
        assert_eq!(resp.status(), 200, "lockdown POST should 200");
        assert_eq!(
            resp.headers().get("x-hole-bridge-version").unwrap(),
            "test",
            "version header stamped on the lockdown response"
        );
        let _ = resp.into_body().collect().await;

        // GET /v1/status reflects the intent (same connection).
        let status = get_status(&mut client).await;
        assert!(status.lockdown_enabled, "status must reflect the set intent");
        assert!(!status.lockdown_active, "no cover engaged while stopped");

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn lockdown_post_errors_without_state_dir() {
    // A kill-switch request the bridge cannot persist must fail loudly, not
    // silently 200: a silent Ok would make the GUI believe lockdown is armed
    // when nothing was written. `mock_proxy()` has no `.with_state_dir(..)`.
    rt().block_on(async {
        let path = test_socket_path("lockdown-no-statedir");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let resp = post_lockdown(&mut client, true).await;
        assert_eq!(
            resp.status(),
            500,
            "lockdown POST without a state_dir must error, not silently succeed"
        );
        let _ = resp.into_body().collect().await;

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn update_apply_lockdown_off_without_consent_is_refused() {
    // The consent seam: a lockdown-off update without consent must be refused
    // BEFORE any extract/spawn, with 403 (a client precondition failure, not a
    // server error). `mock_proxy()` defaults lockdown off.
    rt().block_on(async {
        let path = test_socket_path("update-apply-no-consent");
        let log_dir = tempfile::tempdir().unwrap().keep();
        let server =
            IpcServer::bind_with_dirs(&path, mock_proxy(), "test", log_dir.clone(), log_dir.clone(), None).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let resp = post_update_apply(&mut client, "/tmp/x.msi", false).await;
        assert_eq!(
            resp.status(),
            403,
            "lockdown-off update without consent must be refused with 403"
        );
        let _ = resp.into_body().collect().await;
        // No marker was written (the refusal preceded the marker write).
        assert!(hole_common::update_marker::read(&log_dir).is_none());

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn update_apply_with_existing_marker_is_409() {
    // Single-occupancy: a present marker means a cutover is already in flight.
    rt().block_on(async {
        let path = test_socket_path("update-apply-409");
        let log_dir = tempfile::tempdir().unwrap().keep();
        hole_common::update_marker::write(
            &log_dir,
            &hole_common::update_marker::MarkerInfo {
                version: hole_common::update_marker::MARKER_VERSION,
                from_version: "0.2.0".into(),
                to_version: "0.3.0".into(),
                pid: 1,
                started_at_unix: 0,
            },
            None,
        )
        .unwrap();
        let server =
            IpcServer::bind_with_dirs(&path, mock_proxy(), "test", log_dir.clone(), log_dir.clone(), None).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        // Consent true so the 409 occupancy check (which runs first) is what fires.
        let resp = post_update_apply(&mut client, "/tmp/x.msi", true).await;
        assert_eq!(resp.status(), 409, "a second cutover must be rejected");
        let _ = resp.into_body().collect().await;

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

/// Build a genuine `com.hole.app` bundle under `parent` so the macOS app_dest
/// pre-flight passes and a test can reach the payload re-verify step. On Windows
/// there is no app_dest gate, so callers pass `None` instead.
#[cfg(target_os = "macos")]
fn make_valid_app_dest(parent: &std::path::Path) -> std::path::PathBuf {
    let app = parent.join("Hole.app");
    let contents = app.join("Contents");
    std::fs::create_dir_all(contents.join("MacOS")).unwrap();
    std::fs::write(
        contents.join("Info.plist"),
        "<?xml version=\"1.0\"?>\n<plist><dict>\n<key>CFBundleIdentifier</key>\n<string>com.hole.app</string>\n</dict></plist>\n",
    )
    .unwrap();
    app
}

#[skuld::test]
fn update_apply_unverifiable_payload_is_422_and_clears_the_marker() {
    // The bridge re-verifies the payload offline before anything irreversible.
    // A present payload whose manifest is not signed by the production key (the
    // GUI is untrusted) is refused with 422. The marker is claimed before staging
    // (single-occupancy), then cleared on the verify failure — so no cutover is
    // left in progress and no actor is spawned.
    rt().block_on(async {
        let path = test_socket_path("update-apply-422");
        let log_dir = tempfile::tempdir().unwrap().keep();
        let payload_dir = tempfile::tempdir().unwrap();
        let payload = payload_dir.path().join("hole.msi");
        std::fs::write(&payload, b"hello world").unwrap();

        // macOS gates the destination before the payload; supply a genuine bundle
        // so the re-verify step is what fails here. Windows has no app_dest gate.
        #[cfg(target_os = "macos")]
        let app_dest_dir = tempfile::tempdir().unwrap();
        #[cfg(target_os = "macos")]
        let app_dest = make_valid_app_dest(app_dest_dir.path());
        #[cfg(target_os = "macos")]
        let app_dest = Some(app_dest.to_string_lossy().into_owned());
        #[cfg(not(target_os = "macos"))]
        let app_dest: Option<String> = None;

        let server =
            IpcServer::bind_with_dirs(&path, mock_proxy(), "test", log_dir.clone(), log_dir.clone(), None).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        // Consent true so the 403/409 gates pass and re-verification is reached;
        // the manifest is well-formed but not production-signed.
        let resp = post_update_apply_full(
            &mut client,
            &payload.to_string_lossy(),
            true,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  hole.msi\n",
            "untrusted comment: forged\nnot-a-real-signature\n",
            "hole.msi",
            app_dest.as_deref(),
        )
        .await;
        assert_eq!(resp.status(), 422, "an unverifiable payload must be refused with 422");
        let _ = resp.into_body().collect().await;
        // The marker is claimed then cleared on the verify failure — no cutover
        // is left in progress.
        assert!(
            hole_common::update_marker::read(&log_dir).is_none(),
            "a verify failure must clear the marker it claimed"
        );

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

/// A post-marker failure must clear the marker (else the GUI masks Disconnected
/// and a later shutdown wrongly disarms the cover). A non-existent payload passes
/// consent/409/app_dest, the marker is claimed, then `stage_payload` fails to copy
/// the source (I/O) → 500 and the marker is cleared. macOS-gated: there the
/// private staging dir is the per-test `state_dir`, so concurrent tests don't
/// collide; on Windows it is the shared install dir (production serializes that via
/// the single global marker, which per-test markers can't reproduce). The extract/
/// spawn clears are unreachable in-test (they need a production-signed payload) but
/// use this same proven clear-on-failure pattern.
#[cfg(target_os = "macos")]
#[skuld::test]
fn update_apply_staging_io_failure_clears_the_marker() {
    rt().block_on(async {
        let path = test_socket_path("update-apply-stage-io");
        let log_dir = tempfile::tempdir().unwrap().keep();
        let payload_dir = tempfile::tempdir().unwrap();
        let missing = payload_dir.path().join("does-not-exist.dmg");

        let app_dest_dir = tempfile::tempdir().unwrap();
        let app_dest = Some(make_valid_app_dest(app_dest_dir.path()).to_string_lossy().into_owned());

        let server =
            IpcServer::bind_with_dirs(&path, mock_proxy(), "test", log_dir.clone(), log_dir.clone(), None).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let resp = post_update_apply_full(
            &mut client,
            &missing.to_string_lossy(),
            true,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  hole.dmg\n",
            "untrusted comment: forged\nnot-a-real-signature\n",
            "hole.dmg",
            app_dest.as_deref(),
        )
        .await;
        assert_eq!(resp.status(), 500, "a staging I/O failure is a server fault");
        let _ = resp.into_body().collect().await;
        assert!(
            hole_common::update_marker::read(&log_dir).is_none(),
            "a post-marker staging failure must clear the marker it claimed"
        );

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

/// macOS: a `.app` swap target whose bundle identity is not `com.hole.app` (a
/// spoofed `Evil.app`) is refused 400 BEFORE the marker — the bridge anchors the
/// swap to a root-trusted identity, never the GUI-supplied path. A destination
/// precondition is distinct from a payload-verify failure (which is 422). Runs on
/// the macOS unprivileged lane (the rejection precedes any privileged step).
#[cfg(target_os = "macos")]
#[skuld::test]
fn update_apply_spoofed_app_dest_is_400_no_marker() {
    rt().block_on(async {
        let path = test_socket_path("update-apply-app-dest-422");
        let log_dir = tempfile::tempdir().unwrap().keep();
        let payload_dir = tempfile::tempdir().unwrap();
        let payload = payload_dir.path().join("hole.dmg");
        std::fs::write(&payload, b"hello world").unwrap();

        // A bundle with a foreign CFBundleIdentifier — the security case.
        let evil_dir = tempfile::tempdir().unwrap();
        let evil = evil_dir.path().join("Evil.app");
        std::fs::create_dir_all(evil.join("Contents").join("MacOS")).unwrap();
        std::fs::write(
            evil.join("Contents").join("Info.plist"),
            "<?xml version=\"1.0\"?>\n<plist><dict>\n<key>CFBundleIdentifier</key>\n<string>com.evil.app</string>\n</dict></plist>\n",
        )
        .unwrap();

        let server = IpcServer::bind_with_dirs(&path, mock_proxy(), "test", log_dir.clone(), log_dir.clone(), None).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        // Consent true so the destination gate (not consent/409) is what fires;
        // the payload/manifest never matter because app_dest is checked first.
        let resp = post_update_apply_full(
            &mut client,
            &payload.to_string_lossy(),
            true,
            "deadbeef  hole.dmg\n",
            "sig",
            "hole.dmg",
            Some(&evil.to_string_lossy()),
        )
        .await;
        assert_eq!(resp.status(), 400, "a spoofed bundle identity must be refused with 400");
        let _ = resp.into_body().collect().await;
        assert!(
            hole_common::update_marker::read(&log_dir).is_none(),
            "a destination rejection must not write a marker"
        );

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn invalid_request_returns_error_response() {
    rt().block_on(async {
        let path = test_socket_path("invalid");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Send garbage body to start endpoint
        let req = http::Request::builder()
            .method("POST")
            .uri(ROUTE_START)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from("not valid json!!")))
            .unwrap();
        let resp = client.send(req).await;
        assert!(resp.status().is_client_error());

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn server_handles_client_disconnect() {
    rt().block_on(async {
        let path = test_socket_path("disconnect");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let stream = LocalStream::connect(&path).await.unwrap();
        drop(stream);

        handle.await.unwrap();
    });
}

#[skuld::test]
fn start_request_starts_proxy() {
    rt().block_on(async {
        let path = test_socket_path("start");
        let pm = mock_proxy();
        let server = IpcServer::bind(&path, pm, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Start
        assert_eq!(consume(post_start(&mut client, &sample_config(), "t").await).await, 200);

        // Status should show running
        let status = get_status(&mut client).await;
        assert!(status.running, "expected running=true after Start");

        // Stop (cleanup)
        assert_eq!(consume(post_stop(&mut client).await).await, 200);

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn stop_request_stops_proxy() {
    rt().block_on(async {
        let path = test_socket_path("stop");
        let pm = mock_proxy();
        let server = IpcServer::bind(&path, pm, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Start
        consume(post_start(&mut client, &sample_config(), "t").await).await;

        // Stop
        assert_eq!(consume(post_stop(&mut client).await).await, 200);

        // Status should show stopped
        let status = get_status(&mut client).await;
        assert!(!status.running, "expected running=false after Stop");

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn start_failure_returns_error() {
    rt().block_on(async {
        let path = test_socket_path("start-fail");
        let pm = failing_proxy();
        let server = IpcServer::bind(&path, pm, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let resp = post_start(&mut client, &sample_config(), "t").await;

        match start_error_body(resp).await {
            StartError::Failed { message } => assert!(
                message.contains("mock failure"),
                "expected mock failure message, got: {message}"
            ),
            other => panic!("expected StartError::Failed, got {other:?}"),
        }

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn reload_request_reloads_proxy() {
    rt().block_on(async {
        let path = test_socket_path("reload");
        let pm = mock_proxy();
        let server = IpcServer::bind(&path, pm, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Start first
        consume(post_start(&mut client, &sample_config(), "t").await).await;

        // Reload
        assert_eq!(consume(post_reload(&mut client, &sample_config()).await).await, 200);

        // Should still be running after reload
        let status = get_status(&mut client).await;
        assert!(status.running, "expected running=true after Reload");

        // Cleanup
        consume(post_stop(&mut client).await).await;

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn run_cancellation_aborts_connection_handlers() {
    rt().block_on(async {
        let path = test_socket_path("run-cancel");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        // Connect a client so there's an active connection handler task
        let mut client = TestClient::connect(&path).await;
        let status = get_status(&mut client).await;
        assert!(!status.running);

        // Cancel the server (simulates shutdown via select!)
        handle.abort();
        let _ = handle.await;

        // The connection handler should have been aborted by JoinSet::drop.
        // A subsequent request must fail — the hyper client observes the
        // FIN/RST on the closed connection and errors. If a regression
        // makes send_request hang on a dead connection, the test
        // framework's overall timeout surfaces the hang.
        //
        // ready() is intentionally omitted: the server is already dead, so we're
        // testing that send_request on a broken connection fails.
        #[allow(clippy::disallowed_methods)]
        let result = client
            .sender
            .send_request(
                http::Request::builder()
                    .method("GET")
                    .uri(ROUTE_STATUS)
                    .header("host", "localhost")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await;
        assert!(result.is_err(), "request should fail after server cancellation");
    });
}

#[skuld::test]
fn unknown_route_returns_404() {
    rt().block_on(async {
        let path = test_socket_path("404");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let req = http::Request::builder()
            .method("GET")
            .uri("/v1/nonexistent")
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.send(req).await;
        assert_eq!(resp.status(), 404);

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn wrong_method_returns_405() {
    rt().block_on(async {
        let path = test_socket_path("405");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let req = http::Request::builder()
            .method("POST")
            .uri(ROUTE_STATUS)
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.send(req).await;
        assert_eq!(resp.status(), 405);

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

// New endpoint helpers ================================================================================================

async fn get_metrics(client: &mut TestClient) -> MetricsResponse {
    let req = http::Request::builder()
        .method("GET")
        .uri(ROUTE_METRICS)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.send(req).await;
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

async fn get_diagnostics(client: &mut TestClient) -> DiagnosticsResponse {
    let req = http::Request::builder()
        .method("GET")
        .uri(ROUTE_DIAGNOSTICS)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.send(req).await;
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

// New endpoint tests ==================================================================================================

#[skuld::test]
fn metrics_returns_zeros_when_stopped() {
    rt().block_on(async {
        let path = test_socket_path("metrics-stopped");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let metrics = get_metrics(&mut client).await;

        assert_eq!(metrics.bytes_in, 0);
        assert_eq!(metrics.bytes_out, 0);
        assert_eq!(metrics.speed_in_bps, 0);
        assert_eq!(metrics.speed_out_bps, 0);
        assert_eq!(metrics.uptime_secs, 0);

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn metrics_returns_uptime_when_running() {
    rt().block_on(async {
        let path = test_socket_path("metrics-running");
        let pm = mock_proxy();
        let server = IpcServer::bind(&path, pm, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Start proxy
        assert_eq!(consume(post_start(&mut client, &sample_config(), "t").await).await, 200);

        let metrics = get_metrics(&mut client).await;
        // Running but idle: no traffic injected into the mock, so totals are 0.
        assert_eq!(metrics.bytes_in, 0);
        assert_eq!(metrics.bytes_out, 0);
        // uptime_secs should be >= 0 (may be 0 if < 1s elapsed, which is fine)
        // The important thing is no error occurs.

        // Cleanup
        consume(post_stop(&mut client).await).await;

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn metrics_reports_traffic_totals_when_running() {
    rt().block_on(async {
        let path = test_socket_path("metrics-traffic");
        let (pm, traffic) = mock_proxy_with_traffic();
        let server = IpcServer::bind(&path, pm, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        assert_eq!(consume(post_start(&mut client, &sample_config(), "t").await).await, 200);

        traffic.bytes_in.fetch_add(1_048_576, Ordering::SeqCst);
        traffic.bytes_out.fetch_add(65_536, Ordering::SeqCst);

        let metrics = get_metrics(&mut client).await;
        assert_eq!(metrics.bytes_in, 1_048_576);
        assert_eq!(metrics.bytes_out, 65_536);

        consume(post_stop(&mut client).await).await;
        let metrics = get_metrics(&mut client).await;
        assert_eq!(metrics.bytes_in, 0, "stopped bridge reports zero totals");
        assert_eq!(metrics.bytes_out, 0);
        assert_eq!(metrics.speed_in_bps, 0, "stopped bridge reports zero speeds");
        assert_eq!(metrics.speed_out_bps, 0);

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn metrics_reports_speed_over_window() {
    rt().block_on(async {
        let path = test_socket_path("metrics-speed");
        let (pm, traffic) = mock_proxy_with_traffic();
        let pm_for_shift = Arc::clone(&pm);
        let server = IpcServer::bind(&path, pm, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        assert_eq!(consume(post_start(&mut client, &sample_config(), "t").await).await, 200);

        // First poll establishes the rate window.
        let first = get_metrics(&mut client).await;
        assert_eq!(first.speed_in_bps, 0, "no window exists before the first poll");

        // Plumbing-only assertion: bytes arriving between two polls must
        // surface as a nonzero speed. The exact rate math is unit-tested
        // under a paused clock in proxy_manager_tests.rs. The 1ms rewind
        // makes the second poll's `elapsed > 0` structural — without it,
        // both polls landing on the same clock tick would hit the
        // `elapsed.is_zero()` branch and return the previous (zero) speed.
        traffic.bytes_in.fetch_add(1_000_000_000, Ordering::SeqCst);
        pm_for_shift
            .lock()
            .await
            .shift_traffic_window_for_test(std::time::Duration::from_millis(1));

        let metrics = get_metrics(&mut client).await;
        assert!(metrics.speed_in_bps > 0, "speed_in_bps must reflect the byte delta");

        consume(post_stop(&mut client).await).await;
        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn diagnostics_bridge_running() {
    rt().block_on(async {
        let path = test_socket_path("diag-running");
        let pm = mock_proxy();
        let server = IpcServer::bind(&path, pm, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Start proxy
        assert_eq!(consume(post_start(&mut client, &sample_config(), "t").await).await, 200);

        let diag = get_diagnostics(&mut client).await;
        assert_eq!(diag.app, "ok");
        assert_eq!(diag.bridge, "ok");
        assert_eq!(diag.network, "ok"); // MockRouting.default_gateway() succeeds
                                        // vpn_server and internet are always "unknown" on the wire — the
                                        // GUI computes them from the selected ServerEntry's persisted
                                        // validation state.
        assert_eq!(diag.vpn_server, "unknown");
        assert_eq!(diag.internet, "unknown");

        // Cleanup
        consume(post_stop(&mut client).await).await;

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn diagnostics_network_error_when_gateway_unavailable() {
    rt().block_on(async {
        let path = test_socket_path("diag-net-err");
        let server = IpcServer::bind(&path, gateway_failing_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let diag = get_diagnostics(&mut client).await;

        // Bridge IPC is up; the host has no detectable default gateway.
        assert_eq!(diag.app, "ok");
        assert_eq!(diag.bridge, "ok");
        assert_eq!(diag.network, "error");
        // vpn_server and internet are always "unknown" on the wire — the
        // GUI computes them from the selected ServerEntry's persisted
        // validation state.
        assert_eq!(diag.vpn_server, "unknown");
        assert_eq!(diag.internet, "unknown");

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn diagnostics_proxy_stopped() {
    rt().block_on(async {
        let path = test_socket_path("diag-stopped");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let diag = get_diagnostics(&mut client).await;

        // Bridge IPC is up (we are handling this request); the proxy is stopped
        // but no operation has failed, so `pm.last_error()` is None and the
        // diagnostics handler reports `bridge = "ok"`. App is always "ok" by
        // convention (bridge can't observe the GUI directly). Network is
        // computed from the host's default gateway and the MockRouting returns
        // Ok. vpn_server and internet are always "unknown" on the wire — the
        // GUI computes them from the selected ServerEntry's persisted
        // validation state.
        assert_eq!(diag.app, "ok");
        assert_eq!(diag.bridge, "ok");
        assert_eq!(diag.network, "ok");
        assert_eq!(diag.vpn_server, "unknown");
        assert_eq!(diag.internet, "unknown");

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn diagnostics_bridge_error_after_failed_start() {
    rt().block_on(async {
        let path = test_socket_path("diag-bridge-err");
        let server = IpcServer::bind(&path, gateway_failing_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Trigger a failed start so ProxyManager.last_error is populated.
        // The gateway-failing mock makes default_gateway return Err, which
        // ProxyManager::start now records via inspect_err.
        let resp = post_start(&mut client, &sample_config(), "t").await;
        assert_eq!(resp.status(), 500);
        let _ = resp.into_body().collect().await;

        let diag = get_diagnostics(&mut client).await;
        // Bridge IPC is up but the most recent operation failed — this is
        // exactly the situation the old hardcoded "ok" was masking.
        assert_eq!(diag.app, "ok");
        assert_eq!(diag.bridge, "error");

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

/// PII guarantee (#470): a failed start populates `last_error` (which can carry
/// a path/hostname), but `StatusResponse.error` surfaces only the path-free
/// death reason — None here, since a failed start is not an out-of-band death.
/// So the rich error never reaches the GUI toast even though diagnostics see it.
#[skuld::test]
fn status_error_excludes_failed_start_detail() {
    rt().block_on(async {
        let path = test_socket_path("status-no-pii");
        let server = IpcServer::bind(&path, gateway_failing_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let resp = post_start(&mut client, &sample_config(), "t").await;
        assert_eq!(resp.status(), 500);
        let _ = resp.into_body().collect().await;

        let status = get_status(&mut client).await;
        assert_eq!(
            status.error, None,
            "failed-start detail must not reach StatusResponse.error"
        );
        // Diagnostics still see the failure via last_error (covered by
        // diagnostics_bridge_error_after_failed_start).

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

// No dedicated log-capture test for the `error!("proxy start failed")`
// path (and the analogous `handle_stop`/`handle_reload` calls); the
// HTTP-500 + error message is covered by `start_failure_returns_error`
// (line ~363). A thread-local `set_default` capture could be added now
// that the global subscriber level-rejects noisy third-party events.

// Cancel tests ========================================================================================================

/// Parse the typed `StartError` from a Start-route 500 body.
async fn start_error_body(resp: http::Response<hyper::body::Incoming>) -> StartError {
    assert_eq!(resp.status(), 500, "expected 500 for a failed start");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[skuld::test]
fn cancel_while_start_in_flight_returns_cancelled() {
    // Two concurrent connections. A posts Start against a gated mock so
    // start hangs inside MockProxy::start. B posts Cancel. A's Start response must come back
    // with 500 + "cancelled" promptly (not after the full gate duration,
    // which never elapses in this test).
    rt().block_on(async {
        let path = test_socket_path("cancel-in-flight");
        let gate = Arc::new(tokio::sync::Notify::new());
        let (entered_tx, entered_rx) = oneshot::channel();
        let server = IpcServer::bind(&path, gated_proxy(gate.clone(), entered_tx), "test").unwrap();
        // Bound the accept loop to exactly the two connections this test
        // uses, instead of running indefinitely. See `run_n` docstring.
        let handle = tokio::spawn(async move { server.run_n(2).await });

        // Connection A: owns its client end. Spawn a task that drives the
        // start request so this test task can issue a cancel concurrently.
        let path_a = path.clone();
        let start_future = tokio::spawn(async move {
            let mut client_a = TestClient::connect(&path_a).await;
            let resp = post_start(&mut client_a, &sample_config(), "t").await;
            (client_a, resp)
        });

        // Park until A is *known* to be inside MockProxy::start (before
        // it awaits the gate). Deterministic — no sleep.
        entered_rx.await.expect("MockProxy::start never entered");

        // Connection B: cancel the in-flight start. Must succeed without
        // waiting for the in-flight Start (which never completes since the
        // gate is not released).
        let mut client_b = TestClient::connect(&path).await;
        let cancel_resp = post_cancel(&mut client_b, "t").await;
        assert_eq!(
            cancel_resp.status(),
            200,
            "cancel must succeed even while start is in flight"
        );

        // Wait for A's Start to return. With cancellation working correctly
        // the select! branch fires, drop-safety unwinds the partial state,
        // and Cancelled is returned promptly. If cancellation regresses,
        // start_future hangs forever and the test framework's overall
        // timeout surfaces the failure.
        let (_client_a, resp_a) = start_future.await.expect("start task panicked");
        assert_eq!(start_error_body(resp_a).await, StartError::Cancelled);

        // Release the gate so the mock's start() future can settle if it
        // is still parked anywhere; harmless no-op if already dropped.
        gate.notify_one();
        // run_n(2) returns once both connections are handled; abort is a
        // belt-and-suspenders cleanup.
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn cancel_before_start_is_pre_armed_and_consumed() {
    // A cancel arriving before any start is in flight pre-arms a flag
    // that the next start consumes. The next Start returns 500 +
    // "cancelled" immediately without even attempting to acquire the
    // proxy mutex or call Proxy::start.
    rt().block_on(async {
        let path = test_socket_path("cancel-prearm");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        // Single client connection — use run_once to avoid long-lived
        // accept polling on Windows.
        let handle = tokio::spawn(async move { server.run_once().await });

        let mut client = TestClient::connect(&path).await;

        // Pre-arm: cancel attempt A with no start in flight — still 200 Ack.
        let resp = post_cancel(&mut client, "A").await;
        assert_eq!(consume(resp).await, 200);

        // Start carrying the SAME attempt id A — rejected as cancelled,
        // consuming the named pre-arm.
        let start_resp = post_start(&mut client, &sample_config(), "A").await;
        assert_eq!(start_error_body(start_resp).await, StartError::Cancelled);

        // A second start (a different attempt B) with no pre-arm succeeds.
        assert_eq!(consume(post_start(&mut client, &sample_config(), "B").await).await, 200);

        // Cleanup
        consume(post_stop(&mut client).await).await;

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn cancel_with_no_start_is_ack_idempotent() {
    // Double-cancel with no start in flight — both 200. The pre-arm flag
    // is idempotent: arming it twice is equivalent to arming it once.
    rt().block_on(async {
        let path = test_socket_path("cancel-noop");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move { server.run_once().await });

        let mut client = TestClient::connect(&path).await;

        assert_eq!(consume(post_cancel(&mut client, "t").await).await, 200);
        assert_eq!(consume(post_cancel(&mut client, "t").await).await, 200);

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn concurrent_start_is_rejected_with_conflict() {
    // Client A holds a start parked inside MockProxy::start on the gate. Client B
    // sends a second Start concurrently. B must be rejected with 409
    // Conflict rather than silently overwriting A's token slot — the
    // slot is single-occupancy because a Cancel targets exactly one
    // in-flight start.
    rt().block_on(async {
        let path = test_socket_path("concurrent-start");
        let gate = Arc::new(tokio::sync::Notify::new());
        let (entered_tx, entered_rx) = oneshot::channel();
        let server = IpcServer::bind(&path, gated_proxy(gate.clone(), entered_tx), "test").unwrap();
        // 3 connections: A start, B start, C cancel.
        let handle = tokio::spawn(async move { server.run_n(3).await });

        // Client A parks inside MockProxy::start.
        let path_a = path.clone();
        let a_future = tokio::spawn(async move {
            let mut client_a = TestClient::connect(&path_a).await;
            let resp = post_start(&mut client_a, &sample_config(), "t").await;
            (client_a, resp)
        });

        // Park until A is inside MockProxy::start (token registered).
        entered_rx.await.expect("MockProxy::start never entered");

        // Client B sends a concurrent Start and must be rejected.
        let mut client_b = TestClient::connect(&path).await;
        let b_resp = post_start(&mut client_b, &sample_config(), "t").await;
        assert_eq!(
            b_resp.status(),
            409,
            "concurrent start must be rejected with 409 Conflict"
        );
        let b_body = b_resp.into_body().collect().await.unwrap().to_bytes();
        let b_err: ErrorResponse = serde_json::from_slice(&b_body).unwrap();
        assert!(
            b_err.message.contains("already in progress"),
            "unexpected message: {}",
            b_err.message
        );

        // B's rejection must not have perturbed A's token slot — a
        // subsequent cancel must still reach A. Send it.
        let mut client_c = TestClient::connect(&path).await;
        assert_eq!(consume(post_cancel(&mut client_c, "t").await).await, 200);

        // A's start must return Cancelled. If cancellation regresses,
        // a_future hangs and the test framework's timeout surfaces it.
        let (_client_a, a_resp) = a_future.await.expect("A task panicked");
        assert_eq!(start_error_body(a_resp).await, StartError::Cancelled);

        gate.notify_one();
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn stale_prearm_does_not_cancel_unrelated_start() {
    // #465 regression (the reported P0). Attempt A starts and succeeds; a late
    // Cancel(A) loses the race and pre-arms (no in-flight start); the frontend's
    // compensating follow-up Stop fires. The NEXT, unrelated Connect (attempt B)
    // must SUCCEED — the stale pre-arm for A can never match B's id.
    //
    // This inverts the old `sequential_start_cancel_start_consumes_pre_arm_once`,
    // which codified the bug (Start→Stop→Cancel→Start returned CANCELLED).
    rt().block_on(async {
        let path = test_socket_path("stale-prearm-unrelated");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move { server.run_once().await });

        let mut client = TestClient::connect(&path).await;

        // Attempt A: start succeeds.
        assert_eq!(consume(post_start(&mut client, &sample_config(), "A").await).await, 200);
        // User clicks Cancel late — Start(A) already succeeded, so this Cancel
        // arrives with no in-flight start and pre-arms for A.
        assert_eq!(consume(post_cancel(&mut client, "A").await).await, 200);
        // Frontend's compensating follow-up Stop.
        assert_eq!(consume(post_stop(&mut client).await).await, 200);

        // Attempt B: a brand-new connect. Must NOT consume the stale A arm.
        assert_eq!(
            consume(post_start(&mut client, &sample_config(), "B").await).await,
            200,
            "second, unrelated Connect must succeed — the stale pre-arm for A must not kill it"
        );

        consume(post_stop(&mut client).await).await;
        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn named_prearm_still_cancels_its_own_attempt() {
    // The legitimate pre-arm race must still work: a Cancel that beats its own
    // Start's registration (SAME id) still cancels THAT start. Guards against a
    // fix that over-corrects and breaks the race the pre-arm was built for.
    rt().block_on(async {
        let path = test_socket_path("named-prearm-same");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move { server.run_once().await });
        let mut client = TestClient::connect(&path).await;

        assert_eq!(consume(post_cancel(&mut client, "A").await).await, 200); // pre-arm A
        let start = post_start(&mut client, &sample_config(), "A").await; // same id
        assert_eq!(start_error_body(start).await, StartError::Cancelled);
        // A fresh attempt afterward succeeds (the arm was a one-shot for A).
        assert_eq!(consume(post_start(&mut client, &sample_config(), "B").await).await, 200);

        consume(post_stop(&mut client).await).await;
        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn prearm_without_arriving_start_does_not_block_future_starts() {
    // Cancel(A) arms with no in-flight start; A's start NEVER arrives and no
    // Stop fires (the case clear-on-stop alone cannot fix). The next unrelated
    // Start(B) must still SUCCEED and self-heal the stale A arm, so a subsequent
    // Start(C) also succeeds.
    rt().block_on(async {
        let path = test_socket_path("prearm-never-arrives");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move { server.run_once().await });
        let mut client = TestClient::connect(&path).await;

        assert_eq!(consume(post_cancel(&mut client, "A").await).await, 200); // arm A, no start
        assert_eq!(consume(post_start(&mut client, &sample_config(), "B").await).await, 200);
        consume(post_stop(&mut client).await).await;
        // Self-heal proven: C is unaffected by the long-dead A arm.
        assert_eq!(consume(post_start(&mut client, &sample_config(), "C").await).await, 200);

        consume(post_stop(&mut client).await).await;
        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn cross_id_cancel_does_not_cancel_unrelated_in_flight_start() {
    // Start(B) parks in-flight on the gate. Cancel(A) (A != B) arrives: it must
    // 200 and pre-arm A WITHOUT signalling B's token. Releasing the gate lets B
    // complete normally (200), proving an unrelated cancel never aborts it.
    rt().block_on(async {
        let path = test_socket_path("cross-id-cancel");
        let gate = Arc::new(tokio::sync::Notify::new());
        let (entered_tx, entered_rx) = oneshot::channel();
        let server = IpcServer::bind(&path, gated_proxy(gate.clone(), entered_tx), "test").unwrap();
        let handle = tokio::spawn(async move { server.run_n(2).await });

        // Connection B: a start parked inside MockProxy::start.
        let path_b = path.clone();
        let start_future = tokio::spawn(async move {
            let mut client_b = TestClient::connect(&path_b).await;
            let resp = post_start(&mut client_b, &sample_config(), "B").await;
            (client_b, resp)
        });
        entered_rx.await.expect("MockProxy::start never entered");

        // Connection A: cancel a DIFFERENT attempt. Must 200 and not touch B.
        let mut client_a = TestClient::connect(&path).await;
        assert_eq!(consume(post_cancel(&mut client_a, "A").await).await, 200);

        // Release the gate: B is not cancelled, so it returns 200.
        gate.notify_one();
        let (_client_b, resp_b) = start_future.await.expect("start task panicked");
        assert_eq!(consume(resp_b).await, 200, "an unrelated cancel must not abort B");

        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn concurrent_double_cancel_during_start_both_succeed() {
    // Two Cancel requests arrive on separate connections while a single
    // Start is in flight. Both must succeed with 200 — the cancel path
    // is idempotent, and the second cancel sees the token already
    // signaled and is a no-op that still returns 200. The in-flight
    // Start must return Cancelled promptly.
    rt().block_on(async {
        let path = test_socket_path("double-cancel");
        let gate = Arc::new(tokio::sync::Notify::new());
        let (entered_tx, entered_rx) = oneshot::channel();
        let server = IpcServer::bind(&path, gated_proxy(gate.clone(), entered_tx), "test").unwrap();
        // 3 connections: A start, B cancel, C cancel.
        let handle = tokio::spawn(async move { server.run_n(3).await });

        // Client A parks inside MockProxy::start.
        let path_a = path.clone();
        let a_future = tokio::spawn(async move {
            let mut client_a = TestClient::connect(&path_a).await;
            let resp = post_start(&mut client_a, &sample_config(), "t").await;
            (client_a, resp)
        });
        entered_rx.await.expect("MockProxy::start never entered");

        // Two concurrent cancels on separate connections.
        let path_b = path.clone();
        let b_task = tokio::spawn(async move {
            let mut client = TestClient::connect(&path_b).await;
            post_cancel(&mut client, "t").await
        });
        let path_c = path.clone();
        let c_task = tokio::spawn(async move {
            let mut client = TestClient::connect(&path_c).await;
            post_cancel(&mut client, "t").await
        });

        let b_resp = b_task.await.unwrap();
        let c_resp = c_task.await.unwrap();
        assert_eq!(b_resp.status(), 200);
        assert_eq!(c_resp.status(), 200);

        // A's start returns Cancelled. If cancellation regresses,
        // a_future hangs and the test framework's timeout surfaces it.
        let (_client_a, a_resp) = a_future.await.expect("A task panicked");
        assert_eq!(start_error_body(a_resp).await, StartError::Cancelled);

        gate.notify_one();
        handle.abort();
        let _ = handle.await;
    });
}

// SDDL tests (Windows only) ===========================================================================================

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_sddl_without_extra_sids() {
    let sddl = crate::ipc::build_sddl(&[]);
    // Must start with the base SDDL (SYSTEM + Administrators)
    assert!(
        sddl.starts_with(crate::ipc::SDDL_BASE),
        "SDDL should start with base: {sddl}"
    );
    // The hole group SID ACE may or may not be present depending on whether
    // the group exists on this machine. Either way, no extra user SIDs.
    // Count ACE entries: each starts with "(A;;"
    let ace_count = sddl.matches("(A;;").count();
    // Base has 2 (SYSTEM + BA), group adds 0 or 1
    assert!(
        ace_count == 2 || ace_count == 3,
        "expected 2 or 3 ACEs (base + optional group), got {ace_count} in: {sddl}"
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_sddl_with_extra_sids() {
    let fake_sid = "S-1-5-21-1234567890-1234567890-1234567890-1001";
    let sddl = crate::ipc::build_sddl(&[fake_sid]);
    assert!(
        sddl.contains(&format!("(A;;GA;;;{fake_sid})")),
        "SDDL should contain extra SID ACE: {sddl}"
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_sddl_with_multiple_extra_sids() {
    let sid1 = "S-1-5-21-1111111111-1111111111-1111111111-1001";
    let sid2 = "S-1-5-21-2222222222-2222222222-2222222222-1002";
    let sddl = crate::ipc::build_sddl(&[sid1, sid2]);
    assert!(
        sddl.contains(&format!("(A;;GA;;;{sid1})")),
        "SDDL should contain first extra SID: {sddl}"
    );
    assert!(
        sddl.contains(&format!("(A;;GA;;;{sid2})")),
        "SDDL should contain second extra SID: {sddl}"
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_sddl_rejects_malformed_sid() {
    // A malformed SID with SDDL metacharacters should be ignored
    let malformed = "S-1-1-0)(A;;GA;;;S-1-1-0";
    let sddl = crate::ipc::build_sddl(&[malformed]);
    assert!(!sddl.contains(malformed), "malformed SID should be rejected: {sddl}");
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn is_valid_sid_string_accepts_valid() {
    assert!(crate::ipc::is_valid_sid_string("S-1-5-21-1234567890-1001"));
    assert!(crate::ipc::is_valid_sid_string("S-1-1-0"));
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn is_valid_sid_string_rejects_invalid() {
    assert!(!crate::ipc::is_valid_sid_string(""));
    assert!(!crate::ipc::is_valid_sid_string("not-a-sid"));
    assert!(!crate::ipc::is_valid_sid_string("S-1-1-0)(A;;GA;;;S-1-1-0"));
    assert!(!crate::ipc::is_valid_sid_string("S-1-1-0 "));
}

// bind() smoke tests — the production-path bind, which in cfg(test) uses
// the unrestricted LocalListener::bind and skips apply_socket_permissions.

#[skuld::test]
fn bind_accepts_connection() {
    rt().block_on(async {
        let path = test_socket_path("bind-accept");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });
        let stream = LocalStream::connect(&path).await.unwrap();
        drop(stream);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn bind_status_query() {
    rt().block_on(async {
        let path = test_socket_path("bind-status");
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let status = get_status(&mut client).await;
        assert!(!status.running);
        assert_eq!(status.uptime_secs, 0);

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

// Socket lifecycle tests ==============================================================================================

#[skuld::test]
fn socket_recreated_on_bind() {
    rt().block_on(async {
        let path = test_socket_path("recreate");

        // First bind
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        assert!(path.exists(), "socket file should exist after bind");
        drop(server); // Drop removes the file
        assert!(!path.exists(), "socket file should be removed after drop");

        // Second bind (recreates the socket)
        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        assert!(path.exists(), "socket file should exist after second bind");
        drop(server);
    });
}

#[skuld::test]
fn socket_removed_on_drop() {
    rt().block_on(async {
        let path = test_socket_path("drop-cleanup");

        let server = IpcServer::bind(&path, mock_proxy(), "test").unwrap();
        assert!(path.exists(), "socket file should exist after bind");

        drop(server);
        assert!(!path.exists(), "socket file should be removed after drop");
    });
}
