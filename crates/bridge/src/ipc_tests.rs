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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tun_engine::gateway::{GatewayInfo, NextHop};
use tun_engine::routing::failclosed::lockdown_state;
use tun_engine::routing::{self as routing, state as route_state, RoutedFamilies, RoutesInstalled, Routing};
use tun_engine::{RoutingError, TunIdentity};

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
    /// If `Some(n)`, `start` succeeds for its first `n` calls and fails
    /// (with `fail_message`) on every call after — independent of
    /// `fail_start`, which fails from the very first call. Lets a test
    /// drive a `reload` whose *initial* start succeeded but whose
    /// stop+start slow-path retry fails.
    fail_from_call: Option<u32>,
    start_calls: AtomicU32,
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
    /// Message for the `fail_start` error. A plugin-chain failure can embed
    /// the resolved server address (garter formats `remote_host` into its
    /// chain errors), and that string reaches a GUI toast.
    fail_message: String,
}

impl MockProxy {
    fn new() -> Self {
        Self {
            fail_start: AtomicBool::new(false),
            fail_from_call: None,
            start_calls: AtomicU32::new(0),
            traffic: Arc::new(MockTraffic::default()),
            start_gate: None,
            start_entered: std::sync::Mutex::new(None),
            fail_message: "mock failure".to_string(),
        }
    }

    fn failing() -> Self {
        Self {
            fail_start: AtomicBool::new(true),
            ..Self::new()
        }
    }

    fn failing_with(message: &str) -> Self {
        Self {
            fail_start: AtomicBool::new(true),
            fail_message: message.to_string(),
            ..Self::new()
        }
    }

    /// Succeeds on the first `start` call, fails every one after — for a
    /// test driving a `reload` whose initial start must succeed and whose
    /// slow-path retry must fail.
    fn failing_from_second_start(message: &str) -> Self {
        Self {
            fail_from_call: Some(1),
            fail_message: message.to_string(),
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
        let call_index = self.start_calls.fetch_add(1, Ordering::SeqCst);
        let fails_this_call =
            self.fail_start.load(Ordering::SeqCst) || self.fail_from_call.is_some_and(|n| call_index >= n);
        if fails_this_call {
            return Err(ProxyError::Runtime(io::Error::other(self.fail_message.clone())));
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
    /// Fails BOTH `default_gateway` (server-scoped) and `default_route`
    /// (diagnostics) — "the gateway is unavailable" as a caller-independent
    /// fact about the mocked host.
    fail_gateway: AtomicBool,
    /// Fails ONLY `default_gateway` (server-scoped), leaving `default_route`
    /// (diagnostics) succeeding — proves the diagnostics poll does not go
    /// through the server-scoped path (`the_diagnostics_probe_does_not_take_a_server`).
    fail_server_gateway_only: AtomicBool,
    /// Number of `release_all_covers` calls, so a test can assert the
    /// unconditional escape fired exactly once (or not at all). `Arc`-shared
    /// (mirroring `MockProxy::traffic`) so a test can clone it out BEFORE
    /// `routing` moves into the `ProxyManager`.
    release_all_calls: Arc<AtomicU32>,
    /// `release_all_covers` returns `RoutingError::RouteSetup` when set.
    fail_release: Arc<AtomicBool>,
    /// What `lockdown_cover_presence` reports — a test's stand-in for the OS
    /// probe. Defaults to `Absent`.
    cover_presence: std::sync::Mutex<tun_engine::routing::CoverPresence>,
}

impl MockRouting {
    fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            fail_gateway: AtomicBool::new(false),
            fail_server_gateway_only: AtomicBool::new(false),
            release_all_calls: Arc::new(AtomicU32::new(0)),
            fail_release: Arc::new(AtomicBool::new(false)),
            cover_presence: std::sync::Mutex::new(tun_engine::routing::CoverPresence::Absent),
        }
    }

    /// Builder: report `presence` from `lockdown_cover_presence` instead of
    /// the default `Absent`.
    fn with_cover_presence(self, presence: tun_engine::routing::CoverPresence) -> Self {
        *self.cover_presence.lock().unwrap() = presence;
        self
    }

    fn failing_gateway(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            fail_gateway: AtomicBool::new(true),
            fail_server_gateway_only: AtomicBool::new(false),
            release_all_calls: Arc::new(AtomicU32::new(0)),
            fail_release: Arc::new(AtomicBool::new(false)),
            cover_presence: std::sync::Mutex::new(tun_engine::routing::CoverPresence::Absent),
        }
    }

    fn failing_server_gateway_only(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            fail_gateway: AtomicBool::new(false),
            fail_server_gateway_only: AtomicBool::new(true),
            release_all_calls: Arc::new(AtomicU32::new(0)),
            fail_release: Arc::new(AtomicBool::new(false)),
            cover_presence: std::sync::Mutex::new(tun_engine::routing::CoverPresence::Absent),
        }
    }
}

impl Routing for MockRouting {
    type Installed = MockRoutes;

    fn install(&self, tun: &TunIdentity, server_ip: IpAddr, gateway: &GatewayInfo) -> Result<MockRoutes, RoutingError> {
        let interface_name = gateway.interface_name.as_str();
        // Match SystemRouting ordering: write the state file BEFORE
        // any mutation, so tests that assert on `bridge-routes.json`
        // see the same write-then-clear lifecycle as production.
        let persisted = route_state::RouteState {
            version: route_state::SCHEMA_VERSION,
            tun_name: tun.alias().to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
            original_gateway: Some(gateway.gateway_ip),
            route_form: match gateway.next_hop {
                NextHop::Via(_) => route_state::RouteForm::Via,
                NextHop::OnLink => route_state::RouteForm::OnLink,
            },
            installed: routing::planned_routes(server_ip),
            stale: Vec::new(),
        };
        route_state::save(&self.state_dir, &persisted, None)
            .map_err(|e| RoutingError::RouteSetup(format!("mock persist failed: {e}")))?;
        Ok(MockRoutes {
            state_dir: self.state_dir.clone(),
        })
    }

    fn default_gateway(&self, _dest: IpAddr) -> Result<GatewayInfo, RoutingError> {
        if self.fail_gateway.load(Ordering::SeqCst) || self.fail_server_gateway_only.load(Ordering::SeqCst) {
            return Err(RoutingError::Gateway("mock gateway failure".into()));
        }
        Ok(GatewayInfo {
            gateway_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            next_hop: NextHop::Via(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            interface_name: "MockEthernet".into(),
            interface_index: 1,
            ipv6_available: false,
        })
    }

    /// Deliberately ignores `fail_server_gateway_only` — that flag configures
    /// the SERVER-SCOPED mock failure `default_gateway` returns, and this is
    /// the destination-independent diagnostics probe. If diagnostics routed
    /// through the server-scoped mock instead,
    /// `the_diagnostics_probe_does_not_take_a_server` would catch it.
    fn default_route(&self) -> Result<GatewayInfo, RoutingError> {
        if self.fail_gateway.load(Ordering::SeqCst) {
            return Err(RoutingError::Gateway("mock gateway failure".into()));
        }
        Ok(GatewayInfo {
            gateway_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            next_hop: NextHop::Via(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            interface_name: "MockEthernet".into(),
            interface_index: 1,
            ipv6_available: false,
        })
    }

    type Cover = MockCover;

    fn install_failclosed_cover(
        &self,
        _server_ip: IpAddr,
        _resolver_ip: Option<IpAddr>,
    ) -> Result<MockCover, RoutingError> {
        Ok(MockCover)
    }

    fn install_lockdown(
        &self,
        _server_ip: IpAddr,
        _tun: &TunIdentity,
        _app_ids: &[PathBuf],
    ) -> Result<MockCover, RoutingError> {
        Ok(MockCover)
    }

    fn release_all_covers(&self) -> Result<(), RoutingError> {
        self.release_all_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_release.load(Ordering::SeqCst) {
            return Err(RoutingError::RouteSetup("mock release_all_covers failure".into()));
        }
        Ok(())
    }

    fn lockdown_cover_presence(&self) -> tun_engine::routing::CoverPresence {
        *self.cover_presence.lock().unwrap()
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

impl RoutesInstalled for MockRoutes {
    // `install` above always persists the full `planned_routes(server_ip)`
    // set — this module's mock never simulates a partial install — so the
    // families routed are always both.
    fn routed_families(&self) -> RoutedFamilies {
        RoutedFamilies { v4: true, v6: true }
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

/// `mock_proxy_with_state_dir` variant whose mock routing reports
/// `presence` from `lockdown_cover_presence` — a test's stand-in for the OS
/// probe, independent of whether any session is running.
fn mock_proxy_with_cover_presence(
    presence: tun_engine::routing::CoverPresence,
) -> Arc<Mutex<ProxyManager<MockProxy, MockRouting>>> {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let routing = MockRouting::new(state_dir.clone()).with_cover_presence(presence);
    let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(state_dir);
    Arc::new(Mutex::new(pm))
}

/// `mock_proxy_with_state_dir` variant that also hands back the mock
/// routing's `release_all_calls` / `fail_release` handles (cloned out BEFORE
/// `routing` moves into the manager, mirroring `mock_proxy_with_traffic`), so
/// a test can assert the escape fired and drive a failure. Presence defaults
/// to `Live` — the escape is now gated on `cover_step`, so a test exercising
/// `release_all_covers` needs a presence that actually calls for a release.
#[allow(clippy::type_complexity)]
fn mock_proxy_with_release_state() -> (
    Arc<Mutex<ProxyManager<MockProxy, MockRouting>>>,
    Arc<AtomicU32>,
    Arc<AtomicBool>,
    PathBuf,
) {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let routing = MockRouting::new(state_dir.clone()).with_cover_presence(tun_engine::routing::CoverPresence::Live);
    let release_all_calls = Arc::clone(&routing.release_all_calls);
    let fail_release = Arc::clone(&routing.fail_release);
    let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(state_dir.clone());
    (Arc::new(Mutex::new(pm)), release_all_calls, fail_release, state_dir)
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

/// Only the SERVER-SCOPED `default_gateway` fails; `default_route`
/// (diagnostics) still succeeds.
fn server_gateway_failing_proxy() -> Arc<Mutex<ProxyManager<MockProxy, MockRouting>>> {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let routing = MockRouting::failing_server_gateway_only(state_dir);
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
            server: "127.0.0.1".into(),
            server_port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "pw".to_string().into(),
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

async fn post_unblock(client: &mut TestClient) -> http::Response<hyper::body::Incoming> {
    let req = http::Request::builder()
        .method("POST")
        .uri(ROUTE_UNBLOCK)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
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
                cover_presence: hole_common::protocol::CoverPresence::Absent,
                blocked_until_connected: false,
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
        assert_eq!(
            status.cover_presence,
            hole_common::protocol::CoverPresence::Absent,
            "no cover engaged while stopped"
        );

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn an_adopted_cover_with_no_session_reports_engaged() {
    // A cover left behind by a crashed prior process — adopted on this
    // bridge's start, with no session ever created in THIS process — must
    // still surface as engaged. `cover_presence` is a measured probe of the
    // OS, not a derivation from `Posture`, so it owes nothing to the
    // in-process session that would otherwise be the only source of truth.
    rt().block_on(async {
        let path = test_socket_path("adopted-cover-no-session");
        let server = IpcServer::bind(
            &path,
            mock_proxy_with_cover_presence(tun_engine::routing::CoverPresence::Live),
            "test",
        )
        .unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let status = get_status(&mut client).await;
        assert!(!status.running, "no session exists in this process");
        assert_eq!(
            status.cover_presence,
            hole_common::protocol::CoverPresence::Live,
            "the measured cover must be reported even with no session"
        );

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

// POST /v1/unblock ====================================================================================================

async fn parse_error_body(resp: http::Response<hyper::body::Incoming>) -> hole_common::protocol::ErrorResponse {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[skuld::test]
fn unblock_clears_covers_and_returns_ok() {
    rt().block_on(async {
        let path = test_socket_path("unblock-ok");
        let (proxy, release_all_calls, _fail_release, _dir) = mock_proxy_with_release_state();
        let server = IpcServer::bind(&path, proxy, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let resp = post_unblock(&mut client).await;
        assert_eq!(resp.status(), 200, "unblock on a clean, idle manager must 200");
        let _ = resp.into_body().collect().await;
        assert_eq!(release_all_calls.load(Ordering::SeqCst), 1);

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

/// The escape never refuses. A session still running with a live
/// cover and the target going `Off` is exactly the wedged-teardown case the
/// escape exists for; it must release the cover and 200, not 409.
#[skuld::test]
fn a_wedged_teardown_with_an_off_target_releases_the_cover() {
    rt().block_on(async {
        let path = test_socket_path("unblock-running");
        let (proxy, release_all_calls, _fail_release, dir) = mock_proxy_with_release_state();
        // Seed the intent ON so the post-unblock "now off" assertion below
        // actually exercises the persist — a fresh tempdir with no
        // bridge-lockdown.json already reads `false`, which would let that
        // assertion pass vacuously regardless of whether the handler wrote
        // anything.
        lockdown_state::set_enabled(&dir, true, None).unwrap();
        // `handle_unblock` persists through `IpcState::state_dir`, not the
        // proxy manager's own — `bind_with_dirs` with the SAME `dir` mirrors
        // production wiring (`foreground.rs` passes one `state_dir` to both).
        let server = IpcServer::bind_with_dirs(&path, proxy, "test", dir.clone(), dir.clone(), None).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let start_resp = post_start(&mut client, &sample_config(), "attempt-1").await;
        assert_eq!(consume(start_resp).await, 200, "setup: the session must start");

        let resp = post_unblock(&mut client).await;
        assert_eq!(
            resp.status(),
            200,
            "the escape never refuses, even with a session still running"
        );
        let _ = resp.into_body().collect().await;
        assert_eq!(
            release_all_calls.load(Ordering::SeqCst),
            1,
            "a live cover must be released regardless of the running session"
        );
        assert!(!lockdown_state::load_enabled(&dir), "the intent must be recorded off");

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn unblock_reports_a_failed_release() {
    rt().block_on(async {
        let path = test_socket_path("unblock-fail");
        let (proxy, _release_all_calls, fail_release, _dir) = mock_proxy_with_release_state();
        fail_release.store(true, Ordering::SeqCst);
        let server = IpcServer::bind(&path, proxy, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let resp = post_unblock(&mut client).await;
        assert_eq!(
            resp.status(),
            500,
            "a failed release must be reported, not silently swallowed as 200"
        );
        let _ = resp.into_body().collect().await;

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn unblock_error_bodies_carry_no_filesystem_path() {
    fn assert_no_path(message: &str) {
        assert!(
            !message.contains('\\') && !message.contains('/'),
            "error body reaching a GUI toast must carry no filesystem path: {message:?}"
        );
    }

    rt().block_on(async {
        // The 500 (failed release) case — the only error case unblock has
        // left, now that the escape never refuses.
        let path = test_socket_path("unblock-nopath-500");
        let (proxy, _calls, fail_release, _dir) = mock_proxy_with_release_state();
        fail_release.store(true, Ordering::SeqCst);
        let server = IpcServer::bind(&path, proxy, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });
        let mut client = TestClient::connect(&path).await;
        let resp = post_unblock(&mut client).await;
        assert_eq!(resp.status(), 500);
        assert_no_path(&parse_error_body(resp).await.message);
        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn lockdown_off_releases_covers_through_the_same_path() {
    rt().block_on(async {
        let path = test_socket_path("lockdown-off-releases");
        let (proxy, release_all_calls, _fail_release, _dir) = mock_proxy_with_release_state();
        let server = IpcServer::bind(&path, proxy, "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let resp = post_lockdown(&mut client, false).await;
        assert_eq!(
            resp.status(),
            200,
            "turning the toggle off with nothing running must 200"
        );
        let _ = resp.into_body().collect().await;
        assert_eq!(
            release_all_calls.load(Ordering::SeqCst),
            1,
            "the toggle must release through the SAME path unblock uses, not just persist the intent"
        );

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

/// Seam guard with the sibling teardown item: `handle_unblock` must consume
/// no session posture at all, so a stopping session's reported posture can
/// never reach this decision — the escape reads only the reconciler's
/// target/presence, off the proxy mutex entirely.
#[skuld::test]
fn the_unblock_handler_reads_no_session_posture() {
    let src = include_str!("ipc.rs");
    let start = src
        .find("async fn handle_unblock")
        .expect("handle_unblock must exist in ipc.rs");
    let after_start = &src[start + 1..];
    let end = after_start
        .find("\nasync fn ")
        .or_else(|| after_start.find("\nfn "))
        .map(|i| start + 1 + i)
        .unwrap_or(src.len());
    let handler_src = &src[start..end];

    let pattern = regex::Regex::new(r"(?i)posture|holder").unwrap();
    assert!(
        !pattern.is_match(handler_src),
        "handle_unblock must take no Posture/holder input — the escape reads only the \
         reconciler's target/presence, never a session's reported posture:\n{handler_src}"
    );
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
        assert!(!hole_common::update_marker::is_present(&log_dir));

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
                driver: cosca::identity::ProcessId::current()
                    .to_record()
                    .expect("persist this process's identity"),
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
            !hole_common::update_marker::is_present(&log_dir),
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
            !hole_common::update_marker::is_present(&log_dir),
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
            !hole_common::update_marker::is_present(&log_dir),
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
fn setting_the_target_persists_the_startup_preference() {
    // #979 — at the IPC layer rather than the pure
    // save/load round-trip `target_tests.rs` already covers: an actual Start
    // request carrying `x-hole-on-startup` writes the preference, and a
    // fresh `load_startup_preference` (no in-memory state carried over,
    // simulating a bridge restart) reads it back.
    rt().block_on(async {
        let path = test_socket_path("on-startup-persist");
        let state_dir = tempfile::tempdir().unwrap().keep();
        let server =
            IpcServer::bind_with_dirs(&path, mock_proxy(), "test", state_dir.clone(), state_dir.clone(), None).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let req = http::Request::builder()
            .method("POST")
            .uri(ROUTE_START)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header(ATTEMPT_ID_HEADER, "t")
            .header(ON_STARTUP_HEADER, "always_connect")
            .body(Full::new(Bytes::from(serde_json::to_vec(&sample_config()).unwrap())))
            .unwrap();
        consume(client.send(req).await).await;

        let pref = target::load_startup_preference(&state_dir);
        assert_eq!(
            pref.on_startup,
            StartupBehavior::AlwaysConnect,
            "a fresh load must read back the preference the IPC Start carried"
        );

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

#[skuld::test]
fn a_start_with_no_startup_preference_leaves_the_persisted_one_alone() {
    // #979: the CLI has no Settings preference to push and sends no
    // `X-Hole-On-Startup` header at all (distinct from an old client, which
    // omits it not knowing it exists — both look identical on the wire, and
    // are handled identically: nothing pushed). Either way, a Start missing
    // the header must never downgrade a persisted preference (e.g. a real
    // `AlwaysConnect` the GUI set) down to the wire default. It still
    // records the connect as the fallback candidate for `AlwaysConnect` —
    // that much is true regardless of who started it.
    rt().block_on(async {
        let path = test_socket_path("on-startup-noop");
        let state_dir = tempfile::tempdir().unwrap().keep();
        target::save_startup_preference(
            &state_dir,
            &target::StartupPreference {
                on_startup: StartupBehavior::AlwaysConnect,
                candidate: None,
            },
            None,
        )
        .unwrap();
        let server =
            IpcServer::bind_with_dirs(&path, mock_proxy(), "test", state_dir.clone(), state_dir.clone(), None).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let req = http::Request::builder()
            .method("POST")
            .uri(ROUTE_START)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header(ATTEMPT_ID_HEADER, "t")
            // deliberately no ON_STARTUP_HEADER
            .body(Full::new(Bytes::from(serde_json::to_vec(&sample_config()).unwrap())))
            .unwrap();
        consume(client.send(req).await).await;

        let pref = target::load_startup_preference(&state_dir);
        assert_eq!(
            pref.on_startup,
            StartupBehavior::AlwaysConnect,
            "a Start with no on_startup header must not overwrite the persisted preference"
        );
        assert_eq!(
            pref.candidate.map(|c| c.server.server.expose().to_owned()),
            Some(sample_config().server.server.expose().to_owned()),
            "a successful start still updates the AlwaysConnect fallback candidate"
        );

        drop(client);
        handle.abort();
        let _ = handle.await;
    });
}

/// Build an `IpcState` directly (bypassing `IpcServer::bind*`, which cannot
/// wire up the test-only persist gate) so `persist_after_start` can be
/// parked exactly inside its write window — between `start_cancellable`
/// returning and the
/// target/startup-preference write landing. `proxy`'s own `state_dir` must
/// be `dir`, same as `IpcState::state_dir`, for `handle_stop`'s write
/// (via `ProxyManager::state_dir`) and `handle_start`'s (via this state's
/// `state_dir`) to land in the same file.
fn ipc_state_with_persist_gate(
    dir: PathBuf,
) -> (
    Arc<IpcState<MockProxy, MockRouting>>,
    Arc<tokio::sync::Notify>,
    oneshot::Receiver<()>,
) {
    let routing = MockRouting::new(dir.clone());
    let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.clone());
    let proxy = Arc::new(Mutex::new(pm));
    let routing_handle = proxy.try_lock().unwrap().routing_handle();
    let cover_invalidated = proxy.try_lock().unwrap().cover_invalidation_handle();
    let gate = Arc::new(tokio::sync::Notify::new());
    let (entered_tx, entered_rx) = oneshot::channel();
    let state = Arc::new(IpcState {
        proxy,
        routing: routing_handle,
        cover_invalidated,
        unblock_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        start_cancel: Arc::new(std::sync::Mutex::new(StartCancelState::default())),
        version: "test".to_string(),
        log_dir: dir.clone(),
        state_dir: dir,
        owner: None,
        persist_gate: Some(gate.clone()),
        persist_entered: std::sync::Mutex::new(Some(entered_tx)),
    });
    (state, gate, entered_rx)
}

#[skuld::test]
async fn a_stop_landing_while_a_start_persists_does_not_get_reverted_to_connected() {
    // The start's persist runs inside the proxy lock, so a Stop dispatched
    // while a Start is mid-persist cannot begin its own write until the
    // Start's is durably on disk. Off must win, never be reverted back to
    // Connected by the Start's write landing later.
    let dir = tempfile::tempdir().unwrap().keep();
    let (state, persist_gate, persist_entered) = ipc_state_with_persist_gate(dir.clone());

    let state_a = state.clone();
    let start = tokio::spawn(async move {
        handle_start(
            axum::extract::State(state_a),
            axum::http::HeaderMap::new(),
            Json(sample_config()),
        )
        .await
    });

    // Park until A is *known* to be inside its persist window (holding the
    // proxy lock, start_cancellable already returned) — deterministic, no
    // sleep.
    persist_entered.await.expect("persist_after_start never entered");

    // B's Stop needs the same proxy lock A is holding through its persist;
    // it cannot run until A's whole critical section — persist included —
    // completes. Spawn it so it queues rather than blocking this task.
    let state_b = state.clone();
    let stop = tokio::spawn(async move { handle_stop(axum::extract::State(state_b)).await });

    // Let A's persist proceed. Only once it (and the rest of A's critical
    // section) finishes does the lock free up for B.
    persist_gate.notify_one();

    let _ = start.await.expect("A task panicked").expect("A's start must succeed");
    let _ = stop.await.expect("B task panicked").expect("B's stop must succeed");

    assert_eq!(
        target::load(&dir),
        Target::Off,
        "a Stop dispatched while Start was mid-persist must win: it must not be reverted back to \
         Connected by the Start's own persist finishing later"
    );
}

#[skuld::test]
async fn a_second_start_cannot_begin_while_the_first_is_still_persisting() {
    // `save_startup_preference`'s read-modify-write now shares the target
    // file's lock, and `handle_start`'s single-occupancy `in_flight` guard
    // holds until the persist has completed — so two overlapping starts can
    // never have their persist windows in flight together. A second Start
    // dispatched while the first is mid-persist is rejected with 409.
    let dir = tempfile::tempdir().unwrap().keep();
    let (state, persist_gate, persist_entered) = ipc_state_with_persist_gate(dir.clone());

    let state_a = state.clone();
    let start_a = tokio::spawn(async move {
        handle_start(
            axum::extract::State(state_a),
            axum::http::HeaderMap::new(),
            Json(sample_config()),
        )
        .await
    });

    persist_entered.await.expect("persist_after_start never entered");

    // B's Start while A is mid-persist: must be rejected outright (409-
    // equivalent `StartHandlerError::Concurrent`) rather than being admitted
    // to race A's still-in-flight preference write.
    let state_b = state.clone();
    let start_b = handle_start(
        axum::extract::State(state_b),
        axum::http::HeaderMap::new(),
        Json(sample_config()),
    )
    .await;
    assert!(
        matches!(start_b, Err(StartHandlerError::Concurrent)),
        "a second start must be rejected (StartHandlerError::Concurrent) while the first is still persisting"
    );

    persist_gate.notify_one();
    let _ = start_a.await.expect("A task panicked").expect("A's start must succeed");
}

#[skuld::test]
fn ipc_start_never_engages_the_cover_even_on_failure() {
    // #979: `handle_start` hardcodes `covered = false` unconditionally now —
    // there is no wire signal left that can make an IPC-driven start covered
    // (`X-Hole-Covered` was deleted; the only remaining source of a covered
    // start is the bridge's own boot-time reconcile, which bypasses IPC
    // entirely). A failed IPC start must therefore never leave the host
    // fail-closed, regardless of any header a client sends.
    rt().block_on(async {
        let path = test_socket_path("ipc-start-uncovered");
        let server = IpcServer::bind(&path, failing_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });
        let mut client = TestClient::connect(&path).await;
        consume(post_start(&mut client, &sample_config(), "t").await).await;
        let status = get_status(&mut client).await;
        assert!(
            !status.blocked_until_connected,
            "an IPC-driven start must never stay fail-closed on failure"
        );
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

/// Build an `IpcState` directly, backed by `dir` for both `state.state_dir`
/// (what `handle_start`/`handle_reload` persist through) and the proxy's
/// own `with_state_dir` (what `MockRouting` and `set_lockdown_intent` read),
/// same pairing `ipc_state_with_persist_gate` uses — without that helper's
/// persist-gate machinery, which these tests don't need.
fn ipc_state_with_dir(dir: PathBuf) -> Arc<IpcState<MockProxy, MockRouting>> {
    ipc_state_with_dir_and_proxy(dir, MockProxy::new())
}

/// As [`ipc_state_with_dir`], but with a caller-supplied `MockProxy` — for a
/// test that needs its `start` calls to behave differently across a
/// start/reload sequence (e.g. succeed then fail).
fn ipc_state_with_dir_and_proxy(dir: PathBuf, proxy: MockProxy) -> Arc<IpcState<MockProxy, MockRouting>> {
    let routing = MockRouting::new(dir.clone());
    let pm = ProxyManager::new(proxy, routing).with_state_dir(dir.clone());
    let proxy = Arc::new(Mutex::new(pm));
    let (routing_handle, cover_invalidated) = {
        let guard = proxy.try_lock().unwrap();
        (guard.routing_handle(), guard.cover_invalidation_handle())
    };
    Arc::new(IpcState {
        proxy,
        routing: routing_handle,
        cover_invalidated,
        unblock_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        start_cancel: Arc::new(std::sync::Mutex::new(StartCancelState::default())),
        version: "test".to_string(),
        log_dir: dir.clone(),
        state_dir: dir,
        owner: None,
        persist_gate: None,
        persist_entered: std::sync::Mutex::new(None),
    })
}

#[skuld::test]
async fn reload_persists_the_new_config_on_the_hot_swap_path() {
    // 4d0e66d7: a reload whose config is structurally the same (only
    // filters differ) takes `ProxyManager::reload`'s fast, hot-swap path,
    // which never calls `start_cancellable` — so nothing wrote the new
    // config to the persisted target until this handler does. Left
    // unpersisted, a crash right after this reload would recover with the
    // PRE-reload filters, silently reverting the swap.
    let dir = tempfile::tempdir().unwrap().keep();
    let state = ipc_state_with_dir(dir.clone());

    let _ = handle_start(
        axum::extract::State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(sample_config()),
    )
    .await
    .expect("start must succeed");

    let mut reloaded = sample_config();
    reloaded.filters = vec![hole_common::config::FilterRule {
        address: "example.com".to_string(),
        matching: hole_common::config::MatchType::Exactly,
        action: hole_common::config::FilterAction::Block,
    }];

    let _ = handle_reload(axum::extract::State(state.clone()), Json(reloaded.clone()))
        .await
        .expect("reload must succeed");

    match target::load(&dir) {
        Target::Connected { config } => assert_eq!(
            *config, reloaded,
            "a hot-swapped reload must persist the NEW config, filters included"
        ),
        other => panic!("expected Target::Connected after a successful reload, got {other:?}"),
    }
}

#[skuld::test]
async fn reload_persists_the_new_config_on_the_stop_start_path() {
    // 4d0e66d7: a reload whose config differs structurally (here,
    // `local_port`) takes `ProxyManager::reload`'s slow stop+start path,
    // which calls `ProxyManager::start` directly — the ProxyManager-level
    // entry point that, like `handle_start`'s own call to
    // `start_cancellable`, never persists on its own (persistence is this
    // IPC layer's job, same division `persist_after_start` already keeps
    // for a plain Start).
    let dir = tempfile::tempdir().unwrap().keep();
    let state = ipc_state_with_dir(dir.clone());

    let _ = handle_start(
        axum::extract::State(state.clone()),
        axum::http::HeaderMap::new(),
        Json(sample_config()),
    )
    .await
    .expect("start must succeed");

    let mut reloaded = sample_config();
    reloaded.local_port = sample_config().local_port + 1;

    let _ = handle_reload(axum::extract::State(state.clone()), Json(reloaded.clone()))
        .await
        .expect("reload must succeed");

    match target::load(&dir) {
        Target::Connected { config } => assert_eq!(
            *config, reloaded,
            "a stop+start reload must persist the NEW config, not the pre-reload one"
        ),
        other => panic!("expected Target::Connected after a successful reload, got {other:?}"),
    }
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

/// The diagnostics poll runs with no session (and so no `server_ip`) —
/// `ProxyManager::default_route` must not go through the server-scoped
/// `Routing::default_gateway`, which a probe with no server could not even
/// call correctly. `server_gateway_failing_proxy` fails ONLY the
/// server-scoped method, so this would read `network: "error"` if
/// diagnostics routed through it instead.
#[skuld::test]
fn the_diagnostics_probe_does_not_take_a_server() {
    rt().block_on(async {
        let path = test_socket_path("diag-no-server");
        let server = IpcServer::bind(&path, server_gateway_failing_proxy(), "test").unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let diag = get_diagnostics(&mut client).await;
        assert_eq!(diag.network, "ok");

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

#[skuld::test]
fn build_cutover_marker_carries_this_processs_identity() {
    let me = cosca::identity::ProcessId::current();
    let m = super::build_cutover_marker(me.to_record().expect("persist this process's identity"));
    assert_eq!(m.version, hole_common::update_marker::MARKER_VERSION);
    assert_eq!(
        cosca::identity::ProcessId::try_from(&m.driver).expect("the marker's driver must restore"),
        me,
        "the marker must name the writing process, not a synthesized record"
    );
}

#[skuld::test]
fn extraction_failure_omits_the_path() {
    // An IPC error message reaches a GUI toast verbatim, so the path-bearing
    // detail must land in bridge.log while the client message stays PII-free.
    use garter::test_utils::WaitableWriter;
    use garter::tracing_test::set_default_in_current_thread;

    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .finish();
    let _g = set_default_in_current_thread(subscriber);

    let e = io::Error::other("read C:\\ProgramData\\hole\\state\\.update-staging\\hole.exe");
    let (code, message) = super::extraction_failure(&e);

    assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !message.contains("ProgramData"),
        "message must not carry the path: {message}"
    );
    assert!(
        !message.contains('\\'),
        "message must not carry a path separator: {message}"
    );

    // The path-bearing detail must still reach bridge.log for diagnosis.
    let log = writer.snapshot();
    assert!(log.contains("ProgramData"), "log must carry the redacted detail: {log}");
}

// Redaction arming and the IPC boundary ===============================================================================
//
// `203.0.113.7` is RFC 5737 documentation space and appears in no other
// fixture. The registry is process-global and grow-only; these run under
// `cargo nextest`, one process per test.

const REDACT_ADDR: &str = "203.0.113.7";
const REDACT_ENTRY_ID: &str = "8f2a1c04-0000-0000-0000-000000000000";

/// A capture wrapped exactly as production wraps the log-file writer.
fn redacting_capture() -> (
    impl tracing::Subscriber + Send + Sync,
    garter::test_utils::WaitableWriter,
) {
    let writer = garter::test_utils::WaitableWriter::new();
    let sink = writer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || util::redact::RedactingWriter::new(sink.clone()))
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    (subscriber, writer)
}

fn ipc_state(proxy: Arc<Mutex<ProxyManager<MockProxy, MockRouting>>>) -> Arc<IpcState<MockProxy, MockRouting>> {
    let dir = tempfile::tempdir().unwrap().keep();
    let (routing, cover_invalidated) = {
        let guard = proxy
            .try_lock()
            .expect("proxy mutex must be uncontended at construction time");
        (guard.routing_handle(), guard.cover_invalidation_handle())
    };
    Arc::new(IpcState {
        proxy,
        routing,
        cover_invalidated,
        unblock_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        start_cancel: Arc::new(std::sync::Mutex::new(StartCancelState::default())),
        version: "test".to_string(),
        log_dir: dir.clone(),
        state_dir: dir,
        owner: None,
        persist_gate: None,
        persist_entered: std::sync::Mutex::new(None),
    })
}

fn redaction_config() -> ProxyConfig {
    let mut config = sample_config();
    config.server.id = REDACT_ENTRY_ID.to_string();
    config.server.server = REDACT_ADDR.into();
    config
}

/// Stands in for the open-ended set of producers the sink exists for: a
/// dependency at the default global `info`, which no per-site edit reaches.
fn emit_third_party_line() {
    tracing::info!(target: "some_dependency::dialer", "creating connection to {REDACT_ADDR}:8388");
}

#[skuld::test]
async fn start_request_arms_redaction_before_it_logs() {
    let (subscriber, writer) = redacting_capture();
    let token = hole_common::logging::redact_arm::token_for(REDACT_ENTRY_ID);
    {
        let _g = garter::tracing_test::set_default_in_current_thread(subscriber);
        let _ = super::handle_start(
            axum::extract::State(ipc_state(mock_proxy())),
            axum::http::HeaderMap::new(),
            Json(redaction_config()),
        )
        .await;
        emit_third_party_line();
    }

    assert_eq!(
        util::redact::redact_str(REDACT_ADDR),
        token,
        "the start handler must arm the configured address"
    );
    let log = writer.snapshot();
    assert!(
        log.contains("ProxyManager::start_cancellable entered"),
        "the handler did not reach the start path at all: {log}"
    );
    assert!(!log.contains(REDACT_ADDR), "the address reached the log: {log}");
    assert!(log.contains(&token), "the token is missing from the log: {log}");
}

#[skuld::test]
async fn test_server_request_arms_redaction_before_it_logs() {
    // A separate axum route with its own arming call: it would ship unarmed
    // while `start_request_arms_redaction_before_it_logs` still passed.
    let (subscriber, writer) = redacting_capture();
    let token = hole_common::logging::redact_arm::token_for(REDACT_ENTRY_ID);
    let mut entry = redaction_config().server;
    entry.plugin = Some("definitely-not-a-real-plugin-binary".into());
    {
        let _g = garter::tracing_test::set_default_in_current_thread(subscriber);
        let _ = super::handle_test_server(
            axum::extract::State(ipc_state(mock_proxy())),
            Json(hole_common::protocol::TestServerRequest {
                entry,
                dns: hole_common::config::DnsConfig::default(),
            }),
        )
        .await;
        emit_third_party_line();
    }

    assert_eq!(
        util::redact::redact_str(REDACT_ADDR),
        token,
        "the test-server handler must arm the configured address"
    );
    let log = writer.snapshot();
    assert!(!log.contains(REDACT_ADDR), "the address reached the log: {log}");
}

#[skuld::test]
async fn an_outgoing_error_carrying_the_address_is_redacted() {
    // Asserts on the **response**, not the log: `StartError::Failed`'s doc
    // claims a PII-free message and nothing enforced it. The bridge's
    // registry is armed by the same handler, so the claim becomes a property.
    let token = hole_common::logging::redact_arm::token_for(REDACT_ENTRY_ID);
    let proxy = Arc::new(Mutex::new(ProxyManager::new(
        MockProxy::failing_with(&format!("creating connection to {REDACT_ADDR}:443 failed")),
        MockRouting::new(tempfile::tempdir().unwrap().keep()),
    )));

    let result = super::handle_start(
        axum::extract::State(ipc_state(proxy)),
        axum::http::HeaderMap::new(),
        Json(redaction_config()),
    )
    .await;

    let Err(super::StartHandlerError::Failed(e)) = result else {
        panic!("expected a typed start failure");
    };
    let wire = serde_json::to_string(&e).expect("serialize the outgoing error");
    assert!(
        !wire.contains(REDACT_ADDR),
        "the toast would have carried the address: {wire}"
    );
    assert!(wire.contains(&token), "the outgoing error lost its token: {wire}");
}

/// M3 (#1033): `handle_reload` must arm and redact exactly as `handle_start`
/// does. `reload`'s slow path (`stop()` + `start(config)`) runs precisely
/// when the incoming server differs from the running one — i.e. exactly
/// when the incoming host has never been armed in this process
/// (`start_inner` only arms the *resolved IP*, never the configured host).
/// Before the fix, a failure on that path put the configured address in
/// clear into both `bridge.log` and this handler's error body.
#[skuld::test]
async fn reload_to_a_different_server_that_fails_is_redacted_in_log_and_response() {
    let (subscriber, writer) = redacting_capture();
    let token = hole_common::logging::redact_arm::token_for(REDACT_ENTRY_ID);

    let dir = tempfile::tempdir().unwrap().keep();
    let state = ipc_state_with_dir_and_proxy(
        dir,
        MockProxy::failing_from_second_start(&format!("creating connection to {REDACT_ADDR}:443 failed")),
    );

    // `redaction_config()`'s server (id `REDACT_ENTRY_ID`, address
    // `REDACT_ADDR`) differs from `sample_config()`'s, so `reload`'s
    // `structural_same` check is false and it takes the stop+start slow
    // path — the one `MockProxy::failing_from_second_start` is built to fail.
    let reloaded = redaction_config();

    let (status, body) = {
        let _g = garter::tracing_test::set_default_in_current_thread(subscriber);
        let _ = handle_start(
            axum::extract::State(state.clone()),
            axum::http::HeaderMap::new(),
            Json(sample_config()),
        )
        .await
        .expect("initial start must succeed");

        let result = handle_reload(axum::extract::State(state.clone()), Json(reloaded)).await;
        emit_third_party_line();

        let Err((status, Json(body))) = result else {
            panic!("expected the stop+start reload to fail");
        };
        (status, body)
    };

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !body.message.contains(REDACT_ADDR),
        "the response body carried the address: {}",
        body.message
    );
    assert!(
        body.message.contains(&token),
        "the response body lost its token: {}",
        body.message
    );

    let log = writer.snapshot();
    assert!(!log.contains(REDACT_ADDR), "the address reached the log: {log}");
    assert!(log.contains(&token), "the token is missing from the log: {log}");
}

// Unblock vs post-start persist =======================================================================================

/// Holding the proxy lock across the persist closed the
/// Start-vs-Stop race, because `handle_stop` takes that same lock and simply
/// queues. It cannot close Start-vs-Unblock: `handle_unblock` takes NO proxy
/// lock by design (it must work while a wedged teardown holds one), so it runs
/// *inside* the start's persist window. The closure ignoring `current` is what
/// makes that a lost update — the write is unconditional, so it reverts an
/// unblock that already committed.
#[skuld::test]
async fn an_unblock_during_the_post_start_persist_is_not_reverted() {
    let dir = tempfile::tempdir().unwrap().keep();
    let (state, persist_gate, persist_entered) = ipc_state_with_persist_gate(dir.clone());

    let state_a = state.clone();
    let start = tokio::spawn(async move {
        handle_start(
            axum::extract::State(state_a),
            axum::http::HeaderMap::new(),
            Json(sample_config()),
        )
        .await
    });

    // Park until the start is known to be inside its persist window.
    persist_entered.await.expect("persist_after_start never entered");

    // Unblock needs no proxy lock, so unlike a Stop it does not queue behind
    // the start — it commits `Target::Off` while the start is still parked.
    let _ = handle_unblock(axum::extract::State(state.clone()))
        .await
        .expect("unblock must succeed");

    persist_gate.notify_one();
    let _ = start.await.expect("start task panicked").expect("start must succeed");

    assert_eq!(
        target::load(&dir),
        Target::Off,
        "an Unblock that committed while Start was mid-persist was silently reverted to Connected"
    );
    assert!(
        target::load_startup_preference(&dir).candidate.is_none(),
        "the declined target write still recorded an auto-connect candidate, leaving the two \
         records disagreeing about what the user last asked for"
    );
}

// Status probe placement ==============================================================================================

/// `handle_status` used to reach cover presence through `pm.cover_presence()`
/// while holding `state.proxy.lock()`. On macOS that probe forks
/// `pfctl -s labels`, and the GUI polls status every 5s for the life of the
/// app — so every poll ran a subprocess inside the same critical section
/// `handle_start` and `stop_with` need.
///
/// Asserted structurally rather than by racing two tasks: the runtime version
/// can only conclude "still serialised" by waiting, and the only way to bound
/// that wait is a timeout, which this project forbids for synchronisation.
/// `IpcState` already carries the same `Arc<R>` (added for `handle_unblock`),
/// so the invariant is simply that this file never takes the manager's route.
#[skuld::test]
fn status_reads_presence_off_the_routing_handle_not_the_proxy_manager() {
    let ipc_rs = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("ipc.rs");
    let text = std::fs::read_to_string(&ipc_rs).expect("failed to read ipc.rs");
    // A literal `.` before the name, so `routing.lockdown_cover_presence()`
    // — the sanctioned route — does not match.
    let pattern = regex::Regex::new(r"\.cover_presence\s*\(").unwrap();
    let sites = crate::reconciler::reconciler_tests::call_sites_by_function(&text, &pattern);
    assert!(
        sites.is_empty(),
        "ipc.rs reaches cover presence through the ProxyManager, which means the OS probe runs \
         inside the proxy lock: {sites:?}. Read it from `state.routing` instead."
    );
}
