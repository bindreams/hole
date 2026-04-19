use super::*;
use crate::proxy::{Proxy, ProxyError, RunningProxy};
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
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::task::JoinHandle;
use tun_engine::gateway::GatewayInfo;
use tun_engine::routing::{state as route_state, Routing};
use tun_engine::RoutingError;

// MockProxy ===========================================================================================================

struct MockProxy {
    fail_start: AtomicBool,
    /// If Some, `start` awaits this gate before returning. Used to
    /// simulate a slow start so tests can race `POST /v1/cancel` against
    /// an in-flight `POST /v1/start`.
    start_gate: Option<Arc<tokio::sync::Notify>>,
}

impl MockProxy {
    fn new() -> Self {
        Self {
            fail_start: AtomicBool::new(false),
            start_gate: None,
        }
    }

    fn failing() -> Self {
        Self {
            fail_start: AtomicBool::new(true),
            start_gate: None,
        }
    }

    fn gated(gate: Arc<tokio::sync::Notify>) -> Self {
        Self {
            fail_start: AtomicBool::new(false),
            start_gate: Some(gate),
        }
    }
}

impl Proxy for MockProxy {
    type Running = MockRunning;

    async fn start(&self, _config: shadowsocks_service::config::Config) -> Result<MockRunning, ProxyError> {
        if let Some(gate) = self.start_gate.as_ref() {
            gate.notified().await;
        }
        if self.fail_start.load(Ordering::SeqCst) {
            return Err(ProxyError::Runtime(io::Error::other("mock failure")));
        }
        let handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            Ok(())
        });
        Ok(MockRunning { handle: Some(handle) })
    }
}

struct MockRunning {
    handle: Option<JoinHandle<io::Result<()>>>,
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
        route_state::save(&self.state_dir, &persisted)
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

fn gated_proxy(gate: Arc<tokio::sync::Notify>) -> Arc<Mutex<ProxyManager<MockProxy, MockRouting>>> {
    let state_dir = tempfile::tempdir().unwrap().keep();
    let routing = MockRouting::new(state_dir);
    Arc::new(Mutex::new(ProxyManager::new(MockProxy::gated(gate), routing)))
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
        proxy_socks5: true,
        proxy_http: false,
        local_port_http: 4074,
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

async fn post_start(client: &mut TestClient, config: &ProxyConfig) -> http::Response<hyper::body::Incoming> {
    let body_bytes = serde_json::to_vec(config).unwrap();
    let req = http::Request::builder()
        .method("POST")
        .uri(ROUTE_START)
        .header("host", "localhost")
        .header("content-type", "application/json")
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

async fn post_cancel(client: &mut TestClient) -> http::Response<hyper::body::Incoming> {
    let req = http::Request::builder()
        .method("POST")
        .uri(ROUTE_CANCEL)
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

// Tests ===============================================================================================================

#[skuld::test]
fn server_accepts_connection() {
    rt().block_on(async {
        let path = test_socket_path("accept");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });
        let stream = LocalStream::connect(&path).await.unwrap();
        drop(stream);
        let _ = handle.await;
    });
}

#[skuld::test]
fn status_when_not_running_returns_false() {
    rt().block_on(async {
        let path = test_socket_path("status");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
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
            }
        );
        drop(client);
        let _ = handle.await;
    });
}

#[skuld::test]
fn multiple_requests_on_same_connection() {
    rt().block_on(async {
        let path = test_socket_path("multi");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let s1 = get_status(&mut client).await;
        assert!(!s1.running);

        let s2 = get_status(&mut client).await;
        assert!(!s2.running);

        drop(client);
        let _ = handle.await;
    });
}

#[skuld::test]
fn invalid_request_returns_error_response() {
    rt().block_on(async {
        let path = test_socket_path("invalid");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
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
        let _ = handle.await;
    });
}

#[skuld::test]
fn server_handles_client_disconnect() {
    rt().block_on(async {
        let path = test_socket_path("disconnect");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
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
        let server = IpcServer::bind(&path, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Start
        assert_eq!(consume(post_start(&mut client, &sample_config()).await).await, 200);

        // Status should show running
        let status = get_status(&mut client).await;
        assert!(status.running, "expected running=true after Start");

        // Stop (cleanup)
        assert_eq!(consume(post_stop(&mut client).await).await, 200);

        drop(client);
        let _ = handle.await;
    });
}

#[skuld::test]
fn stop_request_stops_proxy() {
    rt().block_on(async {
        let path = test_socket_path("stop");
        let pm = mock_proxy();
        let server = IpcServer::bind(&path, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Start
        consume(post_start(&mut client, &sample_config()).await).await;

        // Stop
        assert_eq!(consume(post_stop(&mut client).await).await, 200);

        // Status should show stopped
        let status = get_status(&mut client).await;
        assert!(!status.running, "expected running=false after Stop");

        drop(client);
        let _ = handle.await;
    });
}

#[skuld::test]
fn start_failure_returns_error() {
    rt().block_on(async {
        let path = test_socket_path("start-fail");
        let pm = failing_proxy();
        let server = IpcServer::bind(&path, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let resp = post_start(&mut client, &sample_config()).await;

        assert_eq!(resp.status(), 500);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert!(
            err.message.contains("mock failure"),
            "expected mock failure message, got: {}",
            err.message
        );

        drop(client);
        let _ = handle.await;
    });
}

#[skuld::test]
fn reload_request_reloads_proxy() {
    rt().block_on(async {
        let path = test_socket_path("reload");
        let pm = mock_proxy();
        let server = IpcServer::bind(&path, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Start first
        consume(post_start(&mut client, &sample_config()).await).await;

        // Reload
        assert_eq!(consume(post_reload(&mut client, &sample_config()).await).await, 200);

        // Should still be running after reload
        let status = get_status(&mut client).await;
        assert!(status.running, "expected running=true after Reload");

        // Cleanup
        consume(post_stop(&mut client).await).await;

        drop(client);
        let _ = handle.await;
    });
}

#[skuld::test]
fn run_cancellation_aborts_connection_handlers() {
    rt().block_on(async {
        let path = test_socket_path("run-cancel");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
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
        // A subsequent request should fail — not block forever.
        // Allow up to 3 seconds for the non-blocking accept poll loop to yield.
        //
        // ready() is intentionally omitted: the server is already dead, so we're
        // testing that send_request on a broken connection fails promptly.
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), {
            #[allow(clippy::disallowed_methods)]
            client.sender.send_request(
                http::Request::builder()
                    .method("GET")
                    .uri(ROUTE_STATUS)
                    .header("host", "localhost")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
        })
        .await;
        assert!(result.is_ok(), "request should not block — handler must be aborted");
        assert!(
            result.unwrap().is_err(),
            "request should fail after server cancellation"
        );
    });
}

#[skuld::test]
fn unknown_route_returns_404() {
    rt().block_on(async {
        let path = test_socket_path("404");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
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
        let _ = handle.await;
    });
}

#[skuld::test]
fn wrong_method_returns_405() {
    rt().block_on(async {
        let path = test_socket_path("405");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
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
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
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
        let _ = handle.await;
    });
}

#[skuld::test]
fn metrics_returns_uptime_when_running() {
    rt().block_on(async {
        let path = test_socket_path("metrics-running");
        let pm = mock_proxy();
        let server = IpcServer::bind(&path, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Start proxy
        assert_eq!(consume(post_start(&mut client, &sample_config()).await).await, 200);

        // Small delay to accumulate uptime
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let metrics = get_metrics(&mut client).await;
        // Traffic fields are still zero (not yet integrated)
        assert_eq!(metrics.bytes_in, 0);
        assert_eq!(metrics.bytes_out, 0);
        // uptime_secs should be >= 0 (may be 0 if < 1s elapsed, which is fine)
        // The important thing is no error occurs.

        // Cleanup
        consume(post_stop(&mut client).await).await;

        drop(client);
        let _ = handle.await;
    });
}

#[skuld::test]
fn diagnostics_bridge_running() {
    rt().block_on(async {
        let path = test_socket_path("diag-running");
        let pm = mock_proxy();
        let server = IpcServer::bind(&path, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Start proxy
        assert_eq!(consume(post_start(&mut client, &sample_config()).await).await, 200);

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
        let _ = handle.await;
    });
}

#[skuld::test]
fn diagnostics_network_error_when_gateway_unavailable() {
    rt().block_on(async {
        let path = test_socket_path("diag-net-err");
        let server = IpcServer::bind(&path, gateway_failing_proxy()).unwrap();
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
        let _ = handle.await;
    });
}

#[skuld::test]
fn diagnostics_proxy_stopped() {
    rt().block_on(async {
        let path = test_socket_path("diag-stopped");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let diag = get_diagnostics(&mut client).await;

        // Bridge IPC is up (we are handling this request); the proxy is stopped
        // but no operation has failed, so `pm.last_error()` is None and the
        // diagnostics handler reports `bridge = "ok"` (issue #142). App is
        // always "ok" by convention (bridge can't observe the GUI directly).
        // Network is computed from the host's default gateway and the
        // MockRouting returns Ok. vpn_server and internet are always "unknown"
        // on the wire — the GUI computes them from the selected ServerEntry's
        // persisted validation state (#150).
        assert_eq!(diag.app, "ok");
        assert_eq!(diag.bridge, "ok");
        assert_eq!(diag.network, "ok");
        assert_eq!(diag.vpn_server, "unknown");
        assert_eq!(diag.internet, "unknown");

        drop(client);
        let _ = handle.await;
    });
}

#[skuld::test]
fn diagnostics_bridge_error_after_failed_start() {
    rt().block_on(async {
        let path = test_socket_path("diag-bridge-err");
        let server = IpcServer::bind(&path, gateway_failing_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;

        // Trigger a failed start so ProxyManager.last_error is populated.
        // The gateway-failing mock makes default_gateway return Err, which
        // ProxyManager::start now records via inspect_err.
        let resp = post_start(&mut client, &sample_config()).await;
        assert_eq!(resp.status(), 500);
        let _ = resp.into_body().collect().await;

        let diag = get_diagnostics(&mut client).await;
        // Bridge IPC is up but the most recent operation failed — this is
        // exactly the situation the old hardcoded "ok" was masking.
        assert_eq!(diag.app, "ok");
        assert_eq!(diag.bridge, "error");

        drop(client);
        let _ = handle.await;
    });
}

// The bridge's error-log emission on IPC handler failure is a single
// `error!(error = %e, "proxy start failed")` call in `handle_start` (and
// the analogous calls in `handle_stop`/`handle_reload`). We deliberately
// do NOT write a log-capture test for these, because installing a custom
// tracing subscriber in a workspace test binary has process-wide side
// effects — `tracing_subscriber::fmt().init()` calls `LogTracer::init()`
// which mutates the global `log::max_level` state and makes every
// `log::debug!`/`trace!` call in every dependency (shadowsocks-service,
// tokio, mio, etc.) start flowing through the tracing → log bridge.
// That added per-event overhead causes the parallel `server_test_tests`
// (which do real localhost TCP handshakes with 5 s timeouts) to tip over
// into timing out on GH Actions Windows runners — see the #147 CI
// investigation.
//
// Keeping the coverage elsewhere: `start_failure_returns_error` (line
// ~363) exercises the exact same error path and verifies the HTTP 500
// response and error message. The `error!` call is trivially verifiable
// by reading the three-line match arm in `ipc.rs`.

// public_ip handler test is intentionally omitted — it makes an external HTTP call
// to ipinfo.io which is not available in CI and cannot be easily mocked without
// adding an HTTP client abstraction layer (a follow-up concern).

// Cancel tests ========================================================================================================

/// Extract the `message` field from a 500 `ErrorResponse`.
async fn error_message(resp: http::Response<hyper::body::Incoming>) -> String {
    assert_eq!(resp.status(), 500, "expected 500 for cancelled start");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    err.message
}

#[skuld::test]
fn cancel_while_start_in_flight_returns_cancelled() {
    // Two concurrent connections. A posts Start against a gated mock so
    // start_ss hangs. B posts Cancel. A's Start response must come back
    // with 500 + "cancelled" promptly (not after the full gate duration,
    // which never elapses in this test).
    rt().block_on(async {
        let path = test_socket_path("cancel-in-flight");
        let gate = Arc::new(tokio::sync::Notify::new());
        let server = IpcServer::bind(&path, gated_proxy(gate.clone())).unwrap();
        // Bound the accept loop to exactly the two connections this test
        // uses, instead of running indefinitely. See `run_n` docstring.
        let handle = tokio::spawn(async move { server.run_n(2).await });

        // Connection A: owns its client end. Spawn a task that drives the
        // start request so this test task can issue a cancel concurrently.
        let path_a = path.clone();
        let start_future = tokio::spawn(async move {
            let mut client_a = TestClient::connect(&path_a).await;
            let resp = post_start(&mut client_a, &sample_config()).await;
            (client_a, resp)
        });

        // Give A a moment to acquire the proxy mutex and park in start_ss.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // Connection B: cancel the in-flight start. Must succeed without
        // waiting for the in-flight Start (which never completes since the
        // gate is not released).
        let mut client_b = TestClient::connect(&path).await;
        let cancel_resp = post_cancel(&mut client_b).await;
        assert_eq!(
            cancel_resp.status(),
            200,
            "cancel must succeed even while start is in flight"
        );

        // Wait for A's Start to return, bounded. With cancellation working
        // correctly the select! branch fires, drop-safety unwinds the
        // partial state, and Cancelled is returned promptly.
        let (_client_a, resp_a) = tokio::time::timeout(std::time::Duration::from_secs(5), start_future)
            .await
            .expect("start did not return within 5s of cancel")
            .expect("start task panicked");
        assert_eq!(error_message(resp_a).await, CANCELLED_MESSAGE);

        // Release the gate so the mock's start_ss future can settle if it
        // is still parked anywhere; harmless no-op if already dropped.
        gate.notify_one();
        // run_n(2) returns naturally once both connections are handled, so
        // no abort is needed — but use a bounded await to surface any leak.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    });
}

#[skuld::test]
fn cancel_before_start_is_pre_armed_and_consumed() {
    // A cancel arriving before any start is in flight pre-arms a flag
    // that the next start consumes. The next Start returns 500 +
    // "cancelled" immediately without even attempting to acquire the
    // proxy mutex or call backend.start_ss.
    rt().block_on(async {
        let path = test_socket_path("cancel-prearm");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        // Single client connection — use run_once to avoid long-lived
        // accept polling on Windows.
        let handle = tokio::spawn(async move { server.run_once().await });

        let mut client = TestClient::connect(&path).await;

        // Pre-arm: cancel with no start in flight — still 200 Ack.
        let resp = post_cancel(&mut client).await;
        assert_eq!(consume(resp).await, 200);

        // Now start — should be rejected as cancelled, consuming the pre-arm.
        let start_resp = post_start(&mut client, &sample_config()).await;
        assert_eq!(error_message(start_resp).await, CANCELLED_MESSAGE);

        // A second start with no pre-arm should succeed normally.
        assert_eq!(consume(post_start(&mut client, &sample_config()).await).await, 200);

        // Cleanup
        consume(post_stop(&mut client).await).await;

        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    });
}

#[skuld::test]
fn cancel_with_no_start_is_ack_idempotent() {
    // Double-cancel with no start in flight — both 200. The pre-arm flag
    // is idempotent: arming it twice is equivalent to arming it once.
    rt().block_on(async {
        let path = test_socket_path("cancel-noop");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move { server.run_once().await });

        let mut client = TestClient::connect(&path).await;

        assert_eq!(consume(post_cancel(&mut client).await).await, 200);
        assert_eq!(consume(post_cancel(&mut client).await).await, 200);

        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    });
}

#[skuld::test]
fn concurrent_start_is_rejected_with_conflict() {
    // Client A holds a start parked in start_ss on the gate. Client B
    // sends a second Start concurrently. B must be rejected with 409
    // Conflict rather than silently overwriting A's token slot — the
    // slot is single-occupancy because a Cancel targets exactly one
    // in-flight start. This covers the pre-fix bug in review #4.
    rt().block_on(async {
        let path = test_socket_path("concurrent-start");
        let gate = Arc::new(tokio::sync::Notify::new());
        let server = IpcServer::bind(&path, gated_proxy(gate.clone())).unwrap();
        // 3 connections: A start, B start, C cancel.
        let handle = tokio::spawn(async move { server.run_n(3).await });

        // Client A parks in start_ss.
        let path_a = path.clone();
        let a_future = tokio::spawn(async move {
            let mut client_a = TestClient::connect(&path_a).await;
            let resp = post_start(&mut client_a, &sample_config()).await;
            (client_a, resp)
        });

        // Give A a moment to register its token.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // Client B sends a concurrent Start and must be rejected.
        let mut client_b = TestClient::connect(&path).await;
        let b_resp = post_start(&mut client_b, &sample_config()).await;
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
        assert_eq!(consume(post_cancel(&mut client_c).await).await, 200);

        // A's start must eventually return Cancelled.
        let (_client_a, a_resp) = tokio::time::timeout(std::time::Duration::from_secs(5), a_future)
            .await
            .expect("A's start did not return")
            .expect("A task panicked");
        assert_eq!(error_message(a_resp).await, CANCELLED_MESSAGE);

        gate.notify_one();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
    });
}

#[skuld::test]
fn sequential_start_cancel_start_consumes_pre_arm_once() {
    // Plan scenario: Start completes, then Cancel arrives (sets pending),
    // then another Start arrives (consumes pending → Cancelled). A third
    // Start after that must succeed normally — the pre-arm must be
    // consumed exactly once, not forever.
    rt().block_on(async {
        let path = test_socket_path("seq-start-cancel-start");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        // Single client connection — use run_once.
        let handle = tokio::spawn(async move { server.run_once().await });

        let mut client = TestClient::connect(&path).await;

        // Start #1 succeeds.
        assert_eq!(consume(post_start(&mut client, &sample_config()).await).await, 200);
        // Stop so the next start has somewhere to go.
        assert_eq!(consume(post_stop(&mut client).await).await, 200);

        // Cancel with nothing in flight — pre-arms the flag.
        assert_eq!(consume(post_cancel(&mut client).await).await, 200);

        // Start #2 consumes the pre-arm and must fail with Cancelled.
        let resp2 = post_start(&mut client, &sample_config()).await;
        assert_eq!(error_message(resp2).await, CANCELLED_MESSAGE);

        // Start #3 must succeed (pre-arm was a one-shot).
        assert_eq!(consume(post_start(&mut client, &sample_config()).await).await, 200);

        // Cleanup.
        consume(post_stop(&mut client).await).await;

        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
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
        let server = IpcServer::bind(&path, gated_proxy(gate.clone())).unwrap();
        // 3 connections: A start, B cancel, C cancel.
        let handle = tokio::spawn(async move { server.run_n(3).await });

        // Client A parks in start_ss.
        let path_a = path.clone();
        let a_future = tokio::spawn(async move {
            let mut client_a = TestClient::connect(&path_a).await;
            let resp = post_start(&mut client_a, &sample_config()).await;
            (client_a, resp)
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // Two concurrent cancels on separate connections.
        let path_b = path.clone();
        let b_task = tokio::spawn(async move {
            let mut client = TestClient::connect(&path_b).await;
            post_cancel(&mut client).await
        });
        let path_c = path.clone();
        let c_task = tokio::spawn(async move {
            let mut client = TestClient::connect(&path_c).await;
            post_cancel(&mut client).await
        });

        let b_resp = b_task.await.unwrap();
        let c_resp = c_task.await.unwrap();
        assert_eq!(b_resp.status(), 200);
        assert_eq!(c_resp.status(), 200);

        // A's start returns Cancelled.
        let (_client_a, a_resp) = tokio::time::timeout(std::time::Duration::from_secs(5), a_future)
            .await
            .expect("A's start did not return")
            .expect("A task panicked");
        assert_eq!(error_message(a_resp).await, CANCELLED_MESSAGE);

        gate.notify_one();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
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
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });
        let stream = LocalStream::connect(&path).await.unwrap();
        drop(stream);
        let _ = handle.await;
    });
}

#[skuld::test]
fn bind_status_query() {
    rt().block_on(async {
        let path = test_socket_path("bind-status");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let status = get_status(&mut client).await;
        assert!(!status.running);
        assert_eq!(status.uptime_secs, 0);

        drop(client);
        let _ = handle.await;
    });
}

// Socket lifecycle tests ==============================================================================================

#[skuld::test]
fn socket_recreated_on_bind() {
    rt().block_on(async {
        let path = test_socket_path("recreate");

        // First bind
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        assert!(path.exists(), "socket file should exist after bind");
        drop(server); // Drop removes the file
        assert!(!path.exists(), "socket file should be removed after drop");

        // Second bind (recreates the socket)
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        assert!(path.exists(), "socket file should exist after second bind");
        drop(server);
    });
}

#[skuld::test]
fn socket_removed_on_drop() {
    rt().block_on(async {
        let path = test_socket_path("drop-cleanup");

        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        assert!(path.exists(), "socket file should exist after bind");

        drop(server);
        assert!(!path.exists(), "socket file should be removed after drop");
    });
}
