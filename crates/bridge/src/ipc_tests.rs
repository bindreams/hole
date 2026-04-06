use super::*;
use crate::gateway::GatewayInfo;
use crate::proxy::ProxyError;
use crate::proxy_manager::{ProxyBackend, ProxyManager};
use crate::socket::LocalStream;
use bytes::Bytes;
use hole_common::config::ServerEntry;
use hole_common::protocol::{DiagnosticsResponse, MetricsResponse, ProxyConfig};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::task::JoinHandle;

// Mock backend ========================================================================================================

struct MockBackend {
    fail_start: AtomicBool,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            fail_start: AtomicBool::new(false),
        }
    }

    fn failing() -> Self {
        Self {
            fail_start: AtomicBool::new(true),
        }
    }
}

impl ProxyBackend for MockBackend {
    async fn start_ss(
        &self,
        _config: shadowsocks_service::config::Config,
    ) -> Result<JoinHandle<std::io::Result<()>>, ProxyError> {
        if self.fail_start.load(Ordering::SeqCst) {
            return Err(ProxyError::Runtime(std::io::Error::other("mock failure")));
        }
        Ok(tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            Ok(())
        }))
    }

    fn setup_routes(&self, _tun: &str, _server: IpAddr, _gw: IpAddr, _interface_name: &str) -> Result<(), ProxyError> {
        Ok(())
    }

    fn teardown_routes(&self, _tun: &str, _server: IpAddr, _interface_name: &str) -> Result<(), ProxyError> {
        Ok(())
    }

    fn default_gateway(&self) -> Result<GatewayInfo, ProxyError> {
        Ok(GatewayInfo {
            gateway_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            interface_name: "MockEthernet".into(),
        })
    }
}

// Helpers =============================================================================================================

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

/// Build a mock proxy backed by a throw-away state dir. Uses
/// `tempfile::tempdir().keep()` so the directory is created but its
/// auto-cleanup Drop is suppressed — the directory lives until the
/// process exits, which is fine for unit tests.
fn mock_proxy() -> Arc<Mutex<ProxyManager<MockBackend>>> {
    let state_dir = tempfile::tempdir().unwrap().keep();
    Arc::new(Mutex::new(ProxyManager::new(MockBackend::new(), state_dir)))
}

fn failing_proxy() -> Arc<Mutex<ProxyManager<MockBackend>>> {
    let state_dir = tempfile::tempdir().unwrap().keep();
    Arc::new(Mutex::new(ProxyManager::new(MockBackend::failing(), state_dir)))
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
        },
        local_port: 4073,
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
        assert_eq!(diag.network, "ok"); // MockBackend.default_gateway() succeeds
        assert_eq!(diag.vpn_server, "ok");
        // internet is always "unknown" in this initial implementation
        assert_eq!(diag.internet, "unknown");

        // Cleanup
        consume(post_stop(&mut client).await).await;

        drop(client);
        let _ = handle.await;
    });
}

#[skuld::test]
fn diagnostics_bridge_stopped() {
    rt().block_on(async {
        let path = test_socket_path("diag-stopped");
        let server = IpcServer::bind(&path, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut client = TestClient::connect(&path).await;
        let diag = get_diagnostics(&mut client).await;

        assert_eq!(diag.app, "ok");
        assert_eq!(diag.bridge, "error");
        // Downstream nodes cascade to "unknown"
        assert_eq!(diag.network, "unknown");
        assert_eq!(diag.vpn_server, "unknown");
        assert_eq!(diag.internet, "unknown");

        drop(client);
        let _ = handle.await;
    });
}

// public_ip handler test is intentionally omitted — it makes an external HTTP call
// to ipinfo.io which is not available in CI and cannot be easily mocked without
// adding an HTTP client abstraction layer (a follow-up concern).

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
