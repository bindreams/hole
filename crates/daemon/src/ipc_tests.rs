use super::*;
use crate::proxy::ProxyError;
use crate::proxy_manager::{ProxyBackend, ProxyManager};
use crate::socket::LocalStream;
use bytes::Bytes;
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::task::JoinHandle;

// Mock backend =====

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

    fn setup_routes(&self, _tun: &str, _server: IpAddr, _gw: IpAddr) -> Result<(), ProxyError> {
        Ok(())
    }

    fn teardown_routes(&self, _server: IpAddr) -> Result<(), ProxyError> {
        Ok(())
    }

    fn default_gateway(&self) -> Result<IpAddr, ProxyError> {
        Ok(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
    }
}

// Helpers =====

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

fn mock_proxy() -> Arc<Mutex<ProxyManager<MockBackend>>> {
    Arc::new(Mutex::new(ProxyManager::new(MockBackend::new())))
}

fn failing_proxy() -> Arc<Mutex<ProxyManager<MockBackend>>> {
    Arc::new(Mutex::new(ProxyManager::new(MockBackend::failing())))
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
        plugin_path: None,
    }
}

fn test_socket_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hole-ipc-test-{}-{suffix}.sock", std::process::id()))
}

/// Connect to a test IPC server and perform HTTP/1.1 handshake.
async fn http_connect(path: &Path) -> (http1::SendRequest<Full<Bytes>>, tokio::task::JoinHandle<()>) {
    let stream = LocalStream::connect(path).await.unwrap();
    let io = TokioIo::new(stream);
    let (sender, conn) = http1::handshake(io).await.unwrap();
    let handle = tokio::spawn(async move {
        let _ = conn.await;
    });
    (sender, handle)
}

async fn get_status(sender: &mut http1::SendRequest<Full<Bytes>>) -> StatusResponse {
    let req = http::Request::builder()
        .method("GET")
        .uri(ROUTE_STATUS)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
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

async fn post_start(
    sender: &mut http1::SendRequest<Full<Bytes>>,
    config: &ProxyConfig,
) -> http::Response<hyper::body::Incoming> {
    let body_bytes = serde_json::to_vec(config).unwrap();
    let req = http::Request::builder()
        .method("POST")
        .uri(ROUTE_START)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap();
    sender.send_request(req).await.unwrap()
}

async fn post_stop(sender: &mut http1::SendRequest<Full<Bytes>>) -> http::Response<hyper::body::Incoming> {
    let req = http::Request::builder()
        .method("POST")
        .uri(ROUTE_STOP)
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    sender.send_request(req).await.unwrap()
}

async fn post_reload(
    sender: &mut http1::SendRequest<Full<Bytes>>,
    config: &ProxyConfig,
) -> http::Response<hyper::body::Incoming> {
    let body_bytes = serde_json::to_vec(config).unwrap();
    let req = http::Request::builder()
        .method("POST")
        .uri(ROUTE_RELOAD)
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap();
    sender.send_request(req).await.unwrap()
}

// Tests =====

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

        let (mut sender, conn_handle) = http_connect(&path).await;
        let status = get_status(&mut sender).await;

        assert_eq!(
            status,
            StatusResponse {
                running: false,
                uptime_secs: 0,
                error: None,
            }
        );
        drop(sender);
        let _ = conn_handle.await;
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

        let (mut sender, conn_handle) = http_connect(&path).await;
        let s1 = get_status(&mut sender).await;
        assert!(!s1.running);

        let s2 = get_status(&mut sender).await;
        assert!(!s2.running);

        drop(sender);
        let _ = conn_handle.await;
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

        let (mut sender, conn_handle) = http_connect(&path).await;

        // Send garbage body to start endpoint
        let req = http::Request::builder()
            .method("POST")
            .uri(ROUTE_START)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from("not valid json!!")))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert!(resp.status().is_client_error());

        drop(sender);
        let _ = conn_handle.await;
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

        let (mut sender, conn_handle) = http_connect(&path).await;

        // Start
        assert_eq!(consume(post_start(&mut sender, &sample_config()).await).await, 200);

        // Status should show running
        let status = get_status(&mut sender).await;
        assert!(status.running, "expected running=true after Start");

        // Stop (cleanup)
        assert_eq!(consume(post_stop(&mut sender).await).await, 200);

        drop(sender);
        let _ = conn_handle.await;
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

        let (mut sender, conn_handle) = http_connect(&path).await;

        // Start
        consume(post_start(&mut sender, &sample_config()).await).await;

        // Stop
        assert_eq!(consume(post_stop(&mut sender).await).await, 200);

        // Status should show stopped
        let status = get_status(&mut sender).await;
        assert!(!status.running, "expected running=false after Stop");

        drop(sender);
        let _ = conn_handle.await;
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

        let (mut sender, conn_handle) = http_connect(&path).await;
        let resp = post_start(&mut sender, &sample_config()).await;

        assert_eq!(resp.status(), 500);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert!(
            err.message.contains("mock failure"),
            "expected mock failure message, got: {}",
            err.message
        );

        drop(sender);
        let _ = conn_handle.await;
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

        let (mut sender, conn_handle) = http_connect(&path).await;

        // Start first
        consume(post_start(&mut sender, &sample_config()).await).await;

        // Reload
        assert_eq!(consume(post_reload(&mut sender, &sample_config()).await).await, 200);

        // Should still be running after reload
        let status = get_status(&mut sender).await;
        assert!(status.running, "expected running=true after Reload");

        // Cleanup
        consume(post_stop(&mut sender).await).await;

        drop(sender);
        let _ = conn_handle.await;
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
        let (mut sender, _conn_handle) = http_connect(&path).await;
        let status = get_status(&mut sender).await;
        assert!(!status.running);

        // Cancel the server (simulates shutdown via select!)
        handle.abort();
        let _ = handle.await;

        // The connection handler should have been aborted by JoinSet::drop.
        // A subsequent request should fail — not block forever.
        // Allow up to 3 seconds for the non-blocking accept poll loop to yield.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            sender.send_request(
                http::Request::builder()
                    .method("GET")
                    .uri(ROUTE_STATUS)
                    .header("host", "localhost")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            ),
        )
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

        let (mut sender, conn_handle) = http_connect(&path).await;
        let req = http::Request::builder()
            .method("GET")
            .uri("/v1/nonexistent")
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 404);

        drop(sender);
        let _ = conn_handle.await;
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

        let (mut sender, conn_handle) = http_connect(&path).await;
        let req = http::Request::builder()
            .method("POST")
            .uri(ROUTE_STATUS)
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 405);

        drop(sender);
        let _ = conn_handle.await;
        let _ = handle.await;
    });
}

// Socket lifecycle tests =====

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
