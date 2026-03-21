use super::*;
use crate::proxy::ProxyError;
use crate::proxy_manager::{ProxyBackend, ProxyManager};
use bytes::Bytes;
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use interprocess::local_socket::traits::tokio::Stream as StreamTrait;
use std::net::{IpAddr, Ipv4Addr};
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

/// Generate a test socket name. On macOS, returns a temp file path.
#[cfg(target_os = "windows")]
fn test_socket_name(suffix: &str) -> String {
    format!("hole-test-{suffix}")
}

#[cfg(target_os = "macos")]
fn test_socket_name(suffix: &str) -> String {
    format!("/tmp/hole-test-{suffix}.sock")
}

/// Connect to a test IPC server and perform HTTP/1.1 handshake.
async fn http_connect(name: &str) -> (http1::SendRequest<Full<Bytes>>, tokio::task::JoinHandle<()>) {
    let stream = connect_raw(name).await;
    let io = TokioIo::new(stream);
    let (sender, conn) = http1::handshake(io).await.unwrap();
    let handle = tokio::spawn(async move {
        let _ = conn.await;
    });
    (sender, handle)
}

async fn connect_raw(name: &str) -> interprocess::local_socket::tokio::Stream {
    #[cfg(target_os = "windows")]
    {
        use interprocess::local_socket::{GenericNamespaced, ToNsName};
        let ns_name = name.to_ns_name::<GenericNamespaced>().unwrap();
        interprocess::local_socket::tokio::Stream::connect(ns_name)
            .await
            .unwrap()
    }
    #[cfg(target_os = "macos")]
    {
        use interprocess::local_socket::{GenericFilePath, ToFsName};
        let fs_name = name.to_fs_name::<GenericFilePath>().unwrap();
        interprocess::local_socket::tokio::Stream::connect(fs_name)
            .await
            .unwrap()
    }
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

/// Consume and discard a response body (required before next request on keep-alive).
async fn drain(resp: http::Response<hyper::body::Incoming>) -> u16 {
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
        let name = &test_socket_name("accept");
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });
        let stream = connect_raw(name).await;
        drop(stream);
        let _ = handle.await;
    });
}

#[skuld::test]
fn status_when_not_running_returns_false() {
    rt().block_on(async {
        let name = &test_socket_name("status");
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let (mut sender, conn_handle) = http_connect(name).await;
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
        let name = &test_socket_name("multi");
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let (mut sender, conn_handle) = http_connect(name).await;
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
        let name = &test_socket_name("invalid");
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let (mut sender, conn_handle) = http_connect(name).await;

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
        let name = &test_socket_name("disconnect");
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let stream = connect_raw(name).await;
        drop(stream);

        handle.await.unwrap();
    });
}

#[skuld::test]
fn start_request_starts_proxy() {
    rt().block_on(async {
        let name = &test_socket_name("start");
        let pm = mock_proxy();
        let server = IpcServer::bind(name, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let (mut sender, conn_handle) = http_connect(name).await;

        // Start
        assert_eq!(drain(post_start(&mut sender, &sample_config()).await).await, 200);

        // Status should show running
        let status = get_status(&mut sender).await;
        assert!(status.running, "expected running=true after Start");

        // Stop (cleanup)
        assert_eq!(drain(post_stop(&mut sender).await).await, 200);

        drop(sender);
        let _ = conn_handle.await;
        let _ = handle.await;
    });
}

#[skuld::test]
fn stop_request_stops_proxy() {
    rt().block_on(async {
        let name = &test_socket_name("stop");
        let pm = mock_proxy();
        let server = IpcServer::bind(name, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let (mut sender, conn_handle) = http_connect(name).await;

        // Start
        drain(post_start(&mut sender, &sample_config()).await).await;

        // Stop
        assert_eq!(drain(post_stop(&mut sender).await).await, 200);

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
        let name = &test_socket_name("start-fail");
        let pm = failing_proxy();
        let server = IpcServer::bind(name, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let (mut sender, conn_handle) = http_connect(name).await;
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
        let name = &test_socket_name("reload");
        let pm = mock_proxy();
        let server = IpcServer::bind(name, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let (mut sender, conn_handle) = http_connect(name).await;

        // Start first
        drain(post_start(&mut sender, &sample_config()).await).await;

        // Reload
        assert_eq!(drain(post_reload(&mut sender, &sample_config()).await).await, 200);

        // Should still be running after reload
        let status = get_status(&mut sender).await;
        assert!(status.running, "expected running=true after Reload");

        // Cleanup
        drain(post_stop(&mut sender).await).await;

        drop(sender);
        let _ = conn_handle.await;
        let _ = handle.await;
    });
}

#[skuld::test]
fn run_cancellation_aborts_connection_handlers() {
    rt().block_on(async {
        let name = &test_socket_name("run-cancel");
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        // Connect a client so there's an active connection handler task
        let (mut sender, _conn_handle) = http_connect(name).await;
        let status = get_status(&mut sender).await;
        assert!(!status.running);

        // Cancel the server (simulates shutdown via select!)
        handle.abort();
        let _ = handle.await;

        // The connection handler should have been aborted by JoinSet::drop.
        // A subsequent request should fail — not block forever.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
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
        let name = &test_socket_name("404");
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let (mut sender, conn_handle) = http_connect(name).await;
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
        let name = &test_socket_name("405");
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let (mut sender, conn_handle) = http_connect(name).await;
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
