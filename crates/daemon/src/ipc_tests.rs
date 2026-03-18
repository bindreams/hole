use super::*;
use crate::proxy::ProxyError;
use crate::proxy_manager::{ProxyBackend, ProxyManager};
use hole_common::config::ServerEntry;
use hole_common::protocol::{encode, DaemonRequest, DaemonResponse, ProxyConfig};
use interprocess::local_socket::{traits::tokio::Stream as StreamTrait, GenericNamespaced, ToNsName};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

async fn connect_to(name: &str) -> interprocess::local_socket::tokio::Stream {
    let name = name.to_ns_name::<GenericNamespaced>().unwrap();
    interprocess::local_socket::tokio::Stream::connect(name).await.unwrap()
}

async fn send_request(stream: &mut interprocess::local_socket::tokio::Stream, req: &DaemonRequest) -> DaemonResponse {
    let bytes = encode(req).unwrap();
    stream.write_all(&bytes).await.unwrap();

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.unwrap();

    serde_json::from_slice(&body).unwrap()
}

// Existing tests (updated to provide ProxyManager) =====

#[skuld::test]
fn server_accepts_connection() {
    rt().block_on(async {
        let name = "hole-test-accept";
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let _handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });
        let _stream = connect_to(name).await;
    });
}

#[skuld::test]
fn status_when_not_running_returns_false() {
    rt().block_on(async {
        let name = "hole-test-status";
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut stream = connect_to(name).await;
        let resp = send_request(&mut stream, &DaemonRequest::Status).await;

        assert_eq!(
            resp,
            DaemonResponse::Status {
                running: false,
                uptime_secs: 0,
                error: None,
            }
        );
        drop(stream);
        let _ = handle.await;
    });
}

#[skuld::test]
fn multiple_requests_on_same_connection() {
    rt().block_on(async {
        let name = "hole-test-multi";
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut stream = connect_to(name).await;
        let resp1 = send_request(&mut stream, &DaemonRequest::Status).await;
        assert!(matches!(resp1, DaemonResponse::Status { .. }));

        let resp2 = send_request(&mut stream, &DaemonRequest::Status).await;
        assert!(matches!(resp2, DaemonResponse::Status { .. }));

        drop(stream);
        let _ = handle.await;
    });
}

#[skuld::test]
fn invalid_request_returns_error_response() {
    rt().block_on(async {
        let name = "hole-test-invalid";
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut stream = connect_to(name).await;

        // Send garbage with a valid length prefix
        let garbage = b"not valid json!!";
        let len = (garbage.len() as u32).to_be_bytes();
        stream.write_all(&len).await.unwrap();
        stream.write_all(garbage).await.unwrap();

        // Should get an error response
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await.unwrap();
        let body_len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body).await.unwrap();

        let resp: DaemonResponse = serde_json::from_slice(&body).unwrap();
        assert!(matches!(resp, DaemonResponse::Error { .. }));

        drop(stream);
        let _ = handle.await;
    });
}

#[skuld::test]
fn server_handles_client_disconnect() {
    rt().block_on(async {
        let name = "hole-test-disconnect";
        let server = IpcServer::bind(name, mock_proxy()).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let stream = connect_to(name).await;
        drop(stream);

        handle.await.unwrap();
    });
}

// New tests: dispatch → ProxyManager =====

#[skuld::test]
fn start_request_starts_proxy() {
    rt().block_on(async {
        let name = "hole-test-start";
        let pm = mock_proxy();
        let server = IpcServer::bind(name, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut stream = connect_to(name).await;

        // Start
        let resp = send_request(
            &mut stream,
            &DaemonRequest::Start {
                config: sample_config(),
            },
        )
        .await;
        assert_eq!(resp, DaemonResponse::Ack);

        // Status should show running
        let resp = send_request(&mut stream, &DaemonRequest::Status).await;
        match resp {
            DaemonResponse::Status { running, .. } => assert!(running, "expected running=true after Start"),
            other => panic!("expected Status response, got {other:?}"),
        }

        // Stop (cleanup)
        let resp = send_request(&mut stream, &DaemonRequest::Stop).await;
        assert_eq!(resp, DaemonResponse::Ack);

        drop(stream);
        let _ = handle.await;
    });
}

#[skuld::test]
fn stop_request_stops_proxy() {
    rt().block_on(async {
        let name = "hole-test-stop";
        let pm = mock_proxy();
        let server = IpcServer::bind(name, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut stream = connect_to(name).await;

        // Start
        send_request(
            &mut stream,
            &DaemonRequest::Start {
                config: sample_config(),
            },
        )
        .await;

        // Stop
        let resp = send_request(&mut stream, &DaemonRequest::Stop).await;
        assert_eq!(resp, DaemonResponse::Ack);

        // Status should show stopped
        let resp = send_request(&mut stream, &DaemonRequest::Status).await;
        match resp {
            DaemonResponse::Status { running, .. } => assert!(!running, "expected running=false after Stop"),
            other => panic!("expected Status response, got {other:?}"),
        }

        drop(stream);
        let _ = handle.await;
    });
}

#[skuld::test]
fn start_failure_returns_error() {
    rt().block_on(async {
        let name = "hole-test-start-fail";
        let pm = failing_proxy();
        let server = IpcServer::bind(name, pm).unwrap();
        let handle = tokio::spawn(async move {
            server.run_once().await.unwrap();
        });

        let mut stream = connect_to(name).await;
        let resp = send_request(
            &mut stream,
            &DaemonRequest::Start {
                config: sample_config(),
            },
        )
        .await;

        match resp {
            DaemonResponse::Error { message } => {
                assert!(
                    message.contains("mock failure"),
                    "expected mock failure message, got: {message}"
                );
            }
            other => panic!("expected Error response, got {other:?}"),
        }

        drop(stream);
        let _ = handle.await;
    });
}
