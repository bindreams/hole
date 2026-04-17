use crate::proxy::{Proxy, ProxyError, RunningProxy};
use crate::proxy_manager::ProxyManager;
use crate::socket::LocalStream;
use bytes::Bytes;
use hole_common::protocol::{StatusResponse, ROUTE_STATUS};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use tokio::task::JoinHandle;
use tun_engine::gateway::GatewayInfo;
use tun_engine::routing::Routing;
use tun_engine::RoutingError;

// Minimal stub types used only for the foreground-run IPC smoke test.
// None of their methods are exercised by this test — we only construct
// the ProxyManager so `IpcServer::bind` can be bound and the status
// endpoint queried. A shared test-support module would be overkill for
// one use.

struct StubProxy;

impl Proxy for StubProxy {
    type Running = StubRunning;
    async fn start(&self, _config: shadowsocks_service::config::Config) -> Result<StubRunning, ProxyError> {
        Ok(StubRunning {
            handle: Some(tokio::spawn(async { std::future::pending::<io::Result<()>>().await })),
        })
    }
}

struct StubRunning {
    handle: Option<JoinHandle<io::Result<()>>>,
}

impl RunningProxy for StubRunning {
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

impl Drop for StubRunning {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

struct StubRouting {
    state_dir: PathBuf,
}

impl StubRouting {
    fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }
}

impl Routing for StubRouting {
    type Installed = StubRoutes;
    fn install(&self, _: &str, _: IpAddr, _: IpAddr, _: &str) -> Result<StubRoutes, RoutingError> {
        Ok(StubRoutes {
            _state_dir: self.state_dir.clone(),
        })
    }
    fn default_gateway(&self) -> Result<GatewayInfo, RoutingError> {
        Ok(GatewayInfo {
            gateway_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            interface_name: "StubIf".into(),
            interface_index: 1,
            ipv6_available: false,
        })
    }
}

struct StubRoutes {
    // Held only so tests can replicate production-like state-dir behavior
    // if they ever need it. Currently unused — the foreground test never
    // calls start, just binds the IPC server and queries status.
    _state_dir: PathBuf,
}

fn test_socket_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hole-fg-test-{}-{suffix}.sock", std::process::id()))
}

/// Connect to the server with retry (avoids flaky sleep-based waits).
async fn connect_with_retry(path: &Path) -> LocalStream {
    for _ in 0..50 {
        match LocalStream::connect(path).await {
            Ok(stream) => return stream,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    panic!("failed to connect to foreground server after retries");
}

#[skuld::test]
fn foreground_run_accepts_ipc_and_shuts_down() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let path = test_socket_path("fg-ipc");
        let state_dir = tempfile::tempdir().unwrap().keep();

        // Use a channel to trigger graceful shutdown (simulates Ctrl+C)
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let path_clone = path.clone();
        let server_handle = tokio::spawn(async move {
            let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(ProxyManager::new(
                StubProxy,
                StubRouting::new(state_dir),
            )));
            let proxy_shutdown = std::sync::Arc::clone(&proxy);

            let server = crate::ipc::IpcServer::bind(&path_clone, proxy).unwrap();

            tokio::select! {
                result = server.run() => {
                    if let Err(e) = result {
                        tracing::error!(error = %e, "IPC server error");
                    }
                }
                _ = shutdown_rx => {
                    tracing::info!("test shutdown signal received");
                }
            }

            // This is the graceful shutdown path we want to verify runs
            let mut pm = proxy_shutdown.lock().await;
            pm.stop().await.unwrap();
        });

        // Connect with retry instead of fixed sleep
        let stream = connect_with_retry(&path).await;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await.unwrap();
        let _conn = tokio::spawn(async move {
            let _ = conn.await;
        });

        // Query status
        sender.ready().await.unwrap();
        #[allow(clippy::disallowed_methods)]
        let resp = sender
            .send_request(
                http::Request::builder()
                    .method("GET")
                    .uri(ROUTE_STATUS)
                    .header("host", "localhost")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let status: StatusResponse = serde_json::from_slice(&body).unwrap();
        assert!(!status.running);

        // Trigger graceful shutdown and verify the task completes cleanly
        shutdown_tx.send(()).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), server_handle).await;
        assert!(result.is_ok(), "server should shut down within 5s");
        result.unwrap().unwrap(); // Verify no panic during shutdown
    });
}
