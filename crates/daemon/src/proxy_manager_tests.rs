use super::*;
use crate::proxy::ProxyError;
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;

// Mock backend =====

struct MockBackend {
    start_called: Arc<AtomicU32>,
    fail_start: AtomicBool,
    fail_routes: AtomicBool,
    gateway: IpAddr,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            start_called: Arc::new(AtomicU32::new(0)),
            fail_start: AtomicBool::new(false),
            fail_routes: AtomicBool::new(false),
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        }
    }

    fn failing_start() -> Self {
        let mut m = Self::new();
        m.fail_start = AtomicBool::new(true);
        m
    }

    fn failing_routes() -> Self {
        let mut m = Self::new();
        m.fail_routes = AtomicBool::new(true);
        m
    }
}

impl ProxyBackend for MockBackend {
    async fn start_ss(
        &self,
        _config: shadowsocks_service::config::Config,
    ) -> Result<JoinHandle<std::io::Result<()>>, ProxyError> {
        self.start_called.fetch_add(1, Ordering::SeqCst);
        if self.fail_start.load(Ordering::SeqCst) {
            return Err(ProxyError::Runtime(std::io::Error::other("mock start failure")));
        }
        // Spawn a task that just sleeps forever (simulating a running proxy)
        Ok(tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            Ok(())
        }))
    }

    fn setup_routes(&self, _tun_name: &str, _server_ip: IpAddr, _gateway: IpAddr) -> Result<(), ProxyError> {
        if self.fail_routes.load(Ordering::SeqCst) {
            return Err(ProxyError::RouteSetup("mock route failure".into()));
        }
        Ok(())
    }

    fn teardown_routes(&self, _server_ip: IpAddr) -> Result<(), ProxyError> {
        Ok(())
    }

    fn default_gateway(&self) -> Result<IpAddr, ProxyError> {
        Ok(self.gateway)
    }
}

// Helpers =====

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

fn test_config() -> ProxyConfig {
    ProxyConfig {
        server: ServerEntry {
            id: "test-id".into(),
            name: "test-server".into(),
            server: "127.0.0.1".into(),
            server_port: 8388,
            password: "test".into(),
            method: "aes-256-gcm".into(),
            plugin: None,
            plugin_opts: None,
        },
        local_port: 1080,
        plugin_path: None,
    }
}

// Tests =====

#[skuld::test]
fn start_transitions_to_running() {
    rt().block_on(async {
        let mut pm = ProxyManager::new(MockBackend::new());
        assert_eq!(pm.state(), ProxyState::Stopped);

        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);
        assert!(pm.uptime_secs() == 0 || pm.uptime_secs() == 1);

        // Cleanup
        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn stop_transitions_to_stopped() {
    rt().block_on(async {
        let mut pm = ProxyManager::new(MockBackend::new());
        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);

        pm.stop().await.unwrap();
        assert_eq!(pm.state(), ProxyState::Stopped);
    });
}

#[skuld::test]
fn stop_when_stopped_is_noop() {
    rt().block_on(async {
        let mut pm = ProxyManager::new(MockBackend::new());
        assert_eq!(pm.state(), ProxyState::Stopped);

        // Should not error
        pm.stop().await.unwrap();
        assert_eq!(pm.state(), ProxyState::Stopped);
    });
}

#[skuld::test]
fn start_when_running_returns_already_running() {
    rt().block_on(async {
        let mut pm = ProxyManager::new(MockBackend::new());
        pm.start(&test_config()).await.unwrap();

        let err = pm.start(&test_config()).await.unwrap_err();
        assert!(matches!(err, ProxyError::AlreadyRunning));

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn reload_stops_then_starts() {
    rt().block_on(async {
        let backend = MockBackend::new();
        let start_count = Arc::clone(&backend.start_called);

        let mut pm = ProxyManager::new(backend);
        pm.start(&test_config()).await.unwrap();
        assert_eq!(start_count.load(Ordering::SeqCst), 1);

        pm.reload(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);
        // start_ss was called a second time (stop + start)
        assert_eq!(start_count.load(Ordering::SeqCst), 2);

        pm.stop().await.unwrap();
        assert_eq!(pm.state(), ProxyState::Stopped);
    });
}

#[skuld::test]
fn start_failure_stays_stopped() {
    rt().block_on(async {
        let mut pm = ProxyManager::new(MockBackend::failing_start());
        let err = pm.start(&test_config()).await.unwrap_err();

        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(pm.last_error().is_some());
        assert!(err.to_string().contains("mock start failure"));
    });
}

#[skuld::test]
fn route_failure_cancels_ss() {
    rt().block_on(async {
        let backend = MockBackend::failing_routes();
        let start_count = Arc::clone(&backend.start_called);

        let mut pm = ProxyManager::new(backend);
        let err = pm.start(&test_config()).await.unwrap_err();

        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(err.to_string().contains("mock route failure"));
        // start_ss was called (the proxy was started before routes failed)
        assert_eq!(start_count.load(Ordering::SeqCst), 1);
        // But the proxy should have been aborted (task handle aborted)
        assert!(pm.last_error().is_some());
    });
}

#[skuld::test]
fn check_health_detects_crashed_task() {
    rt().block_on(async {
        let mut pm = ProxyManager::new(MockBackend::new());
        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);

        // Abort the task to simulate a crash
        if let Some(ref handle) = pm.task_handle {
            handle.abort();
        }
        // Wait for the abort to propagate
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        pm.check_health();
        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(pm.last_error().unwrap().contains("unexpectedly"));
    });
}

#[skuld::test]
fn uptime_increases_while_running() {
    rt().block_on(async {
        let mut pm = ProxyManager::new(MockBackend::new());
        pm.start(&test_config()).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert!(pm.uptime_secs() >= 1);

        pm.stop().await.unwrap();
        // After stop, uptime should be 0
        assert_eq!(pm.uptime_secs(), 0);
    });
}
