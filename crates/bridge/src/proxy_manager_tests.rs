use super::*;
use crate::gateway::GatewayInfo;
use crate::proxy::ProxyError;
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;

// Mock backend ========================================================================================================

struct MockBackend {
    start_called: Arc<AtomicU32>,
    fail_start: AtomicBool,
    fail_routes: AtomicBool,
    fail_gateway: AtomicBool,
    gateway: IpAddr,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            start_called: Arc::new(AtomicU32::new(0)),
            fail_start: AtomicBool::new(false),
            fail_routes: AtomicBool::new(false),
            fail_gateway: AtomicBool::new(false),
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

    fn failing_gateway() -> Self {
        let mut m = Self::new();
        m.fail_gateway = AtomicBool::new(true);
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

    fn setup_routes(
        &self,
        _tun_name: &str,
        _server_ip: IpAddr,
        _gateway: IpAddr,
        _interface_name: &str,
    ) -> Result<(), ProxyError> {
        if self.fail_routes.load(Ordering::SeqCst) {
            return Err(ProxyError::RouteSetup("mock route failure".into()));
        }
        Ok(())
    }

    fn teardown_routes(&self, _tun_name: &str, _server_ip: IpAddr, _interface_name: &str) -> Result<(), ProxyError> {
        Ok(())
    }

    fn default_gateway(&self) -> Result<GatewayInfo, ProxyError> {
        if self.fail_gateway.load(Ordering::SeqCst) {
            return Err(ProxyError::Gateway("mock gateway failure".into()));
        }
        Ok(GatewayInfo {
            gateway_ip: self.gateway,
            interface_name: "MockEthernet".into(),
        })
    }
}

// Helpers =============================================================================================================

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

/// Build a `ProxyManager` backed by a fresh `TempDir`. Caller must hold
/// the returned `TempDir` for the scope of the manager so its contents
/// (any written `bridge-routes.json`) live until drop.
fn new_manager<B: ProxyBackend>(backend: B) -> (ProxyManager<B>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let pm = ProxyManager::new(backend, dir.path().to_path_buf());
    (pm, dir)
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
            validation: None,
        },
        local_port: 1080,
        filters: Vec::new(),
    }
}

// Tests ===============================================================================================================

#[skuld::test]
fn start_transitions_to_running() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockBackend::new());
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
        let (mut pm, _dir) = new_manager(MockBackend::new());
        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);

        pm.stop().await.unwrap();
        assert_eq!(pm.state(), ProxyState::Stopped);
    });
}

#[skuld::test]
fn stop_when_stopped_is_noop() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockBackend::new());
        assert_eq!(pm.state(), ProxyState::Stopped);

        // Should not error
        pm.stop().await.unwrap();
        assert_eq!(pm.state(), ProxyState::Stopped);
    });
}

#[skuld::test]
fn start_when_running_returns_already_running() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockBackend::new());
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

        let (mut pm, _dir) = new_manager(backend);
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
        let (mut pm, _dir) = new_manager(MockBackend::failing_start());
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

        let (mut pm, _dir) = new_manager(backend);
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
        let (mut pm, _dir) = new_manager(MockBackend::new());
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
fn check_health_does_not_mark_healthy_task_as_crashed() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockBackend::new());
        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);

        // The mock's start_ss spawns a 3600s sleep task — still healthy
        // after a short delay. check_health must NOT flip to Stopped.
        pm.check_health();
        assert_eq!(pm.state(), ProxyState::Running);

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn uptime_increases_while_running() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockBackend::new());
        pm.start(&test_config()).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert!(pm.uptime_secs() >= 1);

        pm.stop().await.unwrap();
        // After stop, uptime should be 0
        assert_eq!(pm.uptime_secs(), 0);
    });
}

// last_error coverage for early-failure paths =========================================================================

#[skuld::test]
fn build_config_failure_sets_last_error() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockBackend::new());
        let mut config = test_config();
        config.server.method = "not-a-real-cipher".into();

        let err = pm.start(&config).await.unwrap_err();
        assert!(matches!(err, ProxyError::InvalidMethod(_)));
        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(pm.last_error().is_some(), "build_ss_config failure must set last_error");
        assert!(pm.last_error().unwrap().contains("not-a-real-cipher"));
    });
}

#[skuld::test]
fn dns_resolution_failure_sets_last_error() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockBackend::new());
        let mut config = test_config();
        // RFC 2606 reserves .invalid for guaranteed-non-resolution. lookup_host
        // returns an error quickly (no real DNS query is sent for reserved TLDs
        // by most resolvers, but even if one is, the upstream NXDOMAIN is fast).
        config.server.server = "test.invalid".into();

        let err = pm.start(&config).await.unwrap_err();
        assert!(matches!(err, ProxyError::DnsResolution { .. }));
        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(
            pm.last_error().is_some(),
            "resolve_server_ip failure must set last_error"
        );
        assert!(pm.last_error().unwrap().contains("test.invalid"));
    });
}

#[skuld::test]
fn gateway_failure_sets_last_error() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockBackend::failing_gateway());

        let err = pm.start(&test_config()).await.unwrap_err();
        assert!(matches!(err, ProxyError::Gateway(_)));
        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(pm.last_error().is_some(), "default_gateway failure must set last_error");
        assert!(pm.last_error().unwrap().contains("mock gateway failure"));
    });
}

#[skuld::test]
fn stop_clears_last_error() {
    rt().block_on(async {
        // Successful start clears last_error itself (line 210). The point of
        // this test is to verify the stop() side: any error left over from a
        // hypothetical earlier failed start must be cleared on a clean stop,
        // so handle_diagnostics doesn't keep reporting bridge=error after the
        // user has rolled out of the failed state. See issue #142.
        let (mut pm, _dir) = new_manager(MockBackend::new());
        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);

        // Inject a stale error to simulate "previous failed start" residue.
        pm.last_error = Some("stale error from a previous run".into());

        pm.stop().await.unwrap();
        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(
            pm.last_error().is_none(),
            "stop() must clear last_error so diagnostics report bridge=ok again"
        );
    });
}

// State-file side effects =============================================================================================

#[skuld::test]
fn start_writes_state_file_then_stop_clears_it() {
    rt().block_on(async {
        let (mut pm, dir) = new_manager(MockBackend::new());
        let state_path = dir.path().join(crate::route_state::STATE_FILE_NAME);
        assert!(!state_path.exists());

        pm.start(&test_config()).await.unwrap();
        assert!(state_path.exists(), "state file must exist while proxy is running");

        // Verify the content contains the server IP
        let loaded = crate::route_state::load(dir.path()).unwrap();
        assert_eq!(loaded.server_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        pm.stop().await.unwrap();
        assert!(!state_path.exists(), "state file must be cleared on clean stop");
    });
}

#[skuld::test]
fn route_failure_clears_stale_state_file() {
    rt().block_on(async {
        let (mut pm, dir) = new_manager(MockBackend::failing_routes());
        let state_path = dir.path().join(crate::route_state::STATE_FILE_NAME);

        let err = pm.start(&test_config()).await.unwrap_err();
        assert!(err.to_string().contains("mock route failure"));

        // Even on setup_routes failure, no stale file should remain
        assert!(
            !state_path.exists(),
            "state file must be cleared on setup_routes failure"
        );
    });
}
