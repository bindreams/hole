use super::*;
use crate::proxy::{Proxy, ProxyError, RunningProxy};
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tun_engine::gateway::GatewayInfo;
use tun_engine::routing::{self, state as route_state, Routing};
use tun_engine::RoutingError;

// MockProxy ===========================================================================================================

/// Thread-safe test instrumentation shared between `MockProxy` (the factory)
/// and the `MockRunning` handles it issues. Each test constructs one and
/// clones `Arc` fields out before handing the mock to `ProxyManager::new`.
#[derive(Default)]
struct MockProxyState {
    start_calls: AtomicU32,
    fail_start: AtomicBool,
    /// If true, `MockRunning::is_alive` returns false — used to simulate
    /// a crashed ss task for `check_health_detects_crashed_task`.
    crashed: AtomicBool,
}

struct MockProxy {
    state: Arc<MockProxyState>,
    /// If Some, `start` awaits this gate before returning — used to park
    /// start mid-flight so cancellation tests can fire the cancel token
    /// while the future is suspended in `proxy.start(...)`.
    start_gate: Option<Arc<tokio::sync::Notify>>,
}

impl MockProxy {
    fn new() -> Self {
        Self {
            state: Arc::new(MockProxyState::default()),
            start_gate: None,
        }
    }

    fn failing_start() -> Self {
        let m = Self::new();
        m.state.fail_start.store(true, Ordering::SeqCst);
        m
    }

    fn with_start_gate(gate: Arc<tokio::sync::Notify>) -> Self {
        let mut m = Self::new();
        m.start_gate = Some(gate);
        m
    }

    fn start_calls_handle(&self) -> Arc<MockProxyState> {
        Arc::clone(&self.state)
    }
}

impl Proxy for MockProxy {
    type Running = MockRunning;

    async fn start(&self, _config: shadowsocks_service::config::Config) -> Result<MockRunning, ProxyError> {
        if let Some(gate) = self.start_gate.as_ref() {
            gate.notified().await;
        }
        self.state.start_calls.fetch_add(1, Ordering::SeqCst);
        if self.state.fail_start.load(Ordering::SeqCst) {
            return Err(ProxyError::Runtime(io::Error::other("mock start failure")));
        }
        // Spawn a long-sleeping task to simulate a running proxy — matches
        // the pre-refactor `MockBackend::start_ss` behavior so `is_alive()`
        // works realistically.
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(())
        });
        Ok(MockRunning {
            state: Arc::clone(&self.state),
            handle: Some(handle),
        })
    }
}

struct MockRunning {
    state: Arc<MockProxyState>,
    handle: Option<JoinHandle<io::Result<()>>>,
}

impl RunningProxy for MockRunning {
    fn is_alive(&self) -> bool {
        if self.state.crashed.load(Ordering::SeqCst) {
            return false;
        }
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
        // Mirror `ShadowsocksRunning::drop` best-effort abort. Without this,
        // the 3600s sleeper leaks for the remainder of the test process.
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

// MockRouting =========================================================================================================

struct MockRoutingState {
    install_calls: AtomicU32,
    teardown_calls: AtomicU32,
    fail_install: AtomicBool,
    fail_gateway: AtomicBool,
}

impl Default for MockRoutingState {
    fn default() -> Self {
        Self {
            install_calls: AtomicU32::new(0),
            teardown_calls: AtomicU32::new(0),
            fail_install: AtomicBool::new(false),
            fail_gateway: AtomicBool::new(false),
        }
    }
}

struct MockRouting {
    state: Arc<MockRoutingState>,
    /// Directory where the crash-recovery state file is written. Each
    /// `MockRouting` owns its own `state_dir` — in production,
    /// `SystemRouting::new(state_dir)` does the same. Tests hand the
    /// routing a `TempDir` (see `new_manager`) to keep writes isolated.
    state_dir: PathBuf,
    gateway: IpAddr,
}

impl MockRouting {
    fn new(state_dir: PathBuf) -> Self {
        Self {
            state: Arc::new(MockRoutingState::default()),
            state_dir,
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        }
    }

    fn failing_install(state_dir: PathBuf) -> Self {
        let m = Self::new(state_dir);
        m.state.fail_install.store(true, Ordering::SeqCst);
        m
    }

    fn failing_gateway(state_dir: PathBuf) -> Self {
        let m = Self::new(state_dir);
        m.state.fail_gateway.store(true, Ordering::SeqCst);
        m
    }

    fn state(&self) -> Arc<MockRoutingState> {
        Arc::clone(&self.state)
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
        self.state.install_calls.fetch_add(1, Ordering::SeqCst);

        // Match `SystemRouting::install`'s critical ordering: write the
        // state file BEFORE any route mutation (or in this case, before
        // the fail flag is checked). This keeps the file-lifecycle tests
        // honest — they observe the same write-then-clear behavior.
        let persisted = route_state::RouteState {
            version: route_state::SCHEMA_VERSION,
            tun_name: tun_name.to_owned(),
            server_ip,
            interface_name: interface_name.to_owned(),
        };
        route_state::save(&self.state_dir, &persisted)
            .map_err(|e| RoutingError::RouteSetup(format!("mock persist failed: {e}")))?;

        if self.state.fail_install.load(Ordering::SeqCst) {
            // Defensive: match `SystemRouting::install`'s error path —
            // clear the stale file we just wrote.
            let _ = route_state::clear(&self.state_dir);
            return Err(RoutingError::RouteSetup("mock install failure".into()));
        }

        Ok(MockRoutes {
            state: Arc::clone(&self.state),
            state_dir: self.state_dir.clone(),
        })
    }

    fn default_gateway(&self) -> Result<GatewayInfo, RoutingError> {
        if self.state.fail_gateway.load(Ordering::SeqCst) {
            return Err(RoutingError::Gateway("mock gateway failure".into()));
        }
        Ok(GatewayInfo {
            gateway_ip: self.gateway,
            interface_name: "MockEthernet".into(),
            interface_index: 1,
            ipv6_available: false,
        })
    }
}

struct MockRoutes {
    state: Arc<MockRoutingState>,
    state_dir: PathBuf,
}

impl Drop for MockRoutes {
    fn drop(&mut self) {
        self.state.teardown_calls.fetch_add(1, Ordering::SeqCst);
        let _ = route_state::clear(&self.state_dir);
    }
}

// Helpers =============================================================================================================

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

/// Build a `ProxyManager` backed by a fresh `TempDir`. Caller must hold
/// the returned `TempDir` for the scope of the manager so its contents
/// (any written `bridge-routes.json`) live until drop.
fn new_manager(proxy: MockProxy) -> (ProxyManager<MockProxy, MockRouting>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::new(dir.path().to_path_buf());
    let pm = ProxyManager::new(proxy, routing);
    (pm, dir)
}

/// `new_manager` variant that allows supplying a preconfigured `MockRouting`
/// (e.g. `MockRouting::failing_install` or `failing_gateway`). Used by the
/// routing/gateway failure tests.
fn new_manager_with_routing(
    proxy: MockProxy,
    routing: MockRouting,
    dir: tempfile::TempDir,
) -> (ProxyManager<MockProxy, MockRouting>, tempfile::TempDir) {
    let pm = ProxyManager::new(proxy, routing);
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
        tunnel_mode: hole_common::protocol::TunnelMode::Full,
        filters: Vec::new(),
        dns: hole_common::config::DnsConfig::default(),
        proxy_socks5: true,
        proxy_http: false,
        local_port_http: 4074,
    }
}

// Tests ===============================================================================================================

#[skuld::test]
fn start_transitions_to_running() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
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
        let (mut pm, _dir) = new_manager(MockProxy::new());
        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);

        pm.stop().await.unwrap();
        assert_eq!(pm.state(), ProxyState::Stopped);
    });
}

#[skuld::test]
fn stop_when_stopped_is_noop() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
        assert_eq!(pm.state(), ProxyState::Stopped);

        pm.stop().await.unwrap();
        assert_eq!(pm.state(), ProxyState::Stopped);
    });
}

#[skuld::test]
fn start_when_running_returns_already_running() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
        pm.start(&test_config()).await.unwrap();

        let err = pm.start(&test_config()).await.unwrap_err();
        assert!(matches!(err, ProxyError::AlreadyRunning));

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn reload_with_same_server_hot_swaps_rules() {
    rt().block_on(async {
        let backend = MockProxy::new();
        let state = backend.start_calls_handle();

        let (mut pm, _dir) = new_manager(backend);
        pm.start(&test_config()).await.unwrap();
        assert_eq!(state.start_calls.load(Ordering::SeqCst), 1);

        // Reload with same server config but different filters — hot-swap path.
        let mut config = test_config();
        config.filters.push(hole_common::config::FilterRule {
            address: "example.com".into(),
            matching: hole_common::config::MatchType::Exactly,
            action: hole_common::config::FilterAction::Block,
        });
        pm.reload(&config).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);
        // start was NOT called a second time (hot swap, no restart)
        assert_eq!(state.start_calls.load(Ordering::SeqCst), 1);

        pm.stop().await.unwrap();
        assert_eq!(pm.state(), ProxyState::Stopped);
    });
}

#[skuld::test]
fn reload_with_different_server_restarts() {
    rt().block_on(async {
        let backend = MockProxy::new();
        let state = backend.start_calls_handle();

        let (mut pm, _dir) = new_manager(backend);
        pm.start(&test_config()).await.unwrap();
        assert_eq!(state.start_calls.load(Ordering::SeqCst), 1);

        // Reload with different server → full stop + start.
        let mut config = test_config();
        config.server.server = "10.0.0.1".into();
        pm.reload(&config).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);
        // start was called a second time (stop + start)
        assert_eq!(state.start_calls.load(Ordering::SeqCst), 2);

        pm.stop().await.unwrap();
        assert_eq!(pm.state(), ProxyState::Stopped);
    });
}

#[skuld::test]
fn start_failure_stays_stopped() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::failing_start());
        let err = pm.start(&test_config()).await.unwrap_err();

        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(pm.last_error().is_some());
        assert!(err.to_string().contains("mock start failure"));
    });
}

#[skuld::test]
fn route_failure_rolls_back_proxy() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let proxy_state = proxy.start_calls_handle();
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::failing_install(dir.path().to_path_buf());
        let routing_state = routing.state();

        let (mut pm, _dir) = new_manager_with_routing(proxy, routing, dir);
        let err = pm.start(&test_config()).await.unwrap_err();

        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(err.to_string().contains("mock install failure"));
        // Proxy was started before routing.install was called.
        assert_eq!(proxy_state.start_calls.load(Ordering::SeqCst), 1);
        // install_calls incremented once (the failing call).
        assert_eq!(routing_state.install_calls.load(Ordering::SeqCst), 1);
        // `MockRoutes` was never returned, so the teardown counter stayed at 0.
        assert_eq!(routing_state.teardown_calls.load(Ordering::SeqCst), 0);
        assert!(pm.last_error().is_some());
    });
}

#[skuld::test]
fn check_health_detects_crashed_task() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.start_calls_handle();

        let (mut pm, _dir) = new_manager(proxy);
        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);

        // Simulate a crashed ss task by flipping the shared state's
        // `crashed` flag. The running `MockRunning` reads this from its
        // cloned `Arc<MockProxyState>` via `is_alive()`.
        state.crashed.store(true, Ordering::SeqCst);

        pm.check_health();
        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(pm.last_error().unwrap().contains("unexpectedly"));
    });
}

#[skuld::test]
fn check_health_clears_active_config_so_reload_restarts() {
    // Regression guard: check_health must clear active_config, otherwise
    // a subsequent reload would take the hot-swap path (no-op) instead
    // of starting a new proxy.
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.start_calls_handle();

        let (mut pm, _dir) = new_manager(proxy);
        pm.start(&test_config()).await.unwrap();
        assert_eq!(state.start_calls.load(Ordering::SeqCst), 1);

        // Simulate crash.
        state.crashed.store(true, Ordering::SeqCst);
        pm.check_health();
        assert_eq!(pm.state(), ProxyState::Stopped);

        // Un-crash so the next start succeeds.
        state.crashed.store(false, Ordering::SeqCst);

        // Reload must detect that we're not running and do a full start.
        pm.reload(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);
        assert_eq!(state.start_calls.load(Ordering::SeqCst), 2);

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn check_health_does_not_mark_healthy_task_as_crashed() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);

        // The mock's start spawns a 3600s sleep task — still healthy
        // after a short delay. check_health must NOT flip to Stopped.
        pm.check_health();
        assert_eq!(pm.state(), ProxyState::Running);

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn uptime_increases_while_running() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
        pm.start(&test_config()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(pm.uptime_secs() >= 1);

        pm.stop().await.unwrap();
        // After stop, uptime should be 0
        assert_eq!(pm.uptime_secs(), 0);
    });
}

// #165 regression guard ===============================================================================================

/// The #165 bug was that every start→stop cycle ran real `netsh` because
/// `RouteGuard::drop` bypassed the `ProxyBackend` trait. The post-#165
/// design makes the teardown RAII guard the `Routing::Installed`
/// associated type, so `MockRoutes::drop` (not `routing::teardown_routes`)
/// runs on stop. This test asserts that directly: if a future regression
/// reintroduces a bypass, `teardown_calls` will stay at 0 after a clean
/// start→stop and the assertion will fail.
#[skuld::test]
fn stop_runs_mock_teardown_not_real_netsh() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let routing_state = routing.state();

        let (mut pm, _dir) = new_manager_with_routing(proxy, routing, dir);
        pm.start(&test_config()).await.unwrap();
        assert_eq!(routing_state.teardown_calls.load(Ordering::SeqCst), 0);

        pm.stop().await.unwrap();
        assert_eq!(
            routing_state.teardown_calls.load(Ordering::SeqCst),
            1,
            "MockRoutes::Drop must run exactly once per stop — if this fails, a real-routing bypass has been reintroduced (regression of #165)"
        );
    });
}

/// Runtime belt-and-suspenders for the compile-time `disallowed_methods`
/// clippy lint. Runs serial so the global counter is exclusively owned
/// during this test. Asserts absolute zero because any nonzero value
/// proves a proxy_manager test path spawned a real routing subprocess.
#[skuld::test(serial)]
fn proxy_manager_tests_never_spawn_routing_subprocess() {
    routing::ROUTING_SUBPROCESS_SPAWN_COUNT.store(0, Ordering::SeqCst);

    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
        for _ in 0..10 {
            pm.start(&test_config()).await.unwrap();
            pm.stop().await.unwrap();
        }
    });

    let count = routing::ROUTING_SUBPROCESS_SPAWN_COUNT.load(Ordering::SeqCst);
    eprintln!("proxy_manager start/stop cycles spawned {count} routing subprocesses");
    assert_eq!(
        count, 0,
        "proxy_manager tests must not spawn routing subprocesses (regression of #165)"
    );
}

// last_error coverage for early-failure paths =========================================================================

#[skuld::test]
fn build_config_failure_sets_last_error() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
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
        let (mut pm, _dir) = new_manager(MockProxy::new());
        let mut config = test_config();
        // RFC 2606 reserves .invalid for guaranteed-non-resolution.
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
        let proxy = MockProxy::new();
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::failing_gateway(dir.path().to_path_buf());
        let (mut pm, _dir) = new_manager_with_routing(proxy, routing, dir);

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
        // Successful start clears last_error itself. The point of this
        // test is to verify the stop() side: any error left over from a
        // hypothetical earlier failed start must be cleared on a clean
        // stop. See issue #142.
        let (mut pm, _dir) = new_manager(MockProxy::new());
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
        let (mut pm, dir) = new_manager(MockProxy::new());
        let state_path = dir.path().join(route_state::STATE_FILE_NAME);
        assert!(!state_path.exists());

        pm.start(&test_config()).await.unwrap();
        assert!(state_path.exists(), "state file must exist while proxy is running");

        // Verify the content contains the server IP
        let loaded = route_state::load(dir.path()).unwrap();
        assert_eq!(loaded.server_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        pm.stop().await.unwrap();
        assert!(!state_path.exists(), "state file must be cleared on clean stop");
    });
}

#[skuld::test]
fn route_failure_clears_stale_state_file() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join(route_state::STATE_FILE_NAME);
        let routing = MockRouting::failing_install(dir.path().to_path_buf());

        let (mut pm, _dir) = new_manager_with_routing(proxy, routing, dir);
        let err = pm.start(&test_config()).await.unwrap_err();
        assert!(err.to_string().contains("mock install failure"));

        // Even on install failure, no stale file should remain — the
        // mock's `install` error path clears the file it just wrote,
        // mirroring `SystemRouting::install`'s defensive rollback.
        assert!(
            !state_path.exists(),
            "state file must be cleared on routing.install failure"
        );
    });
}

// Cancellation ========================================================================================================

#[skuld::test]
fn start_cancellable_succeeds_when_not_cancelled() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
        let token = CancellationToken::new();
        pm.start_cancellable(&test_config(), token).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);
        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn start_cancellable_cancelled_during_ss_start_rolls_back() {
    rt().block_on(async {
        let gate = Arc::new(tokio::sync::Notify::new());
        let proxy = MockProxy::with_start_gate(gate.clone());
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let routing_state = routing.state();
        let state_path = dir.path().join(route_state::STATE_FILE_NAME);

        let (mut pm, _dir) = new_manager_with_routing(proxy, routing, dir);
        let token = CancellationToken::new();

        // Fire off the cancel after a short delay so the start is already
        // parked in `proxy.start(...)`.
        let cancel_clone = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel_clone.cancel();
        });

        let err = pm.start_cancellable(&test_config(), token).await.unwrap_err();
        assert!(matches!(err, ProxyError::Cancelled), "expected Cancelled, got {err:?}");
        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(
            pm.last_error().is_none(),
            "ProxyError::Cancelled must NOT be recorded as last_error"
        );
        assert!(
            !state_path.exists(),
            "state file must be cleared on cancel during proxy.start"
        );
        // routing.install was never called, so no teardown should have run.
        assert_eq!(routing_state.install_calls.load(Ordering::SeqCst), 0);
        assert_eq!(routing_state.teardown_calls.load(Ordering::SeqCst), 0);

        // The gate is still held — release it so the spawned mock task
        // can drop cleanly.
        gate.notify_one();
    });
}

#[skuld::test]
fn start_cancellable_cancel_before_start_returns_immediately() {
    rt().block_on(async {
        let (mut pm, dir) = new_manager(MockProxy::new());
        let state_path = dir.path().join(route_state::STATE_FILE_NAME);
        let token = CancellationToken::new();
        token.cancel(); // already cancelled before start is even called

        let err = pm.start_cancellable(&test_config(), token).await.unwrap_err();
        assert!(matches!(err, ProxyError::Cancelled));
        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(pm.last_error().is_none());
        assert!(!state_path.exists());
    });
}

#[skuld::test]
fn start_cancellable_late_cancel_on_finished_token_is_noop() {
    // Sanity check that cancelling a CancellationToken AFTER its owning
    // start has already completed is a harmless no-op.
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
        let token = CancellationToken::new();
        pm.start_cancellable(&test_config(), token.clone()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);

        // Late cancel — must not panic, must not mutate proxy state.
        token.cancel();
        assert_eq!(pm.state(), ProxyState::Running);
        assert!(pm.last_error().is_none());

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn start_cancellable_dropped_future_runs_guards() {
    // Drop-safety: even without CancellationToken, dropping the start
    // future at an await point must clean up. Uses `tokio::time::timeout`
    // with a very short deadline to force the drop while `proxy.start`
    // is parked on the gate.
    rt().block_on(async {
        let gate = Arc::new(tokio::sync::Notify::new());
        let proxy = MockProxy::with_start_gate(gate.clone());
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let routing_state = routing.state();
        let state_path = dir.path().join(route_state::STATE_FILE_NAME);

        let (mut pm, _dir) = new_manager_with_routing(proxy, routing, dir);
        let token = CancellationToken::new();

        // Short deadline — the future will be dropped before proxy.start
        // ever returns (the gate is never released).
        let result = tokio::time::timeout(Duration::from_millis(50), pm.start_cancellable(&test_config(), token)).await;
        assert!(result.is_err(), "expected elapsed timeout");

        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(
            !state_path.exists(),
            "install was never called so the state file was never written"
        );
        assert_eq!(routing_state.install_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            routing_state.teardown_calls.load(Ordering::SeqCst),
            0,
            "routing.install never ran, so teardown should not have either"
        );

        gate.notify_one();
    });
}

#[skuld::test]
fn reload_creates_fresh_uncancellable_token() {
    // reload() with a different server internally calls start_cancellable
    // with a fresh token that is never signaled. Verifies the full-restart
    // reload path still works after the cancellation refactor.
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.start_calls_handle();

        let (mut pm, _dir) = new_manager(proxy);
        pm.start(&test_config()).await.unwrap();
        assert_eq!(state.start_calls.load(Ordering::SeqCst), 1);

        // Different server triggers full stop + start path.
        let mut config = test_config();
        config.server.server = "10.0.0.1".into();
        pm.reload(&config).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);
        assert_eq!(state.start_calls.load(Ordering::SeqCst), 2);

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn reload_when_not_running_starts() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.start_calls_handle();

        let (mut pm, _dir) = new_manager(proxy);
        assert_eq!(pm.state(), ProxyState::Stopped);

        pm.reload(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);
        assert_eq!(state.start_calls.load(Ordering::SeqCst), 1);

        pm.stop().await.unwrap();
    });
}

// Phase-1 instrumentation tests for #247 ==============================================================================

/// Smoke-test: `apply_dns_settings` emits an INFO log `"apply_dns_settings done"`
/// with an `elapsed_ms` field. Phase-2 observation of #247 depends on this
/// line appearing at INFO so users don't need to raise the log level to
/// diagnose the ~10s stall.
///
/// Uses a nonexistent upstream interface name so the underlying `netsh` /
/// `networksetup` calls fail fast (adapter not found), but the wrapping
/// instrumentation still emits the diagnostic.
#[skuld::test]
fn apply_dns_settings_emits_done_info_log() {
    use crate::dns::connector::DirectConnector;
    use crate::dns::forwarder::DnsForwarder;
    use crate::dns::server::LocalDnsServer;
    use crate::test_support::log_capture::VecWriter;
    use hole_common::config::DnsConfig;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    use tracing_subscriber::util::SubscriberInitExt;

    rt().block_on(async {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
        );
        let _guard = subscriber.set_default();

        // Bind LocalDnsServer to an ephemeral loopback port so the test
        // doesn't fight with anything else on :53.
        let forwarder = Arc::new(DnsForwarder::new(
            DnsConfig::default(),
            Arc::new(DirectConnector),
            false,
        ));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let srv = LocalDnsServer::bind(addr, forwarder).await.expect("bind ephemeral");

        let _ = apply_dns_settings(&srv, "hole-test-nonexistent-iface-xyz", None).await;

        let output = writer.snapshot_string();
        assert!(
            output.contains("apply_dns_settings done"),
            "expected 'apply_dns_settings done' in INFO log; got:\n{output}"
        );
        assert!(
            output.contains("elapsed_ms"),
            "expected 'elapsed_ms' in INFO log; got:\n{output}"
        );
        assert!(output.contains("INFO"), "expected INFO level; got:\n{output}");
    });
}

// Phase 1 #248 — forwarder self-test tests ============================================================================
//
// `build_local_dns` fires a detached post-bind self-test (via
// `spawn_forwarder_self_test`) so Phase 2 observation can tell
// "forwarder works at bind time" from "forwarder is fundamentally
// broken". These tests assert log output + the detach contract
// (spawn_forwarder_self_test must return immediately; the spawned task
// runs in the background).

#[cfg(test)]
mod self_test {
    use super::*;
    use crate::dns::connector::{BoxedStream, UpstreamConnector, UpstreamUdp};
    use crate::dns::forwarder::DnsForwarder;
    use crate::test_support::log_capture::VecWriter;
    use async_trait::async_trait;
    use hole_common::config::{DnsConfig, DnsProtocol};
    use std::io;
    use std::sync::Arc as SArc;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    use tracing_subscriber::util::SubscriberInitExt;

    /// A connector that immediately fails every connect. Drives the
    /// dead-upstream path in tests — the forwarder will fail every
    /// attempt, but the spawned self-test must not stall the caller.
    struct DeadConnector;
    #[async_trait]
    impl UpstreamConnector for DeadConnector {
        async fn connect_tcp(&self, _target: std::net::SocketAddr) -> io::Result<BoxedStream> {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "dead connector"))
        }
        async fn connect_udp(&self, _target: std::net::SocketAddr) -> io::Result<Box<dyn UpstreamUdp>> {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "dead connector"))
        }
    }

    fn test_dns_cfg() -> DnsConfig {
        DnsConfig {
            enabled: true,
            servers: vec!["127.0.0.1".parse().unwrap()],
            protocol: DnsProtocol::PlainTcp,
            intercept_udp53: true,
        }
    }

    /// Core contract: `spawn_forwarder_self_test` must return to its caller
    /// immediately regardless of how slow the self-test itself is. The
    /// 3×1500ms + 5s budget runs on a detached tokio task; the caller is
    /// never blocked.
    #[skuld::test]
    fn spawn_forwarder_self_test_returns_immediately() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), SArc::new(DeadConnector), false));
                let start = std::time::Instant::now();
                spawn_forwarder_self_test(forwarder, vec!["127.0.0.1".parse().unwrap()]);
                let elapsed = start.elapsed();
                assert!(
                    elapsed < std::time::Duration::from_millis(100),
                    "spawn_forwarder_self_test must return immediately (tokio::spawn is \
                     non-blocking); returned after {elapsed:?}"
                );
            });
    }

    /// When `dns_cfg.servers` is empty, the self-test must log a `skipped`
    /// line and never call into the forwarder.
    #[skuld::test]
    fn self_test_empty_servers_logs_skipped() {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
        );
        let _guard = subscriber.set_default();

        // Current-thread runtime so `tokio::spawn` in
        // `spawn_forwarder_self_test` schedules on the test thread —
        // `set_default` is thread-local; a multi-thread runtime would
        // run the spawned task on a worker without the subscriber.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), SArc::new(DeadConnector), false));
                spawn_forwarder_self_test(forwarder, vec![]);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            });

        let output = writer.snapshot_string();
        assert!(
            output.contains("forwarder self-test skipped: no servers configured"),
            "expected skipped log; got:\n{output}"
        );
    }

    /// Dead upstream → self-test must log `forwarder self-test failed` at
    /// INFO with `attempts=3`. This is the signal Phase 2 uses to know the
    /// tunnel itself is broken, not a transient later issue.
    #[skuld::test]
    fn self_test_dead_upstream_logs_failed() {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
        );
        let _guard = subscriber.set_default();

        // Current-thread runtime — see `self_test_empty_servers_logs_skipped`
        // for why the shared multi-thread `rt()` doesn't work here.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), SArc::new(DeadConnector), false));
                spawn_forwarder_self_test(forwarder, vec!["127.0.0.1".parse().unwrap()]);
                // Wait for the self-test to exhaust retries. 3 × 1500ms =
                // 4.5s worst case; give it a little extra for CI jitter.
                tokio::time::sleep(std::time::Duration::from_secs(6)).await;
            });

        let output = writer.snapshot_string();
        assert!(
            output.contains("forwarder self-test failed"),
            "expected 'forwarder self-test failed' in log; got:\n{output}"
        );
        assert!(output.contains("INFO"), "expected INFO level; got:\n{output}");
    }
}
