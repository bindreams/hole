// `CancellationToken::new` is pervasive across these tests as the test
// harness's root signal; module-level allow per clippy.toml's
// "Bridge cancellation contract" sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

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
use tokio::sync::oneshot;
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
    /// Last shadowsocks Config passed to `start` — lets tests assert
    /// which local instances a start produced (e.g. the pure-VPN
    /// internal ephemeral SOCKS5 instance, #459).
    last_config: std::sync::Mutex<Option<shadowsocks_service::config::Config>>,
}

struct MockProxy {
    state: Arc<MockProxyState>,
    /// If Some, `start` awaits this gate before returning — used to park
    /// start mid-flight so cancellation tests can fire the cancel token
    /// while the future is suspended in `proxy.start(...)`.
    start_gate: Option<Arc<tokio::sync::Notify>>,
    /// If Some, `start` fires this sender on entry — before awaiting
    /// `start_gate`. Lets tests park until `start` is *known* to be in
    /// flight, instead of sleeping. One-shot per MockProxy. See
    /// bindreams/hole#383.
    start_entered: std::sync::Mutex<Option<oneshot::Sender<()>>>,
}

impl MockProxy {
    fn new() -> Self {
        Self {
            state: Arc::new(MockProxyState::default()),
            start_gate: None,
            start_entered: std::sync::Mutex::new(None),
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

    fn with_entered_signal(mut self, tx: oneshot::Sender<()>) -> Self {
        self.start_entered = std::sync::Mutex::new(Some(tx));
        self
    }

    fn start_calls_handle(&self) -> Arc<MockProxyState> {
        Arc::clone(&self.state)
    }
}

impl Proxy for MockProxy {
    type Running = MockRunning;

    async fn start(&self, config: shadowsocks_service::config::Config) -> Result<MockRunning, ProxyError> {
        *self.state.last_config.lock().unwrap() = Some(config);
        // Fire entered signal BEFORE awaiting the gate.
        if let Some(tx) = self.start_entered.lock().unwrap().take() {
            let _ = tx.send(());
        }
        if let Some(gate) = self.start_gate.as_ref() {
            gate.notified().await;
        }
        self.state.start_calls.fetch_add(1, Ordering::SeqCst);
        if self.state.fail_start.load(Ordering::SeqCst) {
            return Err(ProxyError::Runtime(io::Error::other("mock start failure")));
        }
        // Spawn a long-sleeping task to simulate a running proxy so the
        // returned handle reports `is_alive()` realistically.
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
        // dns.enabled = false avoids the #388 forwarder self-test gate in
        // happy-path tests — MockProxy doesn't bind a real TCP listener,
        // so the forwarder's Socks5Connector to `127.0.0.1:1080` would
        // time out after 4.5s on every test. Tests that exercise the
        // gate enable DNS explicitly (see the self_test mod).
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

        // Simulate "1.1s has elapsed since start" by rewinding the
        // started_at marker. Deterministic — no sleep.
        pm.shift_started_at_for_test(Duration::from_millis(1100));
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
        let (entered_tx, entered_rx) = oneshot::channel();
        let proxy = MockProxy::with_start_gate(gate.clone()).with_entered_signal(entered_tx);
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let routing_state = routing.state();
        let state_path = dir.path().join(route_state::STATE_FILE_NAME);

        let (mut pm, _dir) = new_manager_with_routing(proxy, routing, dir);
        let token = CancellationToken::new();

        // Fire the cancel once `proxy.start(...)` is *known* to be parked
        // on the gate. Deterministic — no sleep.
        let cancel_clone = token.clone();
        tokio::spawn(async move {
            entered_rx.await.expect("MockProxy::start never entered");
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
    // future at an await point must clean up. Uses the `entered` signal
    // to know when proxy.start is parked on the gate, then drops the
    // future via a `select!` race — deterministic, no time-based wait.
    rt().block_on(async {
        let gate = Arc::new(tokio::sync::Notify::new());
        let (entered_tx, entered_rx) = oneshot::channel();
        let proxy = MockProxy::with_start_gate(gate.clone()).with_entered_signal(entered_tx);
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let routing_state = routing.state();
        let state_path = dir.path().join(route_state::STATE_FILE_NAME);

        let (mut pm, _dir) = new_manager_with_routing(proxy, routing, dir);
        let token = CancellationToken::new();

        // Race the start future against the entered signal. When the
        // entered arm wins, `select!` drops the `&mut f` arm and the
        // surrounding scope drops `f`, running the drop-safety guards.
        {
            let cfg = test_config();
            let f = pm.start_cancellable(&cfg, token);
            tokio::pin!(f);
            tokio::select! {
                _ = &mut f => panic!("start should not complete while gate is unfired"),
                res = entered_rx => res.expect("MockProxy::start never entered"),
            }
        }

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

// Pure-VPN (#459) =====================================================================================================

#[skuld::test]
fn pure_vpn_start_binds_internal_ephemeral_socks5() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.start_calls_handle();
        let (mut pm, _dir) = new_manager(proxy);
        let mut config = test_config();
        config.proxy_socks5 = false;
        config.proxy_http = false;

        pm.start(&config).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);

        {
            let guard = state.last_config.lock().unwrap();
            let ss_config = guard.as_ref().expect("proxy.start captured a config");
            assert_eq!(ss_config.local.len(), 1, "exactly one internal SOCKS5 instance");
            let addr = ss_config.local[0].config.addr.as_ref().expect("local must have addr");
            let sock = match addr {
                shadowsocks::config::ServerAddr::SocketAddr(s) => *s,
                other => panic!("expected SocketAddr, got {other:?}"),
            };
            assert_eq!(sock.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            assert_ne!(sock.port(), 0, "ephemeral port must be resolved, not 0");
            assert_ne!(sock.port(), config.local_port, "configured port must stay unused");
        }

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn pure_vpn_start_cancellable_during_proxy_start() {
    rt().block_on(async {
        let gate = Arc::new(tokio::sync::Notify::new());
        let (entered_tx, entered_rx) = oneshot::channel();
        let proxy = MockProxy::with_start_gate(gate.clone()).with_entered_signal(entered_tx);
        let (mut pm, _dir) = new_manager(proxy);
        let mut config = test_config();
        config.proxy_socks5 = false;
        config.proxy_http = false;
        let token = CancellationToken::new();

        // Fire the cancel once `proxy.start(...)` is *known* to be parked
        // on the gate (inside the bind_ephemeral op). Deterministic — no
        // sleep.
        let cancel_clone = token.clone();
        tokio::spawn(async move {
            entered_rx.await.expect("MockProxy::start never entered");
            cancel_clone.cancel();
        });

        let err = pm.start_cancellable(&config, token).await.unwrap_err();
        assert!(matches!(err, ProxyError::Cancelled), "expected Cancelled, got {err:?}");
        assert_eq!(pm.state(), ProxyState::Stopped);

        // The gate is still held — release it so the spawned mock task
        // can drop cleanly.
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

// DNS-apply instrumentation tests =====================================================================================

/// Smoke-test: `apply_dns_settings` must emit an INFO log
/// `"apply_dns_settings done"` with an `elapsed_ms` field so the ~10s
/// stall is diagnosable without raising the log level.
///
/// Uses a nonexistent upstream interface name so the underlying `netsh` /
/// `networksetup` calls fail fast (adapter not found), but the wrapping
/// instrumentation still emits the diagnostic.
#[skuld::test]
fn dns_apply_emits_done_info_log() {
    use crate::dns::system::{Dns, SystemDns};
    use crate::test_support::log_capture::VecWriter;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio_util::sync::CancellationToken;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    // Current-thread runtime so `tokio::spawn` in `SystemDns::apply`
    // (or anything downstream) stays on the test thread. The helper
    // asserts this at install time. See bindreams/hole#302.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let writer = VecWriter::new();
            let subscriber = tracing_subscriber::registry().with(
                fmt::layer()
                    .with_writer(writer.clone())
                    .with_ansi(false)
                    .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
            );
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

            let dns = SystemDns::default();
            // Adapter doesn't exist — `Win32Real::get_settings` returns
            // `Ok(None)` so nothing is captured and apply also no-ops, but
            // the surrounding `apply_dns_settings done` INFO log still fires.
            let mut applied = dns
                .apply(
                    vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                    vec!["hole-test-nonexistent-iface-xyz".into()],
                    vec![],
                    None,
                    CancellationToken::new(),
                )
                .await
                .expect("apply ok with missing adapter");
            applied.shutdown().await;

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

// TUN skipped from capture, kept in apply =============================================================================
//
// The TUN adapter is created by `routing.install` immediately before
// `apply_dns_settings` runs. Its prior DNS is whatever Windows defaults a
// brand-new adapter to — unknowable and uninteresting. Calling
// `netsh show dnsservers` against a freshly-created adapter is also the
// slowest case on Windows. So capture runs on upstream only; apply still
// runs on both.
//
// Test strategy: DEBUG-level log capture, assert the per-alias lines from
// `dns::system::windows` show the expected asymmetry.

#[cfg(target_os = "windows")]
#[skuld::test]
fn dns_apply_skips_tun_from_capture_keeps_in_apply() {
    use crate::dns::system::{Dns, SystemDns};
    use crate::proxy::TUN_DEVICE_NAME;
    use crate::test_support::log_capture::VecWriter;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio_util::sync::CancellationToken;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    // Current-thread runtime — see `dns_apply_emits_done_info_log`
    // for why the multi-thread `rt()` is unsafe with `set_default`.
    // bindreams/hole#302.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let writer = VecWriter::new();
            let subscriber = tracing_subscriber::registry().with(
                fmt::layer()
                    .with_writer(writer.clone())
                    .with_ansi(false)
                    .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
            );
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

            // Upstream alias uses a distinctive name so we can grep for it.
            // Mirrors `start_inner`'s phase 7 wiring: capture_aliases=
            // [upstream] (TUN skipped), apply_aliases=
            // [TUN, upstream].
            let dns = SystemDns::default();
            let mut applied = dns
                .apply(
                    vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                    vec!["hole-p4-test-upstream-xyz".into()],
                    vec![TUN_DEVICE_NAME.into(), "hole-p4-test-upstream-xyz".into()],
                    None,
                    CancellationToken::new(),
                )
                .await
                .expect("apply ok");
            applied.shutdown().await;

            let output = writer.snapshot_string();

            // The per-FFI lines from `Win32Real` are emitted on the
            // blocking pool thread (the `apply_windows` loop dispatches
            // each backend call via `spawn_blocking`) so the test's
            // thread-local subscriber never sees them. We assert on the
            // wrapper lines from `apply_windows` instead — those run on
            // the test thread.
            //
            // Both fake aliases are missing from the system: capture
            // surfaces `"DNS capture: adapter not found; skipping
            // alias=..."` (debug); apply surfaces `"DNS apply failed;
            // continuing alias=..."` (warn). Capture must NEVER carry
            // the TUN alias; apply MUST carry both.

            // CAPTURE side: only the upstream alias appears.
            let capture_lines: Vec<&str> = output
                .lines()
                .filter(|l| l.contains("DNS capture: adapter not found"))
                .collect();
            assert!(
                !capture_lines.is_empty(),
                "expected at least one capture-side DEBUG line; got:\n{output}"
            );
            for line in &capture_lines {
                assert!(
                    !line.contains(&format!("alias={TUN_DEVICE_NAME}")),
                    "capture ran on TUN — expected to be skipped. line: {line}"
                );
            }
            assert!(
                capture_lines
                    .iter()
                    .any(|l| l.contains("alias=hole-p4-test-upstream-xyz")),
                "capture should have run on upstream alias; got:\n{output}"
            );

            // APPLY side: the TUN alias DOES appear — we still set
            // loopback DNS on the TUN so the OS's best-route-to-DNS
            // lookup lands on 127.x.
            let apply_lines: Vec<&str> = output
                .lines()
                .filter(|l| l.contains("DNS apply failed; continuing"))
                .collect();
            assert!(
                apply_lines
                    .iter()
                    .any(|l| l.contains(&format!("alias={TUN_DEVICE_NAME}"))),
                "apply should have run on TUN alias; got:\n{output}"
            );
            assert!(
                apply_lines
                    .iter()
                    .any(|l| l.contains("alias=hole-p4-test-upstream-xyz")),
                "apply should have run on upstream alias; got:\n{output}"
            );
        });
}

// Transports-driven UDP-drop policy ===================================================================================
//
// The three `RunningState`/`Dispatcher::new` start sites read
// `udp_available_from_chain(plugin_chain.transports())`. The derivation
// is the testable unit: a TCP-only chain (`[tcp]`) yields `false`, a
// TCP+UDP chain yields `true`, and no plugin yields `true`. Standing up a
// real `ProxyManager` start needs elevation (routing/TUN), so the
// derivation is extracted into `udp_available_from_chain(Option<Transports>)`
// and tested directly — the same value flows into all three start sites.

#[skuld::test]
fn udp_unavailable_when_chain_reports_tcp_only() {
    // A TCP-only plugin (plain v2ray-plugin) reports `[tcp]` via sitrep.
    assert!(!udp_available_from_chain(Some(garter::Transports::TCP)));
}

#[skuld::test]
fn udp_available_when_chain_reports_tcp_and_udp() {
    // A UDP-capable plugin (galoshes, YAMUX) reports `[tcp, udp]`.
    assert!(udp_available_from_chain(Some(
        garter::Transports::TCP | garter::Transports::UDP
    )));
}

#[skuld::test]
fn udp_available_when_chain_reports_udp_only() {
    // Defensive: UDP present in the set is sufficient regardless of TCP.
    assert!(udp_available_from_chain(Some(garter::Transports::UDP)));
}

#[skuld::test]
fn udp_available_when_no_plugin() {
    // No plugin chain — the raw SOCKS5 path always carries UDP.
    assert!(udp_available_from_chain(None));
}

#[skuld::test]
fn udp_unavailable_when_chain_reports_empty_transports() {
    // Degenerate (a chain that serves nothing): UDP is not present, so
    // the privacy-preserving default is to drop Proxy-routed UDP.
    assert!(!udp_available_from_chain(Some(garter::Transports::empty())));
}

// Forwarder self-test gate tests ======================================================================================
//
// `start_inner` runs `run_forwarder_self_test` synchronously BEFORE
// installing TUN routes / applying system DNS. A failed gate returns
// `Err(ProxyError::ForwarderSelfTestFailed)` and the locally-owned RAII
// guards unwind without ever hijacking the user's system DNS into a
// dead tunnel.

#[cfg(test)]
mod self_test {
    use super::*;
    use crate::dns::connector::{ConnectedStream, UpstreamConnector, UpstreamUdp};
    use crate::dns::forwarder::DnsForwarder;
    use crate::test_support::log_capture::VecWriter;
    use async_trait::async_trait;
    use hole_common::config::{DnsConfig, DnsProtocol};
    use std::io;
    use std::sync::Arc as SArc;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    /// A connector that immediately fails every connect. Drives the
    /// dead-upstream path in tests — the forwarder will fail every
    /// attempt, surfacing as `SelfTestOutcome::Failed`.
    struct DeadConnector;
    #[async_trait]
    impl UpstreamConnector for DeadConnector {
        async fn connect_tcp(&self, _target: std::net::SocketAddr) -> io::Result<ConnectedStream> {
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

    /// Empty servers → `run_forwarder_self_test` logs `skipped` and
    /// returns `Ok(0)`. Empty-servers in production is rejected at
    /// `build_local_dns` *before* `run_forwarder_self_test` is even
    /// called (test below: `build_local_dns_returns_err_for_empty_servers`);
    /// this test pins the helper's contract in isolation.
    #[skuld::test]
    fn self_test_empty_servers_returns_ok_zero() {
        let writer = VecWriter::new();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let subscriber = tracing_subscriber::registry().with(
                    fmt::layer()
                        .with_writer(writer.clone())
                        .with_ansi(false)
                        .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), SArc::new(DeadConnector), false));
                let outcome = run_forwarder_self_test(forwarder, vec![], false, CancellationToken::new()).await;
                assert!(matches!(outcome, SelfTestOutcome::Ok { attempts: 0 }));
            });

        let output = writer.snapshot_string();
        assert!(
            output.contains("forwarder self-test skipped: no servers configured"),
            "expected skipped log; got:\n{output}"
        );
    }

    /// Dead upstream → `run_forwarder_self_test` returns
    /// `SelfTestOutcome::Failed { attempts: 3, .. }` and logs `forwarder
    /// self-test failed` at INFO. `into_result` then maps that to
    /// `ProxyError::ForwarderSelfTestFailed`.
    #[skuld::test]
    fn self_test_dead_upstream_returns_failed() {
        let writer = VecWriter::new();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let subscriber = tracing_subscriber::registry().with(
                    fmt::layer()
                        .with_writer(writer.clone())
                        .with_ansi(false)
                        .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), SArc::new(DeadConnector), false));
                let outcome = run_forwarder_self_test(
                    forwarder,
                    vec!["127.0.0.1".parse().unwrap()],
                    false,
                    CancellationToken::new(),
                )
                .await;
                let SelfTestOutcome::Failed { attempts, reason } = outcome else {
                    panic!("expected Failed");
                };
                assert_eq!(attempts, 3);
                assert!(
                    !reason.is_empty(),
                    "Failed reason must be non-empty for diagnostic value"
                );
                // into_result maps to the canonical error variant.
                let err = SelfTestOutcome::Failed {
                    attempts: 3,
                    reason: reason.clone(),
                }
                .into_result(4500)
                .unwrap_err();
                assert!(matches!(
                    err,
                    ProxyError::ForwarderSelfTestFailed {
                        attempts: 3,
                        elapsed_ms: 4500,
                        ..
                    }
                ));
            });

        let output = writer.snapshot_string();
        assert!(
            output.contains("forwarder self-test failed"),
            "expected 'forwarder self-test failed' in log; got:\n{output}"
        );
        assert!(output.contains("INFO"), "expected INFO level; got:\n{output}");
    }

    /// When self-test fails AND `diagnostic_plugin_tap=true`,
    /// emit a `warn!` breadcrumb pointing the reader to the tap output
    /// above. Const-anchored so a text change breaks only the const.
    #[skuld::test]
    fn self_test_failure_with_tap_enabled_emits_correlation_hint() {
        let writer = VecWriter::new();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let subscriber = tracing_subscriber::registry().with(
                    fmt::layer()
                        .with_writer(writer.clone())
                        .with_ansi(false)
                        .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), SArc::new(DeadConnector), false));
                let _ = run_forwarder_self_test(
                    forwarder,
                    vec!["127.0.0.1".parse().unwrap()],
                    true,
                    CancellationToken::new(),
                )
                .await;
            });

        let output = writer.snapshot_string();
        assert!(
            output.contains(super::TAP_ENABLED_HINT),
            "expected TAP_ENABLED_HINT in log; got:\n{output}"
        );
        assert!(
            !output.contains(super::TAP_DISABLED_HINT),
            "tap=true must NOT emit the disabled hint; got:\n{output}"
        );
    }

    /// When self-test fails AND tap is OFF, emit a `warn!`
    /// remediation hint pointing the reader to the config flag.
    #[skuld::test]
    fn self_test_failure_without_tap_emits_remediation_hint() {
        let writer = VecWriter::new();

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let subscriber = tracing_subscriber::registry().with(
                    fmt::layer()
                        .with_writer(writer.clone())
                        .with_ansi(false)
                        .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let forwarder = SArc::new(DnsForwarder::new(test_dns_cfg(), SArc::new(DeadConnector), false));
                let _ = run_forwarder_self_test(
                    forwarder,
                    vec!["127.0.0.1".parse().unwrap()],
                    false,
                    CancellationToken::new(),
                )
                .await;
            });

        let output = writer.snapshot_string();
        assert!(
            output.contains(super::TAP_DISABLED_HINT),
            "expected TAP_DISABLED_HINT in log; got:\n{output}"
        );
        assert!(
            !output.contains(super::TAP_ENABLED_HINT),
            "tap=false must NOT emit the enabled hint; got:\n{output}"
        );
    }

    /// `build_local_dns` rejects the degenerate `enabled=true, servers=[]`
    /// config: a live TUN would strand every in-tunnel UDP/53 flow at the
    /// LocalDnsEndpoint with no upstream to forward to.
    #[skuld::test]
    fn build_local_dns_returns_err_for_empty_servers() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let cfg = DnsConfig {
                    enabled: true,
                    servers: vec![], // degenerate
                    protocol: DnsProtocol::PlainTcp,
                    intercept_udp53: true,
                };
                match build_local_dns(&cfg, 1080, false, CancellationToken::new()).await {
                    Err(ProxyError::ForwarderSelfTestFailed {
                        attempts: 0,
                        elapsed_ms: 0,
                        ..
                    }) => {}
                    Err(other) => panic!("unexpected error variant: {other:?}"),
                    Ok(_) => panic!("expected ForwarderSelfTestFailed for empty servers"),
                }
            });
    }

    /// `is_dns_reply_ok` reply-decode contract — direct unit
    /// tests of the RCODE check. Without these, a regression in the
    /// mask (`0x0F` → `0xF0`) or the length check would only surface
    /// once the gate runs against real upstream DNS in production.
    #[skuld::test]
    fn is_dns_reply_ok_treats_noerror_as_success() {
        let mut reply = vec![0u8; 12];
        reply[3] = 0x00; // RCODE = 0 (NoError)
        assert!(super::is_dns_reply_ok(&reply));
    }

    #[skuld::test]
    fn is_dns_reply_ok_treats_nxdomain_as_success() {
        let mut reply = vec![0u8; 12];
        reply[3] = 0x03; // RCODE = 3 (NXDOMAIN). Path probe semantic.
        assert!(super::is_dns_reply_ok(&reply));
    }

    #[skuld::test]
    fn is_dns_reply_ok_treats_refused_as_success() {
        let mut reply = vec![0u8; 12];
        reply[3] = 0x05; // RCODE = 5 (REFUSED). Resolver declined, path works.
        assert!(super::is_dns_reply_ok(&reply));
    }

    #[skuld::test]
    fn is_dns_reply_ok_rejects_servfail() {
        let mut reply = vec![0u8; 12];
        reply[3] = 0x02; // RCODE = 2 (SERVFAIL). Upstream explicitly failed.
        assert!(!super::is_dns_reply_ok(&reply));
    }

    #[skuld::test]
    fn is_dns_reply_ok_ignores_high_nibble_of_byte_3() {
        // RFC 1035: low nibble = RCODE; high nibble = Z (reserved) + RA
        // (recursion available). High-nibble bits set MUST NOT mask the
        // RCODE check.
        let mut reply = vec![0u8; 12];
        reply[3] = 0xF2; // high nibble set + RCODE=2
        assert!(!super::is_dns_reply_ok(&reply));
        reply[3] = 0xF0; // high nibble set + RCODE=0
        assert!(super::is_dns_reply_ok(&reply));
    }

    #[skuld::test]
    fn is_dns_reply_ok_rejects_truncated_reply() {
        // Fewer than 12 bytes is not a well-formed DNS header.
        assert!(!super::is_dns_reply_ok(&[]));
        assert!(!super::is_dns_reply_ok(&[0u8; 11]));
    }

    /// `dns.enabled = false` → `build_local_dns` returns
    /// `(None, None)` → gate is skipped entirely in `start_inner`.
    #[skuld::test]
    fn build_local_dns_returns_none_when_disabled() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let cfg = DnsConfig {
                    enabled: false,
                    servers: vec![],
                    protocol: DnsProtocol::PlainTcp,
                    intercept_udp53: true,
                };
                let res = build_local_dns(&cfg, 1080, false, CancellationToken::new()).await;
                let (ep, fwd) = match res {
                    Ok(t) => t,
                    Err(e) => panic!("expected Ok((None, None)) for disabled DNS, got {e:?}"),
                };
                assert!(ep.is_none());
                assert!(fwd.is_none());
            });
    }

    /// the in-TUN LocalDnsEndpoint is the sole OS DNS path, so it
    /// must be constructed whenever DNS is enabled with servers — even if
    /// `intercept_udp53` is false. `build_local_dns` returns a 2-tuple
    /// `(Option<LocalDnsEndpoint>, Option<Arc<DnsForwarder>>)`.
    #[skuld::test]
    fn build_local_dns_builds_endpoint_when_enabled() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let cfg = DnsConfig {
                    enabled: true,
                    servers: vec!["1.1.1.1".parse().unwrap()],
                    protocol: DnsProtocol::PlainTcp,
                    intercept_udp53: false, // legacy flag — endpoint built anyway
                };
                let (ep, fwd) = build_local_dns(&cfg, 1080, false, CancellationToken::new())
                    .await
                    .expect("build_local_dns ok when enabled");
                assert!(ep.is_some(), "endpoint must exist (sole DNS path)");
                assert!(fwd.is_some(), "forwarder must exist for the self-test gate");
            });
    }

    /// **Load-bearing**: when the forwarder self-test fails, `start_cancellable`
    /// returns `Err(ForwarderSelfTestFailed)` AND `routing.install` is NEVER
    /// called. Catches any future regression that re-orders the gate
    /// AFTER route install — re-introducing the #388 dead-tunnel DNS hijack.
    ///
    /// Test plumbing: `MockProxy::new()` does not bind a real TCP listener
    /// on `127.0.0.1:1080`, so the forwarder's `Socks5Connector` connection
    /// fails with ECONNREFUSED on every attempt (the 3×1500ms loop closes
    /// fast on each refused connect, well under the 5s outer budget).
    #[skuld::test]
    fn start_blocks_on_forwarder_self_test_failure() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let routing_state = routing.state();
            let state_path = dir.path().join(route_state::STATE_FILE_NAME);

            let (mut pm, _dir) = new_manager_with_routing(MockProxy::new(), routing, dir);

            // Enable the DNS gate. The forwarder will fail because nothing
            // listens on `127.0.0.1:<local_port>` (MockProxy.start returns
            // Ok without binding).
            let mut cfg = test_config();
            cfg.dns.enabled = true;
            cfg.dns.servers = vec!["127.0.0.1".parse().unwrap()];

            let err = pm.start_cancellable(&cfg, CancellationToken::new()).await.unwrap_err();

            assert!(
                matches!(err, ProxyError::ForwarderSelfTestFailed { .. }),
                "expected ForwarderSelfTestFailed, got {err:?}"
            );
            assert_eq!(pm.state(), ProxyState::Stopped);
            assert_eq!(
                routing_state.install_calls.load(Ordering::SeqCst),
                0,
                "routing.install MUST NOT be called when self-test fails (#388 regression guard)"
            );
            assert_eq!(routing_state.teardown_calls.load(Ordering::SeqCst), 0);
            assert!(!state_path.exists(), "no state file when install never ran");
            assert!(
                pm.last_error()
                    .map(|s| s.contains("forwarder self-test failed"))
                    .unwrap_or(false),
                "last_error should mention the self-test failure; got {:?}",
                pm.last_error()
            );
        });
    }

    /// `dns.enabled = false` → start happy path is unchanged. Gate is
    /// skipped; routes install; proxy transitions to Running.
    #[skuld::test]
    fn start_succeeds_when_dns_disabled() {
        rt().block_on(async {
            let (mut pm, _dir) = new_manager(MockProxy::new());
            // test_config() already has dns.enabled = false.
            pm.start_cancellable(&test_config(), CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(pm.state(), ProxyState::Running);
            pm.stop().await.unwrap();
        });
    }
}
