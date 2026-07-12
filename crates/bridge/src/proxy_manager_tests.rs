// `CancellationToken::new` is pervasive across these tests as the test
// harness's root signal; module-level allow per clippy.toml's
// "Bridge cancellation contract" sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use super::*;
use crate::proxy::{Proxy, ProxyError, RunningProxy, TrafficTotals};
use crate::reachability::ReachabilityVerdict;
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tun_engine::gateway::GatewayInfo;
use tun_engine::routing::failclosed::lockdown_state;
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
    /// Cumulative traffic counters surfaced via `MockRunning::traffic_totals`.
    /// Tests `fetch_add` to simulate tunnel traffic. Zeroed on every
    /// successful `start`, mirroring the fresh `FlowStat` a new
    /// shadowsocks `Server` creates.
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
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

    fn state_handle(&self) -> Arc<MockProxyState> {
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
        // Fresh session ⇒ fresh counters (production: a new Server
        // creates a new FlowStat).
        self.state.bytes_in.store(0, Ordering::SeqCst);
        self.state.bytes_out.store(0, Ordering::SeqCst);
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

    fn traffic_totals(&self) -> TrafficTotals {
        TrafficTotals {
            bytes_in: self.state.bytes_in.load(Ordering::SeqCst),
            bytes_out: self.state.bytes_out.load(Ordering::SeqCst),
        }
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
    cover_engage_calls: AtomicU32,
    cover_disengage_calls: AtomicU32,
    lockdown_engage_calls: AtomicU32,
    lockdown_disengage_calls: AtomicU32,
    fail_lockdown: AtomicBool,
    fail_cover: AtomicBool,
    /// Ordered record of teardown events ("routes" / "lockdown") so a test can
    /// observe the unwind teardown sequence. Shared via the `Arc<MockRoutingState>`
    /// both `MockRoutes` and `MockCover` clone.
    teardown_order: std::sync::Mutex<Vec<&'static str>>,
    /// Last `server_ip` passed to `install`, so a test can assert the bypass
    /// route received the DoH-resolved IP (not a system-resolved one).
    last_install_server_ip: std::sync::Mutex<Option<IpAddr>>,
    /// Last `server_ip` passed to `install_failclosed_cover`, so a test can assert
    /// the cover permits exactly the resolved server IP.
    last_cover_server_ip: std::sync::Mutex<Option<IpAddr>>,
}

impl Default for MockRoutingState {
    fn default() -> Self {
        Self {
            install_calls: AtomicU32::new(0),
            teardown_calls: AtomicU32::new(0),
            fail_install: AtomicBool::new(false),
            fail_gateway: AtomicBool::new(false),
            cover_engage_calls: AtomicU32::new(0),
            cover_disengage_calls: AtomicU32::new(0),
            lockdown_engage_calls: AtomicU32::new(0),
            lockdown_disengage_calls: AtomicU32::new(0),
            fail_lockdown: AtomicBool::new(false),
            fail_cover: AtomicBool::new(false),
            teardown_order: std::sync::Mutex::new(Vec::new()),
            last_install_server_ip: std::sync::Mutex::new(None),
            last_cover_server_ip: std::sync::Mutex::new(None),
        }
    }
}

struct MockRouting {
    state: Arc<MockRoutingState>,
    /// Directory where the crash-recovery state file is written. Each
    /// `MockRouting` owns its own `state_dir` — in production,
    /// `SystemRouting::new(state_dir, owner)` does the same. Tests hand the
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

    fn failing_lockdown(state_dir: PathBuf) -> Self {
        let m = Self::new(state_dir);
        m.state.fail_lockdown.store(true, Ordering::SeqCst);
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
        *self.state.last_install_server_ip.lock().unwrap() = Some(server_ip);

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
        route_state::save(&self.state_dir, &persisted, None)
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

    type Cover = MockCover;

    fn install_failclosed_cover(&self, server_ip: IpAddr) -> Result<MockCover, RoutingError> {
        if self.state.fail_cover.load(Ordering::SeqCst) {
            return Err(RoutingError::RouteSetup("mock cover failure".into()));
        }
        *self.state.last_cover_server_ip.lock().unwrap() = Some(server_ip);
        self.state.cover_engage_calls.fetch_add(1, Ordering::SeqCst);
        Ok(MockCover {
            state: Arc::clone(&self.state),
            lockdown: false,
        })
    }

    fn install_lockdown(
        &self,
        _server_ip: IpAddr,
        _tun_name: &str,
        _app_ids: &[std::path::PathBuf],
    ) -> Result<MockCover, RoutingError> {
        if self.state.fail_lockdown.load(Ordering::SeqCst) {
            return Err(RoutingError::RouteSetup("mock lockdown failure".into()));
        }
        self.state.lockdown_engage_calls.fetch_add(1, Ordering::SeqCst);
        Ok(MockCover {
            state: Arc::clone(&self.state),
            lockdown: true,
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
        self.state.teardown_order.lock().unwrap().push("routes");
        let _ = route_state::clear(&self.state_dir);
    }
}

struct MockCover {
    state: Arc<MockRoutingState>,
    /// Whether this guard holds the standing lockdown cover (vs the transient
    /// fail-closed cover) — selects which disengage counter Drop bumps, mirroring
    /// the kind-aware `failclosed::Cover`.
    lockdown: bool,
}

impl Drop for MockCover {
    fn drop(&mut self) {
        if self.lockdown {
            self.state.lockdown_disengage_calls.fetch_add(1, Ordering::SeqCst);
            self.state.teardown_order.lock().unwrap().push("lockdown");
        } else {
            self.state.cover_disengage_calls.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl tun_engine::routing::CoverGuard for MockCover {
    /// Mirror `failclosed::Cover::disarm`: consume the guard without running
    /// `Drop`, so the disengage counter does NOT move — the cutover persists the
    /// cover instead of disengaging it.
    fn disarm(self) {
        std::mem::forget(self);
    }
}

// MockRouting lockdown instrumentation ================================================================================
//
// These exercise the mock seam directly (no ProxyManager) so the later
// standing-guard lifecycle tests (engage / fail-FATAL / disengage) can rely on
// the counters, fail flag, and kind-aware Drop dispatch being correct.

#[skuld::test]
fn mock_install_lockdown_records_engage_and_drop_records_disengage() {
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::new(dir.path().to_path_buf());
    let state = routing.state();

    let cover = routing
        .install_lockdown(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), "hole-tun", &[])
        .expect("lockdown engages");
    assert_eq!(state.lockdown_engage_calls.load(Ordering::SeqCst), 1);
    // The transient-cover counter must NOT move — the two covers are distinct.
    assert_eq!(state.cover_engage_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.lockdown_disengage_calls.load(Ordering::SeqCst), 0);

    drop(cover);
    assert_eq!(state.lockdown_disengage_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.cover_disengage_calls.load(Ordering::SeqCst), 0);
}

#[skuld::test]
fn mock_failing_lockdown_returns_err_without_recording() {
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::failing_lockdown(dir.path().to_path_buf());
    let state = routing.state();

    let result = routing.install_lockdown(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), "hole-tun", &[]);
    assert!(result.is_err(), "failing_lockdown must return Err");
    assert_eq!(state.lockdown_engage_calls.load(Ordering::SeqCst), 0);
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

/// `new_manager` returning the `MockRoutingState` handle, so a test can read
/// the `server_ip` that `install` received — without a test-only reader on the
/// production manager API.
fn new_manager_capturing(
    proxy: MockProxy,
) -> (
    ProxyManager<MockProxy, MockRouting>,
    Arc<MockRoutingState>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::new(dir.path().to_path_buf());
    let state = routing.state();
    let pm = ProxyManager::new(proxy, routing);
    (pm, state, dir)
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

/// Build a manager whose routing + manager share `dir` as state_dir, with the
/// lockdown intent seeded to `enabled`. The shared state_dir is how the manager
/// reads `bridge-lockdown.json` in `start_inner`.
fn new_manager_with_lockdown(
    proxy: MockProxy,
    routing: MockRouting,
    dir: tempfile::TempDir,
    enabled: bool,
) -> (ProxyManager<MockProxy, MockRouting>, tempfile::TempDir) {
    lockdown_state::set_enabled(dir.path(), enabled, None).unwrap();
    let pm = ProxyManager::new(proxy, routing).with_state_dir(dir.path().to_path_buf());
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
        let state = backend.state_handle();

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
        let state = backend.state_handle();

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
        let proxy_state = proxy.state_handle();
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
        let state = proxy.state_handle();

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

// death_reason: path-free GUI/toast surface, distinct from last_error (#470) ==========================================

#[skuld::test]
fn check_health_sets_path_free_death_reason() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.state_handle();
        let (mut pm, _dir) = new_manager(proxy);
        pm.start(&test_config()).await.unwrap();

        state.crashed.store(true, Ordering::SeqCst);
        pm.check_health();

        assert_eq!(
            pm.death_reason(),
            Some(DEATH_REASON),
            "out-of-band death surfaces the sentinel"
        );
        assert!(
            !DEATH_REASON.contains('/') && !DEATH_REASON.contains('\\'),
            "death reason is path-free"
        );
    });
}

/// The PII guarantee: a failed start records its arbitrary (possibly
/// path-bearing) error in `last_error` for diagnostics, but NEVER in
/// `death_reason` — so it can never reach the GUI status/toast.
#[skuld::test]
fn failed_start_records_last_error_but_not_death_reason() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::failing_start());
        let _ = pm.start(&test_config()).await.unwrap_err();

        assert!(
            pm.last_error().is_some(),
            "failed start records last_error for diagnostics"
        );
        assert_eq!(
            pm.death_reason(),
            None,
            "a failed start is not a death — must not surface to the toast"
        );
    });
}

/// A (re)start supersedes a prior death: the death reason clears so a later
/// poll cannot re-toast a stale death.
#[skuld::test]
fn restart_clears_prior_death_reason() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.state_handle();
        let (mut pm, _dir) = new_manager(proxy);
        pm.start(&test_config()).await.unwrap();

        state.crashed.store(true, Ordering::SeqCst);
        pm.check_health();
        assert_eq!(pm.death_reason(), Some(DEATH_REASON));

        state.crashed.store(false, Ordering::SeqCst);
        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.death_reason(), None, "a successful restart clears the death reason");
    });
}

/// stop() clears the death reason too (a clean stop is not a death).
#[skuld::test]
fn stop_clears_death_reason() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.state_handle();
        let (mut pm, _dir) = new_manager(proxy);
        pm.start(&test_config()).await.unwrap();

        state.crashed.store(true, Ordering::SeqCst);
        pm.check_health();
        assert_eq!(pm.death_reason(), Some(DEATH_REASON));

        // A fresh start then a clean stop must leave no death reason behind.
        state.crashed.store(false, Ordering::SeqCst);
        pm.start(&test_config()).await.unwrap();
        pm.stop().await.unwrap();
        assert_eq!(pm.death_reason(), None);
    });
}

#[skuld::test]
fn check_health_clears_active_config_so_reload_restarts() {
    // Regression guard: check_health must clear active_config, otherwise
    // a subsequent reload would take the hot-swap path (no-op) instead
    // of starting a new proxy.
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.state_handle();

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

// Traffic metrics =====================================================================================================

#[skuld::test]
fn sample_traffic_is_none_when_stopped() {
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
        assert!(pm.sample_traffic().is_none());
    });
}

#[skuld::test]
fn sample_traffic_reports_cumulative_totals() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.state_handle();
        let (mut pm, _dir) = new_manager(proxy);
        pm.start(&test_config()).await.unwrap();

        state.bytes_in.fetch_add(1_048_576, Ordering::SeqCst);
        state.bytes_out.fetch_add(65_536, Ordering::SeqCst);

        let m = pm.sample_traffic().expect("running");
        assert_eq!(m.totals.bytes_in, 1_048_576);
        assert_eq!(m.totals.bytes_out, 65_536);

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn sample_traffic_speed_is_zero_on_first_sample() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.state_handle();
        let (mut pm, _dir) = new_manager(proxy);
        pm.start(&test_config()).await.unwrap();
        state.bytes_in.fetch_add(10_000, Ordering::SeqCst);

        let m = pm.sample_traffic().expect("running");
        assert_eq!(m.speed_in_bps, 0, "no window exists before the first sample");
        assert_eq!(m.speed_out_bps, 0);

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
async fn sample_traffic_computes_speed_over_window() {
    // Current-thread runtime (skuld async) + paused clock: the window's
    // tokio::time::Instant advances exactly 1s, so the speeds are exact.
    tokio::time::pause();
    let proxy = MockProxy::new();
    let state = proxy.state_handle();
    let (mut pm, _dir) = new_manager(proxy);
    pm.start(&test_config()).await.unwrap();
    let _ = pm.sample_traffic().expect("running"); // establish the window at totals (0, 0)

    state.bytes_in.fetch_add(1_000_000, Ordering::SeqCst);
    state.bytes_out.fetch_add(500_000, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(1)).await;

    let m = pm.sample_traffic().expect("running");
    assert_eq!(m.speed_in_bps, 8_000_000, "1_000_000 bytes over exactly 1s");
    assert_eq!(m.speed_out_bps, 4_000_000);

    pm.stop().await.unwrap();
}

#[skuld::test]
fn sample_traffic_resets_on_restart() {
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.state_handle();
        let (mut pm, _dir) = new_manager(proxy);
        pm.start(&test_config()).await.unwrap();
        let _ = pm.sample_traffic().expect("running");
        state.bytes_in.fetch_add(1_000, Ordering::SeqCst);
        pm.stop().await.unwrap();

        // MockProxy::start zeroes the counters, mirroring the fresh
        // FlowStat a new shadowsocks Server creates.
        pm.start(&test_config()).await.unwrap();
        let m = pm.sample_traffic().expect("running");
        assert_eq!(m.totals, TrafficTotals::default(), "fresh session inherits no totals");
        assert_eq!(
            (m.speed_in_bps, m.speed_out_bps),
            (0, 0),
            "fresh session inherits no window"
        );

        pm.stop().await.unwrap();
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

/// The fail-closed cover path must also never spawn a real routing subprocess
/// from a mock — the #165 isolation contract extends to the cover. Engage +
/// drop N covers through the mock and assert zero spawns and balanced
/// engage/disengage counts.
#[skuld::test(serial)]
fn mock_cover_engage_disengage_never_spawns() {
    routing::ROUTING_SUBPROCESS_SPAWN_COUNT.store(0, Ordering::SeqCst);

    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::new(dir.path().to_path_buf());
    let st = routing.state();
    for _ in 0..10 {
        let cover = routing.install_failclosed_cover("1.2.3.4".parse().unwrap()).unwrap();
        drop(cover);
    }

    assert_eq!(routing::ROUTING_SUBPROCESS_SPAWN_COUNT.load(Ordering::SeqCst), 0);
    assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 10);
    assert_eq!(st.cover_disengage_calls.load(Ordering::SeqCst), 10);
}

// Standing lockdown guard lifecycle (#527) ============================================================================
//
// `start_inner` engages the standing lockdown cover AFTER routing.install and
// BEFORE Dns::apply, ONLY when `bridge-lockdown.json` intent is on. The Cover
// is committed to RunningState only on the Ok path; `stop()` disengages it. A
// failed engage under intent-on is fail-FATAL: it aborts the start and the
// locally-owned routes guard tears down (mirror of the forwarder-self-test gate).

#[skuld::test]
fn lockdown_off_does_not_engage_cover() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);

        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);
        assert!(!pm.lockdown_active(), "lockdown OFF must leave no cover engaged");
        assert_eq!(
            st.lockdown_engage_calls.load(Ordering::SeqCst),
            0,
            "lockdown OFF must be byte-identical to today (no engage)"
        );

        pm.stop().await.unwrap();
        assert_eq!(st.lockdown_disengage_calls.load(Ordering::SeqCst), 0);
    });
}

#[skuld::test]
fn lockdown_on_engages_after_install_and_disengages_on_stop() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);

        pm.start(&test_config()).await.unwrap();
        assert_eq!(pm.state(), ProxyState::Running);
        assert!(pm.lockdown_active(), "intent-on start must engage the cover");
        assert_eq!(st.install_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            st.lockdown_engage_calls.load(Ordering::SeqCst),
            1,
            "engaged on a lockdown-on start"
        );
        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            0,
            "still engaged while running"
        );

        pm.stop().await.unwrap();
        assert!(!pm.lockdown_active(), "cover disengaged after stop");
        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            1,
            "disengaged on stop"
        );
    });
}

#[skuld::test]
fn lockdown_engage_failure_is_fatal_and_tears_down() {
    // Fail-FATAL mirror of start_blocks_on_forwarder_self_test_failure: a
    // failed lockdown engage under intent-ON aborts the start and tears down
    // routes (the opposite of the transient cover's fail-open).
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::failing_lockdown(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);

        let err = pm.start(&test_config()).await.unwrap_err();
        assert!(
            err.to_string().contains("mock lockdown failure"),
            "expected the lockdown engage error, got {err}"
        );
        assert_eq!(pm.state(), ProxyState::Stopped);
        // routes WERE installed (engage runs after install) then torn down on
        // the Err unwind — net teardown count equals install count.
        assert_eq!(st.install_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            st.teardown_calls.load(Ordering::SeqCst),
            1,
            "routes must be torn down when lockdown engage fails (fail-FATAL)"
        );
        // The engage never succeeded, so no cover was committed and none disengaged.
        assert_eq!(st.lockdown_engage_calls.load(Ordering::SeqCst), 0);
        assert_eq!(st.lockdown_disengage_calls.load(Ordering::SeqCst), 0);
        assert!(pm.last_error().is_some());
    });
}

#[skuld::test]
fn lockdown_engage_failure_tears_down_routes_only() {
    // Fail-FATAL engage: routes were installed (engage runs after install) then the
    // `?` on install_lockdown unwinds the locally-owned `routes` guard. The lockdown
    // cover is never constructed (the `?` fires before the `lockdown` binding
    // completes), so the ordered recorder must show exactly one teardown — "routes" —
    // and the cover disengage counter must stay at zero. (On a clean stop the order
    // is the reverse — routes then lockdown — by design; see ProxyManager::stop.)
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::failing_lockdown(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);

        let err = pm.start(&test_config()).await.unwrap_err();
        assert!(err.to_string().contains("mock lockdown failure"));
        assert_eq!(pm.state(), ProxyState::Stopped);

        let order = st.teardown_order.lock().unwrap().clone();
        assert_eq!(
            order,
            vec!["routes"],
            "engage failure tears down routes only; no cover was created"
        );
        assert_eq!(st.lockdown_disengage_calls.load(Ordering::SeqCst), 0);
    });
}

#[skuld::test]
fn stop_with_cutover_disarms_lockdown_but_user_stop_disengages() {
    rt().block_on(async {
        // UserStop: the cover Drop disengages (opens the host).
        {
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
            pm.start(&test_config()).await.unwrap();

            pm.stop_with(StopReason::UserStop).await.unwrap();
            assert_eq!(
                st.lockdown_disengage_calls.load(Ordering::SeqCst),
                1,
                "user stop disengages the cover"
            );
        }
        // Cutover: the cover is disarmed (persist-without-disengage) so the
        // persistent filters survive the restart; routes still tear down.
        {
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
            pm.start(&test_config()).await.unwrap();
            assert_eq!(st.teardown_calls.load(Ordering::SeqCst), 0);

            pm.stop_with(StopReason::Cutover).await.unwrap();
            assert_eq!(
                st.lockdown_disengage_calls.load(Ordering::SeqCst),
                0,
                "cutover does NOT disengage the cover (it is disarmed so the filters persist)"
            );
            assert_eq!(
                st.teardown_calls.load(Ordering::SeqCst),
                1,
                "cutover still tears down routes"
            );
        }
    });
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
fn doh_bootstrap_failure_sets_last_error() {
    use crate::dns::bootstrap::DohQuerier;
    struct NeverQuerier;
    #[async_trait::async_trait]
    impl DohQuerier for NeverQuerier {
        async fn query(&self, _s: IpAddr, _w: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
        pm.set_bootstrap_querier_for_test(Arc::new(NeverQuerier));
        let mut config = test_config();
        // RFC 2606 reserves .invalid for guaranteed-non-resolution; the stub
        // querier never answers, so resolve is fail-closed without any network.
        config.server.server = "test.invalid".into();

        let err = pm.start(&config).await.unwrap_err();
        assert!(matches!(err, ProxyError::DohBootstrap(_)), "fail-closed: {err:?}");
        assert_eq!(pm.state(), ProxyState::Stopped);
        assert!(pm.last_error().is_some(), "DoH bootstrap failure must set last_error");
        // last_error is the PII-free DohBootstrap Display — host is in the log, not here.
        assert!(!pm.last_error().unwrap().contains("test.invalid"));
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
        pm.start_cancellable(&test_config(), false, token).await.unwrap();
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

        let err = pm.start_cancellable(&test_config(), false, token).await.unwrap_err();
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

        let err = pm.start_cancellable(&test_config(), false, token).await.unwrap_err();
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
        pm.start_cancellable(&test_config(), false, token.clone())
            .await
            .unwrap();
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
            let f = pm.start_cancellable(&cfg, false, token);
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
        let state = proxy.state_handle();
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

        let err = pm.start_cancellable(&config, false, token).await.unwrap_err();
        assert!(matches!(err, ProxyError::Cancelled), "expected Cancelled, got {err:?}");
        assert_eq!(pm.state(), ProxyState::Stopped);
        // No gate release needed: the cancel drops the parked
        // `proxy.start` future before it passes the gate, so the mock's
        // sleeper task is never spawned.
    });
}

#[skuld::test]
fn reload_creates_fresh_uncancellable_token() {
    // reload() with a different server internally calls start_cancellable
    // with a fresh token that is never signaled. Verifies the full-restart
    // reload path still works after the cancellation refactor.
    rt().block_on(async {
        let proxy = MockProxy::new();
        let state = proxy.state_handle();

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
        let state = proxy.state_handle();

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

// DoH bootstrap wiring ================================================================================================

use crate::dns::bootstrap::DohQuerier;
use hole_common::protocol::TunnelMode;

/// Stub querier resolving exactly one hostname to one IPv4, used to prove
/// `start_inner` resolves via DoH (not the OS) and hands the result downstream.
struct WiringStubQuerier {
    host: String,
    ip: IpAddr,
}

#[async_trait::async_trait]
impl DohQuerier for WiringStubQuerier {
    async fn query(&self, _server: IpAddr, wire: &[u8]) -> Option<Vec<u8>> {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record, RecordType};
        // Only answer the A query (port-free: the stub keys on hostname).
        let q = Message::from_vec(wire).ok()?;
        let question = q.queries.first()?;
        if question.query_type() != RecordType::A {
            return None; // force the resolver onto the A path (IPv4-preferred).
        }
        let IpAddr::V4(v4) = self.ip else { return None };
        let n = Name::from_ascii(format!("{}.", self.host)).ok()?;
        let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
        reply.add_query(Query::query(n.clone(), RecordType::A));
        reply.add_answer(Record::from_rdata(n, 60, RData::A(A(v4))));
        reply.to_vec().ok()
    }
}

fn doh_config_with_server_host(host: &str, mode: TunnelMode) -> ProxyConfig {
    ProxyConfig {
        server: ServerEntry {
            id: "doh-test".into(),
            name: "doh-test".into(),
            server: host.into(),
            server_port: 8388,
            password: "test".into(),
            method: "aes-256-gcm".into(),
            plugin: Some("v2ray-plugin".into()),
            plugin_opts: Some("host=example.com".into()),
            validation: None,
        },
        local_port: 1080,
        tunnel_mode: mode,
        filters: Vec::new(),
        dns: hole_common::config::DnsConfig {
            enabled: false, // skip the forwarder self-test gate
            servers: vec!["1.1.1.1".parse().unwrap()],
            protocol: hole_common::config::DnsProtocol::Https,
            allow_insecure_bootstrap: false,
        },
        proxy_socks5: true,
        proxy_http: false,
        local_port_http: 4074,
        diagnostic_plugin_tap: false,
    }
}

#[skuld::test]
fn full_start_resolves_server_ip_via_doh_and_routes_with_it() {
    let expected: IpAddr = "203.0.113.7".parse().unwrap();
    rt().block_on(async {
        let (mut pm, rstate, _dir) = new_manager_capturing(MockProxy::new());
        pm.set_bootstrap_querier_for_test(Arc::new(WiringStubQuerier {
            host: "proxy.example".into(),
            ip: expected,
        }));
        // A configured plugin would spawn a real subprocess; this Full-mode
        // assertion is about the bypass route, so use a plugin-less config — the
        // resolve still runs above Phase 1 and feeds routing.install.
        let mut config = doh_config_with_server_host("proxy.example", TunnelMode::Full);
        config.server.plugin = None;
        pm.start(&config).await.unwrap();
        assert_eq!(
            *rstate.last_install_server_ip.lock().unwrap(),
            Some(expected),
            "bypass route got the DoH-resolved IP"
        );
        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn bare_ss_dials_doh_resolved_ip_not_hostname() {
    // Bare SS (no plugin) with a HOSTNAME server: the shadowsocks ServerConfig
    // handed to proxy.start must carry the DoH-resolved IP, not the hostname —
    // otherwise shadowsocks-rust OS-resolves the proxy domain at connect time
    // and re-leaks it.
    let expected: IpAddr = "203.0.113.7".parse().unwrap();
    rt().block_on(async {
        let proxy = MockProxy::new();
        let proxy_state = proxy.state_handle();
        let (mut pm, _dir) = new_manager(proxy);
        pm.set_bootstrap_querier_for_test(Arc::new(WiringStubQuerier {
            host: "proxy.example".into(),
            ip: expected,
        }));
        let mut config = doh_config_with_server_host("proxy.example", TunnelMode::Full);
        config.server.plugin = None;
        pm.start(&config).await.unwrap();

        {
            let guard = proxy_state.last_config.lock().unwrap();
            let ss_config = guard.as_ref().expect("proxy.start captured a config");
            match ss_config.server[0].config.addr() {
                shadowsocks::config::ServerAddr::SocketAddr(addr) => {
                    assert_eq!(addr.ip(), expected, "bare-SS endpoint must be the resolved IP");
                    assert_eq!(addr.port(), config.server.server_port);
                }
                other => panic!("bare-SS endpoint must be the resolved IP socket, got {other:?}"),
            }
        }

        pm.stop().await.unwrap();
    });
}

#[skuld::test]
fn socks_only_with_plugin_resolves_via_doh_for_handoff() {
    // SocksOnly returns early (no routing), but the plugin-chain handoff still
    // needs the DoH-resolved IP. The plugin binary is nonexistent so the chain
    // fails; we assert the FAILURE is the plugin spawn (resolve already ran and
    // succeeded) — i.e. NOT a DohBootstrap error.
    let expected: IpAddr = "203.0.113.7".parse().unwrap();
    rt().block_on(async {
        let (mut pm, _dir) = new_manager(MockProxy::new());
        pm.set_bootstrap_querier_for_test(Arc::new(WiringStubQuerier {
            host: "proxy.example".into(),
            ip: expected,
        }));
        let mut config = doh_config_with_server_host("proxy.example", TunnelMode::SocksOnly);
        config.server.plugin = Some("definitely-not-a-real-plugin-binary".into());
        let err = pm.start(&config).await.unwrap_err();
        assert!(
            matches!(err, ProxyError::Plugin(_)),
            "expected plugin-spawn failure AFTER a successful DoH resolve, got {err:?}"
        );
        assert!(
            !matches!(err, ProxyError::DohBootstrap(_)),
            "resolve must have succeeded via the stub querier, not failed: {err:?}"
        );
    });
}

#[skuld::test]
fn full_start_fails_closed_when_doh_cannot_resolve() {
    // A stub that answers nothing → NoAnswer → DohBootstrap, hermetic (no
    // system DNS or network).
    struct NeverQuerier;
    #[async_trait::async_trait]
    impl DohQuerier for NeverQuerier {
        async fn query(&self, _s: IpAddr, _w: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }
    rt().block_on(async {
        let (mut pm, rstate, _dir) = new_manager_capturing(MockProxy::new());
        pm.set_bootstrap_querier_for_test(Arc::new(NeverQuerier));
        let mut config = doh_config_with_server_host("proxy.example", TunnelMode::Full);
        config.server.plugin = None;
        let err = pm.start(&config).await.unwrap_err();
        assert!(
            matches!(err, ProxyError::DohBootstrap(_)),
            "fail-closed start error: {err:?}"
        );
        assert_eq!(
            *rstate.last_install_server_ip.lock().unwrap(),
            None,
            "no route installed on a failed resolve"
        );
    });
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
            allow_insecure_bootstrap: false,
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
                    allow_insecure_bootstrap: false,
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
                    allow_insecure_bootstrap: false,
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

    /// The in-TUN LocalDnsEndpoint is the sole OS DNS path, so it must be
    /// constructed whenever DNS is enabled with servers. `build_local_dns`
    /// returns a 2-tuple `(Option<LocalDnsEndpoint>, Option<Arc<DnsForwarder>>)`.
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
                    allow_insecure_bootstrap: false,
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

            let err = pm
                .start_cancellable(&cfg, false, CancellationToken::new())
                .await
                .unwrap_err();

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

    /// Pure-VPN (#459): the resolved ephemeral port — not
    /// `config.local_port` — must be what `build_local_dns` (and
    /// `Dispatcher::new`) receive. The regression mode is a swap back to
    /// `config.local_port` at a consumer call site, which would make the
    /// forwarder's `Socks5Connector` dial the configured port. Detect it
    /// by listening on `config.local_port` for the duration of a pure-VPN
    /// start with the forwarder enabled and asserting zero connection
    /// attempts. (The start itself fails at the self-test gate either
    /// way — MockProxy binds nothing — which also guarantees every
    /// connector dial has completed before the assertion runs.)
    #[skuld::test]
    fn pure_vpn_start_never_dials_the_configured_port() {
        rt().block_on(async {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let configured_port = listener.local_addr().unwrap().port();

            let (mut pm, _dir) = new_manager(MockProxy::new());
            let mut cfg = test_config();
            cfg.proxy_socks5 = false;
            cfg.proxy_http = false;
            cfg.local_port = configured_port;
            cfg.dns.enabled = true;
            cfg.dns.servers = vec!["127.0.0.1".parse().unwrap()];

            let err = pm
                .start_cancellable(&cfg, false, CancellationToken::new())
                .await
                .unwrap_err();
            assert!(
                matches!(err, ProxyError::ForwarderSelfTestFailed { .. }),
                "expected ForwarderSelfTestFailed, got {err:?}"
            );

            match listener.accept() {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {} // nothing dialed local_port
                Ok((_, peer)) => panic!("pure-VPN start dialed the configured local_port (from {peer})"),
                Err(e) => panic!("unexpected accept error: {e}"),
            }
        });
    }

    /// `dns.enabled = false` → start happy path is unchanged. Gate is
    /// skipped; routes install; proxy transitions to Running.
    #[skuld::test]
    fn start_succeeds_when_dns_disabled() {
        rt().block_on(async {
            let (mut pm, _dir) = new_manager(MockProxy::new());
            // test_config() already has dns.enabled = false.
            pm.start_cancellable(&test_config(), false, CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(pm.state(), ProxyState::Running);
            pm.stop().await.unwrap();
        });
    }

    // Self-test verdict → error mapping (live-Connect reason rewrite) -------------------------------------------------
    //
    // `self_test_error_for` is the pure mapping from a reachability verdict to the
    // `ProxyError` surfaced to the toast: `Blocked` becomes the typed
    // `NetworkBlocked`; `TcpRefused`/`TcpTimeout` rewrite the reason; everything
    // else keeps the original self-test reason. No real TUN / bridge start needed.

    fn original_reason() -> String {
        "attempt 3 timed out".to_string()
    }

    #[skuld::test]
    fn self_test_error_blocked_is_network_blocked() {
        let e = self_test_error_for(Some(ReachabilityVerdict::Blocked), 3, 200, original_reason());
        assert!(
            matches!(e, ProxyError::NetworkBlocked),
            "Blocked must map to the typed NetworkBlocked, got {e:?}"
        );
    }

    #[skuld::test]
    fn self_test_error_tcp_refused_rewrites_reason() {
        let e = self_test_error_for(Some(ReachabilityVerdict::TcpRefused), 3, 200, original_reason());
        match e {
            ProxyError::ForwarderSelfTestFailed { reason, .. } => {
                assert!(reason.contains("refused"), "got {reason:?}");
            }
            other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
        }
    }

    #[skuld::test]
    fn self_test_error_tcp_timeout_rewrites_reason() {
        let e = self_test_error_for(Some(ReachabilityVerdict::TcpTimeout), 3, 200, original_reason());
        match e {
            ProxyError::ForwarderSelfTestFailed { reason, .. } => {
                assert!(reason.contains("did not respond"), "got {reason:?}");
            }
            other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
        }
    }

    #[skuld::test]
    fn self_test_error_reachable_keeps_original() {
        let e = self_test_error_for(Some(ReachabilityVerdict::Reachable), 3, 200, original_reason());
        match e {
            ProxyError::ForwarderSelfTestFailed {
                reason,
                attempts,
                elapsed_ms,
            } => {
                assert_eq!(reason, original_reason());
                assert_eq!(attempts, 3);
                assert_eq!(elapsed_ms, 200);
            }
            other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
        }
    }

    #[skuld::test]
    fn self_test_error_inconclusive_keeps_original() {
        let e = self_test_error_for(Some(ReachabilityVerdict::Inconclusive), 3, 200, original_reason());
        match e {
            ProxyError::ForwarderSelfTestFailed { reason, .. } => assert_eq!(reason, original_reason()),
            other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
        }
    }

    #[skuld::test]
    fn self_test_error_none_keeps_original() {
        let e = self_test_error_for(None, 3, 200, original_reason());
        match e {
            ProxyError::ForwarderSelfTestFailed { reason, .. } => assert_eq!(reason, original_reason()),
            other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
        }
    }

    /// A server config whose `server` points at a closed loopback port, so the
    /// out-of-band probe (no plugin → Raw transport) terminates fast with a
    /// closed-port verdict (`TcpRefused`, or `TcpTimeout` on a Windows runner
    /// that SYN-drops) and the self-test gate fails (MockProxy binds no listener
    /// for the forwarder). Returns the (manager, config) ready to drive the gate.
    fn gate_failure_setup(lockdown: bool) -> (ProxyManager<MockProxy, MockRouting>, ProxyConfig, tempfile::TempDir) {
        // A bound-then-dropped listener yields a port that is closed for the test's
        // duration, so a connect there is refused, not accepted.
        let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = probe_l.local_addr().unwrap();
        drop(probe_l);

        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let (pm, dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, lockdown);

        let mut cfg = test_config();
        cfg.server.server = closed.ip().to_string();
        cfg.server.server_port = closed.port();
        cfg.dns.enabled = true;
        cfg.dns.servers = vec!["127.0.0.1".parse().unwrap()];
        (pm, cfg, dir)
    }

    /// cover-skip: with the lockdown intent ON, the gate must NOT run the probe
    /// (a standing kill-switch cover would block it and we'd mis-report Hole's own
    /// lockdown as censorship). The probe would rewrite the reason to "refused";
    /// with the probe skipped the ORIGINAL self-test reason survives.
    #[skuld::test]
    fn lockdown_on_skips_probe_keeps_original_reason() {
        rt().block_on(async {
            let (mut pm, cfg, _dir) = gate_failure_setup(true);
            let err = pm
                .start_cancellable(&cfg, false, CancellationToken::new())
                .await
                .unwrap_err();
            match err {
                ProxyError::ForwarderSelfTestFailed { reason, .. } => assert!(
                    !reason.contains("refused"),
                    "lockdown-on must skip the probe and keep the original reason, got {reason:?}"
                ),
                other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
            }
        });
    }

    /// Control: with lockdown OFF the probe DOES run, so the same closed-port
    /// server rewrites the reason to the probe's verdict — proving the
    /// lockdown-on skip above is load-bearing, not vacuous. The closed port is
    /// refused on most kernels (`TcpRefused`) but SYN-dropped on Windows GitHub
    /// runners (`TcpTimeout` → "did not respond"); either rewrite proves the
    /// probe ran.
    #[skuld::test]
    fn lockdown_off_runs_probe_rewrites_reason() {
        rt().block_on(async {
            let (mut pm, cfg, _dir) = gate_failure_setup(false);
            let err = pm
                .start_cancellable(&cfg, false, CancellationToken::new())
                .await
                .unwrap_err();
            match err {
                ProxyError::ForwarderSelfTestFailed { reason, .. } => {
                    let rewritten = if cfg!(target_os = "windows") {
                        reason.contains("refused") || reason.contains("did not respond")
                    } else {
                        reason.contains("refused")
                    };
                    assert!(
                        rewritten,
                        "lockdown-off must run the probe and rewrite the reason, got {reason:?}"
                    );
                }
                other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
            }
        });
    }

    // Block-until-connected cover =====================================================================================
    //
    // A covered start (auto-connect intent) engages the fail-closed cover BEFORE
    // start_inner and, on failure, RETAINS it (host stays blocked). The gate
    // fixture fails the start deterministically, so these assert engage/disengage
    // counts + the retained-blocked state via the mock's kind-aware counters.

    /// Gate fixture that also hands back the mock routing state so a test can read
    /// the transient-cover engage/disengage counters. Server is a closed loopback
    /// port (IP literal → resolves trivially, no DoH querier needed).
    fn covered_gate_setup(
        lockdown: bool,
    ) -> (
        ProxyManager<MockProxy, MockRouting>,
        ProxyConfig,
        Arc<MockRoutingState>,
        tempfile::TempDir,
    ) {
        let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = probe_l.local_addr().unwrap();
        drop(probe_l);
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (pm, dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, lockdown);
        let mut cfg = test_config();
        cfg.server.server = closed.ip().to_string();
        cfg.server.server_port = closed.port();
        cfg.dns.enabled = true;
        cfg.dns.servers = vec!["127.0.0.1".parse().unwrap()];
        (pm, cfg, st, dir)
    }

    #[skuld::test]
    fn covered_start_engages_and_retains_cover_on_failure() {
        rt().block_on(async {
            let (mut pm, cfg, st, _dir) = covered_gate_setup(false);
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                1,
                "covered start engages once"
            );
            assert_eq!(
                st.cover_disengage_calls.load(Ordering::SeqCst),
                0,
                "a failed covered start must RETAIN the cover, not disengage it"
            );
            assert!(
                pm.blocked_until_connected(),
                "host stays blocked after a failed covered start"
            );
        });
    }

    #[skuld::test]
    fn cutover_while_blocked_disarms_the_transient_cover_user_stop_disengages() {
        rt().block_on(async {
            // A covered start that failed holds the transient cover (host blocked).
            // A cutover must DISARM it — persist the fail-closed filters across the
            // restart gap — never disengage; a user Disconnect disengages (opens the
            // host). Mirrors stop_with_cutover_disarms_lockdown for the standing cover.
            let (mut pm, cfg, st, _dir) = covered_gate_setup(false);
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert!(pm.blocked_until_connected());
            pm.stop_with(StopReason::Cutover).await.unwrap();
            assert_eq!(
                st.cover_disengage_calls.load(Ordering::SeqCst),
                0,
                "cutover disarms the held cover (filters persist across the restart), never disengages"
            );
            assert!(
                !pm.blocked_until_connected(),
                "the manager releases the cover either way — the disarm keeps only the OS filters"
            );

            // User-stop branch, fresh manager: a Disconnect disengages (opens host).
            let (mut pm, cfg, st, _dir) = covered_gate_setup(false);
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            pm.stop_with(StopReason::UserStop).await.unwrap();
            assert_eq!(
                st.cover_disengage_calls.load(Ordering::SeqCst),
                1,
                "a user Disconnect disengages the held cover"
            );
            assert!(!pm.blocked_until_connected());
        });
    }

    #[skuld::test]
    fn uncovered_start_never_engages_cover() {
        rt().block_on(async {
            let (mut pm, cfg, st, _dir) = covered_gate_setup(false);
            let _ = pm
                .start_cancellable(&cfg, false, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                0,
                "a manual (uncovered) start never engages"
            );
            assert!(!pm.blocked_until_connected());
        });
    }

    #[skuld::test]
    fn covered_start_subsumed_when_lockdown_intent_on() {
        rt().block_on(async {
            // Lockdown intent on: the transient cover is subsumed (the standing
            // lockdown cover holds the line), so we must NOT engage it.
            let (mut pm, cfg, st, _dir) = covered_gate_setup(true);
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                0,
                "lockdown-on subsumes the transient cover"
            );
            assert!(!pm.blocked_until_connected());
        });
    }

    #[skuld::test]
    fn user_stop_while_blocked_releases_cover_and_clears_error() {
        rt().block_on(async {
            let (mut pm, cfg, st, _dir) = covered_gate_setup(false);
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert!(pm.blocked_until_connected());
            pm.stop().await.unwrap();
            assert!(
                !pm.blocked_until_connected(),
                "a user Disconnect opens the blocked host"
            );
            assert_eq!(
                st.cover_disengage_calls.load(Ordering::SeqCst),
                1,
                "stop disengages the retained cover"
            );
            assert!(
                pm.last_error().is_none(),
                "Disconnect-from-blocked clears the stale error"
            );
        });
    }

    #[skuld::test]
    fn same_server_retry_reuses_the_held_cover() {
        rt().block_on(async {
            let (mut pm, cfg, st, _dir) = covered_gate_setup(false);
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            // Retry to the SAME server+resolvers while blocked: reuse the guard.
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                1,
                "same-server retry reuses the guard (no re-engage)"
            );
            assert_eq!(
                st.cover_disengage_calls.load(Ordering::SeqCst),
                0,
                "the reused guard is never disengaged"
            );
            assert!(pm.blocked_until_connected());
        });
    }

    #[skuld::test]
    fn different_server_retry_reuses_held_cover_stays_fail_closed() {
        rt().block_on(async {
            // The transient cover is a global singleton: a different-server retry
            // must NOT engage a second cover (that would self-clobber the shared
            // WFP GUIDs / pf ruleset and fail OPEN). It reuses the single held
            // guard — the new server is simply not permitted, so the retry stays
            // fail-closed.
            let (mut pm, mut cfg, st, _dir) = covered_gate_setup(false);
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            cfg.server.server = "127.0.0.2".into();
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                1,
                "a different-server retry must reuse the held singleton, never engage a second"
            );
            assert_eq!(
                st.cover_disengage_calls.load(Ordering::SeqCst),
                0,
                "the held cover is never disengaged mid-retry (no fall-open)"
            );
            assert!(pm.blocked_until_connected());
        });
    }

    #[skuld::test]
    fn covered_start_success_releases_cover() {
        rt().block_on(async {
            // A covered start that SUCCEEDS releases the cover (the tunnel is the
            // protection now) — blocked_until_connected must be false.
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_routing(MockProxy::new(), routing, dir);
            pm.start_cancellable(&test_config(), true, CancellationToken::new())
                .await
                .unwrap();
            assert_eq!(pm.state(), ProxyState::Running);
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1, "covered start engages");
            assert_eq!(
                st.cover_disengage_calls.load(Ordering::SeqCst),
                1,
                "success releases the cover"
            );
            assert!(!pm.blocked_until_connected());
            pm.stop().await.unwrap();
        });
    }

    #[skuld::test]
    fn covered_start_cancel_releases_cover() {
        rt().block_on(async {
            // A user cancel of a covered start releases the cover (same trust as a
            // disconnect), NOT retains it.
            let gate = Arc::new(tokio::sync::Notify::new());
            let (entered_tx, entered_rx) = oneshot::channel();
            let proxy = MockProxy::with_start_gate(gate.clone()).with_entered_signal(entered_tx);
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_routing(proxy, routing, dir);
            let token = CancellationToken::new();
            let cancel_clone = token.clone();
            tokio::spawn(async move {
                entered_rx.await.expect("MockProxy::start never entered");
                cancel_clone.cancel();
            });
            let err = pm.start_cancellable(&test_config(), true, token).await.unwrap_err();
            assert!(matches!(err, ProxyError::Cancelled), "expected Cancelled, got {err:?}");
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                1,
                "covered start engages before the cancel"
            );
            assert_eq!(
                st.cover_disengage_calls.load(Ordering::SeqCst),
                1,
                "cancel releases the cover"
            );
            assert!(
                !pm.blocked_until_connected(),
                "a cancelled covered start does not leave the host blocked"
            );
            gate.notify_one();
        });
    }

    #[skuld::test]
    fn covered_start_engage_failure_proceeds_uncovered() {
        rt().block_on(async {
            // If the OS cover install FAILS on a fresh covered start, the bridge
            // warns and proceeds UNCOVERED (aborting would leave the user
            // unconnected AND unprotected) — no cover is retained, so the host is
            // not (falsely) reported blocked.
            let (mut pm, cfg, st, _dir) = covered_gate_setup(false);
            st.fail_cover.store(true, Ordering::SeqCst);
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                0,
                "the engage failed, so none is counted"
            );
            assert!(
                !pm.blocked_until_connected(),
                "a failed engage retains no cover — host is not reported blocked"
            );
        });
    }

    #[skuld::test]
    fn covered_start_cover_permits_the_resolved_server_ip() {
        rt().block_on(async {
            // The cover must permit exactly the resolved server IP — the onward
            // connect target (plugin + self-test). A regression passing the wrong
            // value would block the very connection the block-until-connected gate
            // is waiting to succeed.
            let (mut pm, cfg, st, _dir) = covered_gate_setup(false);
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            let permitted = st
                .last_cover_server_ip
                .lock()
                .unwrap()
                .expect("the covered start engaged the cover");
            assert_eq!(
                permitted,
                cfg.server.server.parse::<IpAddr>().unwrap(),
                "the cover permits exactly the resolved server IP"
            );
        });
    }

    /// A one-hostname DoH stub that COUNTS queries, so a test can prove a covered
    /// retry reuses the resolved IP instead of re-querying under the held cover.
    struct CountingQuerier {
        host: String,
        ip: IpAddr,
        queries: AtomicU32,
    }

    #[async_trait::async_trait]
    impl DohQuerier for CountingQuerier {
        async fn query(&self, _server: IpAddr, wire: &[u8]) -> Option<Vec<u8>> {
            use hickory_proto::op::{Message, MessageType, OpCode, Query};
            use hickory_proto::rr::rdata::A;
            use hickory_proto::rr::{Name, RData, Record, RecordType};
            self.queries.fetch_add(1, Ordering::SeqCst);
            let q = Message::from_vec(wire).ok()?;
            if q.queries.first()?.query_type() != RecordType::A {
                return None; // force the resolver onto the A path (IPv4-preferred).
            }
            let IpAddr::V4(v4) = self.ip else { return None };
            let n = Name::from_ascii(format!("{}.", self.host)).ok()?;
            let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
            reply.add_query(Query::query(n.clone(), RecordType::A));
            reply.add_answer(Record::from_rdata(n, 60, RData::A(A(v4))));
            reply.to_vec().ok()
        }
    }

    #[skuld::test]
    fn covered_retry_reuses_the_resolved_ip_without_re_querying_doh() {
        rt().block_on(async {
            // A covered start resolves the server hostname via DoH (uncovered),
            // engages the cover, and fails (host blocked). The cover permits the
            // resolved IP, NOT the DoH resolvers, so a retry MUST reuse the cached
            // IP — re-querying DoH under the held cover would be blocked and wedge
            // the retry. We observe reuse via the DoH querier's call count.
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: "203.0.113.9".parse().unwrap(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier.clone());
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.dns.enabled = true;
            cfg.dns.servers = vec!["1.1.1.1".parse().unwrap()];

            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            let after_first = querier.queries.load(Ordering::SeqCst);
            assert!(after_first >= 1, "the first covered start resolves via DoH");
            assert!(pm.blocked_until_connected(), "the failed covered start holds the cover");

            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                querier.queries.load(Ordering::SeqCst),
                after_first,
                "the covered retry reuses the resolved IP and does NOT re-query DoH under the cover"
            );
        });
    }

    /// The covered start engages the cover before start_inner, so the probe-
    /// suppression predicate (cover_active) sees the live in-process signal even
    /// with NO lockdown intent — the original self-test reason survives. Mirrors
    /// `lockdown_on_skips_probe_keeps_original_reason`; the control is
    /// `lockdown_off_runs_probe_rewrites_reason` (uncovered → probe runs).
    #[skuld::test]
    fn covered_start_without_lockdown_suppresses_probe() {
        rt().block_on(async {
            let (mut pm, cfg, _st, _dir) = covered_gate_setup(false);
            let err = pm.start_cancellable(&cfg, true, CancellationToken::new()).await.unwrap_err();
            match err {
                ProxyError::ForwarderSelfTestFailed { reason, .. } => assert!(
                    !reason.contains("refused"),
                    "a covered start engages a cover, so the probe is skipped and the original reason survives, got {reason:?}"
                ),
                other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
            }
        });
    }

    /// Leak regression: the start-time reachability probe must connect to the
    /// DoH-resolved IP, never OS-resolve the proxy domain. The server is a
    /// non-resolvable domain that ONLY the DoH stub maps — to the closed loopback
    /// port — and lockdown is OFF so the probe runs. Probing the resolved IP hits
    /// the closed port → `TcpRefused`/`TcpTimeout` → the gate reason is rewritten.
    /// If the probe regressed to OS-resolving the domain, the lookup would fail →
    /// `DnsFailed` verdict → `self_test_error_for` keeps the ORIGINAL reason, so
    /// the rewrite assertion fails.
    #[skuld::test]
    fn probe_connects_to_doh_resolved_ip_not_hostname() {
        rt().block_on(async {
            // A bound-then-dropped listener: a port closed for the test's duration,
            // so a connect there is refused (or SYN-dropped → timeout on Windows).
            let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = probe_l.local_addr().unwrap();
            drop(probe_l);

            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(Arc::new(WiringStubQuerier {
                host: "probe-leak.example".into(),
                ip: closed.ip(),
            }));

            let mut cfg = test_config();
            cfg.server.server = "probe-leak.example".into();
            cfg.server.server_port = closed.port();
            cfg.dns.enabled = true;
            cfg.dns.servers = vec!["1.1.1.1".parse().unwrap()];
            cfg.dns.protocol = hole_common::config::DnsProtocol::Https;
            cfg.dns.allow_insecure_bootstrap = false;

            let err = pm
                .start_cancellable(&cfg, false, CancellationToken::new())
                .await
                .unwrap_err();
            match err {
                ProxyError::ForwarderSelfTestFailed { reason, .. } => {
                    let rewritten = if cfg!(target_os = "windows") {
                        reason.contains("refused") || reason.contains("did not respond")
                    } else {
                        reason.contains("refused")
                    };
                    assert!(
                        rewritten,
                        "probe must connect to the DoH-resolved IP (closed port → refused/timeout); \
                         an OS-resolve of the domain would yield DnsFailed and keep the original \
                         reason, got {reason:?}"
                    );
                }
                other => panic!("expected ForwarderSelfTestFailed, got {other:?}"),
            }
        });
    }

    /// End-to-end-ish: a TLS-transport endpoint that accepts TCP then resets the
    /// handshake → the live probe verdict is `Blocked` → `self_test_error_for`
    /// yields the typed `NetworkBlocked`.
    #[skuld::test(name = "proxy_manager_tests::reset_endpoint_maps_to_network_blocked")]
    async fn reset_endpoint_maps_to_network_blocked() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                drop(s);
            }
        });
        let verdict = crate::reachability::probe_server_reachability(
            &a.ip().to_string(),
            a.port(),
            Some("galoshes"),
            Some("tls;host=h"),
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(verdict, ReachabilityVerdict::Blocked);
        assert!(matches!(
            self_test_error_for(Some(verdict), 3, 200, original_reason()),
            ProxyError::NetworkBlocked
        ));
    }
}
