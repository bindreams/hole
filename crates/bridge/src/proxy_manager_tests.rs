// `CancellationToken::new` is pervasive across these tests as the test
// harness's root signal; module-level allow per clippy.toml's
// "Bridge cancellation contract" sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use super::*;
use crate::proxy::{Proxy, ProxyError, RunningProxy, TrafficTotals};
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;
use plugin_e2e::locators::locate_ex_ray;
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
    /// Count of `engage_lockdown_tun` calls (Phase 6, adds the TUN permit).
    lockdown_engage_calls: AtomicU32,
    lockdown_disengage_calls: AtomicU32,
    /// Makes `engage_lockdown_tun` (Phase 6) fail.
    fail_lockdown: AtomicBool,
    fail_cover: AtomicBool,
    /// Ordered record of lifecycle events ("routes" / "lockdown" teardown,
    /// "cover_engage" transient-cover engage) so a test can observe
    /// cross-call ordering — e.g. that a stale standing-cover guard releases
    /// BEFORE the transient cover engages, not after. Shared via the
    /// `Arc<MockRoutingState>` both `MockRoutes` and `MockCover` clone.
    teardown_order: std::sync::Mutex<Vec<&'static str>>,
    /// Last `server_ip` passed to `install`, so a test can assert the bypass
    /// route received the DoH-resolved IP (not a system-resolved one).
    last_install_server_ip: std::sync::Mutex<Option<IpAddr>>,
    /// Last `server_ip` passed to `install_failclosed_cover`, so a test can assert
    /// the cover permits exactly the resolved server IP.
    last_cover_server_ip: std::sync::Mutex<Option<IpAddr>>,
    /// Last `resolver_ip` passed to `install_failclosed_cover`, so a test can
    /// assert the cover permits exactly the ONE pinned resolver (or none).
    last_cover_resolver_ip: std::sync::Mutex<Option<IpAddr>>,
    /// `install_failclosed_cover` fails whenever its `resolver_ip` argument
    /// is a MEMBER of this set, succeeding for every other value — lets a
    /// test simulate "the corrected permit fails to engage, but the previous
    /// one still would" (a singleton set) for the stale-permit repair's
    /// compensating restore, or "both the corrected AND the restore fail"
    /// (a set containing both values) for the double-failure fail-open path.
    /// `fail_cover` (always-fail) is unaffected and takes priority.
    fail_cover_for_resolvers: std::sync::Mutex<std::collections::HashSet<Option<IpAddr>>>,
    /// Last `resolver_ip` passed to `engage_lockdown_tun` (Phase 6, adds the
    /// TUN permit to the cover `install_lockdown_permits` already returned).
    last_lockdown_resolver_ip: std::sync::Mutex<Option<IpAddr>>,
    /// Count of `install_lockdown_permits` calls — the Phase-0, pre-Phase-1
    /// early engage, which returns the cover the running session
    /// holds. Distinct from `lockdown_engage_calls` (Phase 6, stateless
    /// TUN-add on the SAME cover) so a test can prove the EARLY call fires
    /// even when Phase 6 never runs (e.g. the self-test fails first).
    lockdown_permits_calls: AtomicU32,
    /// Last `resolver_ip` passed to `install_lockdown_permits` OR
    /// `reengage_lockdown_permits` (shared -- both are "what does the live
    /// cover now permit").
    last_lockdown_permits_resolver_ip: std::sync::Mutex<Option<IpAddr>>,
    fail_lockdown_permits: AtomicBool,
    /// Count of `reengage_lockdown_permits` calls — the stale-permit REPAIR
    /// path, distinct from `lockdown_permits_calls` (a fresh/first-ever
    /// engage): a repair consumes the held guard directly instead of
    /// dropping it and calling `install_lockdown_permits` again, so a test
    /// can prove the repair path is what actually ran.
    reengage_lockdown_permits_calls: AtomicU32,
    fail_reengage_lockdown_permits: AtomicBool,
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
            last_cover_resolver_ip: std::sync::Mutex::new(None),
            fail_cover_for_resolvers: std::sync::Mutex::new(std::collections::HashSet::new()),
            last_lockdown_resolver_ip: std::sync::Mutex::new(None),
            lockdown_permits_calls: AtomicU32::new(0),
            last_lockdown_permits_resolver_ip: std::sync::Mutex::new(None),
            fail_lockdown_permits: AtomicBool::new(false),
            reengage_lockdown_permits_calls: AtomicU32::new(0),
            fail_reengage_lockdown_permits: AtomicBool::new(false),
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

    /// Makes the Phase-6 TUN-add (`engage_lockdown_tun`) fail, distinct from
    /// `failing_lockdown_permits` (which fails the Phase-0 call).
    fn failing_lockdown(state_dir: PathBuf) -> Self {
        let m = Self::new(state_dir);
        m.state.fail_lockdown.store(true, Ordering::SeqCst);
        m
    }

    /// Makes the Phase-0 early engage (`install_lockdown_permits`) fail,
    /// distinct from `failing_lockdown` (which fails the Phase-6 call).
    fn failing_lockdown_permits(state_dir: PathBuf) -> Self {
        let m = Self::new(state_dir);
        m.state.fail_lockdown_permits.store(true, Ordering::SeqCst);
        m
    }

    /// Makes the stale-permit REPAIR (`reengage_lockdown_permits`) fail,
    /// distinct from `failing_lockdown_permits` (which fails a FRESH
    /// engage) -- simulates the real Windows repair's checked delete
    /// failing loud instead of being silently swallowed.
    fn failing_reengage_lockdown_permits(state_dir: PathBuf) -> Self {
        let m = Self::new(state_dir);
        m.state.fail_reengage_lockdown_permits.store(true, Ordering::SeqCst);
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

    fn install_failclosed_cover(
        &self,
        server_ip: IpAddr,
        resolver_ip: Option<IpAddr>,
    ) -> Result<MockCover, RoutingError> {
        if self.state.fail_cover.load(Ordering::SeqCst) {
            return Err(RoutingError::RouteSetup("mock cover failure".into()));
        }
        if self
            .state
            .fail_cover_for_resolvers
            .lock()
            .unwrap()
            .contains(&resolver_ip)
        {
            return Err(RoutingError::RouteSetup("mock cover failure for this resolver".into()));
        }
        *self.state.last_cover_server_ip.lock().unwrap() = Some(server_ip);
        *self.state.last_cover_resolver_ip.lock().unwrap() = resolver_ip;
        self.state.cover_engage_calls.fetch_add(1, Ordering::SeqCst);
        self.state.teardown_order.lock().unwrap().push("cover_engage");
        Ok(MockCover {
            state: Arc::clone(&self.state),
            lockdown: false,
        })
    }

    fn install_lockdown_permits(
        &self,
        _server_ip: IpAddr,
        resolver_ip: Option<IpAddr>,
        _app_ids: &[std::path::PathBuf],
    ) -> Result<MockCover, RoutingError> {
        if self.state.fail_lockdown_permits.load(Ordering::SeqCst) {
            return Err(RoutingError::RouteSetup("mock lockdown-permits failure".into()));
        }
        *self.state.last_lockdown_permits_resolver_ip.lock().unwrap() = resolver_ip;
        self.state.lockdown_permits_calls.fetch_add(1, Ordering::SeqCst);
        Ok(MockCover {
            state: Arc::clone(&self.state),
            lockdown: true,
        })
    }

    fn reengage_lockdown_permits(
        &self,
        old: MockCover,
        _server_ip: IpAddr,
        resolver_ip: Option<IpAddr>,
        _app_ids: &[std::path::PathBuf],
    ) -> Result<MockCover, (RoutingError, MockCover)> {
        if self.state.fail_reengage_lockdown_permits.load(Ordering::SeqCst) {
            // Give `old` back UNCHANGED -- mirrors the real primitive's
            // atomicity guarantee (an aborted FWPM transaction / a rejected
            // pf reload leaves the OLD state untouched): the caller must be
            // able to keep tracking the SAME still-live guard, not lose it.
            return Err((
                RoutingError::RouteSetup("mock reengage-lockdown-permits failure".into()),
                old,
            ));
        }
        // `old` is consumed WITHOUT running its own Drop on the SUCCESS path
        // -- mirrors the real implementation's contract (the repair's own
        // checked teardown replaces the old guard's ordinary
        // disengage-on-drop, so this must NOT bump `lockdown_disengage_calls`;
        // a real repair produces no observable "gap" between the old and
        // new values, just a replacement).
        std::mem::forget(old);
        *self.state.last_lockdown_permits_resolver_ip.lock().unwrap() = resolver_ip;
        self.state
            .reengage_lockdown_permits_calls
            .fetch_add(1, Ordering::SeqCst);
        Ok(MockCover {
            state: Arc::clone(&self.state),
            lockdown: true,
        })
    }

    fn engage_lockdown_tun(
        &self,
        _tun_name: &str,
        _server_ip: IpAddr,
        resolver_ip: Option<IpAddr>,
    ) -> Result<(), RoutingError> {
        if self.state.fail_lockdown.load(Ordering::SeqCst) {
            return Err(RoutingError::RouteSetup("mock lockdown failure".into()));
        }
        *self.state.last_lockdown_resolver_ip.lock().unwrap() = resolver_ip;
        self.state.lockdown_engage_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
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
fn mock_install_lockdown_permits_records_engage_and_drop_records_disengage() {
    // Phase 0 (`install_lockdown_permits`) is the call that returns the
    // guard the whole standing-cover session holds -- Phase 6
    // (`engage_lockdown_tun`) only adds to it, statelessly, and returns
    // nothing to own.
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::new(dir.path().to_path_buf());
    let state = routing.state();

    let cover = routing
        .install_lockdown_permits(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), None, &[])
        .expect("lockdown engages");
    assert_eq!(state.lockdown_permits_calls.load(Ordering::SeqCst), 1);
    // The transient-cover counter must NOT move — the two covers are distinct.
    assert_eq!(state.cover_engage_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.lockdown_disengage_calls.load(Ordering::SeqCst), 0);

    drop(cover);
    assert_eq!(state.lockdown_disengage_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.cover_disengage_calls.load(Ordering::SeqCst), 0);
}

#[skuld::test]
fn mock_install_lockdown_permits_records_the_resolver_permit() {
    // The standing lockdown cover must receive the same gated resolver
    // permit the transient cover would — recorded so ProxyManager-level tests
    // can assert on it.
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::new(dir.path().to_path_buf());
    let state = routing.state();
    let resolver_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));

    let _cover = routing
        .install_lockdown_permits(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), Some(resolver_ip), &[])
        .expect("lockdown engages");
    assert_eq!(
        *state.last_lockdown_permits_resolver_ip.lock().unwrap(),
        Some(resolver_ip)
    );
}

#[skuld::test]
fn mock_failing_lockdown_permits_returns_err_without_recording() {
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::failing_lockdown_permits(dir.path().to_path_buf());
    let state = routing.state();

    let result = routing.install_lockdown_permits(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), None, &[]);
    assert!(result.is_err(), "failing_lockdown_permits must return Err");
    assert_eq!(state.lockdown_permits_calls.load(Ordering::SeqCst), 0);
}

#[skuld::test]
fn mock_engage_lockdown_tun_records_the_call_and_resolver_without_a_second_guard() {
    // Phase 6 adds the TUN permit to the SAME cover Phase 0 already
    // returned -- it returns `()`, not a second guard, so the ONE cover
    // from Phase 0 (still) owns the whole disengage.
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::new(dir.path().to_path_buf());
    let state = routing.state();
    let resolver_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));

    let cover = routing
        .install_lockdown_permits(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), Some(resolver_ip), &[])
        .expect("lockdown engages");
    routing
        .engage_lockdown_tun("hole-tun", IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), Some(resolver_ip))
        .expect("tun permit added");
    assert_eq!(state.lockdown_engage_calls.load(Ordering::SeqCst), 1);
    assert_eq!(*state.last_lockdown_resolver_ip.lock().unwrap(), Some(resolver_ip));
    // Adding the TUN permit must not disengage or double-engage anything.
    assert_eq!(state.lockdown_disengage_calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.lockdown_permits_calls.load(Ordering::SeqCst), 1);

    drop(cover);
    assert_eq!(
        state.lockdown_disengage_calls.load(Ordering::SeqCst),
        1,
        "the ONE cover from Phase 0 still owns the disengage"
    );
}

#[skuld::test]
fn mock_failing_engage_lockdown_tun_returns_err_without_recording() {
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::failing_lockdown(dir.path().to_path_buf());
    let state = routing.state();

    let result = routing.engage_lockdown_tun("hole-tun", IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), None);
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

/// `plugin_opts` for a plugin config that actually reaches ex-ray's ECH
/// switch: TLS enabled via the bare `tls` flag, a domain `host` (ECH needs
/// an SNI domain to key its DoH lookup on — an absent, empty, or IP-literal
/// `host` means ex-ray dials with an IP-literal `ServerName`, so
/// `ApplyECH` bails before ever dialing DoH), `ech` left at its `auto`
/// default (`crates/ex-ray/config.go:209-223,290-294,334`;
/// `third_party/v2ray-core/transport/internet/tls/ech.go:26-51`). Bare
/// `plugin = Some("ex-ray")` with no options — TCP-only, no `tls`, no
/// `host` — never reaches ECH at all regardless of `ech-doh`; tests that
/// need a real cover permit or an ECH-posture warning must opt in via this
/// constant, matching a real postern config
/// (`a_postern_config_composes_into_holes_pinned_url` in plugin.rs).
const ECH_CAPABLE_OPTS: &str = "tls;host=cdn.example";

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
        let cover = routing
            .install_failclosed_cover("1.2.3.4".parse().unwrap(), None)
            .unwrap();
        drop(cover);
    }

    assert_eq!(routing::ROUTING_SUBPROCESS_SPAWN_COUNT.load(Ordering::SeqCst), 0);
    assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 10);
    assert_eq!(st.cover_disengage_calls.load(Ordering::SeqCst), 10);
}

#[skuld::test(serial)]
fn mock_install_failclosed_cover_records_the_resolver_argument() {
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::new(dir.path().to_path_buf());
    let st = routing.state();
    let resolver: IpAddr = "9.9.9.9".parse().unwrap();

    let cover = routing
        .install_failclosed_cover("1.2.3.4".parse().unwrap(), Some(resolver))
        .unwrap();
    assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(resolver));
    drop(cover);

    let cover = routing
        .install_failclosed_cover("1.2.3.4".parse().unwrap(), None)
        .unwrap();
    assert_eq!(
        *st.last_cover_resolver_ip.lock().unwrap(),
        None,
        "a None resolver_ip must be recorded as None, not left stale from the prior call"
    );
    drop(cover);
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

// Standing lockdown resolver permit ===================================================================================
//
// `ech_resolver_permit` is computed ONCE in `start_cancellable` (the same
// value the transient cover's tests below already exercise extensively) and
// threaded into BOTH `install_lockdown_permits` (Phase 0, before Phase 1 —
// see that fn's doc for why) and `engage_lockdown_tun` (Phase 6, which adds
// the TUN permit to the SAME guard) — see `start_inner`'s entry comment.
// These tests prove the THREADING, not
// the derivation: the derivation itself (`effective_ech_doh` / `ech_doh_url`)
// is already covered by the `covered_start_*_permits_the_constructed_resolver`
// family for the transient cover.

#[skuld::test]
fn lockdown_on_engages_with_no_resolver_permit_when_no_plugin_configured() {
    // No plugin means no later ECH lookup, so BOTH `install_lockdown_permits`
    // (Phase 0) and `engage_lockdown_tun` (Phase 6) must still be called
    // (lockdown always engages when intent is on) but with `None` — negative
    // direction, exercised through the REAL `start_inner` call chain (no
    // plugin needed to reach it, unlike the positive-permit case below).
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);

        pm.start(&test_config()).await.unwrap();
        assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *st.last_lockdown_permits_resolver_ip.lock().unwrap(),
            None,
            "no plugin configured means no resolver permit at the Phase-0 early engage either"
        );
        assert_eq!(st.lockdown_engage_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *st.last_lockdown_resolver_ip.lock().unwrap(),
            None,
            "no plugin configured means no resolver permit, even under lockdown"
        );
    });
}

/// Stage a copy of the real `ex-ray` binary (built by `cargo xtask ex-ray`)
/// into a fresh, test-private tempdir and return the exact spawn path.
/// Panics loud, never skips, matching
/// `server_test_tests.rs::run_test_with_v2ray_plugin_happy_path`'s contract
/// for a missing build. Callers pass the result to
/// `ProxyManager::set_plugin_path_override_for_test` -- no shared destination
/// path, no process-global mutation (`resolve_plugin_path`'s next-to-exe/PATH
/// lookup is never consulted).
fn stage_real_ex_ray() -> (tempfile::TempDir, String) {
    let ex_ray = locate_ex_ray();
    assert!(
        ex_ray.is_file(),
        "ex-ray not built at {ex_ray:?} -- run `cargo xtask ex-ray` before running this test"
    );
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join(if cfg!(windows) { "ex-ray.exe" } else { "ex-ray" });
    std::fs::copy(&ex_ray, &dest).expect("copy ex-ray into the test's own private directory");
    let path = dest.to_string_lossy().into_owned();
    (dir, path)
}

#[skuld::test]
fn lockdown_on_permits_the_gated_ech_resolver_for_a_real_plugin_chain() {
    // The resolver permit reaches the standing cover's
    // Phase-0 early engage (`install_lockdown_permits`) -- BEFORE Phase 1, so
    // BEFORE the plugin chain's Phase-4 dial that actually fetches the
    // ECH config. `dns.enabled = true` (the default) is left ON, unlike the
    // old version of this test: it arms the Phase-4 forwarder self-test,
    // which `MockProxy` cannot satisfy (no real SOCKS5 server behind it), so
    // the start still fails overall -- but the assertion is on the EARLY
    // call, which runs regardless of that later, unrelated failure. Exercises
    // the REAL plugin chain end to end (`start_plugin_chain` isn't behind a
    // trait seam), so this proves the value genuinely reaches the routing
    // provider, not just the isolated `MockRouting` contract
    // (`mock_install_lockdown_permits_records_the_call_and_resolver` proves
    // that half).
    rt().block_on(async {
        let (_plugin_dir, plugin_path) = stage_real_ex_ray();

        let resolver: IpAddr = "198.51.100.5".parse().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
        pm.set_plugin_path_override_for_test(plugin_path);
        let mut cfg = test_config();
        // Literal IP: no bootstrap query needed (`PinSource::NoQueryNeeded`),
        // so this test doesn't need a mock DoH querier -- `ech_doh_url` still
        // constructs a real IP-literal URL from `dns.servers`.
        cfg.server.server = "203.0.113.9".into();
        cfg.server.plugin = Some("ex-ray".into());
        cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
        cfg.dns.enabled = true;
        cfg.dns.servers = vec![resolver];

        // The overall start still fails (MockProxy can't satisfy Phase 4), but
        // the early engage already ran by then.
        let _ = pm.start(&cfg).await.unwrap_err();
        assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*st.last_lockdown_permits_resolver_ip.lock().unwrap(), Some(resolver));
    });
}

#[skuld::test]
fn lockdown_on_permits_the_gated_ech_resolver_on_a_covered_start_too() {
    // `start_inner`'s own doc claims `ech_resolver_permit` is threaded through
    // unconditionally, not gated on `covered` -- the standing cover is armed
    // for manual AND covered starts alike. The sibling test above only
    // exercises the manual path (`pm.start`, `covered = false`); this proves
    // the claim on the covered (auto-connect) path too, via
    // `start_cancellable(&cfg, true, ...)`. See that sibling's doc for why
    // `dns.enabled = true` and an `unwrap_err()` are correct here.
    rt().block_on(async {
        let (_plugin_dir, plugin_path) = stage_real_ex_ray();

        let resolver: IpAddr = "198.51.100.5".parse().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
        pm.set_plugin_path_override_for_test(plugin_path);
        let mut cfg = test_config();
        cfg.server.server = "203.0.113.9".into();
        cfg.server.plugin = Some("ex-ray".into());
        cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
        cfg.dns.enabled = true;
        cfg.dns.servers = vec![resolver];

        let _ = pm
            .start_cancellable(&cfg, true, CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*st.last_lockdown_permits_resolver_ip.lock().unwrap(), Some(resolver));
    });
}

#[skuld::test]
fn lockdown_on_omits_the_resolver_permit_for_a_non_ech_capable_plugin() {
    // Negative direction with a REAL plugin chain (not just the pure gate
    // unit tests in plugin.rs): a plugin configured with no `tls`/`host` never
    // reaches ECH, so the reachability gate must keep the lockdown permit at
    // `None` even though a plugin is genuinely running under the cover.
    rt().block_on(async {
        let (_plugin_dir, plugin_path) = stage_real_ex_ray();

        let resolver: IpAddr = "198.51.100.5".parse().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
        pm.set_plugin_path_override_for_test(plugin_path);
        let mut cfg = test_config();
        cfg.server.server = "203.0.113.9".into();
        cfg.server.plugin = Some("ex-ray".into());
        cfg.server.plugin_opts = None; // no tls, no host -- never reaches ECH
        cfg.dns.enabled = false;
        cfg.dns.servers = vec![resolver];

        pm.start(&cfg).await.expect("a real ex-ray chain must start cleanly");
        // Phase 0 (the early engage) and Phase 6 (the TUN-add) share the
        // SAME `ech_resolver_permit` value, computed once in
        // `start_cancellable` -- assert both, not just Phase 6, so a future
        // change that derives the two independently can't silently widen
        // just the Phase-0 permit for this negative case.
        assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *st.last_lockdown_permits_resolver_ip.lock().unwrap(),
            None,
            "a non-ECH-capable plugin config must not widen the Phase-0 early engage either"
        );
        assert_eq!(st.lockdown_engage_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *st.last_lockdown_resolver_ip.lock().unwrap(),
            None,
            "a non-ECH-capable plugin config must not widen the lockdown cover"
        );
    });
}

#[skuld::test]
fn lockdown_on_never_reaches_phase_6_when_the_self_test_fails() {
    // The standing lockdown cover's TUN
    // permit is still only installed at Phase 6 (`routing.install` /
    // `engage_lockdown_tun`) -- that half of the claim stays true, asserted
    // below via `lockdown_engage_calls`. But ex-ray's lazy ECH-config fetch
    // fires on the plugin chain's FIRST REAL DIAL -- which, whenever
    // `dns.enabled` (the default), is the Phase 4 forwarder self-test, run
    // strictly BEFORE Phase 6 -- and the resolver permit that dial needs is
    // now installed at Phase 0 (`install_lockdown_permits`), BEFORE Phase 1,
    // so it is already live by the time Phase 4 runs, regardless of whether
    // Phase 6 is ever reached. This test proves the ordering half of that
    // claim (the Phase-0 call already carries the correct resolver even
    // though the self-test then fails for its own, unrelated reason); it
    // cannot prove the OS-level "fetch actually gets through" half without a
    // real, privileged WFP/pf cover (see `lockdown_privileged_tests.rs`).
    rt().block_on(async {
        let (_plugin_dir, plugin_path) = stage_real_ex_ray();

        let resolver: IpAddr = "198.51.100.5".parse().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
        pm.set_plugin_path_override_for_test(plugin_path);
        let mut cfg = test_config();
        cfg.server.server = "203.0.113.9".into();
        cfg.server.plugin = Some("ex-ray".into());
        cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
        // dns.enabled = true (the default) arms the Phase 4 forwarder
        // self-test, which MockProxy cannot satisfy (no real SOCKS5 server
        // behind it) -- so it fails deterministically, same as a genuinely
        // blocked/unreachable ECH-config fetch would under `ech=always`
        // (crates/ex-ray/third_party/v2ray-core/transport/internet/tls/config.go's
        // `RequireEchSatisfied`: an unobtainable ECH config makes the dial
        // itself fail, not just disable ECH).
        cfg.dns.enabled = true;
        cfg.dns.servers = vec![resolver];

        let err = pm.start(&cfg).await.unwrap_err();
        assert!(
            matches!(
                err,
                ProxyError::ForwarderSelfTestFailed { .. }
                    | ProxyError::TunnelSilent { .. }
                    | ProxyError::NoTunnelConnection { .. }
            ),
            "expected some Phase 4 self-test failure classification, got {err:?}"
        );
        // The Phase-0 early engage already carries the correct resolver,
        // before Phase 4 ever runs.
        assert_eq!(
            st.lockdown_permits_calls.load(Ordering::SeqCst),
            1,
            "the Phase-0 early engage must run before Phase 1, independent of whether Phase 4 later fails"
        );
        assert_eq!(*st.last_lockdown_permits_resolver_ip.lock().unwrap(), Some(resolver));
        assert_eq!(
            st.lockdown_engage_calls.load(Ordering::SeqCst),
            0,
            "Phase 6 (engage_lockdown_tun, where the TUN permit is added) must never run \
             when Phase 4 fails first -- irrelevant to the ECH-fetch gap, since the resolver \
             permit was already live from Phase 0 above"
        );
    });
}

#[skuld::test]
fn lockdown_permits_engage_failure_is_fatal_before_phase_1() {
    // Fail-FATAL, mirroring `engage_lockdown_tun`'s own contract: a failed
    // Phase-0 early engage aborts the start immediately, before Phase 1 ever
    // spawns a plugin chain or Phase 2 touches the proxy -- nothing has been
    // constructed yet, so there is nothing to tear down.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::failing_lockdown_permits(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);

        let err = pm.start(&test_config()).await.unwrap_err();
        assert!(
            err.to_string().contains("mock lockdown-permits failure"),
            "expected the early-engage error, got {err}"
        );
        assert_eq!(pm.state(), ProxyState::Stopped);
        assert_eq!(
            st.install_calls.load(Ordering::SeqCst),
            0,
            "routes must never be installed -- the early engage fails before Phase 1"
        );
        assert_eq!(st.lockdown_engage_calls.load(Ordering::SeqCst), 0);
        assert!(pm.last_error().is_some());
    });
}

#[skuld::test]
fn lockdown_pending_survives_a_start_failure_and_is_disengaged_by_stop() {
    // A covered lockdown-on start that engages the Phase-0 guard and THEN
    // fails at a LATER phase (here, `routing.install` itself -- routes fail
    // before Phase 6 ever calls `engage_lockdown_tun`) must RETAIN that
    // guard, not leave it orphaned with nothing able to disengage it: the
    // running session never existed, so `stop_with`'s `RunningState.lockdown`
    // handling never runs either. `stop()` must still find and disengage the
    // held guard via `lockdown_pending`.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::failing_install(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);

        let err = pm.start(&test_config()).await.unwrap_err();
        assert!(
            err.to_string().contains("mock install failure"),
            "expected the routes-install error, got {err}"
        );
        assert_eq!(pm.state(), ProxyState::Stopped);
        assert_eq!(
            st.lockdown_permits_calls.load(Ordering::SeqCst),
            1,
            "Phase 0 must have engaged before routes failed"
        );
        assert_eq!(
            st.lockdown_engage_calls.load(Ordering::SeqCst),
            0,
            "Phase 6 (TUN permit) never runs -- routes failed first"
        );
        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            0,
            "the Phase-0 guard must be RETAINED on an ordinary failure, not torn down"
        );
        assert!(
            pm.lockdown_active(),
            "lockdown_active must report the held Phase-0 guard even though nothing is running"
        );

        pm.stop().await.unwrap();
        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            1,
            "stop must find and disengage the retained Phase-0 guard"
        );
        assert!(!pm.lockdown_active());
    });
}

#[skuld::test]
fn cutover_while_lockdown_pending_disarms_not_disengages() {
    // Mirrors `cutover_while_blocked_disarms_the_transient_cover_user_stop_disengages`
    // for the STANDING cover's PENDING (not-yet-running) guard specifically:
    // `lockdown_pending_survives_a_start_failure_and_is_disengaged_by_stop`
    // (above) only ever calls `pm.stop()` (== UserStop). The sibling
    // `stop_with_cutover_disarms_lockdown_but_user_stop_disengages` test
    // exercises Cutover, but only AFTER a start that reached `running` --
    // by then the guard already moved out of `lockdown_pending` into
    // `RunningState.lockdown`, so it tests a different branch of
    // `stop_with` than the one this test targets. A covered lockdown-on
    // start that fails BEFORE ever reaching `running` (Phase 0 engaged,
    // Phase 6 never ran) leaves the guard in `lockdown_pending`; a cutover
    // there must DISARM it (persist across the restart), never disengage.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::failing_install(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);

        pm.start_cancellable(&test_config(), true, CancellationToken::new())
            .await
            .expect_err("routing.install fails on this mock");
        assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
        assert!(
            pm.lockdown_active(),
            "sanity: the Phase-0 guard is retained across the Err"
        );

        pm.stop_with(StopReason::Cutover).await.unwrap();
        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            0,
            "cutover must DISARM the still-pending guard (filters persist across the restart), \
             never disengage it -- disengaging here would open the host during the cutover gap \
             the standing cover exists to hold"
        );
        assert!(
            !pm.lockdown_active(),
            "the manager releases lockdown_pending either way -- the disarm keeps only the OS filters"
        );
    });
}

#[skuld::test]
fn lockdown_on_never_engages_for_socks_only_mode() {
    // A MANUAL (uncovered) SocksOnly start never applies lockdown, matching
    // every other manual connect's fail-open-by-design convention -- unlike
    // the covered path (next test), there is no fully-uncovered gap to close
    // here: a manual connect that the user drove directly is not silently
    // "supposed to be" protected.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
        let mut cfg = test_config();
        cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;

        pm.start(&cfg).await.expect("SocksOnly start must still succeed");
        assert_eq!(
            st.lockdown_permits_calls.load(Ordering::SeqCst),
            0,
            "the standing cover must never engage for a SocksOnly start"
        );
        assert_eq!(st.lockdown_engage_calls.load(Ordering::SeqCst), 0);
        assert!(!pm.lockdown_active());

        pm.stop().await.unwrap();
        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            0,
            "nothing was engaged, so there is nothing to disengage"
        );
    });
}

#[skuld::test]
fn covered_socks_only_start_with_lockdown_on_uses_the_standing_cover_not_the_transient_one() {
    // A manual SocksOnly start never applies lockdown (previous test), but a
    // COVERED SocksOnly start under lockdown intent must not be left with
    // NEITHER cover -- and must not use the TRANSIENT cover either: its
    // engage/disengage replace pf's entire main ruleset, which would clobber
    // a standing cover some other run (this process's prior attempt, or an
    // adopted one from before a crash) holds live, and the transient cover's
    // own gate has no way to tell that apart from a clean host. Phase 0 needs
    // no TUN, so it applies here even though Phase 6 (TUN-only) never runs
    // for SocksOnly.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
        let mut cfg = test_config();
        cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;

        pm.start_cancellable(&cfg, true, CancellationToken::new())
            .await
            .expect("SocksOnly covered start must still succeed");
        assert_eq!(
            st.lockdown_permits_calls.load(Ordering::SeqCst),
            1,
            "Phase 0 must engage instead -- a covered start must never be left fully uncovered"
        );
        assert_eq!(
            st.cover_engage_calls.load(Ordering::SeqCst),
            0,
            "the transient cover must never engage while lockdown intent is on -- it could clobber a live standing cover"
        );
        assert!(pm.lockdown_active());

        pm.stop().await.unwrap();
        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            1,
            "stop must release the Phase-0-only guard SocksOnly never completes to Phase 6"
        );
    });
}

#[skuld::test]
fn manual_socks_only_start_does_not_disengage_an_already_armed_standing_cover() {
    // A manual SocksOnly start does not APPLY lockdown (its own test above),
    // but it must not TEAR ONE DOWN either: a prior covered Full-mode attempt
    // may have engaged Phase 0 and then failed, retaining `lockdown_pending`
    // while lockdown intent is still on. The release condition must key on
    // the persisted INTENT, not on whether THIS attempt applies -- a manual
    // SocksOnly start has `lockdown_applies == false` even while intent is
    // on, and there is no replacement cover for an uncovered start to fall
    // back to (the transient cover only engages when `covered`), so gating
    // the release on `lockdown_applies` would silently fail the kill switch
    // open while `lockdown_enabled()` keeps reading true.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::failing_install(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);

        // Attempt 1: covered Full-mode start under lockdown -> Phase 0
        // engages, then `routing.install` (Phase 6) fails -> lockdown_pending
        // retained across the ordinary Err.
        pm.start_cancellable(&test_config(), true, CancellationToken::new())
            .await
            .expect_err("routing.install fails on this mock");
        assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
        assert!(
            pm.lockdown_active(),
            "sanity: the Phase-0 guard is retained across the Err"
        );

        // A manual (uncovered) SocksOnly start, intent still on.
        let mut cfg = test_config();
        cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
        let _ = pm.start(&cfg).await; // outcome irrelevant; only the cover state matters

        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            0,
            "a manual SocksOnly start must NOT disengage an already-armed standing cover"
        );
        assert!(
            pm.lockdown_active(),
            "the kill switch must still read armed after a manual SocksOnly start"
        );
        assert_eq!(
            st.cover_engage_calls.load(Ordering::SeqCst),
            0,
            "a manual (uncovered) start never engages the transient cover either -- fail-open by design"
        );
    });
}

#[skuld::test]
fn lockdown_pending_releases_before_the_transient_cover_engages_when_intent_turns_off() {
    // A covered start that engaged Phase 0 and then failed at Phase 6 (here:
    // `routing.install`) retains `lockdown_pending` (an ordinary Err, not a
    // cancel). If the user then turns lockdown OFF and retries covered, the
    // stale guard must release BEFORE the transient cover engages, not
    // after: on macOS both covers replace the SAME singular pf main
    // ruleset, so releasing the standing guard's restore-to-original AFTER
    // the transient engage would wipe the transient ruleset the retry just
    // installed, leaving the host silently open while believing it's
    // covered.
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::failing_install(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
        let cfg = test_config(); // Full mode

        // Attempt 1: lockdown on -> Phase 0 engages, then `routing.install`
        // (Phase 6) fails -> lockdown_pending retained across the Err.
        pm.start_cancellable(&cfg, true, CancellationToken::new())
            .await
            .expect_err("routing.install fails on this mock");
        assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            0,
            "retained across an ordinary Err"
        );
        assert!(pm.lockdown_active());

        // User turns lockdown off and retries covered.
        pm.set_lockdown_intent(false).unwrap();
        pm.start_cancellable(&cfg, true, CancellationToken::new())
            .await
            .expect_err("routing.install still fails on this mock");

        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            1,
            "the stale Phase-0 guard must be released once intent turns off"
        );
        assert_eq!(
            st.cover_engage_calls.load(Ordering::SeqCst),
            1,
            "the transient cover must engage now that lockdown no longer applies"
        );
        let order = st.teardown_order.lock().unwrap().clone();
        assert_eq!(
            order,
            vec!["lockdown", "cover_engage"],
            "the stale standing-cover guard must release BEFORE the transient cover engages"
        );
    });
}

#[skuld::test]
fn lockdown_pending_survives_cancel() {
    // Unlike the transient cover (released on cancel -- "same trust as a
    // user disconnect"), the standing cover represents the user's
    // PERSISTENT kill-switch intent, independent of any one connection
    // attempt: cancelling a covered start must NOT open the host, and must
    // not tear down a cover that could be protecting a pre-existing
    // (adopted) session.
    //
    // Phase 0 (in `start_cancellable`) engages BEFORE `start_inner`'s Phase 2
    // (`proxy.start`), so parking on `MockProxy`'s start gate and firing the
    // cancel only once `proxy.start` is *known* entered deterministically
    // exercises "Phase 0 already engaged, then cancelled mid-flight" (a
    // pre-cancelled token instead would short-circuit at the DoH bootstrap
    // resolve, strictly BEFORE Phase 0 ever runs, and prove nothing).
    rt().block_on(async {
        let gate = Arc::new(tokio::sync::Notify::new());
        let (entered_tx, entered_rx) = oneshot::channel();
        let proxy = MockProxy::with_start_gate(gate.clone()).with_entered_signal(entered_tx);
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(proxy, routing, dir, true);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            entered_rx.await.expect("MockProxy::start never entered");
            cancel_clone.cancel();
        });

        let err = pm.start_cancellable(&test_config(), true, cancel).await.unwrap_err();
        assert!(matches!(err, ProxyError::Cancelled), "expected Cancelled, got {err:?}");
        assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            0,
            "cancel must NOT disengage the standing cover"
        );
        assert!(
            pm.lockdown_active(),
            "the held guard must still be reported active after a cancel"
        );

        pm.stop().await.unwrap();
        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            1,
            "an explicit stop still disengages it"
        );
        // The gate is still held -- release it so the spawned mock task can
        // drop cleanly (mirrors `start_cancellable_cancelled_during_ss_start_rolls_back`).
        gate.notify_one();
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
        // The Phase-0 guard DID engage (before Phase 1 even ran) and is
        // RETAINED (not the caller's problem that Phase 6 failed later); the
        // Phase-6 TUN-add never succeeded.
        assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
        assert_eq!(st.lockdown_engage_calls.load(Ordering::SeqCst), 0);
        assert_eq!(st.lockdown_disengage_calls.load(Ordering::SeqCst), 0);
        assert!(pm.last_error().is_some());
    });
}

#[skuld::test]
fn lockdown_engage_failure_tears_down_routes_only() {
    // Fail-FATAL Phase-6 engage: routes were installed (Phase 6 runs after
    // install), then the `?` on `engage_lockdown_tun` unwinds `start_inner`'s
    // locally-owned `routes` guard. The Phase-0 guard (`self.lockdown_pending`,
    // engaged BEFORE `start_inner` ever ran) is NOT touched by that unwind —
    // it lives in the caller, not inside `start_inner` — so it stays
    // RETAINED, not torn down: the ordered recorder shows exactly one
    // teardown ("routes") and the disengage counter stays at zero. (On a
    // clean stop the order is the reverse — routes then lockdown — by
    // design; see ProxyManager::stop.)
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let routing = MockRouting::failing_lockdown(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);

        let err = pm.start(&test_config()).await.unwrap_err();
        assert!(err.to_string().contains("mock lockdown failure"));
        assert_eq!(pm.state(), ProxyState::Stopped);

        let order = st.teardown_order.lock().unwrap().clone();
        assert_eq!(order, vec!["routes"], "engage failure tears down routes only");
        assert_eq!(
            st.lockdown_permits_calls.load(Ordering::SeqCst),
            1,
            "the Phase-0 guard WAS engaged"
        );
        assert_eq!(
            st.lockdown_disengage_calls.load(Ordering::SeqCst),
            0,
            "...but retained, not torn down, by the Phase-6 failure"
        );
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
    use crate::dns::forwarder::UpstreamCause;
    struct NeverQuerier;
    #[async_trait::async_trait]
    impl DohQuerier for NeverQuerier {
        async fn query(&self, _s: IpAddr, _w: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            Err(UpstreamCause::Unreachable)
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
use crate::dns::forwarder::UpstreamCause;
struct WiringStubQuerier {
    host: String,
    ip: IpAddr,
}

#[async_trait::async_trait]
impl DohQuerier for WiringStubQuerier {
    async fn query(&self, _server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
        crate::dns::forwarder::answered_or_servfail(wire, || {
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
        })
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
    // A stub that never answers → Unreachable → DohBootstrap, hermetic (no
    // system DNS or network).
    use crate::dns::forwarder::UpstreamCause;
    struct NeverQuerier;
    #[async_trait::async_trait]
    impl DohQuerier for NeverQuerier {
        async fn query(&self, _s: IpAddr, _w: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            Err(UpstreamCause::Unreachable)
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
    use crate::dns::forwarder::UpstreamCause;
    use crate::test_support::log_capture::VecWriter;
    use hole_common::config::{DnsConfig, DnsProtocol};
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    /// The gate REACHES `report_plugin_output`. Driven through the real
    /// `start_inner` failure arm with the mock backends: `MockProxy` binds no
    /// listener, so the forwarder's SOCKS5 connect cannot complete and the gate
    /// fails. No plugin is configured, so the `None` branch is what proves the
    /// call site exists — the `Some` branch differs only in the argument, and
    /// `tests/plugin_chain.rs` proves a real chain's ring holds the child's
    /// lines.
    ///
    /// Which classification comes out is deliberately NOT asserted: the SOCKS5
    /// port is a real one, and pinning a variant would make the test depend on
    /// nothing else being bound there. `classify_failure_covers_every_branch`
    /// and `a_refused_local_hop_is_reported_as_no_connection` pin the variants
    /// against stub connectors that own their outcome.
    #[skuld::test]
    fn a_failed_gate_reaches_the_plugin_output_report() {
        let writer = VecWriter::new();
        // Current-thread: `set_default_in_current_thread` is thread-local, and
        // the gate's work runs in tasks this start spawns.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let subscriber = tracing_subscriber::registry().with(
                    fmt::layer()
                        .with_writer(writer.clone())
                        .with_ansi(false)
                        .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                // A standing lockdown suppresses the out-of-band reachability probe,
                // whose TcpRefused verdict would otherwise replace the gate's own
                // reading (see `self_test_error_for`'s precedence).
                let dir = tempfile::tempdir().unwrap();
                let routing = MockRouting::new(dir.path().to_path_buf());
                let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
                let mut cfg = test_config();
                // A real listener HELD open for the whole test, not a
                // free_port()-allocated number: `free_port` only proves the
                // port was free at the moment it probed, and nothing stops
                // another process claiming and answering on it before the
                // gate dials — a TOCTOU that would flip this run to
                // `Other` (a reply arrived) and fail the assertion below as
                // a flake. The listener never `accept()`s, so the SOCKS5
                // handshake `Socks5Connector::connect_tcp` waits on never
                // completes; the gate still fails (this test's whole point),
                // just via a hung handshake instead of an instant refusal.
                let held_port = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                cfg.local_port = held_port.local_addr().unwrap().port();
                cfg.dns = DnsConfig {
                    enabled: true,
                    servers: vec!["127.0.0.1".parse().unwrap()],
                    protocol: DnsProtocol::PlainTcp,
                    allow_insecure_bootstrap: false,
                };
                pm.start(&cfg).await.expect_err("the gate must fail with no listener");
            });
        let output = writer.snapshot_string();
        assert!(
            output.contains(crate::proxy::plugin_log::NO_PLUGIN_CONFIGURED),
            "the failed gate must report on the plugin chain; got:\n{output}"
        );
    }

    /// The `None` branch above proves the call site exists; this proves the
    /// `Some` branch actually reaches a real chain's lines. Drives the EXACT
    /// expression `start_inner` uses — `plugin_chain.as_ref().map(|c| &**c.log())`
    /// — against a `PluginChain::for_test` seeded with lines, rather than a
    /// hand-constructed `Option<&PluginLog>`, so a regression in that
    /// double-deref/reference conversion would show up here. The spawn +
    /// readiness machinery that BUILDS a real `PluginChain` is proven
    /// separately, against a real child, by `tests/plugin_chain.rs`.
    #[skuld::test]
    async fn a_configured_plugins_lines_reach_the_report_through_the_real_call_site() {
        let log = crate::proxy::plugin_log::PluginLog::new();
        log.push_line("transport/internet/tls: ECH required but no ECH config could be obtained");
        let plugin_chain = Some(crate::proxy::plugin::PluginChain::for_test(
            log,
            CancellationToken::new(),
        ));

        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        {
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
            // The exact expression from start_inner's SelfTestOutcome::Failed arm.
            super::report_plugin_output(plugin_chain.as_ref().map(|c| &**c.log()));
        }

        let output = writer.snapshot_string();
        assert!(
            output.contains("ECH required"),
            "a configured plugin's ring must reach the report through this call site; got:\n{output}"
        );
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
    /// lockdown as censorship). The probe would rewrite this into
    /// `ForwarderSelfTestFailed` with a "refused"/"did not respond" reason; with
    /// the probe skipped, the self-test's own reading decides instead — not one
    /// byte was ever written, so it is the typed `NoTunnelConnection`.
    #[skuld::test]
    fn lockdown_on_skips_probe_keeps_original_reason() {
        rt().block_on(async {
            let (mut pm, cfg, _dir) = gate_failure_setup(true);
            let err = pm
                .start_cancellable(&cfg, false, CancellationToken::new())
                .await
                .unwrap_err();
            assert!(
                matches!(err, ProxyError::NoTunnelConnection { .. }),
                "lockdown-on must skip the probe and keep the self-test's own reading, got {err:?}"
            );
        });
    }

    /// Regression: the same closed-port setup as `lockdown_off_runs_probe_rewrites_reason`
    /// (probe runs, its verdict overrides the gate's own `NoConnection`
    /// reading) must NOT quote the plugin's output — no plugin is
    /// configured here either, so a firing report would say
    /// `NO_PLUGIN_CONFIGURED` beside a failure the code has already
    /// attributed to the probe's verdict, not the (nonexistent) plugin.
    /// Current-thread runtime: `set_default_in_current_thread` is
    /// thread-local, and the gate's work runs in tasks this start spawns.
    #[skuld::test]
    fn a_probe_override_suppresses_the_plugin_output_report() {
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
                        .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let (mut pm, cfg, _dir) = gate_failure_setup(false);
                pm.start_cancellable(&cfg, false, CancellationToken::new())
                    .await
                    .expect_err("both the probe and the gate must fail");
            });
        let output = writer.snapshot_string();
        assert!(
            !output.contains(crate::proxy::plugin_log::NO_PLUGIN_CONFIGURED),
            "the probe's verdict overrides the gate's own reading, so the plugin-output \
             report must not fire; got:\n{output}"
        );
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
    fn different_server_retry_releases_stale_cover_and_re_engages_fresh() {
        rt().block_on(async {
            // End-state for a literal-IP server switch (no DoH — both are literals):
            // a retry to a DIFFERENT server releases the stale cover (it permits only
            // the OLD server) and engages a FRESH cover permitting the new one, never
            // a second cover over the held singleton. The release-before-DoH ORDERING
            // is proven separately by `different_hostname_retry_re_resolves_uncovered…`.
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
                st.cover_disengage_calls.load(Ordering::SeqCst),
                1,
                "the stale cover for the old server is released"
            );
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                2,
                "a fresh cover is engaged for the new server"
            );
            assert_eq!(
                *st.last_cover_server_ip.lock().unwrap(),
                Some("127.0.0.2".parse().unwrap()),
                "the fresh cover permits the new server IP"
            );
            assert!(pm.blocked_until_connected(), "still blocked, now on the new server");
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
    fn covered_start_cover_permits_the_doh_resolved_ip_not_the_hostname() {
        rt().block_on(async {
            // The cover must permit the DoH-RESOLVED IP, not the server hostname —
            // the onward connect target (plugin + self-test) dials the IP. A hostname
            // server routed through the querier makes the resolved IP (203.0.113.9)
            // provably distinct from the config's server string.
            let resolved: IpAddr = "203.0.113.9".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: resolved,
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.dns.enabled = true;
            cfg.dns.servers = vec!["1.1.1.1".parse().unwrap()];
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                *st.last_cover_server_ip.lock().unwrap(),
                Some(resolved),
                "the cover permits the DoH-resolved IP, not the hostname"
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
        async fn query(&self, _server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            crate::dns::forwarder::answered_or_servfail(wire, || {
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
            })
        }
    }

    /// A DoH stub that answers ONLY for one specific resolver address and fails
    /// every other. `CountingQuerier` ignores which resolver it was asked and
    /// answers unconditionally, so it cannot distinguish "the resolver that
    /// answered" from "the first resolver configured" — this one can, by putting
    /// the answering address somewhere OTHER than `dns.servers[0]`.
    struct SelectiveQuerier {
        answering: IpAddr,
        host: String,
        ip: IpAddr,
    }

    #[async_trait::async_trait]
    impl DohQuerier for SelectiveQuerier {
        async fn query(&self, server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            if server != self.answering {
                return Err(UpstreamCause::Unreachable);
            }
            crate::dns::forwarder::answered_or_servfail(wire, || {
                use hickory_proto::op::{Message, MessageType, OpCode, Query};
                use hickory_proto::rr::rdata::A;
                use hickory_proto::rr::{Name, RData, Record, RecordType};
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
            })
        }
    }

    #[skuld::test]
    fn covered_start_cover_permits_the_pinned_ech_resolver() {
        rt().block_on(async {
            // The cover must permit the resolver that ANSWERED the DoH bootstrap —
            // proven by putting a resolver that never answers FIRST in
            // `dns.servers` and the one that DOES answer second. `SelectiveQuerier`
            // fails every server except `answering_resolver`, so a wrong
            // implementation that permits `dns.servers[0]` (or "the first
            // configured resolver") fails this assertion.
            let resolved: IpAddr = "203.0.113.9".parse().unwrap();
            let failing_resolver: IpAddr = "8.8.8.8".parse().unwrap();
            let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(SelectiveQuerier {
                answering: answering_resolver,
                host: "proxy.example".into(),
                ip: resolved,
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.plugin = Some("ex-ray".into());
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            // Forces the forwarder self-test gate, which MockProxy cannot satisfy —
            // deterministic regardless of whether a real `ex-ray` happens to be on
            // PATH on this host (resolve_plugin_path_inner falls back to a bare-name
            // PATH lookup when no sibling binary exists).
            cfg.dns.enabled = true;
            cfg.dns.servers = vec![failing_resolver, answering_resolver];
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                Some(answering_resolver),
                "the cover permits the resolver that ANSWERED, not the first one configured"
            );
        });
    }

    // Integration-level proof of the reachability gate, at the WIRING
    // boundary (`start_cancellable` -> `effective_ech_doh` ->
    // `install_failclosed_cover`), not just the pure `classify_ech_doh`
    // function boundary covered in plugin.rs's own unit tests. A plugin IS
    // configured and a resolver DID answer, but `plugin_opts` never enables
    // TLS (no `tls`, no `mode=quic`) — ex-ray's `buildTLSConfig` (and its
    // whole `ech` switch) is unreachable, so the cover must not widen for a
    // fetch that provably cannot happen.
    #[skuld::test]
    fn covered_start_with_a_non_tls_capable_plugin_does_not_permit_a_resolver() {
        rt().block_on(async {
            let resolved: IpAddr = "203.0.113.9".parse().unwrap();
            let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: resolved,
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.plugin = Some("ex-ray".into());
            cfg.server.plugin_opts = Some("mode=websocket;host=cdn.example".into()); // no `tls`, no `mode=quic`
            cfg.dns.enabled = true;
            cfg.dns.servers = vec![answering_resolver];
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                None,
                "a resolver answered and a plugin is configured, but TLS is never enabled, so ex-ray \
                 never reaches its ECH switch — the cover must not permit the resolver"
            );
        });
    }

    #[skuld::test]
    fn covered_start_without_a_plugin_does_not_permit_any_resolver() {
        rt().block_on(async {
            // No plugin means no later ECH lookup at all — permitting a resolver
            // here would widen the cover for no reason. Uses a HOSTNAME server
            // with a querier that DOES answer (`pin` = `Answered`), so the ONLY
            // reason the permit stays `None` is the plugin gate itself — a
            // literal-IP fixture would already yield `NoQueryNeeded` regardless of
            // that gate and could not isolate it.
            let resolved: IpAddr = "203.0.113.9".parse().unwrap();
            let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: resolved,
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            assert!(cfg.server.plugin.is_none(), "sanity: this scenario requires no plugin");
            cfg.dns.servers = vec![answering_resolver];
            // Outcome (Ok/Err) is irrelevant here: `install_failclosed_cover` is
            // called BEFORE `start_inner` runs, so the assertions below hold
            // either way — no need to force a failure.
            let _ = pm.start_cancellable(&cfg, true, CancellationToken::new()).await;
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                1,
                "sanity: the cover must actually have engaged, or `None` below proves nothing"
            );
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), None);
        });
    }

    #[skuld::test]
    fn covered_start_with_a_literal_server_ip_still_permits_the_constructed_resolver() {
        rt().block_on(async {
            // A literal-IP server needs no bootstrap query at all
            // (`PinSource::NoQueryNeeded` short-circuits before dialing
            // anything), but `ech_doh_url` still constructs a real,
            // IP-literal `ech-doh` URL from the configured `dns.servers`
            // (IPv4-preferred) — Hole authored that address, so
            // config-authorship trust alone is judged sufficient to permit
            // it (`a_literal_server_entry_falls_back_without_a_pin` proves
            // the URL itself) — see `EchDoh::resolver`'s doc.
            let permitted_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            let mut cfg = test_config();
            cfg.server.server = "203.0.113.9".into();
            cfg.server.plugin = Some("ex-ray".into());
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            // Forces the forwarder self-test gate — deterministic regardless of
            // whether `ex-ray` happens to be resolvable via PATH on this host.
            cfg.dns.enabled = true;
            cfg.dns.servers = vec![permitted_resolver];
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(permitted_resolver));
        });
    }

    #[skuld::test]
    fn covered_start_with_insecure_bootstrap_fallback_still_permits_the_constructed_resolver() {
        rt().block_on(async {
            // Every configured resolver failed and the OS resolver supplied the
            // server address (`allow_insecure_bootstrap`, `PinSource::SecureBootstrapFailed`),
            // but `ech_doh_url` still constructs the `ech-doh` URL from
            // `dns.servers` the same way as the literal-IP case above — same
            // reasoning, same permit.
            let permitted_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(Arc::new(DeadQuerier));
            let mut cfg = test_config();
            // Resolvable on every CI host without network.
            cfg.server.server = "localhost".into();
            cfg.server.plugin = Some("ex-ray".into());
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            // Forces the forwarder self-test gate — deterministic regardless of
            // whether `ex-ray` happens to be resolvable via PATH on this host.
            cfg.dns.enabled = true;
            cfg.dns.allow_insecure_bootstrap = true;
            cfg.dns.servers = vec![permitted_resolver];
            let _ = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(permitted_resolver));
        });
    }

    #[skuld::test]
    fn covered_retry_does_not_re_engage_or_change_the_resolver_permit() {
        rt().block_on(async {
            // A same-server retry reuses the cached pin without a
            // fresh DoH query, so the cover — engaged once, at the first attempt —
            // must keep permitting the SAME resolver: never re-engaged, never
            // widened, never narrowed.
            let resolved: IpAddr = "203.0.113.9".parse().unwrap();
            let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: resolved,
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.plugin = Some("ex-ray".into());
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            cfg.dns.enabled = true;
            cfg.dns.servers = vec![answering_resolver];

            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(answering_resolver));

            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                1,
                "the retry reuses the held cover — no second engage"
            );
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                Some(answering_resolver),
                "the recorded resolver permit is still the first attempt's — never re-derived on retry"
            );
        });
    }

    // A retry that NARROWS to nothing needed (e.g. the plugin was removed)
    // must STILL release-then-reengage — see `repair_fallback`'s doc in
    // proxy_manager.rs for why a wider-than-needed permit is a real
    // widening, not a harmless superset.
    #[skuld::test]
    fn covered_retry_narrowing_to_no_permit_re_engages_to_correct_it() {
        rt().block_on(async {
            let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: "203.0.113.9".parse().unwrap(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.plugin = Some("ex-ray".into()); // attempt 1: plugin present
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            cfg.dns.enabled = true;
            cfg.dns.servers = vec![answering_resolver];

            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(answering_resolver));

            cfg.server.plugin = None; // attempt 2: plugin removed, nothing to permit now
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                2,
                "narrowing to no permit must release-then-reengage to correct the cover"
            );
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                None,
                "the corrected (narrower) permit replaces the old, wider one"
            );
        });
    }

    // When a NARROWING repair's corrected engage (to `None`) itself fails,
    // the restore falls back to the OLD (wider) permit — the residual is a
    // kill-switch WIDENING (a live permit for a resolver nothing needs), not
    // an ECH-fetch stall (no fetch is even attempted when the desired
    // permit is `None`). Both the restore-success warning and the
    // structural residual check must describe THIS direction accurately,
    // not reuse the "may stall" wording written for the opposite
    // (widening-repair) failure.
    #[skuld::test]
    fn covered_retry_narrowing_repair_failure_warns_about_the_stale_wide_permit_not_a_stall() {
        use crate::test_support::log_capture::VecWriter;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::{Layer, SubscriberExt};

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
                        .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
                let querier = Arc::new(CountingQuerier {
                    host: "proxy.example".into(),
                    ip: "203.0.113.9".parse().unwrap(),
                    queries: AtomicU32::new(0),
                });
                let dir = tempfile::tempdir().unwrap();
                let routing = MockRouting::new(dir.path().to_path_buf());
                let st = routing.state();
                let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
                pm.set_bootstrap_querier_for_test(querier);
                let mut cfg = test_config();
                cfg.server.server = "proxy.example".into();
                cfg.server.plugin = Some("ex-ray".into()); // attempt 1: plugin present
                cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
                cfg.dns.enabled = true;
                cfg.dns.servers = vec![answering_resolver];

                pm.start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();
                assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(answering_resolver));

                // Attempt 2: plugin removed (wants None), but engaging None
                // is configured to fail — the restore falls back to
                // Some(answering_resolver).
                st.fail_cover_for_resolvers.lock().unwrap().insert(None);
                cfg.server.plugin = None;
                pm.start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();
                assert_eq!(
                    *st.last_cover_resolver_ip.lock().unwrap(),
                    Some(answering_resolver),
                    "the restore falls back to the OLD, wider permit"
                );

                let output = writer.snapshot_string();
                assert!(
                    output.contains("no longer needs"),
                    "expected the over-permit residual wording, not the ECH-stall one; got:\n{output}"
                );
                assert!(
                    !output.contains("ECH fetch may still stall") && !output.contains("does not permit"),
                    "must not claim an ECH-fetch stall risk when no fetch is attempted; got:\n{output}"
                );
            });
    }

    #[skuld::test]
    fn covered_retry_after_adding_a_plugin_repairs_the_stale_permit() {
        rt().block_on(async {
            // Attempt 1 has NO plugin, so the cover engages with
            // `resolver_permit: None`. The user then adds a plugin (same host)
            // and retries. Merely DETECTING the drift and warning would leave
            // the held cover permitting `None` forever while `ech_doh` now
            // targets a real address — a permanent stall. The fix instead
            // REPAIRS it: releases the stale-permit cover and re-engages fresh
            // with the corrected permit, so the retry can actually succeed
            // instead of merely being diagnosed as broken.
            //
            // `dns.enabled = true` on attempt 1 is REQUIRED: with a plugin-less
            // start and the default `dns.enabled = false` (`test_config()`'s own
            // choice, to dodge the forwarder self-test gate), attempt 1
            // SUCCEEDS outright (no gate to fail it) — same shape as
            // `covered_start_success_releases_cover` — which releases the cover
            // on success and leaves nothing held for attempt 2 to find. Setting
            // `dns.enabled = true` routes attempt 1 through the forwarder
            // self-test gate instead, which `MockProxy` cannot satisfy (it binds
            // no real listener), so attempt 1 deterministically fails and RETAINS
            // the cover — the precondition this whole test depends on. The
            // resolved server address is a bound-then-dropped LOOPBACK port
            // (closed, immediate ECONNREFUSED) rather than a routable address —
            // matches `covered_gate_setup`'s own pattern — so the failure is
            // fast and deterministic, not a network-timeout gamble.
            let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = probe_l.local_addr().unwrap();
            drop(probe_l);
            let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: closed.ip(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.server_port = closed.port();
            cfg.server.plugin = None; // attempt 1: no plugin
            cfg.dns.enabled = true; // forces attempt 1 to fail via the self-test gate (see comment above)
            cfg.dns.servers = vec![answering_resolver];

            let err1 = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert!(
                !matches!(err1, ProxyError::Cancelled),
                "sanity: attempt 1 must fail via the self-test gate, not cancel, got {err1:?}"
            );
            assert!(
                pm.blocked_until_connected(),
                "sanity: attempt 1's failure must retain the cover"
            );
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                None,
                "attempt 1 has no plugin, so nothing is permitted"
            );
            assert_eq!(pm.last_ech_doh(), None, "attempt 1 has no plugin, so no ech-doh either");

            cfg.server.plugin = Some("ex-ray".into()); // attempt 2: plugin added
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                2,
                "the stale-permit cover is released and a FRESH cover is engaged — the repair, not just a diagnosis"
            );
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                Some(answering_resolver),
                "the fresh engage permits exactly what THIS attempt's ech-doh now needs"
            );
            assert_eq!(
                pm.last_ech_doh(),
                Some("https://1.0.0.1/dns-query"),
                "and the cover now matches it — no more stall for this retry"
            );
        });
    }

    #[skuld::test]
    fn lockdown_pending_releases_and_reengages_on_resolver_drift() {
        // Mirrors `covered_retry_after_adding_a_plugin_repairs_the_stale_permit`
        // above for the STANDING cover: attempt 1 (no plugin) engages the
        // Phase-0 guard with `resolver_permit: None` and then fails
        // (retaining it); attempt 2 adds a plugin, so `ech_resolver_permit`
        // becomes `Some(answering_resolver)`. Silently REUSING the stale
        // `None`-permit guard (Windows' `FWP_E_ALREADY_EXISTS` swallow means
        // a naive re-add would never update it) would leave block-all still
        // governing the new resolver. This test proves the standing cover
        // repairs the stale guard in place via `reengage_lockdown_permits`
        // (checked delete + strict re-add, not an ordinary drop followed by
        // a fresh `install_lockdown_permits` — see that method's doc for
        // why the distinction matters) with the corrected value.
        rt().block_on(async {
            let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = probe_l.local_addr().unwrap();
            drop(probe_l);
            let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: closed.ip(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.server_port = closed.port();
            cfg.server.plugin = None; // attempt 1: no plugin
            cfg.dns.enabled = true; // forces attempt 1 to fail via the self-test gate
            cfg.dns.servers = vec![answering_resolver];

            let err1 = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert!(
                !matches!(err1, ProxyError::Cancelled),
                "sanity: attempt 1 must fail via the self-test gate, not cancel, got {err1:?}"
            );
            assert!(
                pm.lockdown_active(),
                "sanity: attempt 1's failure must retain the Phase-0 guard"
            );
            assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                *st.last_lockdown_permits_resolver_ip.lock().unwrap(),
                None,
                "attempt 1 has no plugin, so nothing is permitted"
            );

            cfg.server.plugin = Some("ex-ray".into()); // attempt 2: plugin added
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            let _ = pm.start_cancellable(&cfg, true, CancellationToken::new()).await;
            assert_eq!(
                st.lockdown_permits_calls.load(Ordering::SeqCst),
                1,
                "the drift is a REPAIR, not a second fresh engage -- install_lockdown_permits must not be \
                 called again"
            );
            assert_eq!(
                st.reengage_lockdown_permits_calls.load(Ordering::SeqCst),
                1,
                "the stale-permit guard is repaired in place via reengage_lockdown_permits"
            );
            assert_eq!(
                st.lockdown_disengage_calls.load(Ordering::SeqCst),
                0,
                "a repair is NOT an ordinary disengage -- reengage_lockdown_permits consumes the held guard \
                 directly, it is never dropped ordinarily"
            );
            assert_eq!(
                *st.last_lockdown_permits_resolver_ip.lock().unwrap(),
                Some(answering_resolver),
                "the repaired cover permits exactly what THIS attempt's ech-doh now needs"
            );
        });
    }

    #[skuld::test]
    fn lockdown_pending_repair_failure_restores_the_old_identity_not_orphaned() {
        // A stale-permit repair's `reengage_lockdown_permits` failing must
        // NOT leave the guard orphaned (`lockdown_pending: None` while the
        // OS-level cover is actually still live): the underlying primitive
        // guarantees nothing changed on failure (an aborted FWPM
        // transaction / a rejected atomic pf reload), so the repair must
        // restore `lockdown_pending` under the OLD (still-live) identity,
        // not the attempted-but-failed new one -- otherwise a later retry's
        // drift check compares against the wrong value, and a `stop()`
        // would find nothing to disengage even though the OS-level cover
        // is still armed.
        rt().block_on(async {
            let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = probe_l.local_addr().unwrap();
            drop(probe_l);
            let old_resolver: IpAddr = "9.9.9.9".parse().unwrap();
            let new_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: closed.ip(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::failing_reengage_lockdown_permits(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.server_port = closed.port();
            cfg.server.plugin = Some("ex-ray".into());
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            cfg.dns.enabled = true; // forces the self-test gate to fail every attempt
            cfg.dns.servers = vec![old_resolver];

            // Attempt 1: fresh engage (install_lockdown_permits, unaffected
            // by `fail_reengage_lockdown_permits`) with resolver = old_resolver.
            let _ = pm.start_cancellable(&cfg, true, CancellationToken::new()).await;
            assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                *st.last_lockdown_permits_resolver_ip.lock().unwrap(),
                Some(old_resolver)
            );

            // Attempt 2: resolver drifts to new_resolver -> triggers a
            // repair, which this mock is configured to fail.
            cfg.dns.servers = vec![new_resolver];
            let err = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("mock reengage-lockdown-permits failure"),
                "expected the repair's own error, got {err}"
            );

            assert!(
                pm.lockdown_active(),
                "a failed repair must NOT orphan the guard -- the OLD cover is still live"
            );
            assert_eq!(
                pm.lockdown_pending.as_ref().and_then(|p| p.resolver_permit),
                Some(old_resolver),
                "the restored guard must reflect the OLD (still-live) identity, not the attempted new one"
            );

            // A later stop() must still find and disengage the restored
            // guard -- proving it is actually reachable for cleanup, not a
            // phantom `lockdown_active()` merely reports as true.
            pm.stop().await.unwrap();
            assert_eq!(st.lockdown_disengage_calls.load(Ordering::SeqCst), 1);
        });
    }

    // `lockdown_app_ids` only ever populates entries on Windows (App-ID
    // matching has no macOS/Linux equivalent), so this drift can only be
    // observed there -- on other platforms `app_ids` is always `[]` for
    // every attempt and this scenario collapses to "no drift".
    #[cfg(target_os = "windows")]
    #[skuld::test]
    fn lockdown_pending_releases_and_reengages_on_app_ids_drift() {
        // Same shape as `..._on_resolver_drift`, but drifts `app_ids`
        // instead: attempt 1 and attempt 2 use DIFFERENT plugin binaries
        // while `server_ip` and `resolver_permit` both stay unchanged.
        // Neither plugin name is in the v2ray ECH family
        // (`takes_ech_directives`), so `effective_ech_doh` stays `None` and
        // `ech_resolver_permit` is `None` in both attempts -- isolating
        // `app_ids` as the ONLY thing that drifts. Reusing the held guard
        // verbatim (Windows' `FWP_E_ALREADY_EXISTS` swallow means a naive
        // re-add would never update it) would leave the OLD plugin's
        // unrestricted-egress App-ID permit live while the new plugin never
        // gets one.
        rt().block_on(async {
            let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = probe_l.local_addr().unwrap();
            drop(probe_l);
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: closed.ip(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.server_port = closed.port();
            cfg.server.plugin = Some("not-a-real-v2ray-plugin-a".into()); // attempt 1
            cfg.dns.enabled = true; // forces attempt 1 to fail via the self-test gate
            cfg.dns.servers = vec!["1.0.0.1".parse().unwrap()];

            let err1 = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert!(
                !matches!(err1, ProxyError::Cancelled),
                "sanity: attempt 1 must fail via the self-test gate, not cancel, got {err1:?}"
            );
            assert!(
                pm.lockdown_active(),
                "sanity: attempt 1's failure must retain the Phase-0 guard"
            );
            assert_eq!(st.lockdown_permits_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                *st.last_lockdown_permits_resolver_ip.lock().unwrap(),
                None,
                "sanity: neither plugin name takes ECH directives, so nothing is resolver-permitted"
            );

            cfg.server.plugin = Some("not-a-real-v2ray-plugin-b".into()); // attempt 2: DIFFERENT plugin
            let _ = pm.start_cancellable(&cfg, true, CancellationToken::new()).await;
            assert_eq!(
                st.lockdown_permits_calls.load(Ordering::SeqCst),
                1,
                "app_ids drift is a REPAIR, not a second fresh engage -- install_lockdown_permits must not \
                 be called again"
            );
            assert_eq!(
                st.reengage_lockdown_permits_calls.load(Ordering::SeqCst),
                1,
                "app_ids drift ALONE (server_ip and resolver_permit both unchanged) must still repair the \
                 stale guard in place via reengage_lockdown_permits"
            );
            assert_eq!(
                st.lockdown_disengage_calls.load(Ordering::SeqCst),
                0,
                "a repair is NOT an ordinary disengage -- see the resolver-drift test's identical assertion"
            );
        });
    }

    #[skuld::test]
    fn lockdown_pending_repair_preserves_the_original_pin_not_the_revalidated_one() {
        // A stale-permit repair's re-engage must store the guard's ORIGINAL
        // `pin` (pre-`revalidate`), not this attempt's locally revalidated
        // value -- mirrors the transient cover's own `repair_fallback` for
        // the identical reason: `revalidate` only ever downgrades (`Answered`
        // -> `ResolverDeselected`, see its `other => other` arm), so
        // persisting an already-downgraded value would make that loss
        // PERMANENT even once the original resolver returns to
        // `dns.servers` -- `revalidate` never upgrades back to `Answered`.
        rt().block_on(async {
            let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = probe_l.local_addr().unwrap();
            drop(probe_l);
            let r: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: closed.ip(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.server_port = closed.port();
            cfg.server.plugin = Some("ex-ray".into());
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            cfg.dns.enabled = true; // forces the self-test gate to fail every attempt
            cfg.dns.servers = vec![r];

            // Attempt 1: pin resolves to Answered(r); fails via the self-test
            // gate, retaining the guard with pin: Answered(r).
            let _ = pm.start_cancellable(&cfg, true, CancellationToken::new()).await;
            assert_eq!(
                pm.lockdown_pending.as_ref().map(|p| p.pin),
                Some(crate::dns::ech::PinSource::Answered(r)),
                "sanity: attempt 1 engages with a verified pin"
            );

            // Attempt 2: the resolver is deselected -- this attempt's local
            // pin revalidates to ResolverDeselected, which ALSO drifts the
            // resolver permit (no configured server left to fall back to),
            // triggering a stale release + re-engage.
            cfg.dns.servers = Vec::new();
            let _ = pm.start_cancellable(&cfg, true, CancellationToken::new()).await;
            assert_eq!(
                pm.lockdown_pending.as_ref().map(|p| p.pin),
                Some(crate::dns::ech::PinSource::Answered(r)),
                "the re-engage must store the ORIGINAL pin, not this attempt's revalidated ResolverDeselected"
            );
        });
    }

    #[skuld::test]
    fn covered_retry_repair_restores_the_previous_permit_when_the_corrected_engage_fails() {
        rt().block_on(async {
            // Same drift as `covered_retry_after_adding_a_plugin_repairs_the_stale_permit`
            // (attempt 1: no plugin, permit `None`; attempt 2: plugin added, permit
            // should become `Some(answering_resolver)`), but the corrected engage
            // itself FAILS — simulated by `fail_cover_for_resolvers`, which fails
            // `install_failclosed_cover` ONLY for `Some(answering_resolver)`. The
            // repair must not let this failure leave the host uncovered: it falls
            // back to re-engaging the OLD permit (`None`), so the host stays
            // covered by SOMETHING rather than by nothing.
            let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = probe_l.local_addr().unwrap();
            drop(probe_l);
            let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: closed.ip(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.server_port = closed.port();
            cfg.server.plugin = None; // attempt 1: no plugin
            cfg.dns.enabled = true; // forces attempt 1 to fail via the self-test gate
            cfg.dns.servers = vec![answering_resolver];

            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), None);

            // Only the CORRECTED permit fails to engage — the previous one (`None`)
            // still would, if retried.
            st.fail_cover_for_resolvers
                .lock()
                .unwrap()
                .insert(Some(answering_resolver));

            cfg.server.plugin = Some("ex-ray".into()); // attempt 2: plugin added
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();

            assert!(
                pm.blocked_until_connected(),
                "the compensating restore must leave the host covered, not open"
            );
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                2,
                "one failed corrected-permit attempt (uncounted) plus one successful restore of the old permit"
            );
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                None,
                "the restored cover permits the OLD value, not the corrected one that failed to engage"
            );
        });
    }

    #[skuld::test]
    fn covered_retry_repair_restore_warning_fires_when_the_corrected_engage_fails() {
        use crate::test_support::log_capture::VecWriter;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::{Layer, SubscriberExt};

        // Same scenario as the structural test above; asserts the repair's OWN
        // "restored the PREVIOUS permit" log line fires, so the operator sees WHY
        // the cover is narrower than the current attempt's config would derive.
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
                        .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let closed = probe_l.local_addr().unwrap();
                drop(probe_l);
                let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
                let querier = Arc::new(CountingQuerier {
                    host: "proxy.example".into(),
                    ip: closed.ip(),
                    queries: AtomicU32::new(0),
                });
                let dir = tempfile::tempdir().unwrap();
                let routing = MockRouting::new(dir.path().to_path_buf());
                let st = routing.state();
                let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
                pm.set_bootstrap_querier_for_test(querier);
                let mut cfg = test_config();
                cfg.server.server = "proxy.example".into();
                cfg.server.server_port = closed.port();
                cfg.server.plugin = None;
                cfg.dns.enabled = true;
                cfg.dns.servers = vec![answering_resolver];

                pm.start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();
                st.fail_cover_for_resolvers
                    .lock()
                    .unwrap()
                    .insert(Some(answering_resolver));
                cfg.server.plugin = Some("ex-ray".into());
                cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
                pm.start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();

                let output = writer.snapshot_string();
                assert!(
                    output.contains("restored the PREVIOUS permit instead of leaving the host open"),
                    "expected the compensating-restore warning; got:\n{output}"
                );
            });
    }

    // The LIVE cover (restored to the OLD permit) now permits something
    // OTHER than what this attempt's ech_doh needs — the residual-stall
    // warning must fire here too, not just the restore warning above: an
    // operator debugging a stalled connect needs the "may stall" line, not
    // only "a permit correction failed".
    #[skuld::test]
    fn covered_retry_repair_restore_also_fires_the_residual_stall_warning() {
        use crate::test_support::log_capture::VecWriter;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::{Layer, SubscriberExt};

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
                        .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let closed = probe_l.local_addr().unwrap();
                drop(probe_l);
                let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
                let querier = Arc::new(CountingQuerier {
                    host: "proxy.example".into(),
                    ip: closed.ip(),
                    queries: AtomicU32::new(0),
                });
                let dir = tempfile::tempdir().unwrap();
                let routing = MockRouting::new(dir.path().to_path_buf());
                let st = routing.state();
                let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
                pm.set_bootstrap_querier_for_test(querier);
                let mut cfg = test_config();
                cfg.server.server = "proxy.example".into();
                cfg.server.server_port = closed.port();
                cfg.server.plugin = None;
                cfg.dns.enabled = true;
                cfg.dns.servers = vec![answering_resolver];

                pm.start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();
                st.fail_cover_for_resolvers
                    .lock()
                    .unwrap()
                    .insert(Some(answering_resolver));
                cfg.server.plugin = Some("ex-ray".into());
                cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
                pm.start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();

                let output = writer.snapshot_string();
                assert!(
                    output.contains("the fail-closed cover does not permit"),
                    "expected the residual-stall warning on the restore-mismatch path; got:\n{output}"
                );
            });
    }

    // A retry whose desired permit is UNCHANGED from one a previous repair
    // already proved unreachable is not skipped: there is no principled way
    // to tell a transient engage failure (e.g. momentary WFP/pf contention)
    // from a lasting one without trying again, so every matching drift
    // re-attempts the correction. Attempt 3 proves the retry happens (not
    // skipped); attempt 4 proves it lands once the transient failure clears.
    #[skuld::test]
    fn covered_retry_repeats_the_correction_every_time_a_permit_stays_unreachable() {
        rt().block_on(async {
            let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = probe_l.local_addr().unwrap();
            drop(probe_l);
            let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: closed.ip(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.server_port = closed.port();
            cfg.server.plugin = None;
            cfg.dns.enabled = true;
            cfg.dns.servers = vec![answering_resolver];

            // Attempt 1: engages with permit None.
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);

            // Attempt 2: plugin added, wants Some(answering_resolver), that
            // engage keeps failing — restore succeeds.
            st.fail_cover_for_resolvers
                .lock()
                .unwrap()
                .insert(Some(answering_resolver));
            cfg.server.plugin = Some("ex-ray".into());
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                2,
                "attempt 2: one failed corrected attempt (uncounted) + one successful restore"
            );

            // Attempt 3: identical config — still wants the SAME
            // Some(answering_resolver) the previous attempt already proved
            // unreachable. Must re-attempt the correction (fails again,
            // uncounted) and restore again (counted) — not skip.
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                3,
                "a repeat of the same still-unreachable permit must re-attempt the repair, not skip it"
            );
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                None,
                "the held cover still permits the restored OLD value, not the still-unreachable one"
            );

            // Attempt 4: STILL the same desired value, but now able to engage
            // (the transient failure has passed) — the repair lands.
            st.fail_cover_for_resolvers.lock().unwrap().clear();
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                4,
                "a transient failure must not permanently wedge repair for this value"
            );
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                Some(answering_resolver),
                "the repair finally lands once the value is reachable again"
            );
        });
    }

    // The one security-relevant fail-open branch of this state machine:
    // BOTH the corrected engage AND the compensating restore fail. The host
    // must end up genuinely uncovered (not a stale belief that it's still
    // covered), a real reason must be surfaced (not silently cleared as if
    // the attempt succeeded), and the next retry must start fresh rather
    // than staying wedged.
    #[skuld::test]
    fn covered_retry_repair_both_engages_failing_leaves_the_host_uncovered() {
        rt().block_on(async {
            let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = probe_l.local_addr().unwrap();
            drop(probe_l);
            let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: closed.ip(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.server_port = closed.port();
            cfg.server.plugin = None;
            cfg.dns.enabled = true;
            cfg.dns.servers = vec![answering_resolver];

            // Attempt 1: engages with permit None.
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert!(pm.blocked_until_connected());

            // Attempt 2: plugin added, wants Some(answering_resolver) — BOTH
            // that corrected value AND the OLD value (None) it would restore
            // to are configured to fail engaging.
            st.fail_cover_for_resolvers.lock().unwrap().insert(Some(answering_resolver));
            st.fail_cover_for_resolvers.lock().unwrap().insert(None);
            cfg.server.plugin = Some("ex-ray".into());
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();

            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                1,
                "both engage attempts failed — neither counts as a successful engage"
            );
            assert!(
                !pm.blocked_until_connected(),
                "both engages failing must leave the host genuinely UNCOVERED, not a stale belief that it's still covered"
            );
            // NOT the specific cover-engage error text: the covered start still
            // proceeds into `start_inner` on a fail-open engage failure (by
            // design — see the surrounding comment), and its own outcome is
            // what `last_error` ultimately reflects (or clears to `None`, on
            // success) once the whole attempt concludes. The cover-engage
            // failure itself is surfaced separately, in the WARN log (see
            // `covered_retry_repair_both_engages_failing_warns_host_not_blocked`)
            // — checked here only for "a real reason was surfaced", not
            // silently cleared as if the attempt had succeeded.
            assert!(
                pm.last_error().is_some(),
                "an uncovered host must surface SOME reason, not silently read as a clean success — got: {:?}",
                pm.last_error()
            );

            // Attempt 3: unchanged config. With the cover gone, this is an
            // ordinary fresh engage attempt (not a repair) — no wedge.
            st.fail_cover_for_resolvers.lock().unwrap().clear();
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                2,
                "the next retry must re-engage fresh from scratch, not stay wedged uncovered"
            );
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(answering_resolver));
        });
    }

    #[skuld::test]
    fn covered_retry_repair_both_engages_failing_warns_host_not_blocked() {
        use crate::test_support::log_capture::VecWriter;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::{Layer, SubscriberExt};

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
                        .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let closed = probe_l.local_addr().unwrap();
                drop(probe_l);
                let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
                let querier = Arc::new(CountingQuerier {
                    host: "proxy.example".into(),
                    ip: closed.ip(),
                    queries: AtomicU32::new(0),
                });
                let dir = tempfile::tempdir().unwrap();
                let routing = MockRouting::new(dir.path().to_path_buf());
                let st = routing.state();
                let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
                pm.set_bootstrap_querier_for_test(querier);
                let mut cfg = test_config();
                cfg.server.server = "proxy.example".into();
                cfg.server.server_port = closed.port();
                cfg.server.plugin = None;
                cfg.dns.enabled = true;
                cfg.dns.servers = vec![answering_resolver];

                pm.start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();
                st.fail_cover_for_resolvers
                    .lock()
                    .unwrap()
                    .insert(Some(answering_resolver));
                st.fail_cover_for_resolvers.lock().unwrap().insert(None);
                cfg.server.plugin = Some("ex-ray".into());
                cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
                pm.start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();

                let output = writer.snapshot_string();
                assert!(
                    output.contains("failed to engage BOTH the corrected and the previous fail-closed"),
                    "expected the both-failed warning; got:\n{output}"
                );
            });
    }

    // A repair that already failed once for a given desired permit (B) must
    // still repair normally when a LATER retry wants a different value (C):
    // nothing about a prior failed correction lingers onto an unrelated one.
    // Reachable because `ech_doh_url`'s unpinned fallback re-derives from
    // THIS attempt's `dns.servers` every time, even once a pin has gone
    // `ResolverDeselected` for good (`revalidate` never un-deselects it) —
    // editing `dns.servers` between retries changes the fallback address
    // with no fresh DoH query.
    #[skuld::test]
    fn covered_retry_repair_resumes_normally_for_a_different_new_resolver() {
        rt().block_on(async {
            let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = probe_l.local_addr().unwrap();
            drop(probe_l);
            let resolver_a: IpAddr = "1.0.0.1".parse().unwrap();
            let resolver_b: IpAddr = "9.9.9.9".parse().unwrap();
            let resolver_c: IpAddr = "8.8.8.8".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: closed.ip(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.server_port = closed.port();
            cfg.server.plugin = Some("ex-ray".into());
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            cfg.dns.enabled = true;
            cfg.dns.servers = vec![resolver_a];

            // Attempt 1: pin = Answered(A), engages Some(A).
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(resolver_a));

            // Attempt 2: `dns.servers` -> [B]; A is deselected, the fallback
            // picks B. B's engage is configured to fail; the restore falls
            // back to A.
            st.fail_cover_for_resolvers.lock().unwrap().insert(Some(resolver_b));
            cfg.dns.servers = vec![resolver_b];
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                2,
                "attempt 2: restore re-engage"
            );
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                Some(resolver_a),
                "attempt 2: restored to A"
            );

            // Attempt 3: `dns.servers` -> [C] — a different value from either
            // A or B. Must repair normally.
            cfg.dns.servers = vec![resolver_c];
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                3,
                "a different new desired permit must repair normally"
            );
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(resolver_c));
        });
    }

    // A repair must not overwrite the held cover's ORIGINAL pin with the
    // revalidated (possibly downgraded) snapshot from the repairing
    // attempt — `revalidate` only ever downgrades `Answered` to
    // `ResolverDeselected`, never the reverse, so storing the downgraded
    // value back into `BlockedStart::pin` makes the loss PERMANENT: a later
    // retry that restores the original resolver to `dns.servers` can never
    // recover `Answered`, even though a same-host retry that never
    // triggered a repair would have (it always revalidates the covers's
    // ORIGINAL `pin`, untouched). Attempt 3 here reverts `dns.servers` to
    // exactly what attempt 1 answered from — the "unpinned" warning must
    // NOT fire, proving the original `Answered` provenance survived the
    // attempt-2 repair.
    #[skuld::test]
    fn covered_retry_repair_preserves_the_original_pin_across_a_correction() {
        use crate::test_support::log_capture::VecWriter;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::{Layer, SubscriberExt};

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
                    .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
            );
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

            let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let closed = probe_l.local_addr().unwrap();
            drop(probe_l);
            let resolver_a: IpAddr = "1.0.0.1".parse().unwrap();
            let resolver_b: IpAddr = "9.9.9.9".parse().unwrap();
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: closed.ip(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier);
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.server_port = closed.port();
            cfg.server.plugin = Some("ex-ray".into());
            cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
            cfg.dns.enabled = true;
            cfg.dns.servers = vec![resolver_a];

            // Attempt 1: fresh resolve, A answers -> pin = Answered(A).
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(resolver_a));

            // Attempt 2: `dns.servers` -> [B]. A same-host retry never
            // re-resolves, so B is never actually queried this session —
            // ResolverDeselected is the CORRECT pin for attempt 2 itself.
            // The corrected engage (permit Some(B)) succeeds; this is the
            // bug's site: the new BlockedStart must still remember A was
            // ONCE verified-answering, not just that B currently isn't.
            cfg.dns.servers = vec![resolver_b];
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(resolver_b));
            let after_attempt_2 = writer.snapshot_string();
            assert!(
                after_attempt_2.contains("the cached DoH resolver is no longer configured"),
                "attempt 2: B was never queried this session, so the unpinned warning is correct here; got:\n{after_attempt_2}"
            );

            // Attempt 3: `dns.servers` reverts to exactly [A] — the SAME
            // resolver attempt 1 verified answering. Repair corrects the
            // permit back to Some(A); the unpinned warning must NOT
            // reappear, because `revalidate` is being applied to the
            // ORIGINAL Answered(A), not to attempt 2's ResolverDeselected.
            cfg.dns.servers = vec![resolver_a];
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(*st.last_cover_resolver_ip.lock().unwrap(), Some(resolver_a));
            let after_attempt_3 = writer.snapshot_string();
            assert_eq!(
                after_attempt_3.matches("the cached DoH resolver is no longer configured").count(),
                1,
                "attempt 3 reverts to the ORIGINALLY-answered resolver; the unpinned warning must not \
                 fire again (only attempt 2's occurrence should be present) — got:\n{after_attempt_3}"
            );
        });
    }

    // An operator's own `ech-doh` (not Hole's) winning is a stall risk the
    // cover can never fix by permitting it — the residual-stall diagnostic
    // must still name it, distinctly from the "nothing pinned" case.
    #[skuld::test]
    fn covered_start_residual_warning_fires_for_an_operator_ech_doh_override() {
        use crate::test_support::log_capture::VecWriter;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::{Layer, SubscriberExt};

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
                        .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let dir = tempfile::tempdir().unwrap();
                let routing = MockRouting::new(dir.path().to_path_buf());
                let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
                let mut cfg = test_config();
                // Literal-IP server: Hole's own candidate is unpinned
                // (NoQueryNeeded), so it never outranks an IP-literal operator
                // value — the operator's own ech-doh wins.
                cfg.server.server = "203.0.113.9".into();
                cfg.server.plugin = Some("ex-ray".into());
                cfg.server.plugin_opts = Some(format!("{ECH_CAPABLE_OPTS};ech-doh=https://8.8.8.8/dns-query"));
                cfg.dns.enabled = true;
                cfg.dns.servers = vec!["1.0.0.1".parse().unwrap()];
                let _ = pm
                    .start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();

                let output = writer.snapshot_string();
                assert!(
                    output.contains("plugin's own ech-doh"),
                    "expected the operator-override residual warning; got:\n{output}"
                );
            });
    }

    // `ech_doh_url` constructs a real address from the configured resolvers
    // even for `PinSource::NoQueryNeeded`, and the cover permits exactly
    // that address
    // (`covered_start_with_a_literal_server_ip_still_permits_the_constructed_resolver`),
    // so the "genuinely can't permit anything" residual warning must not
    // fire for a literal-IP server.
    #[skuld::test]
    fn covered_start_no_residual_warning_for_a_literal_server_ip() {
        use crate::test_support::log_capture::VecWriter;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::{Layer, SubscriberExt};

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
                        .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let dir = tempfile::tempdir().unwrap();
                let routing = MockRouting::new(dir.path().to_path_buf());
                let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
                let mut cfg = test_config();
                cfg.server.server = "203.0.113.9".into();
                cfg.server.plugin = Some("ex-ray".into());
                cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
                cfg.dns.enabled = true;
                cfg.dns.servers = vec!["1.0.0.1".parse().unwrap()];
                let _ = pm
                    .start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();

                let output = writer.snapshot_string();
                assert!(
                    !output.contains("the fail-closed cover does not permit"),
                    "a literal-IP server's constructed resolver is now permitted; got:\n{output}"
                );
            });
    }

    // `effective_ech_doh` (queried once from the permit-derivation path) must
    // NOT re-trigger `inject_plugin_directives`'s ECH-posture logging — that
    // function runs a SECOND time, for real, when `start_plugin_chain`
    // actually spawns the plugin. A regression that made `effective_ech_doh`
    // call `inject_plugin_directives` (instead of the side-effect-free
    // `classify_ech_doh`) would double-emit every such warning on every
    // start. Literal-IP server: `ech_doh` derives an UNPINNED URL, which
    // emits the "resolver has not been exercised" line exactly once per
    // `inject_plugin_directives` call.
    #[skuld::test]
    fn effective_ech_doh_query_does_not_double_emit_the_injection_warning() {
        use crate::test_support::log_capture::VecWriter;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::{Layer, SubscriberExt};

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
                        .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let dir = tempfile::tempdir().unwrap();
                let routing = MockRouting::new(dir.path().to_path_buf());
                let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
                let mut cfg = test_config();
                cfg.server.server = "203.0.113.9".into();
                cfg.server.plugin = Some("ex-ray".into());
                cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
                cfg.dns.enabled = true;
                cfg.dns.servers = vec!["1.0.0.1".parse().unwrap()];
                let _ = pm
                    .start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();

                let output = writer.snapshot_string();
                let occurrences = output.matches("the ECH lookup uses a resolver that has not been exercised").count();
                assert_eq!(
                    occurrences, 1,
                    "expected exactly one injection-warning emission (from the real spawn's \
                     inject_plugin_directives call, not from effective_ech_doh's permit query too); got {occurrences}:\n{output}"
                );
            });
    }

    #[skuld::test]
    fn covered_start_no_residual_warning_for_a_pinned_resolver() {
        use crate::test_support::log_capture::VecWriter;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::{Layer, SubscriberExt};

        // Negative direction: a healthy, fully-permitted covered start must NOT
        // emit the residual-gap warning — proves it isn't spuriously noisy.
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
                        .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let resolved: IpAddr = "203.0.113.9".parse().unwrap();
                let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
                let querier = Arc::new(CountingQuerier {
                    host: "proxy.example".into(),
                    ip: resolved,
                    queries: AtomicU32::new(0),
                });
                let dir = tempfile::tempdir().unwrap();
                let routing = MockRouting::new(dir.path().to_path_buf());
                let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
                pm.set_bootstrap_querier_for_test(querier);
                let mut cfg = test_config();
                cfg.server.server = "proxy.example".into();
                cfg.server.plugin = Some("ex-ray".into());
                cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
                // Forces the forwarder self-test gate — deterministic regardless of
                // whether `ex-ray` happens to be resolvable via PATH on this host.
                cfg.dns.enabled = true;
                cfg.dns.servers = vec![answering_resolver];
                let _ = pm
                    .start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();

                let output = writer.snapshot_string();
                assert!(
                    !output.contains("the fail-closed cover does not permit"),
                    "a fully-pinned covered start must not emit the residual-gap warning; got:\n{output}"
                );
            });
    }

    #[skuld::test]
    fn covered_retry_repair_warning_fires_when_the_permit_is_stale() {
        use crate::test_support::log_capture::VecWriter;
        use tracing_subscriber::fmt;
        use tracing_subscriber::layer::{Layer, SubscriberExt};

        // Same scenario as covered_retry_after_adding_a_plugin_repairs_the_stale_permit
        // (plugin added between attempts), asserting the repair's OWN log line
        // fires — that test only proves the structural effect (re-engage,
        // corrected permit), not that the operator sees why.
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
                        .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
                );
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

                let probe_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let closed = probe_l.local_addr().unwrap();
                drop(probe_l);
                let answering_resolver: IpAddr = "1.0.0.1".parse().unwrap();
                let querier = Arc::new(CountingQuerier {
                    host: "proxy.example".into(),
                    ip: closed.ip(),
                    queries: AtomicU32::new(0),
                });
                let dir = tempfile::tempdir().unwrap();
                let routing = MockRouting::new(dir.path().to_path_buf());
                let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
                pm.set_bootstrap_querier_for_test(querier);
                let mut cfg = test_config();
                cfg.server.server = "proxy.example".into();
                cfg.server.server_port = closed.port();
                cfg.server.plugin = None;
                cfg.dns.enabled = true;
                cfg.dns.servers = vec![answering_resolver];

                pm.start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();
                cfg.server.plugin = Some("ex-ray".into());
                cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
                pm.start_cancellable(&cfg, true, CancellationToken::new())
                    .await
                    .unwrap_err();

                let output = writer.snapshot_string();
                assert!(
                    output.contains("releasing it so a fresh engage can correct it"),
                    "expected the repair warning on the stale-permit retry; got:\n{output}"
                );
            });
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

    #[skuld::test]
    fn lockdown_covered_retry_reuses_the_resolved_ip_without_re_querying_doh() {
        // Mirrors `covered_retry_reuses_the_resolved_ip_without_re_querying_doh`
        // for the STANDING cover: without `lockdown_pending` participating in
        // the same cache-reuse match as `blocked`, a same-host retry would
        // re-resolve via DoH on every attempt. With no plugin configured, the
        // retained standing cover permits no resolver at all, so a real
        // re-resolve would dial straight into its own block-all and wedge
        // every retry identically -- one layer earlier than the ECH-config
        // fetch this cover exists to unblock.
        rt().block_on(async {
            let querier = Arc::new(CountingQuerier {
                host: "proxy.example".into(),
                ip: "203.0.113.9".parse().unwrap(),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, true);
            pm.set_bootstrap_querier_for_test(querier.clone());
            let mut cfg = test_config();
            cfg.server.server = "proxy.example".into();
            cfg.server.plugin = None; // no plugin -> the standing cover permits no resolver
            cfg.dns.enabled = true; // forces attempt 1 to fail via the self-test gate

            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            let after_first = querier.queries.load(Ordering::SeqCst);
            assert!(after_first >= 1, "the first covered start resolves via DoH");
            assert!(
                pm.lockdown_active(),
                "the failed covered start holds the standing cover's guard"
            );

            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                querier.queries.load(Ordering::SeqCst),
                after_first,
                "the covered retry reuses the resolved IP and does NOT re-query DoH under the standing cover"
            );
        });
    }

    /// A covered start that fails, leaving the cover (and its cached pin) held.
    /// Returns the manager (plus the mock routing state, so a test can assert
    /// on re-engage counts and permits) so a retry can be driven against an
    /// edited config.
    async fn covered_start_holding_the_cover(
        dir: tempfile::TempDir,
    ) -> (
        ProxyManager<MockProxy, MockRouting>,
        ProxyConfig,
        tempfile::TempDir,
        Arc<MockRoutingState>,
    ) {
        let querier = Arc::new(CountingQuerier {
            host: "proxy.example".into(),
            ip: "203.0.113.9".parse().unwrap(),
            queries: AtomicU32::new(0),
        });
        let routing = MockRouting::new(dir.path().to_path_buf());
        let st = routing.state();
        let (mut pm, dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
        pm.set_bootstrap_querier_for_test(querier);
        let mut cfg = test_config();
        cfg.server.server = "proxy.example".into();
        // Forces the forwarder self-test gate, which MockProxy cannot satisfy —
        // deterministic regardless of whether `ex-ray` happens to be resolvable
        // via PATH on this host, so the cover reliably stays held.
        cfg.dns.enabled = true;
        // A real ECH-family name: `ech_doh_will_reach_ex_ray`'s gate needs one
        // for `ech_resolver_permit` to ever be `Some`.
        cfg.server.plugin = Some("ex-ray".into());
        cfg.server.plugin_opts = Some(ECH_CAPABLE_OPTS.into());
        // v6 first so the PIN and the IPv4-preferring fallback disagree — with a
        // single-entry list every assertion below would pass on a discarded pin.
        // `CountingQuerier` ignores which resolver it was asked, so the first
        // entry is the one that answers.
        cfg.dns.servers = vec!["2606:4700:4700::1111".parse().unwrap(), "1.0.0.1".parse().unwrap()];

        pm.start_cancellable(&cfg, true, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(pm.blocked_until_connected(), "the failed covered start holds the cover");
        (pm, cfg, dir, st)
    }

    #[skuld::test]
    fn a_covered_start_pins_the_ech_lookup_to_the_resolver_that_answered() {
        rt().block_on(async {
            let (pm, _cfg, _dir, _st) = covered_start_holding_the_cover(tempfile::tempdir().unwrap()).await;
            assert_eq!(pm.last_ech_doh(), Some("https://[2606:4700:4700::1111]/dns-query"));
        });
    }

    // The retry must keep the pin when nothing changed — a wiring slip that
    // discarded it would still look "unpinned", which the deselection test
    // alone cannot distinguish from the correct answer.
    #[skuld::test]
    fn a_covered_retry_keeps_the_pin_when_the_resolvers_are_unchanged() {
        rt().block_on(async {
            let (mut pm, cfg, _dir, _st) = covered_start_holding_the_cover(tempfile::tempdir().unwrap()).await;
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(pm.last_ech_doh(), Some("https://[2606:4700:4700::1111]/dns-query"));
        });
    }

    // A plugin-less start carries no ECH lookup, so it derives no `ech-doh` —
    // and therefore never reports one as unpinned.
    #[skuld::test]
    fn a_plugin_less_start_derives_no_ech_doh() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            let cfg = test_config();
            assert!(cfg.server.plugin.is_none(), "the default test config has no plugin");
            let _ = pm.start_cancellable(&cfg, false, CancellationToken::new()).await;
            assert_eq!(pm.last_ech_doh(), None);
        });
    }

    // A literal-IP server entry needs no bootstrap query, so nothing is pinned —
    // the URL still comes from the config, IPv4-preferring rather than positional.
    #[skuld::test]
    fn a_literal_server_entry_falls_back_without_a_pin() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            let mut cfg = test_config();
            cfg.server.server = "203.0.113.9".into();
            cfg.server.plugin = Some("hole-694-absent-plugin".into());
            cfg.dns.servers = vec!["2606:4700:4700::1111".parse().unwrap(), "1.0.0.1".parse().unwrap()];
            let _ = pm.start_cancellable(&cfg, false, CancellationToken::new()).await;
            assert_eq!(pm.last_ech_doh(), Some("https://1.0.0.1/dns-query"));
        });
    }

    /// A querier that answers nothing, so every configured resolver fails.
    struct DeadQuerier;

    #[async_trait::async_trait]
    impl DohQuerier for DeadQuerier {
        async fn query(&self, _server: IpAddr, _wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            Err(UpstreamCause::Unreachable)
        }
    }

    // Every resolver failed and the OS resolver supplied the address, so no
    // resolver is known to serve the ECH lookup — the URL is still derived,
    // because omitting it refuses the start under `ech=always`.
    #[skuld::test]
    fn an_insecure_bootstrap_fallback_derives_an_unpinned_url() {
        rt().block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(Arc::new(DeadQuerier));
            let mut cfg = test_config();
            // Resolvable on every CI host without network.
            cfg.server.server = "localhost".into();
            cfg.server.plugin = Some("hole-694-absent-plugin".into());
            cfg.dns.allow_insecure_bootstrap = true;
            cfg.dns.servers = vec!["2606:4700:4700::1111".parse().unwrap(), "1.0.0.1".parse().unwrap()];
            let _ = pm.start_cancellable(&cfg, false, CancellationToken::new()).await;
            assert_eq!(pm.last_ech_doh(), Some("https://1.0.0.1/dns-query"));
        });
    }

    // The cover is keyed by hostname alone, so a retry can arrive with an edited
    // resolver set — `revalidate` must catch that here, not only in isolation.
    // Also proves the drift is REPAIRED, not merely diagnosed: the deselected
    // IPv6 resolver's stale permit must be released and re-engaged to match
    // the NEW fallback address `ech_doh_url` constructs from the retry's own
    // `dns.servers` (`ResolverDeselected` is still permitted — see
    // `EchDoh::resolver`'s doc — just no longer the OLD address) — the same
    // repair path as `covered_retry_after_adding_a_plugin_repairs_the_stale_permit`,
    // exercised here via a resolver SWAP rather than a plugin addition.
    #[skuld::test]
    fn a_covered_retry_drops_a_resolver_the_user_deselected() {
        rt().block_on(async {
            let (mut pm, mut cfg, _dir, st) = covered_start_holding_the_cover(tempfile::tempdir().unwrap()).await;
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                Some("2606:4700:4700::1111".parse().unwrap()),
                "sanity: the initial engage pinned the answering IPv6 resolver"
            );
            cfg.dns.servers = vec!["8.8.8.8".parse().unwrap()];
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(
                pm.last_ech_doh(),
                Some("https://8.8.8.8/dns-query"),
                "a deselected resolver is dropped and the retry's own config supplies the fallback"
            );
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                2,
                "the stale IPv6 permit is released and a fresh cover is re-engaged — the repair, not just a diagnosis"
            );
            assert_eq!(
                *st.last_cover_resolver_ip.lock().unwrap(),
                Some("8.8.8.8".parse().unwrap()),
                "the fresh engage permits the NEW fallback address, not the deselected one"
            );
        });
    }

    /// A DoH stub mapping several hostnames to IPv4s (and counting queries), so a
    /// test can drive a switch between two different-hostname servers.
    struct MappingQuerier {
        map: std::collections::HashMap<String, std::net::Ipv4Addr>,
        queries: AtomicU32,
    }

    #[async_trait::async_trait]
    impl DohQuerier for MappingQuerier {
        async fn query(&self, _server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            crate::dns::forwarder::answered_or_servfail(wire, || {
                use hickory_proto::op::{Message, MessageType, OpCode, Query};
                use hickory_proto::rr::rdata::A;
                use hickory_proto::rr::{Name, RData, Record, RecordType};
                self.queries.fetch_add(1, Ordering::SeqCst);
                let q = Message::from_vec(wire).ok()?;
                let question = q.queries.first()?;
                if question.query_type() != RecordType::A {
                    return None; // force the resolver onto the A path (IPv4-preferred).
                }
                let name = question.name().to_string();
                let ip = *self.map.get(name.trim_end_matches('.'))?;
                let n = Name::from_ascii(&name).ok()?;
                let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
                reply.add_query(Query::query(n.clone(), RecordType::A));
                reply.add_answer(Record::from_rdata(n, 60, RData::A(A(ip))));
                reply.to_vec().ok()
            })
        }
    }

    #[skuld::test]
    fn different_hostname_retry_re_resolves_uncovered_and_re_engages() {
        rt().block_on(async {
            // A covered start blocked on server A, then a retry to a DIFFERENT hostname
            // B, must RELEASE A's cover before resolving B (else DoH under A's cover is
            // blocked and B never resolves), then engage a FRESH cover permitting B's
            // resolved IP. The mock cover is a no-op guard, so this asserts the ordering
            // via observable side-effects: re-resolution happened + cover now permits B.
            let ip_a: IpAddr = "203.0.113.10".parse().unwrap();
            let ip_b: IpAddr = "203.0.113.20".parse().unwrap();
            let querier = Arc::new(MappingQuerier {
                map: std::collections::HashMap::from([
                    ("proxy-a.example".to_string(), std::net::Ipv4Addr::new(203, 0, 113, 10)),
                    ("proxy-b.example".to_string(), std::net::Ipv4Addr::new(203, 0, 113, 20)),
                ]),
                queries: AtomicU32::new(0),
            });
            let dir = tempfile::tempdir().unwrap();
            let routing = MockRouting::new(dir.path().to_path_buf());
            let st = routing.state();
            let (mut pm, _dir) = new_manager_with_lockdown(MockProxy::new(), routing, dir, false);
            pm.set_bootstrap_querier_for_test(querier.clone());
            let mut cfg = test_config();
            cfg.dns.enabled = true;
            cfg.dns.servers = vec!["1.1.1.1".parse().unwrap()];

            cfg.server.server = "proxy-a.example".into();
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(st.cover_engage_calls.load(Ordering::SeqCst), 1);
            assert_eq!(*st.last_cover_server_ip.lock().unwrap(), Some(ip_a));
            let queries_after_a = querier.queries.load(Ordering::SeqCst);

            cfg.server.server = "proxy-b.example".into();
            pm.start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert!(
                querier.queries.load(Ordering::SeqCst) > queries_after_a,
                "the different-hostname retry must RE-RESOLVE (uncovered), never wedge on the stale cover"
            );
            assert_eq!(
                st.cover_disengage_calls.load(Ordering::SeqCst),
                1,
                "the stale cover for server A is released before re-resolving"
            );
            assert_eq!(
                st.cover_engage_calls.load(Ordering::SeqCst),
                2,
                "a fresh cover is engaged for server B"
            );
            assert_eq!(
                *st.last_cover_server_ip.lock().unwrap(),
                Some(ip_b),
                "the fresh cover permits server B's resolved IP"
            );
            assert!(pm.blocked_until_connected(), "still blocked, now on server B");
        });
    }

    /// The covered start engages the cover before start_inner, so the probe-
    /// suppression predicate (cover_active) sees the live in-process signal even
    /// with NO lockdown intent — the self-test's own reading survives instead of
    /// the probe's rewrite. Mirrors `lockdown_on_skips_probe_keeps_original_reason`;
    /// the control is `lockdown_off_runs_probe_rewrites_reason` (uncovered → probe
    /// runs).
    #[skuld::test]
    fn covered_start_without_lockdown_suppresses_probe() {
        rt().block_on(async {
            let (mut pm, cfg, _st, _dir) = covered_gate_setup(false);
            let err = pm
                .start_cancellable(&cfg, true, CancellationToken::new())
                .await
                .unwrap_err();
            assert!(
                matches!(err, ProxyError::NoTunnelConnection { .. }),
                "a covered start engages a cover, so the probe is skipped and the self-test's own \
                 reading (not one byte written) surfaces, got {err:?}"
            );
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
}
