// `CancellationToken::new` is the test harness's root signal; module-level allow per clippy.toml's
// "Bridge cancellation contract" sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use super::*;
use crate::proxy::Proxy;
use crate::proxy_manager::proxy_manager_tests::{test_config, MockProxy, MockRouting, MockRoutingState, MockRunning};
use crate::test_support::mock_dns::{MockDns, MockDnsState};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tun_engine::routing::Routing;
use tun_engine::TunIdentity;

type TestSession = Session<MockRouting, MockDns, Option<MockRunning>>;

const SERVER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

fn rt() -> tokio::runtime::Runtime {
    crate::proxy_manager::proxy_manager_tests::rt()
}

fn tun() -> TunIdentity {
    TunIdentity::synthetic(0xFEED, "hole-tun")
}

/// What a test needs to read back after handing the mocks to a session.
struct Mocks {
    proxy: MockProxy,
    routing: MockRouting,
    routing_state: Arc<MockRoutingState>,
    dns: MockDns,
    dns_state: Arc<MockDnsState>,
    dir: tempfile::TempDir,
}

fn mocks() -> Mocks {
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::new(dir.path().to_path_buf());
    let dns = MockDns::new();
    Mocks {
        routing_state: routing.state(),
        dns_state: dns.state_handle(),
        proxy: MockProxy::new(),
        routing,
        dns,
        dir,
    }
}

async fn running_proxy(proxy: &MockProxy) -> MockRunning {
    let config = crate::proxy::build_ss_config(&test_config(), None, SERVER_IP, None).unwrap();
    proxy.start(config).await.unwrap()
}

fn installed_routes(routing: &MockRouting) -> <MockRouting as Routing>::Installed {
    let gateway = routing.default_gateway(SERVER_IP).unwrap();
    routing.install(&tun(), SERVER_IP, &gateway).unwrap()
}

fn standing_cover(routing: &MockRouting) -> <MockRouting as Routing>::Cover {
    routing
        .install_lockdown(&routing.lock_covers(), SERVER_IP, &tun(), &[])
        .unwrap()
}

async fn applied_dns(dns: &MockDns) -> <MockDns as crate::dns::system::Dns>::Applied {
    use crate::dns::system::Dns;
    dns.apply(
        vec![],
        tun_engine::routing::RoutedFamilies { v4: true, v6: false },
        tun(),
        SERVER_IP,
        CancellationToken::new(),
    )
    .await
    .unwrap()
}

/// Sets its flag when dropped, so a task that owns it reports the moment its future is gone.
struct EndedFlag(Arc<AtomicBool>);

impl Drop for EndedFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A chain whose task runs until `cancel` fires, as garter's runner does, and owns `guard` for as long as its future
/// lives: the guard's `Drop` is the moment the task is gone.
fn endless_chain(guard: impl Send + 'static, cancel: CancellationToken) -> crate::proxy::plugin::PluginChain {
    let stop = cancel.clone();
    let handle = tokio::spawn(async move {
        let _guard = guard;
        stop.cancelled().await;
        garter::Result::Ok(())
    });
    crate::proxy::plugin::PluginChain::over_task_for_test(
        handle,
        cancel,
        crate::proxy::config::BundledPlugin::for_test("v2ray-plugin", std::env::temp_dir().join("ex-ray")),
    )
}

/// Appends its name to a log when dropped.
struct LoggedDrop(crate::test_support::EventLog, &'static str);

impl Drop for LoggedDrop {
    fn drop(&mut self) {
        self.0.lock().unwrap().push(self.1);
    }
}

/// Records a plugin in the state file when dropped, as a chain task still spawning one would.
struct RecordsPluginOnDrop {
    dir: std::path::PathBuf,
    record: cosca::identity::ProcessIdRecord,
}

impl Drop for RecordsPluginOnDrop {
    fn drop(&mut self) {
        crate::plugin_state::append_record(&self.dir, self.record.clone(), None).unwrap();
    }
}

/// Appends `name` to `log` at the moment `token` is cancelled, on the cancelling thread: an awaited task would reach
/// the log only after the code that cancelled it moved on. Keep the returned value alive for the test's duration.
fn log_when_cancelled(
    token: &CancellationToken,
    log: &crate::test_support::EventLog,
    name: &'static str,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    struct LogOnWake(crate::test_support::EventLog, &'static str);
    impl std::task::Wake for LogOnWake {
        fn wake(self: Arc<Self>) {
            self.0.lock().unwrap().push(self.1);
        }
    }
    let mut future: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(token.clone().cancelled_owned());
    let waker = std::task::Waker::from(Arc::new(LogOnWake(Arc::clone(log), name)));
    assert!(
        future
            .as_mut()
            .poll(&mut std::task::Context::from_waker(&waker))
            .is_pending(),
        "the token starts uncancelled"
    );
    future
}

#[skuld::test]
fn teardown_runs_each_phase_once_in_release_order() {
    rt().block_on(async {
        let m = mocks();
        let chain_ended = Arc::new(AtomicBool::new(false));
        let mut session = TestSession::empty();
        session.dns = Some(applied_dns(&m.dns).await);
        session.dispatcher = Some(crate::dispatcher::dispatcher_tests::build_dispatcher_over_cancel(
            |cancel| async move { cancel.cancelled().await },
        ));
        session.expect_plugins(m.dir.path().to_path_buf());
        session.hold_plugin_chain(endless_chain(
            EndedFlag(Arc::clone(&chain_ended)),
            CancellationToken::new(),
        ));
        session.routes = Some(installed_routes(&m.routing));
        session.hold_standing_cover(Some(standing_cover(&m.routing)));
        session.proxy = Some(running_proxy(&m.proxy).await);
        let proxy_state = m.proxy.state_handle();

        // (phase, DNS restored, plugin chain gone, proxy stops, route teardowns) at the moment the phase is entered.
        let mut seen = Vec::new();
        let torn = session
            .teardown(&mut |phase| {
                seen.push((
                    phase,
                    m.dns_state.shutdown_called(),
                    chain_ended.load(Ordering::SeqCst),
                    proxy_state.stop_calls.load(Ordering::SeqCst),
                    m.routing_state.teardown_calls.load(Ordering::SeqCst),
                ));
            })
            .await;

        // The chain ends inside `ReapPlugins`.
        assert_eq!(
            seen,
            vec![
                (StopPhase::RestoreDns, false, false, 0, 0),
                (StopPhase::StopEngine, true, false, 0, 0),
                (StopPhase::ReapPlugins, true, false, 0, 0),
                (StopPhase::StopProxy, true, true, 0, 0),
                (StopPhase::TearDownRoutes, true, true, 1, 0),
            ]
        );
        assert!(torn.proxy.is_ok());
        assert_eq!(
            *m.routing_state.events.lock().unwrap(),
            ["engage ends", "routes"],
            "teardown hands the cover back instead of deciding its fate"
        );
        assert!(torn.standing_cover.is_some());

        drop(torn);
        assert_eq!(
            *m.routing_state.events.lock().unwrap(),
            ["engage ends", "routes", "lockdown"]
        );
    });
}

#[skuld::test]
fn an_empty_session_enters_no_phase() {
    rt().block_on(async {
        let mut seen = Vec::new();
        let torn = TestSession::empty().teardown(&mut |phase| seen.push(phase)).await;

        assert!(seen.is_empty(), "a phase names work that is about to run: {seen:?}");
        assert!(torn.proxy.is_ok());
        assert!(torn.standing_cover.is_none());
    });
}

/// A session holding every field, each logging to `m.routing_state.events` at the moment it is released.
async fn session_logging_releases(m: &Mocks) -> (TestSession, Pin<Box<dyn Future<Output = ()> + Send>>) {
    let log = Arc::clone(&m.routing_state.events);
    m.dns_state.log_drops_to(Arc::clone(&log));
    m.proxy.state_handle().log_drops_to(Arc::clone(&log));
    let chain_cancel = CancellationToken::new();
    let chain_watch = log_when_cancelled(&chain_cancel, &log, "plugins");
    let mut session = TestSession::empty();
    session.dns = Some(applied_dns(&m.dns).await);
    // Dropping the dispatcher cancels its driver and waits for it, so the driver's own drop is the dispatcher's.
    session.dispatcher = Some(crate::dispatcher::dispatcher_tests::build_dispatcher_over_cancel(
        |cancel| {
            let logged = LoggedDrop(Arc::clone(&log), "dispatcher");
            async move {
                let _logged = logged;
                cancel.cancelled().await;
            }
        },
    ));
    session.expect_plugins(m.dir.path().to_path_buf());
    session.hold_plugin_chain(endless_chain((), chain_cancel));
    session.proxy = Some(running_proxy(&m.proxy).await);
    session.routes = Some(installed_routes(&m.routing));
    session.hold_standing_cover(Some(standing_cover(&m.routing)));
    (session, chain_watch)
}

const RELEASE_ORDER: [&str; 7] = [
    "engage ends",
    "dns",
    "dispatcher",
    "plugins",
    "proxy",
    "routes",
    "lockdown",
];

#[skuld::test]
fn dropping_a_session_releases_in_teardown_order() {
    // The net for a panic or a dropped future runs in the same order as `teardown`.
    rt().block_on(async {
        let m = mocks();
        let (session, _chain_watch) = session_logging_releases(&m).await;

        drop(session);

        assert_eq!(*m.routing_state.events.lock().unwrap(), RELEASE_ORDER);
    });
}

#[skuld::test]
fn a_teardown_that_panics_releases_what_is_left_in_teardown_order() {
    rt().block_on(async {
        let m = mocks();
        let (session, _chain_watch) = session_logging_releases(&m).await;

        let panicked = tokio::spawn(async move { session.teardown(&mut |_| panic!("a phase panics")).await }).await;

        assert!(panicked.is_err_and(|e| e.is_panic()));
        assert_eq!(*m.routing_state.events.lock().unwrap(), RELEASE_ORDER);
    });
}

#[skuld::test]
fn the_chain_has_ended_before_the_reap_reads_the_state_file() {
    // A chain task still running when the reap reads the state file could record a plugin the reap never sees.
    // This one records its plugin as its future is dropped: only an ended chain has recorded it by the reap.
    rt().block_on(async {
        let m = mocks();
        let mut child = crate::test_support::reap_child::EchoChild::spawn();
        let mut session = TestSession::empty();
        session.expect_plugins(m.dir.path().to_path_buf());
        session.hold_plugin_chain(endless_chain(
            RecordsPluginOnDrop {
                dir: m.dir.path().to_path_buf(),
                record: child.record(),
            },
            CancellationToken::new(),
        ));
        session.proxy = Some(running_proxy(&m.proxy).await);

        let _ = session.teardown(&mut |_| {}).await;

        assert!(
            !child.echoes(),
            "the plugin a chain records while it ends must be reaped by the same teardown"
        );
    });
}

#[skuld::test]
fn expecting_plugins_again_keeps_the_chain_already_held() {
    rt().block_on(async {
        let m = mocks();
        let mut session = TestSession::empty();
        session.expect_plugins(m.dir.path().to_path_buf());
        session.hold_plugin_chain(endless_chain((), CancellationToken::new()));

        session.expect_plugins(m.dir.path().to_path_buf());

        assert!(session.plugin_chain().is_some(), "a held chain is not dropped unjoined");
    });
}

#[skuld::test]
fn a_proxy_that_fails_to_stop_does_not_stop_the_later_phases() {
    rt().block_on(async {
        let m = mocks();
        let proxy_state = m.proxy.state_handle();
        proxy_state.fail_stop.store(true, Ordering::SeqCst);
        let mut session = TestSession::empty();
        session.routes = Some(installed_routes(&m.routing));
        session.hold_standing_cover(Some(standing_cover(&m.routing)));
        session.proxy = Some(running_proxy(&m.proxy).await);

        let torn = session.teardown(&mut |_| {}).await;

        assert!(torn.proxy.is_err(), "the proxy's own error is reported");
        assert_eq!(proxy_state.stop_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *m.routing_state.events.lock().unwrap(),
            ["engage ends", "routes"],
            "routes are still torn down and the cover is still handed back"
        );
        assert!(torn.standing_cover.is_some());
    });
}

#[skuld::test]
fn a_session_without_a_cover_hands_none_back() {
    rt().block_on(async {
        let m = mocks();
        let mut session = TestSession::empty();
        session.hold_standing_cover(None);
        session.proxy = Some(running_proxy(&m.proxy).await);

        let torn = session.teardown(&mut |_| {}).await;

        assert!(torn.standing_cover.is_none());
    });
}

#[skuld::test]
fn a_session_with_a_ready_chain_reaps_its_recorded_plugins() {
    // The state a start that fails after its chain became ready hands to `teardown`.
    rt().block_on(async {
        let m = mocks();
        let mut child = crate::test_support::reap_child::EchoChild::spawn();
        crate::plugin_state::append_record(m.dir.path(), child.record(), None).unwrap();
        let mut session = TestSession::empty();
        session.expect_plugins(m.dir.path().to_path_buf());
        session.hold_plugin_chain(endless_chain((), CancellationToken::new()));
        session.proxy = Some(running_proxy(&m.proxy).await);
        let proxy_state = m.proxy.state_handle();

        let torn = session.teardown(&mut |_| {}).await;

        assert!(torn.proxy.is_ok());
        assert_eq!(proxy_state.stop_calls.load(Ordering::SeqCst), 1);
        assert!(
            !child.echoes(),
            "the recorded plugin must not answer after the teardown"
        );
    });
}
