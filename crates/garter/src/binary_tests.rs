// `CancellationToken::new` roots the shutdown signal of the reader tests.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;

use crate::binary::BinaryPlugin;
use crate::plugin::ChainPlugin;

#[skuld::test]
fn binary_plugin_name_from_path() {
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", None);
    assert_eq!(plugin.name(), "v2ray-plugin");
}

#[skuld::test]
#[cfg(windows)]
fn binary_plugin_name_from_windows_path() {
    let plugin = BinaryPlugin::new(r"C:\plugins\v2ray-plugin.exe", None);
    assert_eq!(plugin.name(), "v2ray-plugin");
}

#[skuld::test]
fn binary_plugin_with_options() {
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", Some("tls;host=example.com"));
    assert_eq!(plugin.name(), "v2ray-plugin");
}

// SIP003 env-var direction tests ======================================================================================

/// In Client mode (no `server` key in options) `BinaryPlugin` maps
/// `local → SS_LOCAL_*` and `remote → SS_REMOTE_*`. This matches v2ray-plugin's
/// client-mode interpretation: bind on SS_LOCAL, dial SS_REMOTE.
#[skuld::test]
fn sip003_env_client_mode_straight_through() {
    let listen: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let dial: SocketAddr = "203.0.113.1:8388".parse().unwrap();
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", Some("tls;host=example.com"));
    let env = plugin.sip003_env(listen, dial).unwrap();
    assert_eq!(env.ss_local_host, "127.0.0.1");
    assert_eq!(env.ss_local_port, 9001);
    assert_eq!(env.ss_remote_host, "203.0.113.1");
    assert_eq!(env.ss_remote_port, 8388);
}

/// In Server mode (bare `server` key in options) `BinaryPlugin` must SWAP
/// the env vars: `local → SS_REMOTE_*` and `remote → SS_LOCAL_*`. Reason:
/// v2ray-plugin's server-mode `parseEnv` swaps SS_LOCAL/SS_REMOTE
/// semantics again (SS_REMOTE = inbound listener, SS_LOCAL = outbound
/// dial), so a double-swap restores the chain's intended direction.
/// Without this swap the binary listens on `remote` and forwards to
/// `local`, colliding with the previous chain link. See bindreams/hole#396.
#[skuld::test]
fn sip003_env_server_mode_swaps_addresses() {
    let listen: SocketAddr = "[::]:80".parse().unwrap();
    let dial: SocketAddr = "127.0.0.1:45589".parse().unwrap();
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", Some("server;host=example.com"));
    let env = plugin.sip003_env(listen, dial).unwrap();
    // Swap: BinaryPlugin's `local` (where the chain wants the binary to
    // bind, [::]:80) must reach v2ray-plugin as SS_REMOTE so its
    // server-mode swap interprets it as the listen address.
    assert_eq!(env.ss_remote_host, "::");
    assert_eq!(env.ss_remote_port, 80);
    assert_eq!(env.ss_local_host, "127.0.0.1");
    assert_eq!(env.ss_local_port, 45589);
}

/// `server` keyword is detected by SIP003 key parser, not substring match.
/// `servername=...` is NOT server mode.
#[skuld::test]
fn sip003_env_client_mode_when_options_only_have_servername() {
    let listen: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let dial: SocketAddr = "203.0.113.1:8388".parse().unwrap();
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", Some("servername=cdn.example.com"));
    let env = plugin.sip003_env(listen, dial).unwrap();
    assert_eq!(env.ss_local_host, "127.0.0.1");
    assert_eq!(env.ss_local_port, 9001);
    assert_eq!(env.ss_remote_host, "203.0.113.1");
    assert_eq!(env.ss_remote_port, 8388);
}

// Pinned here because this is the call site that actually wires
// SS_LOCAL/SS_REMOTE, not just a diagnostic mode read: a malformed
// per-plugin `options:` string must not silently pick a chain direction.
#[skuld::test]
fn sip003_env_errors_on_malformed_options() {
    let listen: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let dial: SocketAddr = "203.0.113.1:8388".parse().unwrap();
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", Some(r"server;path=/a\"));
    assert!(plugin.sip003_env(listen, dial).is_err());
}

// Readiness-mode tests ================================================================================================

#[skuld::test]
fn readiness_mode_defaults_to_probe() {
    let p = crate::BinaryPlugin::new("/nonexistent", None);
    assert_eq!(p.readiness_mode_for_test(), crate::binary::ReadinessMode::Probe);
}

#[skuld::test]
fn readiness_mode_auto_is_selectable() {
    let p = crate::BinaryPlugin::new("/nonexistent", None).readiness(crate::binary::ReadinessMode::Auto);
    assert_eq!(p.readiness_mode_for_test(), crate::binary::ReadinessMode::Auto);
}

// GOTRACEBACK env test ================================================================================================

#[skuld::test]
fn fixed_env_sets_gotraceback_crash() {
    // The always-injected env pairs include GOTRACEBACK=crash so a Go
    // plugin (ex-ray) dumps full goroutine state to stderr on a native fault
    // (the bridge relays that stderr through tracing). Harmless to Rust
    // plugins, which ignore it. See bindreams/hole#438.
    let pairs = crate::binary::fixed_plugin_env();
    assert!(
        pairs.iter().any(|(k, v)| *k == "GOTRACEBACK" && *v == "crash"),
        "GOTRACEBACK=crash must be injected: {pairs:?}"
    );
}

#[skuld::test]
fn fixed_env_sets_no_color() {
    // Regression pin: fixed_plugin_env must inject both NO_COLOR and
    // CLICOLOR (see the doc comment on fixed_plugin_env for why).
    let pairs = crate::binary::fixed_plugin_env();
    assert!(
        pairs.iter().any(|(k, v)| *k == "NO_COLOR" && *v == "1"),
        "NO_COLOR=1 must be injected: {pairs:?}"
    );
    assert!(
        pairs.iter().any(|(k, v)| *k == "CLICOLOR" && *v == "0"),
        "CLICOLOR=0 must be injected: {pairs:?}"
    );
}

// Post-exit reader drain ==============================================================================================
//
// Every test runs on a paused clock: elapsed time is only what `advance` says, so a wait that is
// really a timer shows up as a result that depends on `advance`, not on scheduling luck.

use std::future::Future;
use std::pin::{pin, Pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use cosca::Containment;
use tokio::sync::{oneshot, Notify};
use tokio::task::JoinHandle;

use crate::binary::{
    drain_readers_after_exit, end_plugin, shut_plugin_down, supervise_plugin, PluginEnd, PluginTree, Supervised,
};
use crate::test_utils::WaitableWriter;
use crate::tracing_test::set_default_in_current_thread;

/// Stands in for a runaway test: a paused runtime that goes idle jumps the clock, so a join that
/// never finishes fails here instead of hanging.
const VIRTUAL_HANG: Duration = Duration::from_secs(24 * 3600);

/// The failure bound on the wait for a plugin's output, written out so a change to it fails here.
const EOF_BOUND: Duration = Duration::from_secs(5);

/// A timer's deadline is rounded up to the next millisecond; advancing this far past a bound fires it.
const TIMER_SLACK: Duration = Duration::from_millis(2);

/// Every containment `cosca` names, each paired with whether the drain waits for the tree's own exit
/// edge after a kill. That is only where the edge is kernel-owned: a live process cannot leave a
/// cgroup or a job object without exiting. The macOS fd marker has an edge too, but a live process
/// can close its copy of the marker and stay up, so the edge proves nothing there.
const CONTAINMENTS: [(Containment, bool); 8] = [
    (Containment::CgroupV2, true),
    (Containment::JobObject, true),
    (Containment::ProcessGroup, false),
    (Containment::Session, false),
    (Containment::FdMarker, false),
    (Containment::TreeWalk, false),
    (Containment::Delegated, false),
    (Containment::None, false),
];

fn poll_once<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}

fn subscriber() -> (impl tracing::Subscriber + Send + Sync, WaitableWriter) {
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    (subscriber, writer)
}

/// A reader task that finishes once `release` fires.
fn gated_reader() -> (oneshot::Sender<()>, JoinHandle<()>) {
    let (release, gate) = oneshot::channel::<()>();
    (
        release,
        tokio::spawn(async move {
            let _ = gate.await;
        }),
    )
}

/// A reader task that never finishes by itself, and a receiver that resolves when the task is dropped.
fn held_reader() -> (oneshot::Receiver<()>, JoinHandle<()>) {
    struct Dropped(Option<oneshot::Sender<()>>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }
    let (dropped, observe) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _guard = Dropped(Some(dropped));
        std::future::pending::<()>().await;
    });
    (observe, task)
}

fn finished_reader() -> JoinHandle<()> {
    tokio::spawn(async {})
}

fn kill_failed() -> Result<(), cosca::error::Error> {
    Err(cosca::error::Error::Containment {
        detail: "test: the kill failed".into(),
    })
}

fn kill_root_refused() -> cosca::error::Error {
    cosca::error::Error::Containment {
        detail: "test: the root kill was refused".into(),
    }
}

fn reap_failed() -> cosca::error::Error {
    cosca::error::Error::Containment {
        detail: "test: the reap failed".into(),
    }
}

fn unsupported() -> cosca::error::Error {
    cosca::error::Error::Unsupported {
        op: "kill_tree".into(),
        platform: "test",
        detail: "no tree of its own".into(),
    }
}

/// The calls the drain made on a tree, in order.
type Calls = Arc<Mutex<Vec<&'static str>>>;

/// Answers the teardown's calls as scripted, recording them in order: `kill` runs once, on `kill_tree`;
/// the tree's exit edge resolves once `edge` is notified (or errors, for `edge_fails`); a root watched
/// for its grace has exited within it unless `root_outlives_grace`; a root watched without a bound has
/// exited unless `root_never_exits`; `root_watch_fails` makes every watch of the root fail; `reap`
/// waits for `kill_root` when `reap_waits_for_kill`.
///
/// A root counts as running while `root_never_exits` or `root_outlives_grace` holds. A zero-grace
/// watch (the probe) reports it running; `kill_tree` takes it down unless `root_survives_tree_kill`
/// (a root whose kill was refused to this process). `exit_watch_pends_first_poll` makes the unbounded
/// watch return `Pending` once before it answers, as the real watch does, and `reap_never_completes`
/// makes `reap` wait for a root that nothing can make exit; `probe_fails` makes the zero-grace probe fail.
struct FakeTree<K> {
    containment: Containment,
    kill: Option<K>,
    edge: Arc<Notify>,
    edge_fails: bool,
    root_outlives_grace: bool,
    root_watch_fails: bool,
    root_never_exits: bool,
    reap_waits_for_kill: bool,
    root_killed: Arc<Notify>,
    terminate_fails: bool,
    kill_root_fails: bool,
    reap_fails: bool,
    exit_watch_pends_first_poll: bool,
    root_survives_tree_kill: bool,
    reap_never_completes: bool,
    /// `reap` waits for this to be notified: the root exits when the test says so.
    reap_waits_for: Option<Arc<Notify>>,
    probe_fails: bool,
    /// What `reap` reports.
    exit_status: std::process::ExitStatus,
    tree_killed: bool,
    graces: Arc<Mutex<Vec<Duration>>>,
    calls: Calls,
}

impl<K: FnOnce() -> Result<(), cosca::error::Error>> FakeTree<K> {
    /// A tree whose exit edge has not fired.
    fn new(containment: Containment, kill: K) -> Self {
        Self {
            containment,
            kill: Some(kill),
            edge: Arc::new(Notify::new()),
            edge_fails: false,
            root_outlives_grace: false,
            root_watch_fails: false,
            root_never_exits: false,
            reap_waits_for_kill: false,
            root_killed: Arc::new(Notify::new()),
            terminate_fails: false,
            kill_root_fails: false,
            reap_fails: false,
            exit_watch_pends_first_poll: false,
            root_survives_tree_kill: false,
            reap_never_completes: false,
            reap_waits_for: None,
            probe_fails: false,
            exit_status: std::process::ExitStatus::default(),
            tree_killed: false,
            graces: Arc::default(),
            calls: Calls::default(),
        }
    }

    /// A tree whose exit edge has already fired.
    fn drained(containment: Containment, kill: K) -> Self {
        let tree = Self::new(containment, kill);
        tree.edge.notify_one();
        tree
    }

    fn record(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

impl<K: FnOnce() -> Result<(), cosca::error::Error>> PluginTree for FakeTree<K> {
    fn containment(&self) -> Containment {
        self.containment
    }

    async fn wait_root_exit(&self) -> Result<(), cosca::error::Error> {
        self.record("wait_root_exit");
        if self.root_watch_fails {
            return Err(unsupported());
        }
        if self.exit_watch_pends_first_poll {
            tokio::task::yield_now().await;
        }
        if self.root_never_exits {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn wait_root_exit_within(&self, grace: Duration) -> Result<bool, cosca::error::Error> {
        self.record("wait_root_exit_within");
        self.graces.lock().unwrap().push(grace);
        if self.root_watch_fails || self.probe_fails && grace.is_zero() {
            return Err(unsupported());
        }
        let running = self.root_never_exits || self.root_outlives_grace;
        if self.tree_killed && !self.root_survives_tree_kill || !running {
            return Ok(true);
        }
        // A root that is running now has not exited at a zero grace; within a real grace it exits
        // unless `root_outlives_grace`.
        Ok(!grace.is_zero() && !self.root_outlives_grace)
    }

    fn terminate(&self) -> Result<(), cosca::error::Error> {
        self.record("terminate");
        if self.terminate_fails {
            return Err(unsupported());
        }
        Ok(())
    }

    fn kill_root(&mut self) -> Result<(), cosca::error::Error> {
        self.record("kill_root");
        self.root_killed.notify_one();
        if self.kill_root_fails {
            return Err(kill_root_refused());
        }
        Ok(())
    }

    fn kill_tree(&mut self) -> Result<(), cosca::error::Error> {
        self.record("kill_tree");
        self.tree_killed = true;
        (self.kill.take().expect("the tree was killed twice"))()
    }

    async fn wait_tree_drained(&self) -> Result<(), cosca::error::Error> {
        self.record("wait_tree_drained");
        if self.edge_fails {
            return Err(unsupported());
        }
        self.edge.notified().await;
        Ok(())
    }

    async fn reap(&mut self) -> Result<std::process::ExitStatus, cosca::error::Error> {
        if self.reap_never_completes {
            self.record("reap");
            std::future::pending::<()>().await;
        }
        if self.reap_waits_for_kill {
            self.root_killed.notified().await;
        }
        if let Some(exits) = &self.reap_waits_for {
            exits.notified().await;
        }
        self.record("reap");
        if self.reap_fails {
            return Err(reap_failed());
        }
        Ok(self.exit_status)
    }

    fn disarm(&mut self) {
        self.record("disarm");
    }
}

fn drained_tree(containment: Containment) -> FakeTree<impl FnOnce() -> Result<(), cosca::error::Error>> {
    FakeTree::drained(containment, || Ok(()))
}

/// After a kill, a tree whose exit edge is kernel-owned is waited on with no bound: its members are
/// gone only when the edge says so, however long that takes.
#[skuld::test]
async fn a_kernel_owned_tree_is_waited_for_its_exit_edge_with_no_bound() {
    tokio::time::pause();
    for containment in [Containment::CgroupV2, Containment::JobObject] {
        let mut tree = FakeTree::new(containment, || Ok(()));
        let edge = tree.edge.clone();
        let drain = drain_readers_after_exit("p", &mut tree, finished_reader(), finished_reader());
        let mut drain = pin!(drain);

        assert!(poll_once(drain.as_mut()).is_pending());
        tokio::time::advance(EOF_BOUND + VIRTUAL_HANG).await;
        assert!(
            poll_once(drain.as_mut()).is_pending(),
            "{containment:?}: ended by elapsed time"
        );

        edge.notify_one();
        tokio::time::timeout(VIRTUAL_HANG, drain)
            .await
            .expect("the drain must finish once the tree's exit edge fires");
    }
}

/// A pipe holder can sit outside the tree (a process that moved to another cgroup, a handle
/// duplicated into a process outside the job), so even a drained kernel-owned tree does not
/// guarantee EOF: the reader wait has the bound, warns by plugin name, and aborts the readers.
#[skuld::test]
async fn a_reader_held_outside_a_drained_tree_ends_at_the_bound_with_a_warning() {
    tokio::time::pause();
    for containment in [Containment::CgroupV2, Containment::JobObject] {
        let (subscriber, writer) = subscriber();
        let _g = set_default_in_current_thread(subscriber);
        let (out_dropped, stdout) = held_reader();
        let mut tree = drained_tree(containment);
        let drain = drain_readers_after_exit("outside-plugin", &mut tree, stdout, finished_reader());
        let mut drain = pin!(drain);

        assert!(poll_once(drain.as_mut()).is_pending());
        tokio::time::advance(EOF_BOUND - Duration::from_millis(1)).await;
        assert!(
            poll_once(drain.as_mut()).is_pending(),
            "{containment:?}: ended before the bound"
        );
        tokio::time::advance(TIMER_SLACK).await;
        assert!(
            poll_once(drain.as_mut()).is_ready(),
            "{containment:?}: still waiting at the bound"
        );

        tokio::time::timeout(VIRTUAL_HANG, out_dropped)
            .await
            .unwrap_or_else(|_| panic!("{containment:?}: the reader was detached, not aborted"))
            .ok();
        let log = writer.snapshot();
        assert!(
            log.contains("WARN") && log.contains("outside-plugin") && log.contains("cut"),
            "{containment:?}: the warning must name the plugin and say the output was cut:\n{log}"
        );
    }
}

/// The order is kill, then the tree's exit edge (only where it is kernel-owned), then the readers:
/// the readers here reach EOF only because the kill ran, as a reader held by a grandchild does.
#[skuld::test]
async fn the_tree_is_killed_then_its_exit_edge_awaited_then_the_readers() {
    tokio::time::pause();
    let (subscriber, writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);

    for (containment, edge_awaited) in CONTAINMENTS {
        let (release, stdout) = gated_reader();
        let mut tree = FakeTree::drained(containment, move || {
            release.send(()).unwrap();
            Ok(())
        });
        tokio::time::timeout(
            VIRTUAL_HANG,
            drain_readers_after_exit("p", &mut tree, stdout, finished_reader()),
        )
        .await
        .unwrap_or_else(|_| panic!("{containment:?}: the readers were awaited before the kill"));

        let expected: &[&str] = if edge_awaited {
            &["kill_tree", "wait_tree_drained"]
        } else {
            &["kill_tree"]
        };
        assert_eq!(tree.calls(), expected, "{containment:?}");
    }
    assert!(!writer.snapshot().contains("WARN"), "{}", writer.snapshot());
}

/// Where there is no kernel-owned edge, the wait ends at the bound, says so by plugin name, and
/// ABORTS the readers (dropping them), so their holds on the readiness sender are released.
#[skuld::test]
async fn a_weak_containment_join_ends_at_the_bound_with_a_warning_and_aborts_the_readers() {
    tokio::time::pause();
    for containment in [
        Containment::ProcessGroup,
        Containment::Session,
        Containment::FdMarker,
        Containment::TreeWalk,
        Containment::Delegated,
        Containment::None,
    ] {
        let (subscriber, writer) = subscriber();
        let _g = set_default_in_current_thread(subscriber);
        let (out_dropped, stdout) = held_reader();
        let (err_dropped, stderr) = held_reader();
        let mut tree = drained_tree(containment);
        let drain = drain_readers_after_exit("held-plugin", &mut tree, stdout, stderr);
        let mut drain = pin!(drain);

        assert!(poll_once(drain.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(poll_once(drain.as_mut()).is_pending(), "{containment:?}: ended early");
        tokio::time::advance(EOF_BOUND - Duration::from_millis(501)).await;
        assert!(
            poll_once(drain.as_mut()).is_pending(),
            "{containment:?}: ended before the bound"
        );
        assert!(
            !writer.snapshot().contains("held-plugin"),
            "{containment:?}: warned before the bound"
        );

        tokio::time::advance(TIMER_SLACK).await;
        assert!(
            poll_once(drain.as_mut()).is_ready(),
            "{containment:?}: still waiting at the bound"
        );

        // Aborted, not detached: both reader tasks are dropped.
        tokio::time::timeout(VIRTUAL_HANG, async {
            let _ = out_dropped.await;
            let _ = err_dropped.await;
        })
        .await
        .unwrap_or_else(|_| panic!("{containment:?}: the readers were detached, not aborted"));

        let log = writer.snapshot();
        assert!(
            log.contains("WARN") && log.contains("held-plugin") && log.contains("cut"),
            "{containment:?}: the warning must name the plugin and say the output was cut:\n{log}"
        );
        assert!(
            log.contains("(a process it started holds them); its output"),
            "{containment:?}: the warning text is mangled:\n{log}"
        );
    }
}

/// A kill that did not happen leaves the tree's exit edge unproven: it is not waited on, and the
/// readers get the bound, even on a kernel-owned containment.
#[skuld::test]
async fn a_failed_kill_skips_the_exit_edge_and_gives_even_a_kernel_owned_join_the_bound() {
    tokio::time::pause();
    let (subscriber, _writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let (dropped, stdout) = held_reader();
    let mut tree = FakeTree::new(Containment::JobObject, kill_failed);
    let calls = tree.calls.clone();
    let drain = drain_readers_after_exit("p", &mut tree, stdout, finished_reader());
    let mut drain = pin!(drain);

    assert!(poll_once(drain.as_mut()).is_pending());
    tokio::time::advance(EOF_BOUND + TIMER_SLACK).await;
    assert!(poll_once(drain.as_mut()).is_ready());
    tokio::time::timeout(VIRTUAL_HANG, dropped)
        .await
        .expect("the reader must be aborted at the bound")
        .ok();
    assert_eq!(*calls.lock().unwrap(), ["kill_tree"]);
}

/// An exit edge that cannot be awaited does not strand the drain: the readers still get the bound.
#[skuld::test]
async fn an_exit_edge_that_errors_falls_back_to_the_bounded_reader_wait() {
    tokio::time::pause();
    let (subscriber, writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let (dropped, stdout) = held_reader();
    let mut tree = FakeTree::new(Containment::CgroupV2, || Ok(()));
    tree.edge_fails = true;
    let drain = drain_readers_after_exit("p", &mut tree, stdout, finished_reader());
    let mut drain = pin!(drain);

    assert!(poll_once(drain.as_mut()).is_pending());
    tokio::time::advance(EOF_BOUND + TIMER_SLACK).await;
    assert!(poll_once(drain.as_mut()).is_ready());
    tokio::time::timeout(VIRTUAL_HANG, dropped)
        .await
        .expect("the reader must be aborted at the bound")
        .ok();
    assert!(writer.snapshot().contains("DEBUG"), "{}", writer.snapshot());
}

/// A join that completes inside the bound is silent.
#[skuld::test]
async fn a_weak_containment_join_that_reaches_eof_does_not_warn() {
    tokio::time::pause();
    let (subscriber, writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let (release, stdout) = gated_reader();
    let mut tree = drained_tree(Containment::ProcessGroup);
    let drain = drain_readers_after_exit("quiet-plugin", &mut tree, stdout, finished_reader());
    let mut drain = pin!(drain);
    assert!(poll_once(drain.as_mut()).is_pending());
    tokio::time::advance(EOF_BOUND - Duration::from_millis(1)).await;
    release.send(()).unwrap();
    tokio::time::timeout(VIRTUAL_HANG, drain).await.unwrap();

    assert!(!writer.snapshot().contains("quiet-plugin"), "{}", writer.snapshot());
}

/// A kill error on a tree that can tear down is a failure to bring it down: loud.
#[skuld::test]
async fn a_kill_error_on_a_tree_that_can_tear_down_warns() {
    tokio::time::pause();
    let (subscriber, writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let mut tree = FakeTree::new(Containment::ProcessGroup, kill_failed);
    drain_readers_after_exit("loud-plugin", &mut tree, finished_reader(), finished_reader()).await;

    let log = writer.snapshot();
    assert!(
        log.contains("WARN") && log.contains("loud-plugin") && log.contains("the kill failed"),
        "{log}"
    );
}

/// A tree with no tear-down of its own (nested, or uncontained) has nothing to kill; the refusal is
/// not a warning, but it is not dropped either.
#[skuld::test]
async fn a_kill_error_on_a_tree_that_cannot_tear_down_is_logged_at_debug() {
    tokio::time::pause();
    for containment in [Containment::Delegated, Containment::None] {
        let (subscriber, writer) = subscriber();
        let _g = set_default_in_current_thread(subscriber);

        let mut tree = FakeTree::new(containment, || Err(unsupported()));
        drain_readers_after_exit("nested-plugin", &mut tree, finished_reader(), finished_reader()).await;

        let log = writer.snapshot();
        assert!(!log.contains("WARN"), "{containment:?}: {log}");
        assert!(
            log.contains("DEBUG") && log.contains("nested-plugin") && log.contains("no tree of its own"),
            "{containment:?}: the kill error must be logged at debug:\n{log}"
        );
    }
}

// The sitrep stdout reader at EOF -------------------------------------------------------------------------------------

use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::binary::{spawn_sitrep_stdout_reader, FailureHold};
use crate::sitrep::{PluginReady, SitrepEvent, StartError, Transports, SITREP_PROTOCOL};

type ReadyResult = Result<PluginReady, StartError>;

fn sitrep_line(event: &SitrepEvent) -> String {
    format!("{}\n", serde_json::to_string(event).unwrap())
}

fn hello(protocol: &str) -> String {
    sitrep_line(&SitrepEvent::Hello {
        protocol: protocol.into(),
    })
}

/// Runs the sitrep stdout reader over `stdout_lines`, then EOF on a plugin whose stderr is still open.
/// `local` refuses connections, so a probe never readies it. The token is the chain's shutdown.
async fn sitrep_reader_over(
    stdout_lines: &str,
    auto: bool,
) -> (
    oneshot::Receiver<ReadyResult>,
    JoinHandle<()>,
    CancellationToken,
    FailureHold,
) {
    let freed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (mut plugin_stdout, host_stdout) = tokio::io::duplex(4096);
    plugin_stdout.write_all(stdout_lines.as_bytes()).await.unwrap();
    drop(plugin_stdout);
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();
    let (reader, failure) = spawn_sitrep_stdout_reader(
        host_stdout,
        "eof-plugin".into(),
        freed,
        shutdown.clone(),
        ready_tx,
        auto,
        None,
    );
    (ready_rx, reader, shutdown, failure)
}

/// A sitrep plugin's readiness travels on stdout, so once stdout is closed without `ready` it never
/// readies: the reader has the plugin taken down however long its stderr stays open, and the failure
/// it held is what `deliver` sends.
#[skuld::test]
async fn at_sitrep_stdout_eof_without_ready_the_plugin_is_taken_down_and_the_failure_held() {
    tokio::time::pause();
    for (lines, auto) in [
        (String::new(), false),
        (hello(SITREP_PROTOCOL), false),
        // `Auto` stands its probe down on a supported hello.
        (hello(SITREP_PROTOCOL), true),
    ] {
        let (mut ready_rx, reader, _shutdown, failure) = sitrep_reader_over(&lines, auto).await;
        tokio::time::timeout(VIRTUAL_HANG, reader)
            .await
            .unwrap_or_else(|_| panic!("auto={auto}, {lines:?}: the reader waited on a stderr that stays open"))
            .unwrap();

        assert!(
            poll_once(pin!(failure.failed())).is_ready(),
            "auto={auto}, {lines:?}: the plugin was not taken down"
        );
        assert!(
            poll_once(pin!(&mut ready_rx)).is_pending(),
            "auto={auto}, {lines:?}: the reader sent the failure itself"
        );
        failure.deliver();
        let ready = ready_rx.await;
        assert!(
            matches!(&ready, Ok(Err(StartError::Fatal { detail, .. })) if detail.contains("closed its sitrep stream")),
            "auto={auto}, {lines:?}: {ready:?}"
        );
    }
}

/// Where a probe owns readiness (`Auto` with no supported hello, or after an unknown-major
/// fallback), closed stdout says nothing about the plugin's listener: the probe decides.
#[skuld::test]
async fn at_stdout_eof_a_probe_that_owns_readiness_decides() {
    tokio::time::pause();
    for (lines, auto) in [
        (String::new(), true),
        (hello("sitrep-9.0.0"), false),
        (hello("sitrep-9.0.0"), true),
    ] {
        let (mut ready_rx, reader, shutdown, failure) = sitrep_reader_over(&lines, auto).await;
        tokio::time::timeout(VIRTUAL_HANG, reader)
            .await
            .unwrap_or_else(|_| panic!("auto={auto}, {lines:?}: the reader never ended"))
            .unwrap();

        assert!(
            poll_once(pin!(failure.failed())).is_pending(),
            "auto={auto}, {lines:?}: the plugin was taken down while a probe owns readiness"
        );
        failure.deliver();
        assert!(
            poll_once(pin!(&mut ready_rx)).is_pending(),
            "auto={auto}, {lines:?}: the reader failed a start the probe still owns"
        );
        shutdown.cancel();
        // The probe ends on shutdown and drops the sender unsent.
        assert!(ready_rx.await.is_err());
    }
}

#[skuld::test]
async fn a_ready_before_stdout_eof_is_not_overwritten() {
    tokio::time::pause();
    let listen: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let lines = hello(SITREP_PROTOCOL)
        + &sitrep_line(&SitrepEvent::Ready {
            listen,
            transports: Transports::TCP,
        });
    let (ready_rx, _reader, _shutdown, failure) = sitrep_reader_over(&lines, false).await;

    let ready = tokio::time::timeout(VIRTUAL_HANG, ready_rx).await.unwrap();
    assert!(
        poll_once(pin!(failure.failed())).is_pending(),
        "a ready is not a failure"
    );
    assert!(matches!(&ready, Ok(Ok(r)) if r.listen == listen), "{ready:?}");
}

// A start failure follows the plugin's output -------------------------------------------------------------------------

const STDERR_LINE: &str = "fatal: injected crash on stderr";

/// Stands in for the stderr reader, held back until the returned sender fires: it then relays
/// [`STDERR_LINE`] into `relayed` and finishes.
fn held_back_stderr(relayed: Arc<Mutex<Vec<&'static str>>>) -> (oneshot::Sender<()>, JoinHandle<()>) {
    let (release, gate) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _ = gate.await;
        relayed.lock().unwrap().push(STDERR_LINE);
    });
    (release, task)
}

/// Every way the sitrep stdout reader fails a start: stdout closing before `ready`, and each failing
/// event. Each pairs with whether the plugin's root is still running when the reader decides.
fn start_failures() -> Vec<(&'static str, String, bool)> {
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let after_hello = |event| hello(SITREP_PROTOCOL) + &sitrep_line(&event);
    vec![
        ("stdout closed, root exited", hello(SITREP_PROTOCOL), false),
        ("stdout closed, root alive", hello(SITREP_PROTOCOL), true),
        (
            "fatal, root exited",
            after_hello(SitrepEvent::Fatal {
                detail: "boom".into(),
                errno: None,
            }),
            false,
        ),
        (
            "fatal, root alive",
            after_hello(SitrepEvent::Fatal {
                detail: "boom".into(),
                errno: None,
            }),
            true,
        ),
        (
            "bind conflict, root alive",
            after_hello(SitrepEvent::BindConflict { errno: 98, addr }),
            true,
        ),
        (
            "empty transports, root alive",
            after_hello(SitrepEvent::Ready {
                listen: addr,
                transports: Transports::empty(),
            }),
            true,
        ),
    ]
}

/// A plugin's last words on stderr reach the log before the start failure reaches the caller, whichever
/// way the failure is found and whether or not the plugin is still running. The stderr reader is held
/// back by the test, so the order is the code's, not the scheduler's.
#[skuld::test]
async fn a_start_failure_is_not_delivered_before_the_plugins_stderr() {
    tokio::time::pause();
    for (case, lines, root_alive) in start_failures() {
        let relayed = Arc::new(Mutex::new(Vec::new()));
        let (release_stderr, stderr) = held_back_stderr(relayed.clone());
        let (mut ready_rx, reader, shutdown, failure) = sitrep_reader_over(&lines, false).await;
        let (stdout_done_tx, stdout_done) = oneshot::channel::<()>();
        let stdout = tokio::spawn(async move {
            reader.await.unwrap();
            let _ = stdout_done_tx.send(());
        });
        let mut tree = drained_tree(Containment::ProcessGroup);
        tree.root_never_exits = root_alive;
        let sup = supervise_plugin("p", &mut tree, &shutdown, GRACE, stdout, stderr, Some(failure));
        let mut sup = pin!(sup);

        // The reader has decided, and the stderr line is still unrelayed.
        tokio::select! {
            biased;
            _ = stdout_done => {}
            _ = &mut sup => panic!("{case}: the plugin ended with its stderr held back"),
        }
        assert!(
            poll_once(pin!(&mut ready_rx)).is_pending(),
            "{case}: the start failed before the plugin's stderr was relayed"
        );

        release_stderr.send(()).unwrap();
        tokio::time::timeout(VIRTUAL_HANG, sup)
            .await
            .unwrap_or_else(|_| panic!("{case}: the plugin never ended"))
            .unwrap();
        let ready = ready_rx.await;
        assert!(matches!(ready, Ok(Err(_))), "{case}: {ready:?}");
        assert_eq!(*relayed.lock().unwrap(), [STDERR_LINE], "{case}");
    }
}

/// A plugin whose start failed is not asked to exit: it gets its grace to exit on its own, and a root
/// that does is reported with its own status, so a `fatal` followed by a nonzero exit still reaches
/// the lifecycle channel.
#[skuld::test]
async fn a_root_that_exits_on_its_own_after_a_start_failure_is_reported_as_exited_and_never_signalled() {
    tokio::time::pause();
    for (containment, edge_awaited) in CONTAINMENTS {
        let (_ready_rx, reader, shutdown, failure) = sitrep_reader_over(&hello(SITREP_PROTOCOL), false).await;
        reader.await.unwrap();
        let mut tree = drained_tree(containment);
        tree.root_never_exits = true;
        let end = tokio::time::timeout(
            VIRTUAL_HANG,
            supervise_plugin(
                "p",
                &mut tree,
                &shutdown,
                GRACE,
                finished_reader(),
                finished_reader(),
                Some(failure),
            ),
        )
        .await
        .expect("the plugin must end")
        .unwrap();

        assert!(
            matches!(&end.end, PluginEnd::Exited(s) if s.success()),
            "{containment:?}"
        );
        let mut expected = vec!["wait_root_exit", "wait_root_exit_within", "wait_root_exit_within"];
        expected.extend(killed_then_reaped(edge_awaited));
        assert_eq!(tree.calls(), expected, "{containment:?}: no terminate, no root kill");
        assert_eq!(
            *tree.graces.lock().unwrap(),
            [Duration::ZERO, GRACE],
            "{containment:?}: a probe, then the grace"
        );
    }
}

/// A root that outlives its grace after a start failure is killed, and ends as a shutdown does.
#[skuld::test]
async fn a_root_that_outlives_its_grace_after_a_start_failure_is_killed_without_being_asked() {
    tokio::time::pause();
    let (_ready_rx, reader, shutdown, failure) = sitrep_reader_over(&hello(SITREP_PROTOCOL), false).await;
    reader.await.unwrap();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_never_exits = true;
    tree.root_outlives_grace = true;
    let end = tokio::time::timeout(
        VIRTUAL_HANG,
        supervise_plugin(
            "p",
            &mut tree,
            &shutdown,
            GRACE,
            finished_reader(),
            finished_reader(),
            Some(failure),
        ),
    )
    .await
    .expect("the plugin must end")
    .unwrap();

    assert!(matches!(end.end, PluginEnd::ShutDown) && end.start_failed);
    assert_eq!(
        tree.calls(),
        [
            "wait_root_exit",
            "wait_root_exit_within",
            "wait_root_exit_within",
            "kill_root",
            "kill_tree",
            "reap",
            "disarm"
        ]
    );
}

/// A chain shutdown outranks a failed start: the plugin is asked to exit, as for any shutdown.
#[skuld::test]
async fn a_shutdown_outranks_a_start_failure() {
    tokio::time::pause();
    let (_ready_rx, reader, shutdown, failure) = sitrep_reader_over(&hello(SITREP_PROTOCOL), false).await;
    reader.await.unwrap();
    shutdown.cancel();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_never_exits = true;
    tokio::time::timeout(
        VIRTUAL_HANG,
        supervise_plugin(
            "p",
            &mut tree,
            &shutdown,
            GRACE,
            finished_reader(),
            finished_reader(),
            Some(failure),
        ),
    )
    .await
    .expect("the plugin must end")
    .unwrap();

    assert!(tree.calls().contains(&"terminate"), "{:?}", tree.calls());
}

/// A reader still holding its pipe at the bound is given up on, so it holds no failure: the readiness
/// sender drops unsent, after that bound, and the caller's "exited before ready" follows the drain.
#[skuld::test]
async fn a_stdout_reader_given_up_on_at_the_bound_leaves_the_readiness_sender_to_drop() {
    tokio::time::pause();
    let (subscriber, writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);
    let freed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    // The plugin's end of stdout stays open: a process outside the tree holds it.
    let (_held_open, host_stdout) = tokio::io::duplex(4096);
    let (ready_tx, mut ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();
    let (reader, failure) = spawn_sitrep_stdout_reader(
        host_stdout,
        "held-plugin".into(),
        freed,
        shutdown.clone(),
        ready_tx,
        false,
        None,
    );
    let mut tree = drained_tree(Containment::ProcessGroup);
    let end = supervise_plugin(
        "held-plugin",
        &mut tree,
        &shutdown,
        GRACE,
        reader,
        finished_reader(),
        Some(failure),
    );
    let mut end = pin!(end);

    assert!(poll_once(end.as_mut()).is_pending());
    assert!(poll_once(pin!(&mut ready_rx)).is_pending(), "the start failed early");
    tokio::time::advance(EOF_BOUND + TIMER_SLACK).await;
    assert!(poll_once(end.as_mut()).is_ready(), "still waiting at the bound");

    assert!(ready_rx.await.is_err(), "no failure was held, so none is delivered");
    assert!(writer.snapshot().contains("held-plugin"), "{}", writer.snapshot());
}

/// An unwatchable root whose reap fails ends without a tree kill, but its output wait is still bounded
/// and surfaced, so a failure delivered after it is behind what the plugin wrote.
#[skuld::test]
async fn an_unwatchable_root_whose_reap_fails_still_waits_for_its_output_at_the_bound() {
    tokio::time::pause();
    let (subscriber, writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);
    let (out_dropped, stdout) = held_reader();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_watch_fails = true;
    tree.reap_fails = true;
    let shutdown = CancellationToken::new();
    let end = supervise_plugin("p", &mut tree, &shutdown, GRACE, stdout, finished_reader(), None);
    let mut end = pin!(end);

    assert!(poll_once(end.as_mut()).is_pending(), "ended before the output did");
    tokio::time::advance(EOF_BOUND + TIMER_SLACK).await;
    assert!(matches!(poll_once(end.as_mut()), Poll::Ready(Err(_))));
    tokio::time::timeout(VIRTUAL_HANG, out_dropped).await.unwrap().ok();
    assert!(
        writer.snapshot().contains("the plugin's output pipes were still open"),
        "{}",
        writer.snapshot()
    );
}

// A decided failure is never dropped ----------------------------------------------------------------------------------

/// A supervision that is dropped before it delivers (its task aborted, or unwinding) still reports what its reader
/// decided.
#[skuld::test]
async fn a_hold_that_is_dropped_delivers_the_failure_it_holds() {
    tokio::time::pause();
    let (ready_rx, shutdown, failure) = decided_start_failure().await;
    drop(shutdown);
    drop(failure);

    assert!(matches!(ready_rx.await, Ok(Err(StartError::Fatal { .. }))));
}

/// A reader that decides after the hold has ended finds nobody to hold the failure, and sends it itself. The hold has
/// ended when it is delivered, dropped, or closed while still alive.
#[skuld::test]
async fn a_failure_decided_after_the_hold_ended_is_sent_by_the_reader() {
    tokio::time::pause();
    for ended_by in ["delivered", "dropped", "closed, still alive"] {
        let freed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let (mut plugin_stdout, host_stdout) = tokio::io::duplex(4096);
        plugin_stdout
            .write_all(hello(SITREP_PROTOCOL).as_bytes())
            .await
            .unwrap();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (reader, mut failure) = spawn_sitrep_stdout_reader(
            host_stdout,
            "p".into(),
            freed,
            CancellationToken::new(),
            ready_tx,
            false,
            None,
        );
        let mut ready_rx = pin!(ready_rx);

        // Nothing was decided yet, so the hold has nothing to deliver.
        let _alive = match ended_by {
            "delivered" => {
                assert!(!failure.deliver(), "{ended_by}");
                None
            }
            "dropped" => {
                drop(failure);
                None
            }
            _ => {
                assert!(!failure.finish(), "{ended_by}");
                Some(failure)
            }
        };
        assert!(poll_once(ready_rx.as_mut()).is_pending(), "{ended_by}");

        // Stdout closes: the reader decides the stream closed before `ready`.
        drop(plugin_stdout);
        reader.await.unwrap();
        let ready = tokio::time::timeout(VIRTUAL_HANG, ready_rx)
            .await
            .unwrap_or_else(|_| panic!("{ended_by}: the failure was held for a hold that had ended"));
        assert!(
            matches!(&ready, Ok(Err(StartError::Fatal { detail, .. })) if detail.contains("closed its sitrep stream")),
            "{ended_by}: {ready:?}"
        );
    }
}

// Teardown order ------------------------------------------------------------------------------------------------------
//
// A pgid-based containment signals the root's process group id, which the OS may recycle the moment
// the root is reaped. The tree is therefore killed while the root is still unreaped.

fn killed_then_reaped(edge_awaited: bool) -> Vec<&'static str> {
    let mut calls = vec!["kill_tree"];
    calls.extend(edge_awaited.then_some("wait_tree_drained"));
    calls.extend(["reap", "disarm"]);
    calls
}

#[skuld::test]
async fn an_exited_root_is_reaped_only_after_its_tree_is_killed() {
    tokio::time::pause();
    for (containment, edge_awaited) in CONTAINMENTS {
        let mut tree = drained_tree(containment);
        let status = end_plugin("p", &mut tree, finished_reader(), finished_reader()).await;

        assert!(
            status.unwrap().success(),
            "{containment:?}: the reaped status is returned"
        );
        assert_eq!(tree.calls(), killed_then_reaped(edge_awaited), "{containment:?}");
    }
}

#[skuld::test]
async fn a_root_that_exits_within_its_grace_is_reaped_after_the_tree_kill() {
    tokio::time::pause();
    for (containment, edge_awaited) in CONTAINMENTS {
        let mut tree = drained_tree(containment);
        let grace = Duration::from_secs(5);
        shut_plugin_down("p", &mut tree, grace, finished_reader(), finished_reader())
            .await
            .unwrap();

        let mut expected = vec!["terminate", "wait_root_exit_within"];
        expected.extend(killed_then_reaped(edge_awaited));
        assert_eq!(tree.calls(), expected, "{containment:?}");
    }
}

#[skuld::test]
async fn a_root_that_outlives_its_shutdown_grace_is_killed_before_the_tree_sweep_and_the_reap() {
    tokio::time::pause();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_outlives_grace = true;
    shut_plugin_down(
        "p",
        &mut tree,
        Duration::from_secs(5),
        finished_reader(),
        finished_reader(),
    )
    .await
    .unwrap();

    assert_eq!(
        tree.calls(),
        [
            "terminate",
            "wait_root_exit_within",
            "kill_root",
            "kill_tree",
            "reap",
            "disarm"
        ]
    );
}

#[skuld::test]
async fn a_shutdown_whose_grace_watch_fails_escalates_to_a_kill() {
    tokio::time::pause();
    let (subscriber, writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_watch_fails = true;
    shut_plugin_down(
        "watched",
        &mut tree,
        Duration::from_secs(5),
        finished_reader(),
        finished_reader(),
    )
    .await
    .unwrap();

    assert_eq!(
        tree.calls(),
        [
            "terminate",
            "wait_root_exit_within",
            "kill_root",
            "kill_tree",
            "reap",
            "disarm"
        ]
    );
    assert!(writer.snapshot().contains("watched"), "{}", writer.snapshot());
}

#[skuld::test]
async fn a_shutdown_whose_terminate_fails_escalates_to_a_kill() {
    tokio::time::pause();
    for (containment, edge_awaited) in CONTAINMENTS {
        let mut tree = drained_tree(containment);
        tree.terminate_fails = true;
        shut_plugin_down(
            "p",
            &mut tree,
            Duration::from_secs(5),
            finished_reader(),
            finished_reader(),
        )
        .await
        .unwrap();

        let mut expected = vec!["terminate", "kill_root"];
        expected.extend(killed_then_reaped(edge_awaited));
        assert_eq!(tree.calls(), expected, "{containment:?}");
    }
}

// Supervising a plugin: the wiring `BinaryPlugin::run` calls ----------------------------------------------------------

const GRACE: Duration = Duration::from_secs(5);

async fn supervise(tree: &mut impl PluginTree, shutdown: &CancellationToken) -> Supervised {
    tokio::time::timeout(
        VIRTUAL_HANG,
        supervise_plugin("p", tree, shutdown, GRACE, finished_reader(), finished_reader(), None),
    )
    .await
    .expect("the plugin must end")
    .unwrap()
}

fn cancelled() -> CancellationToken {
    let token = CancellationToken::new();
    token.cancel();
    token
}

/// A root that exits on its own is watched without being reaped, its tree is killed, and only then is
/// it reaped.
#[skuld::test]
async fn a_root_that_exits_on_its_own_has_its_tree_killed_before_it_is_reaped() {
    tokio::time::pause();
    for (containment, edge_awaited) in CONTAINMENTS {
        let mut tree = drained_tree(containment);
        let end = supervise(&mut tree, &CancellationToken::new()).await;

        assert!(
            matches!(&end.end, PluginEnd::Exited(s) if s.success()),
            "{containment:?}"
        );
        let mut expected = vec!["wait_root_exit"];
        expected.extend(killed_then_reaped(edge_awaited));
        assert_eq!(tree.calls(), expected, "{containment:?}");
    }
}

/// On shutdown the root is asked to exit, given its grace, and its tree is killed before the reap.
#[skuld::test]
async fn a_shutdown_request_kills_the_tree_before_the_reap() {
    tokio::time::pause();
    for (containment, edge_awaited) in CONTAINMENTS {
        let mut tree = drained_tree(containment);
        tree.root_never_exits = true;
        let end = supervise(&mut tree, &cancelled()).await;

        assert!(matches!(end.end, PluginEnd::ShutDown), "{containment:?}");
        let mut expected = vec![
            "wait_root_exit",
            "wait_root_exit_within",
            "terminate",
            "wait_root_exit_within",
        ];
        expected.extend(killed_then_reaped(edge_awaited));
        assert_eq!(tree.calls(), expected, "{containment:?}");
    }
}

/// A root that outlives its grace is killed first; its tree is still killed before the reap.
#[skuld::test]
async fn a_shutdown_request_kills_a_root_that_outlives_its_grace_before_the_tree_and_the_reap() {
    tokio::time::pause();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_never_exits = true;
    tree.root_outlives_grace = true;
    let end = supervise(&mut tree, &cancelled()).await;

    assert!(matches!(end.end, PluginEnd::ShutDown));
    assert_eq!(
        tree.calls(),
        [
            "wait_root_exit",
            "wait_root_exit_within",
            "terminate",
            "wait_root_exit_within",
            "kill_root",
            "kill_tree",
            "reap",
            "disarm"
        ]
    );
}

/// An exit that has already happened is a fact a shutdown request does not erase: the plugin is
/// ended as exited (so its status is reported), not as shut down.
#[skuld::test]
async fn an_exit_that_already_happened_outranks_a_shutdown_request() {
    tokio::time::pause();
    for (containment, edge_awaited) in CONTAINMENTS {
        let mut tree = drained_tree(containment);
        let end = supervise(&mut tree, &cancelled()).await;

        assert!(
            matches!(&end.end, PluginEnd::Exited(s) if s.success()),
            "{containment:?}"
        );
        let mut expected = vec!["wait_root_exit"];
        expected.extend(killed_then_reaped(edge_awaited));
        assert_eq!(tree.calls(), expected, "{containment:?}");
    }
}

/// The real exit watch is `Pending` on its first poll even for a root that is already a zombie, so a
/// shutdown request that is already pending reaches its arm first. The root is then checked once with
/// a zero-grace probe, and an exit it shows is still reported as an exit.
#[skuld::test]
async fn an_exit_the_watch_has_not_yet_delivered_outranks_a_pending_shutdown_request() {
    tokio::time::pause();
    for (containment, edge_awaited) in CONTAINMENTS {
        let mut tree = drained_tree(containment);
        tree.exit_watch_pends_first_poll = true;
        let end = supervise(&mut tree, &cancelled()).await;

        assert!(
            matches!(&end.end, PluginEnd::Exited(s) if s.success()),
            "{containment:?}"
        );
        let mut expected = vec!["wait_root_exit", "wait_root_exit_within"];
        expected.extend(killed_then_reaped(edge_awaited));
        assert_eq!(tree.calls(), expected, "{containment:?}");
        assert_eq!(
            *tree.graces.lock().unwrap(),
            [Duration::ZERO],
            "{containment:?}: a probe, not a wait"
        );
    }
}

/// The probe does not turn a shutdown into an exit: a root that is still running is shut down.
#[skuld::test]
async fn a_running_root_is_shut_down_when_its_pending_exit_watch_loses_to_the_request() {
    tokio::time::pause();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_never_exits = true;
    tree.exit_watch_pends_first_poll = true;
    let end = supervise(&mut tree, &cancelled()).await;

    assert!(matches!(end.end, PluginEnd::ShutDown));
    assert_eq!(*tree.graces.lock().unwrap(), [Duration::ZERO, GRACE]);
}

/// A probe that cannot say (the watch is unavailable) leaves the request standing.
#[skuld::test]
async fn a_shutdown_request_stands_when_the_probe_cannot_read_the_root() {
    tokio::time::pause();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_never_exits = true;
    tree.exit_watch_pends_first_poll = true;
    tree.probe_fails = true;
    let end = supervise(&mut tree, &cancelled()).await;

    assert!(matches!(end.end, PluginEnd::ShutDown));
}

/// The same holds when the exit could not be watched and the root is reaped instead.
#[skuld::test]
async fn a_reaped_exit_outranks_a_shutdown_request_when_the_exit_cannot_be_watched() {
    tokio::time::pause();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_watch_fails = true;
    let end = supervise(&mut tree, &cancelled()).await;

    assert!(matches!(&end.end, PluginEnd::Exited(s) if s.success()));
    assert_eq!(tree.calls(), ["wait_root_exit", "reap", "disarm"]);
}

// The reaped root's handle is disarmed --------------------------------------------------------------------------------
//
// Dropping a cosca child signals its process group id before it checks whether the root was reaped,
// so a handle that outlives the reap would `killpg` an id the OS may have recycled. The disarm is the
// last call on every path that reaped, and is absent from every path that did not.

#[skuld::test]
async fn a_root_whose_reap_fails_is_not_disarmed() {
    tokio::time::pause();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.reap_fails = true;
    let ended = end_plugin("p", &mut tree, finished_reader(), finished_reader()).await;

    assert!(ended.is_err());
    assert_eq!(tree.calls(), ["kill_tree", "reap"]);
}

#[skuld::test]
async fn an_unwatchable_root_whose_reap_fails_is_not_disarmed() {
    tokio::time::pause();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_watch_fails = true;
    tree.reap_fails = true;
    let ended = tokio::time::timeout(
        VIRTUAL_HANG,
        supervise_plugin(
            "p",
            &mut tree,
            &CancellationToken::new(),
            GRACE,
            finished_reader(),
            finished_reader(),
            None,
        ),
    )
    .await
    .expect("the plugin must end");

    assert!(ended.is_err());
    assert_eq!(tree.calls(), ["wait_root_exit", "reap"]);
}

/// A shutdown that interrupts the reap of an unwatchable root has not reaped anything yet.
#[skuld::test]
async fn a_shutdown_that_interrupts_the_reap_disarms_only_after_its_own_reap() {
    tokio::time::pause();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_watch_fails = true;
    tree.reap_waits_for_kill = true;
    let calls = tree.calls.clone();
    let shutdown = CancellationToken::new();
    let end = supervise_plugin(
        "p",
        &mut tree,
        &shutdown,
        GRACE,
        finished_reader(),
        finished_reader(),
        None,
    );
    let mut end = pin!(end);
    assert!(poll_once(end.as_mut()).is_pending());
    assert!(
        !calls.lock().unwrap().contains(&"disarm"),
        "nothing is disarmed while the root is unreaped"
    );
    shutdown.cancel();
    tokio::time::timeout(VIRTUAL_HANG, end).await.unwrap().unwrap();

    let calls = calls.lock().unwrap();
    assert_eq!(calls.iter().filter(|c| **c == "disarm").count(), 1);
    assert_eq!(calls.last(), Some(&"disarm"));
}

// A refused root kill -------------------------------------------------------------------------------------------------

/// A root that cannot be killed (an elevated wrapper) is no reason to leave its tree running: the
/// tree is still killed, drained and reaped, and the refusal is what the caller sees.
#[skuld::test]
async fn a_refused_root_kill_still_kills_the_tree_and_reaps_and_is_reported() {
    tokio::time::pause();
    for (containment, edge_awaited) in CONTAINMENTS {
        let mut tree = drained_tree(containment);
        tree.root_outlives_grace = true;
        tree.kill_root_fails = true;
        let ended = shut_plugin_down("p", &mut tree, GRACE, finished_reader(), finished_reader()).await;

        assert!(
            matches!(&ended, Err(cosca::error::Error::Containment { detail }) if detail.contains("root kill")),
            "{containment:?}: the refusal is reported"
        );
        // The tree kill took the refused root down with it: the probe sees that, and the root is reaped.
        let mut expected = vec!["terminate", "wait_root_exit_within", "kill_root", "kill_tree"];
        expected.extend(edge_awaited.then_some("wait_tree_drained"));
        expected.extend(["wait_root_exit_within", "reap", "disarm"]);
        assert_eq!(tree.calls(), expected, "{containment:?}");
        assert_eq!(
            *tree.graces.lock().unwrap(),
            [GRACE, Duration::ZERO],
            "{containment:?}: a probe, not a wait"
        );
    }
}

/// When the root kill is refused and the reap fails too, the first error is the one reported.
#[skuld::test]
async fn a_refused_root_kill_is_reported_ahead_of_a_failed_reap() {
    tokio::time::pause();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_outlives_grace = true;
    tree.kill_root_fails = true;
    tree.reap_fails = true;
    let ended = shut_plugin_down("p", &mut tree, GRACE, finished_reader(), finished_reader()).await;

    assert!(matches!(&ended, Err(cosca::error::Error::Containment { detail }) if detail.contains("root kill")));
    assert_eq!(
        tree.calls(),
        [
            "terminate",
            "wait_root_exit_within",
            "kill_root",
            "kill_tree",
            "wait_root_exit_within",
            "reap"
        ]
    );
}

/// A refused root kill that leaves the root alive after the tree kill too (an elevated or setuid
/// wrapper) must not park `run` on a reap nothing can finish: the refusal is returned, the handle
/// stays armed (nothing was reaped), and the refusal is logged at once.
#[skuld::test]
async fn a_refused_root_kill_that_leaves_the_root_alive_is_returned_without_reaping_it() {
    tokio::time::pause();
    let (subscriber, writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);
    for (containment, edge_awaited) in CONTAINMENTS {
        let mut tree = drained_tree(containment);
        tree.root_outlives_grace = true;
        tree.kill_root_fails = true;
        tree.root_survives_tree_kill = true;
        tree.reap_never_completes = true;
        let ended = tokio::time::timeout(
            VIRTUAL_HANG,
            shut_plugin_down("wrapper", &mut tree, GRACE, finished_reader(), finished_reader()),
        )
        .await
        .unwrap_or_else(|_| panic!("{containment:?}: the shutdown waits on a root nothing can end"));

        assert!(
            matches!(&ended, Err(cosca::error::Error::Containment { detail }) if detail.contains("root kill")),
            "{containment:?}: the refusal is returned"
        );
        let mut expected = vec!["terminate", "wait_root_exit_within", "kill_root", "kill_tree"];
        expected.extend(edge_awaited.then_some("wait_tree_drained"));
        expected.push("wait_root_exit_within");
        assert_eq!(tree.calls(), expected, "{containment:?}: no reap, no disarm");
    }

    let log = writer.snapshot();
    let refusals: Vec<_> = log
        .lines()
        .filter(|l| l.contains("failed to kill the plugin's root"))
        .collect();
    assert_eq!(
        refusals.len(),
        CONTAINMENTS.len(),
        "one warning per refusal:
{log}"
    );
    assert!(
        refusals
            .iter()
            .all(|l| l.contains("WARN") && l.contains("wrapper") && l.contains("root kill was refused")),
        "{refusals:?}"
    );
}

// The exit watch is unavailable ---------------------------------------------------------------------------------------
//
// cosca's non-reaping watch needs `pidfd_open` on Linux (absent before 5.3, or denied by a seccomp
// profile). Without it the root is reaped first, which frees its pid, so a tree kill that signals a
// process group id could hit an unrelated group that was handed the recycled id.

/// Every containment, each paired with whether `kill_tree` finds the tree through an id the root's
/// reap releases (cosca: `ProcessGroup` and `Session` are `killpg`; a macOS `FdMarker` also fires
/// `killpg` on its pgid; `TreeWalk` enumerates descendants from the root's pid).
const KILLS_BY_PGID: [(Containment, bool); 8] = [
    (Containment::CgroupV2, false),
    (Containment::JobObject, false),
    (Containment::ProcessGroup, true),
    (Containment::Session, true),
    (Containment::FdMarker, true),
    (Containment::TreeWalk, true),
    (Containment::Delegated, false),
    (Containment::None, false),
];

fn count_matching(log: &str, needle: &str) -> usize {
    log.lines().filter(|l| l.contains(needle)).count()
}

/// The root is reaped first. A tree whose kill names a process group id is then left alone, and only
/// the bounded wait for the output follows; any other tree is still killed.
#[skuld::test]
async fn a_root_whose_exit_cannot_be_watched_is_reaped_first_and_a_pgid_tree_is_left_alone() {
    tokio::time::pause();
    for (containment, kills_by_pgid) in KILLS_BY_PGID {
        let (subscriber, writer) = subscriber();
        let _g = set_default_in_current_thread(subscriber);
        let (out_dropped, stdout) = held_reader();
        let mut tree = drained_tree(containment);
        tree.root_watch_fails = true;
        let calls = tree.calls.clone();
        let shutdown = CancellationToken::new();
        let end = supervise_plugin(
            "unwatched",
            &mut tree,
            &shutdown,
            GRACE,
            stdout,
            finished_reader(),
            None,
        );
        let mut end = pin!(end);

        // The held stdout ends the wait for the output at its bound, on every containment.
        assert!(poll_once(end.as_mut()).is_pending(), "{containment:?}");
        tokio::time::advance(EOF_BOUND + TIMER_SLACK).await;
        let end = match poll_once(end.as_mut()) {
            Poll::Ready(end) => end.unwrap(),
            Poll::Pending => panic!("{containment:?}: still waiting at the bound"),
        };
        tokio::time::timeout(VIRTUAL_HANG, out_dropped).await.unwrap().ok();

        assert!(
            matches!(&end.end, PluginEnd::Exited(s) if s.success()),
            "{containment:?}"
        );
        let edge_awaited = CONTAINMENTS.iter().any(|(c, edge)| *c == containment && *edge);
        let expected: &[&str] = match (kills_by_pgid, edge_awaited) {
            (true, _) => &["wait_root_exit", "reap", "disarm"],
            (false, true) => &["wait_root_exit", "reap", "disarm", "kill_tree", "wait_tree_drained"],
            (false, false) => &["wait_root_exit", "reap", "disarm", "kill_tree"],
        };
        assert_eq!(*calls.lock().unwrap(), expected, "{containment:?}");

        let log = writer.snapshot();
        let fallback: Vec<_> = log.lines().filter(|l| l.contains("cannot be watched")).collect();
        assert_eq!(
            fallback.len(),
            1,
            "{containment:?}: the fallback is logged once:\n{log}"
        );
        assert!(
            fallback[0].contains("DEBUG") && fallback[0].contains("unwatched"),
            "{containment:?}: the fallback is a debug line naming the plugin: {}",
            fallback[0]
        );
        assert_eq!(
            count_matching(&log, "the plugin's output pipes were still open"),
            1,
            "{containment:?}: the bounded wait warns:\n{log}"
        );
    }
}

/// A root that cannot be asked to exit has no grace to spend: it is killed at once.
#[skuld::test]
async fn an_unwatchable_root_that_cannot_be_asked_to_exit_is_killed_at_once() {
    tokio::time::pause();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_watch_fails = true;
    tree.terminate_fails = true;
    tree.reap_waits_for_kill = true;
    let calls = tree.calls.clone();
    let shutdown = CancellationToken::new();
    let end = supervise_plugin(
        "p",
        &mut tree,
        &shutdown,
        GRACE,
        finished_reader(),
        finished_reader(),
        None,
    );
    let mut end = pin!(end);

    assert!(poll_once(end.as_mut()).is_pending());
    shutdown.cancel();
    let end = tokio::time::timeout(VIRTUAL_HANG, end)
        .await
        .expect("must end")
        .unwrap();

    assert!(matches!(end.end, PluginEnd::ShutDown));
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "wait_root_exit",
            "terminate",
            "kill_root",
            "kill_tree",
            "reap",
            "disarm"
        ]
    );
}

// A take-down while the exit cannot be watched ------------------------------------------------------------------------
//
// With no watch, reaping is the only way to see the root exit, and the reap frees its pid. A take-down therefore has no
// grace to give: it kills the root, then the tree, then reaps, on every containment.

/// A reader that has decided the start failed, so the plugin is to be taken down.
async fn decided_start_failure() -> (
    oneshot::Receiver<Result<PluginReady, StartError>>,
    CancellationToken,
    FailureHold,
) {
    let (ready_rx, reader, shutdown, failure) = sitrep_reader_over(&hello(SITREP_PROTOCOL), false).await;
    reader.await.unwrap();
    (ready_rx, shutdown, failure)
}

#[skuld::test]
async fn a_take_down_of_an_unwatchable_root_kills_it_at_once_then_its_tree_then_reaps() {
    tokio::time::pause();
    for taken_down_by in [TakenDownBy::Shutdown, TakenDownBy::StartFailure] {
        for (containment, _) in KILLS_BY_PGID {
            let (shutdown, failure) = match taken_down_by {
                TakenDownBy::Shutdown => (cancelled(), None),
                TakenDownBy::StartFailure => {
                    let (_ready_rx, shutdown, failure) = decided_start_failure().await;
                    (shutdown, Some(failure))
                }
            };
            let mut tree = drained_tree(containment);
            tree.root_watch_fails = true;
            tree.reap_waits_for_kill = true;
            let sup = supervise_plugin(
                "p",
                &mut tree,
                &shutdown,
                GRACE,
                finished_reader(),
                finished_reader(),
                failure,
            );
            let ended = tokio::time::timeout(VIRTUAL_HANG, sup)
                .await
                .expect("the plugin must end")
                .unwrap();

            assert!(
                matches!(ended.end, PluginEnd::ShutDown),
                "{taken_down_by:?}, {containment:?}"
            );
            let calls = tree.calls();
            let position = |call: &str| calls.iter().position(|c| *c == call);
            assert!(
                position("kill_root") < position("kill_tree") && position("kill_tree") < position("reap"),
                "{taken_down_by:?}, {containment:?}: {calls:?}"
            );
        }
    }
}

// What `BinaryPlugin::run` returns ------------------------------------------------------------------------------------

fn exit_status(code: i32) -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        std::os::unix::process::ExitStatusExt::from_raw(code << 8)
    }
    #[cfg(windows)]
    {
        std::os::windows::process::ExitStatusExt::from_raw(code as u32)
    }
}

fn supervised(end: PluginEnd, start_failed: bool) -> Supervised {
    Supervised { end, start_failed }
}

#[skuld::test]
fn a_plugin_ended_by_a_shutdown_or_exiting_cleanly_is_ok() {
    assert!(supervised(PluginEnd::ShutDown, false).outcome("p").is_ok());
    assert!(supervised(PluginEnd::Exited(exit_status(0)), false)
        .outcome("p")
        .is_ok());
}

#[skuld::test]
fn a_plugin_that_exits_with_a_code_is_an_error_naming_it() {
    assert!(matches!(
        supervised(PluginEnd::Exited(exit_status(3)), false).outcome("p"),
        Err(crate::Error::PluginExit { name, code: 3 }) if name == "p"
    ));
}

#[cfg(unix)]
#[skuld::test]
fn a_plugin_that_dies_to_a_signal_is_an_error_naming_it() {
    let status = std::os::unix::process::ExitStatusExt::from_raw(9);
    assert!(matches!(
        supervised(PluginEnd::Exited(status), false).outcome("p"),
        Err(crate::Error::PluginKilled { name }) if name == "p"
    ));
}

/// A plugin whose start failed did not run to a clean end, however it ended: `run` must not return `Ok`, and the
/// error names the plugin and says the start failed.
#[skuld::test]
fn a_plugin_whose_start_failed_is_an_error_naming_it_unless_its_exit_status_already_is() {
    for end in [PluginEnd::ShutDown, PluginEnd::Exited(exit_status(0))] {
        let err = supervised(end, true)
            .outcome("p")
            .expect_err("a failed start is not a clean end");
        assert!(
            matches!(&err, crate::Error::Chain(msg) if msg.contains("'p'") && msg.contains("failed to start")),
            "{err:?}"
        );
    }
    assert!(matches!(
        supervised(PluginEnd::Exited(exit_status(3)), true).outcome("p"),
        Err(crate::Error::PluginExit { code: 3, .. })
    ));
}

// A failed start never ends `Ok` --------------------------------------------------------------------------------------
//
// Whichever way a plugin whose start failed ends, `run` returns an error. Its exit code, or the signal that killed it,
// still names the error when it has one.

/// The result of `run`, as a tag: what kind of error, or `ok`.
fn run_result(result: crate::Result<()>) -> String {
    match result {
        Ok(()) => "ok".into(),
        Err(crate::Error::PluginExit { code, .. }) => format!("exit {code}"),
        Err(crate::Error::PluginKilled { .. }) => "killed".into(),
        Err(crate::Error::Chain(_)) => "chain error".into(),
        Err(other) => format!("{other:?}"),
    }
}

/// How the plugin's end comes about.
#[derive(Clone, Copy, Debug)]
enum EndsBy {
    /// The root exits on its own, and its exit is watched.
    ExitingItself,
    /// The root exits on its own, and its exit cannot be watched.
    ExitingItselfUnwatched,
    /// The chain shuts down while the root runs; it exits within its grace.
    Shutdown,
    /// The reader decided the start failed; the root exits within its grace.
    StartFailureThenExit,
    /// The reader decided the start failed; the root outlives its grace and is killed.
    StartFailureThenKill,
}

#[skuld::test]
async fn a_plugin_whose_start_failed_never_ends_ok() {
    tokio::time::pause();
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut statuses = vec![
        ("exit 0", exit_status(0), None),
        ("exit 3", exit_status(3), Some("exit 3")),
    ];
    #[cfg(unix)]
    statuses.push((
        "signal",
        std::os::unix::process::ExitStatusExt::from_raw(9),
        Some("killed"),
    ));

    let mut failures = Vec::new();
    for ends_by in [
        EndsBy::ExitingItself,
        EndsBy::ExitingItselfUnwatched,
        EndsBy::Shutdown,
        EndsBy::StartFailureThenExit,
        EndsBy::StartFailureThenKill,
    ] {
        for start_failed in [false, true] {
            if !start_failed && matches!(ends_by, EndsBy::StartFailureThenExit | EndsBy::StartFailureThenKill) {
                continue;
            }
            for (status_name, status, status_error) in &statuses {
                let (shutdown, failure) = if start_failed {
                    let (_ready_rx, shutdown, failure) = decided_start_failure().await;
                    (shutdown, Some(failure))
                } else {
                    (CancellationToken::new(), None)
                };
                let mut tree = drained_tree(Containment::ProcessGroup);
                tree.exit_status = *status;
                match ends_by {
                    EndsBy::ExitingItself => {}
                    EndsBy::ExitingItselfUnwatched => tree.root_watch_fails = true,
                    EndsBy::Shutdown => {
                        tree.root_never_exits = true;
                        shutdown.cancel();
                    }
                    EndsBy::StartFailureThenExit => tree.root_never_exits = true,
                    EndsBy::StartFailureThenKill => {
                        tree.root_never_exits = true;
                        tree.root_outlives_grace = true;
                    }
                }
                let result = tokio::time::timeout(
                    VIRTUAL_HANG,
                    supervise_plugin(
                        "p",
                        &mut tree,
                        &shutdown,
                        GRACE,
                        finished_reader(),
                        finished_reader(),
                        failure,
                    ),
                )
                .await
                .expect("the plugin must end")
                .unwrap()
                .outcome("p");

                // Only an exit has a status to report; a plugin taken down ends on the take-down.
                let exited = matches!(
                    ends_by,
                    EndsBy::ExitingItself | EndsBy::ExitingItselfUnwatched | EndsBy::StartFailureThenExit
                );
                let expected = match status_error {
                    Some(tag) if exited => (*tag).to_owned(),
                    _ if start_failed => "chain error".to_owned(),
                    _ => "ok".to_owned(),
                };
                let got = run_result(result);
                if got != expected {
                    failures.push(format!(
                        "{ends_by:?}, start_failed={start_failed}, {status_name}: want {expected}, got {got}"
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} rows failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// A take-down leaves no descendant ------------------------------------------------------------------------------------
//
// Every take-down of a running plugin, on every containment, whether or not its exit can be watched, kills the plugin's
// tree. Where the kill signals a process group id it happens while the root is unreaped, because the OS may recycle the
// id the moment the root is reaped.

#[derive(Clone, Copy, Debug)]
enum TakenDownBy {
    Shutdown,
    StartFailure,
}

#[derive(Clone, Copy, Debug)]
enum RootExit {
    /// The root exits on its own while the take-down is under way.
    WithinGrace,
    /// The root keeps running until it is killed.
    OutlivesGrace,
}

#[skuld::test]
async fn every_take_down_kills_the_plugins_tree() {
    tokio::time::pause();
    let mut failures = Vec::new();
    for taken_down_by in [TakenDownBy::Shutdown, TakenDownBy::StartFailure] {
        for watched in [true, false] {
            for root_exit in [RootExit::WithinGrace, RootExit::OutlivesGrace] {
                for (containment, kills_by_pgid) in KILLS_BY_PGID {
                    let row = format!("{taken_down_by:?}, watched={watched}, {root_exit:?}, {containment:?}");
                    let (shutdown, failure) = match taken_down_by {
                        TakenDownBy::Shutdown => (CancellationToken::new(), None),
                        TakenDownBy::StartFailure => {
                            let (_ready_rx, shutdown, failure) = decided_start_failure().await;
                            (shutdown, Some(failure))
                        }
                    };
                    let exits = Arc::new(Notify::new());
                    let mut tree = drained_tree(containment);
                    tree.root_never_exits = true;
                    match (watched, root_exit) {
                        (true, RootExit::WithinGrace) => {}
                        (true, RootExit::OutlivesGrace) => tree.root_outlives_grace = true,
                        (false, RootExit::WithinGrace) => {
                            tree.root_watch_fails = true;
                            tree.reap_waits_for = Some(exits.clone());
                        }
                        (false, RootExit::OutlivesGrace) => {
                            tree.root_watch_fails = true;
                            tree.reap_waits_for_kill = true;
                        }
                    }
                    let calls = tree.calls.clone();
                    let sup = supervise_plugin(
                        "p",
                        &mut tree,
                        &shutdown,
                        GRACE,
                        finished_reader(),
                        finished_reader(),
                        failure,
                    );
                    let mut sup = pin!(sup);
                    let _ = poll_once(sup.as_mut());
                    if matches!(taken_down_by, TakenDownBy::Shutdown) {
                        shutdown.cancel();
                    }
                    let _ = poll_once(sup.as_mut());
                    exits.notify_one();
                    if tokio::time::timeout(VIRTUAL_HANG, sup).await.is_err() {
                        failures.push(format!("{row}: the plugin never ended"));
                        continue;
                    }

                    let calls = calls.lock().unwrap().clone();
                    let position = |call: &str| calls.iter().position(|c| *c == call);
                    let Some(tree_killed) = position("kill_tree") else {
                        failures.push(format!("{row}: the tree was never killed: {calls:?}"));
                        continue;
                    };
                    let reaped = position("reap").expect("the root is reaped");
                    if kills_by_pgid && tree_killed > reaped {
                        failures.push(format!(
                            "{row}: the process group was signalled after the reap: {calls:?}"
                        ));
                    }
                    if position("disarm") != Some(reaped + 1) {
                        failures.push(format!("{row}: the handle is disarmed right after the reap: {calls:?}"));
                    }
                    if watched {
                        let killed_root = position("kill_root");
                        match root_exit {
                            RootExit::WithinGrace if killed_root.is_some() => {
                                failures.push(format!("{row}: a root that exited by itself was killed: {calls:?}"))
                            }
                            RootExit::OutlivesGrace if !(killed_root < Some(tree_killed)) || killed_root.is_none() => {
                                failures.push(format!(
                                    "{row}: the root outlived its grace and was not killed first: {calls:?}"
                                ))
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} rows failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
