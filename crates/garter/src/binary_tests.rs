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

use crate::binary::{drain_readers_after_exit, end_plugin, shut_plugin_down, supervise_plugin, PluginEnd, PluginTree};
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
        if self.root_never_exits {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn wait_root_exit_within(&self, _grace: Duration) -> Result<bool, cosca::error::Error> {
        self.record("wait_root_exit_within");
        if self.root_watch_fails {
            return Err(unsupported());
        }
        Ok(!self.root_outlives_grace)
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
        Ok(())
    }

    fn kill_tree(&mut self) -> Result<(), cosca::error::Error> {
        self.record("kill_tree");
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
        if self.reap_waits_for_kill {
            self.root_killed.notified().await;
        }
        self.record("reap");
        Ok(std::process::ExitStatus::default())
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

use crate::binary::spawn_sitrep_stdout_reader;
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
/// `local` refuses connections, so a probe never readies it.
async fn sitrep_reader_over(
    stdout_lines: &str,
    auto: bool,
) -> (oneshot::Receiver<ReadyResult>, JoinHandle<()>, CancellationToken) {
    let freed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (mut plugin_stdout, host_stdout) = tokio::io::duplex(4096);
    plugin_stdout.write_all(stdout_lines.as_bytes()).await.unwrap();
    drop(plugin_stdout);
    let (ready_tx, ready_rx) = oneshot::channel();
    let shutdown = CancellationToken::new();
    let reader = spawn_sitrep_stdout_reader(
        host_stdout,
        "eof-plugin".into(),
        freed,
        shutdown.clone(),
        ready_tx,
        auto,
        None,
    );
    (ready_rx, reader, shutdown)
}

/// A sitrep plugin's readiness travels on stdout, so once stdout is closed without `ready` it never
/// readies: the start fails at once, however long its stderr stays open.
#[skuld::test]
async fn at_sitrep_stdout_eof_without_ready_the_start_fails_at_once() {
    tokio::time::pause();
    for (lines, auto) in [
        (String::new(), false),
        (hello(SITREP_PROTOCOL), false),
        // `Auto` stands its probe down on a supported hello.
        (hello(SITREP_PROTOCOL), true),
    ] {
        let (ready_rx, _reader, _shutdown) = sitrep_reader_over(&lines, auto).await;

        let ready = tokio::time::timeout(VIRTUAL_HANG, ready_rx)
            .await
            .unwrap_or_else(|_| panic!("auto={auto}, {lines:?}: the start waited on a stderr that stays open"));
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
        let (mut ready_rx, reader, shutdown) = sitrep_reader_over(&lines, auto).await;
        tokio::time::timeout(VIRTUAL_HANG, reader)
            .await
            .unwrap_or_else(|_| panic!("auto={auto}, {lines:?}: the reader never ended"))
            .unwrap();

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
    let (ready_rx, _reader, _shutdown) = sitrep_reader_over(&lines, false).await;

    let ready = tokio::time::timeout(VIRTUAL_HANG, ready_rx).await.unwrap();
    assert!(matches!(&ready, Ok(Ok(r)) if r.listen == listen), "{ready:?}");
}

// Teardown order ------------------------------------------------------------------------------------------------------
//
// A pgid-based containment signals the root's process group id, which the OS may recycle the moment
// the root is reaped. The tree is therefore killed while the root is still unreaped.

fn killed_then_reaped(edge_awaited: bool) -> Vec<&'static str> {
    let mut calls = vec!["kill_tree"];
    calls.extend(edge_awaited.then_some("wait_tree_drained"));
    calls.push("reap");
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
        ["terminate", "wait_root_exit_within", "kill_root", "kill_tree", "reap"]
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
        ["terminate", "wait_root_exit_within", "kill_root", "kill_tree", "reap"]
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

async fn supervise(tree: &mut impl PluginTree, shutdown: &CancellationToken) -> PluginEnd {
    supervise_plugin("p", tree, shutdown, GRACE, finished_reader(), finished_reader())
        .await
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

        assert!(matches!(&end, PluginEnd::Exited(s) if s.success()), "{containment:?}");
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

        assert!(matches!(end, PluginEnd::ShutDown), "{containment:?}");
        let mut expected = vec!["terminate", "wait_root_exit_within"];
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

    assert!(matches!(end, PluginEnd::ShutDown));
    assert_eq!(
        tree.calls(),
        ["terminate", "wait_root_exit_within", "kill_root", "kill_tree", "reap"]
    );
}

// The exit watch is unavailable ---------------------------------------------------------------------------------------
//
// cosca's non-reaping watch needs `pidfd_open` on Linux (absent before 5.3, or denied by a seccomp
// profile). Without it the root is reaped first, which frees its pid, so a tree kill that signals a
// process group id could hit an unrelated group that was handed the recycled id.

/// Every containment, each paired with whether `kill_tree` signals a process group id (cosca:
/// `ProcessGroup` and `Session` are `killpg`; a macOS `FdMarker` also fires `killpg` on its pgid).
const KILLS_BY_PGID: [(Containment, bool); 8] = [
    (Containment::CgroupV2, false),
    (Containment::JobObject, false),
    (Containment::ProcessGroup, true),
    (Containment::Session, true),
    (Containment::FdMarker, true),
    (Containment::TreeWalk, false),
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
        let end = supervise_plugin("unwatched", &mut tree, &shutdown, GRACE, stdout, finished_reader());
        let mut end = pin!(end);

        // The held stdout ends the wait for the output at its bound, on every containment.
        assert!(poll_once(end.as_mut()).is_pending(), "{containment:?}");
        tokio::time::advance(EOF_BOUND + TIMER_SLACK).await;
        let end = match poll_once(end.as_mut()) {
            Poll::Ready(end) => end.unwrap(),
            Poll::Pending => panic!("{containment:?}: still waiting at the bound"),
        };
        tokio::time::timeout(VIRTUAL_HANG, out_dropped).await.unwrap().ok();

        assert!(matches!(&end, PluginEnd::Exited(s) if s.success()), "{containment:?}");
        let edge_awaited = CONTAINMENTS.iter().any(|(c, edge)| *c == containment && *edge);
        let expected: &[&str] = match (kills_by_pgid, edge_awaited) {
            (true, _) => &["wait_root_exit", "reap"],
            (false, true) => &["wait_root_exit", "reap", "kill_tree", "wait_tree_drained"],
            (false, false) => &["wait_root_exit", "reap", "kill_tree"],
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

/// A shutdown that arrives while the root is being reaped (its exit could not be watched) ends the
/// plugin as any shutdown does: the root is still unreaped, so its tree is killed before the reap.
#[skuld::test]
async fn a_shutdown_while_the_exit_cannot_be_watched_still_kills_the_tree_before_the_reap() {
    tokio::time::pause();
    let mut tree = drained_tree(Containment::ProcessGroup);
    tree.root_watch_fails = true;
    tree.reap_waits_for_kill = true;
    let calls = tree.calls.clone();
    let shutdown = CancellationToken::new();
    let end = supervise_plugin("p", &mut tree, &shutdown, GRACE, finished_reader(), finished_reader());
    let mut end = pin!(end);

    assert!(
        poll_once(end.as_mut()).is_pending(),
        "the reap waits for the root to exit"
    );
    shutdown.cancel();
    let end = tokio::time::timeout(VIRTUAL_HANG, end)
        .await
        .expect("the shutdown must end the plugin")
        .unwrap();

    assert!(matches!(end, PluginEnd::ShutDown));
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "wait_root_exit",
            "terminate",
            "wait_root_exit_within",
            "kill_root",
            "kill_tree",
            "reap"
        ]
    );
}
