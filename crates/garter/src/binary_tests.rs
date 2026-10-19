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
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use cosca::Containment;
use tokio::sync::{oneshot, Notify};
use tokio::task::JoinHandle;

use crate::binary::{await_stderr_after_stdout_eof, drain_readers_after_exit, kill_guarantees_eof, READER_EOF_BOUND};
use crate::test_utils::WaitableWriter;
use crate::tracing_test::set_default_in_current_thread;

/// Stands in for a runaway test: a paused runtime that goes idle jumps the clock, so a join that
/// never finishes fails here instead of hanging.
const VIRTUAL_HANG: Duration = Duration::from_secs(24 * 3600);

/// A timer's deadline is rounded up to the next millisecond; advancing this far past a bound fires it.
const TIMER_SLACK: Duration = Duration::from_millis(2);

/// Every containment `cosca` names, each paired with whether tearing the tree down guarantees the
/// child's pipes reach EOF. Written out from cosca's own account of which edges are kernel-owned.
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

#[skuld::test]
fn kill_guarantees_eof_is_decided_per_containment() {
    for (containment, expected) in CONTAINMENTS {
        assert_eq!(kill_guarantees_eof(containment), expected, "{containment:?}");
    }
}

/// The wait must not read a timer's expiry as "the readers are done": a reader that has not reached
/// EOF is not finished however much time has passed.
#[skuld::test]
async fn a_kernel_owned_join_is_not_ended_by_elapsed_time() {
    tokio::time::pause();
    for containment in [Containment::CgroupV2, Containment::JobObject] {
        let (release, stdout) = gated_reader();
        let drain = drain_readers_after_exit("p", containment, || Ok(()), stdout, finished_reader());
        let mut drain = pin!(drain);

        assert!(poll_once(drain.as_mut()).is_pending());
        tokio::time::advance(READER_EOF_BOUND + VIRTUAL_HANG).await;
        assert!(
            poll_once(drain.as_mut()).is_pending(),
            "{containment:?}: ended by elapsed time"
        );

        release.send(()).unwrap();
        tokio::time::timeout(VIRTUAL_HANG, drain)
            .await
            .expect("the join must finish once the reader reaches EOF");
    }
}

/// The tree is killed BEFORE the wait: here the reader reaches EOF only because the kill ran, as a
/// reader held by a grandchild does. On a weak containment a wait-then-kill order would also end,
/// but only by the bound's warning, so the log must be silent.
#[skuld::test]
async fn the_tree_is_killed_before_the_readers_are_awaited() {
    tokio::time::pause();
    let (subscriber, writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);

    for (containment, _) in CONTAINMENTS {
        let killed = std::sync::atomic::AtomicBool::new(false);
        let (release, stdout) = gated_reader();
        let kill = || {
            killed.store(true, std::sync::atomic::Ordering::SeqCst);
            release.send(()).unwrap();
            Ok(())
        };
        tokio::time::timeout(
            VIRTUAL_HANG,
            drain_readers_after_exit("p", containment, kill, stdout, finished_reader()),
        )
        .await
        .unwrap_or_else(|_| panic!("{containment:?}: the readers were awaited before the kill"));
        assert!(
            killed.load(std::sync::atomic::Ordering::SeqCst),
            "{containment:?}: no kill"
        );
    }
    assert!(!writer.snapshot().contains("WARN"), "{}", writer.snapshot());
}

/// Where EOF is not guaranteed, the wait ends at the bound, says so by plugin name, and ABORTS the
/// readers (dropping them), so their holds on the readiness sender are released.
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
        let drain = drain_readers_after_exit("held-plugin", containment, || Ok(()), stdout, stderr);
        let mut drain = pin!(drain);

        assert!(poll_once(drain.as_mut()).is_pending());
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(
            poll_once(drain.as_mut()).is_pending(),
            "{containment:?}: ended at the old 100ms"
        );
        tokio::time::advance(READER_EOF_BOUND - Duration::from_millis(501)).await;
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

/// A kill that did not happen removes the guarantee, even on a kernel-owned containment.
#[skuld::test]
async fn a_failed_kill_gives_even_a_kernel_owned_join_the_bound() {
    tokio::time::pause();
    let (subscriber, _writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let (dropped, stdout) = held_reader();
    let drain = drain_readers_after_exit("p", Containment::JobObject, kill_failed, stdout, finished_reader());
    let mut drain = pin!(drain);

    assert!(poll_once(drain.as_mut()).is_pending());
    tokio::time::advance(READER_EOF_BOUND + TIMER_SLACK).await;
    assert!(poll_once(drain.as_mut()).is_ready());
    tokio::time::timeout(VIRTUAL_HANG, dropped)
        .await
        .expect("the reader must be aborted at the bound")
        .ok();
}

/// A join that completes inside the bound is silent.
#[skuld::test]
async fn a_weak_containment_join_that_reaches_eof_does_not_warn() {
    tokio::time::pause();
    let (subscriber, writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let (release, stdout) = gated_reader();
    let drain = drain_readers_after_exit(
        "quiet-plugin",
        Containment::ProcessGroup,
        || Ok(()),
        stdout,
        finished_reader(),
    );
    let mut drain = pin!(drain);
    assert!(poll_once(drain.as_mut()).is_pending());
    tokio::time::advance(READER_EOF_BOUND - Duration::from_millis(1)).await;
    release.send(()).unwrap();
    tokio::time::timeout(VIRTUAL_HANG, drain).await.unwrap();

    assert!(!writer.snapshot().contains("quiet-plugin"), "{}", writer.snapshot());
}

// The sitrep reader's wait for the stderr reader, after stdout EOF ----------------------------------------------------

#[skuld::test]
async fn the_stderr_wait_on_a_kernel_owned_containment_is_not_ended_by_elapsed_time() {
    tokio::time::pause();
    for containment in [Containment::CgroupV2, Containment::JobObject] {
        let stderr_done = Notify::new();
        let wait = await_stderr_after_stdout_eof("p", containment, &stderr_done);
        let mut wait = pin!(wait);

        assert!(poll_once(wait.as_mut()).is_pending());
        tokio::time::advance(READER_EOF_BOUND + VIRTUAL_HANG).await;
        assert!(
            poll_once(wait.as_mut()).is_pending(),
            "{containment:?}: ended by elapsed time"
        );

        stderr_done.notify_one();
        tokio::time::timeout(VIRTUAL_HANG, wait).await.unwrap();
    }
}

#[skuld::test]
async fn the_stderr_wait_on_a_weak_containment_ends_at_the_bound_with_a_warning() {
    tokio::time::pause();
    let (subscriber, writer) = subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let stderr_done = Notify::new();
    let wait = await_stderr_after_stdout_eof("stderr-held-plugin", Containment::ProcessGroup, &stderr_done);
    let mut wait = pin!(wait);

    assert!(poll_once(wait.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(500)).await;
    assert!(poll_once(wait.as_mut()).is_pending(), "ended at the old 100ms");
    tokio::time::advance(READER_EOF_BOUND + TIMER_SLACK).await;
    assert!(poll_once(wait.as_mut()).is_ready());

    let log = writer.snapshot();
    assert!(
        log.contains("WARN") && log.contains("stderr-held-plugin"),
        "the warning must name the plugin:\n{log}"
    );
    assert!(
        log.contains("later; reporting it as exited before ready"),
        "the warning text is mangled:\n{log}"
    );
}

/// stderr finishing first (the common crash shape) is a stored wake, not a wait.
#[skuld::test]
async fn the_stderr_wait_returns_at_once_when_stderr_already_finished() {
    tokio::time::pause();
    for (containment, _) in CONTAINMENTS {
        let stderr_done = Notify::new();
        stderr_done.notify_one();
        let wait = await_stderr_after_stdout_eof("p", containment, &stderr_done);
        assert!(poll_once(pin!(wait)).is_ready(), "{containment:?}");
    }
}
