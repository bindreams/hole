//! TapPlugin behavioral tests.
//!
//! Tests use stub `ChainPlugin` impls (defined locally per scenario) that
//! bind a TCP listener on `local` and exercise a specific failure mode
//! the tap should classify. The tap forwards inbound connections via an
//! internal port to the stub, so the tests assert on the structured
//! tracing fields the tap emits on close: `bytes_to_plugin`,
//! `bytes_from_plugin`, `ttfb_ms`, `close_kind`.
//!
//! Subscriber capture goes through
//! [`crate::tracing_test::set_default_in_current_thread`], which enforces
//! the current-thread tokio runtime invariant — see
//! [bindreams/hole#302](https://github.com/bindreams/hole/issues/302).
//! `#[skuld::test] async fn` builds a current-thread runtime by default.

// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per the hole workspace clippy.toml's "Bridge cancellation contract"
// sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::counting::CountingStream;
use crate::plugin::ChainPlugin;
use crate::tap::TapPlugin;
use crate::test_utils::WaitableWriter;
use crate::tracing_test::set_default_in_current_thread;

// Subscriber capture ==================================================================================================

fn make_subscriber() -> (impl tracing::Subscriber + Send + Sync, WaitableWriter) {
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_target(true)
        .finish();
    (subscriber, writer)
}

// Stubs ===============================================================================================================

/// Test plugin that binds `local` and runs one of several behaviors per
/// accepted TCP connection.
struct StubPlugin {
    behavior: Behavior,
}

#[derive(Clone, Copy)]
enum Behavior {
    /// Read N bytes, echo them back, then close.
    Echo { read_bytes: usize },
    /// Accept and immediately drop the connection (no bytes either way).
    SilentDrop,
    /// Set SO_LINGER=0 and drop — sends RST instead of FIN. Cross-platform via socket2.
    Reset,
    /// Read N bytes, sleep, close without writing (the #248 shape).
    SilentAfterRead { read_bytes: usize, delay: Duration },
}

#[async_trait::async_trait]
impl ChainPlugin for StubPlugin {
    fn name(&self) -> &str {
        "stub"
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: tokio::sync::oneshot::Sender<Result<crate::sitrep::PluginReady, crate::sitrep::StartError>>,
    ) -> crate::Result<()> {
        let listener = TcpListener::bind(local)
            .await
            .map_err(|e| crate::Error::Chain(format!("stub bind {local}: {e}")))?;
        let actual = listener.local_addr().unwrap_or(local);
        let _ = ready.send(Ok(crate::sitrep::PluginReady {
            listen: actual,
            transports: crate::sitrep::Transports::TCP,
        }));
        let behavior = self.behavior;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                accept = listener.accept() => match accept {
                    Ok((stream, _peer)) => {
                        tokio::spawn(handle_stub_conn(stream, behavior));
                    }
                    Err(_) => return Ok(()),
                }
            }
        }
    }
}

async fn handle_stub_conn(mut stream: TcpStream, behavior: Behavior) {
    match behavior {
        Behavior::Echo { read_bytes } => {
            let mut buf = vec![0u8; read_bytes];
            if stream.read_exact(&mut buf).await.is_ok() {
                let _ = stream.write_all(&buf).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            }
        }
        Behavior::SilentDrop => {
            drop(stream);
        }
        Behavior::Reset => {
            // SO_LINGER=0 + drop → RST. Use socket2 to flip the option.
            let std_stream: std::net::TcpStream = stream.into_std().expect("into_std");
            let socket = socket2::Socket::from(std_stream);
            let _ = socket.set_linger(Some(Duration::ZERO));
            drop(socket);
        }
        Behavior::SilentAfterRead { read_bytes, delay } => {
            let mut buf = vec![0u8; read_bytes];
            if stream.read_exact(&mut buf).await.is_ok() {
                tokio::time::sleep(delay).await;
                drop(stream);
            }
        }
    }
}

/// Never binds anything and returns immediately without ever sending on its
/// `ready` channel — the shape `TapPlugin::run`'s inner-exit race (see its
/// doc comment) exists to detect.
struct ExitsBeforeReadyPlugin;

#[async_trait::async_trait]
impl ChainPlugin for ExitsBeforeReadyPlugin {
    fn name(&self) -> &str {
        "exits-before-ready"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: tokio::sync::oneshot::Sender<Result<crate::sitrep::PluginReady, crate::sitrep::StartError>>,
    ) -> crate::Result<()> {
        drop(ready);
        Ok(())
    }
}

/// Drops its readiness channel unsent (like `ExitsBeforeReadyPlugin`) but
/// returns a specific `Err` from `run()` itself — the shape a malformed
/// SS_PLUGIN_OPTIONS string produces (`BinaryPlugin::run` fails via
/// `Mode::from_plugin_options`? before ever touching `ready`). Pins that
/// this reaches the tap's `ready.send`, not just `join`'s own return value.
struct ExitsWithASpecificErrorPlugin;

#[async_trait::async_trait]
impl ChainPlugin for ExitsWithASpecificErrorPlugin {
    fn name(&self) -> &str {
        "exits-with-a-specific-error"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: tokio::sync::oneshot::Sender<Result<crate::sitrep::PluginReady, crate::sitrep::StartError>>,
    ) -> crate::Result<()> {
        drop(ready);
        Err(crate::Error::Chain(
            "malformed SS_PLUGIN_OPTIONS: plugin options end in an unpaired backslash".into(),
        ))
    }
}

/// Sends a specific `StartError::BindConflict` on its own readiness channel
/// then exits — the shape that used to collapse to a bare
/// `ExitedBeforeReady` through the tap's inner-exit race arm before it
/// recovered a delivered error the same way the chain aggregator does. See
/// `TapPlugin::run`'s inner-exit race doc comment.
struct BindConflictPlugin;

#[async_trait::async_trait]
impl ChainPlugin for BindConflictPlugin {
    fn name(&self) -> &str {
        "bind-conflict"
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: tokio::sync::oneshot::Sender<Result<crate::sitrep::PluginReady, crate::sitrep::StartError>>,
    ) -> crate::Result<()> {
        let _ = ready.send(Err(crate::sitrep::StartError::BindConflict {
            errno: 10048,
            addr: local,
        }));
        Ok(())
    }
}

/// Mimics `BinaryPlugin::run`'s real shape (not `BindConflictPlugin`'s
/// simplified one): hands `ready` to a DETACHED spawned task — never
/// joined by `run` itself before it returns — that sends a specific
/// `StartError` only after a couple of scheduler yields. `run` returns
/// `Ok(())` immediately, well before that send happens. This is the exact
/// race `TapPlugin::run`'s `join` arm uses `drain_for_delivered_error`
/// (await, not `try_recv`) to close.
struct DetachedSenderPlugin;

#[async_trait::async_trait]
impl ChainPlugin for DetachedSenderPlugin {
    fn name(&self) -> &str {
        "detached-sender"
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: tokio::sync::oneshot::Sender<Result<crate::sitrep::PluginReady, crate::sitrep::StartError>>,
    ) -> crate::Result<()> {
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
            let _ = ready.send(Err(crate::sitrep::StartError::BindConflict {
                errno: 10048,
                addr: local,
            }));
        });
        Ok(())
    }
}

fn unused_remote() -> SocketAddr {
    // The stubs ignore `remote`; any valid address works.
    "127.0.0.1:1".parse().unwrap()
}

async fn pick_local() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    addr
}

// Test runner =========================================================================================================

/// Run a test scenario: spawn the tap-wrapped plugin, run `client_body`,
/// then cancel shutdown and await the plugin to exit. Returns the
/// captured subscriber output.
async fn run_with_tap<F, Fut>(behavior: Behavior, client_body: F) -> String
where
    F: FnOnce(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let (subscriber, writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let local = pick_local().await;
    let remote = unused_remote();
    let shutdown = CancellationToken::new();
    let inner = Box::new(StubPlugin { behavior }) as Box<dyn ChainPlugin>;
    let tap = Box::new(TapPlugin::wrap(inner));

    // Register event waits BEFORE spawning the plugin so an unusually
    // fast emit can't race past us.
    let ready_rx = writer.wait_for("plugin tap: ready");
    let closed_rx = writer.wait_for("plugin tap: closed");

    let plugin_shutdown = shutdown.clone();
    // These tests synchronize on the "plugin tap: ready" tracing event rather
    // than the readiness channel, so a throwaway oneshot is passed for the
    // unused `ready` param.
    let (ready_tx, _ready_rx) = tokio::sync::oneshot::channel();
    let plugin_handle = tokio::spawn(async move { tap.run(local, remote, plugin_shutdown, ready_tx).await });

    // Park until tap signals ready via tracing event. No timeout — the
    // test framework bounds wall time; if tap is broken the failure is
    // clear ("test took too long" vs "tap never bound"). Deterministic.
    tokio::task::spawn_blocking(move || ready_rx.recv().expect("tap never signaled ready"))
        .await
        .unwrap();

    // Run the user-supplied client interaction.
    client_body(local).await;

    // Park until the tap logs "closed" for the connection (event-driven, no sleep).
    tokio::task::spawn_blocking(move || closed_rx.recv().expect("tap never signaled close"))
        .await
        .unwrap();

    shutdown.cancel();
    let _ = plugin_handle.await;

    writer.snapshot()
}

// Tests ===============================================================================================================

#[skuld::test]
async fn echo_records_round_trip_byte_counts_and_ttfb() {
    let captured = run_with_tap(Behavior::Echo { read_bytes: 5 }, |local| async move {
        let mut s = TcpStream::connect(local).await.unwrap();
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        let _ = s.shutdown().await;
    })
    .await;

    assert!(
        captured.contains("plugin tap: accepted"),
        "missing accept line:\n{captured}"
    );
    assert!(
        captured.contains("plugin tap: closed"),
        "missing close line:\n{captured}"
    );
    assert!(
        captured.contains("bytes_to_plugin=5"),
        "want bytes_to_plugin=5:\n{captured}"
    );
    assert!(
        captured.contains("bytes_from_plugin=5"),
        "want bytes_from_plugin=5:\n{captured}"
    );
    assert!(
        captured.contains("close_kind=graceful"),
        "want close_kind=graceful:\n{captured}"
    );
    assert!(
        captured.contains("ttfb_ms=Some("),
        "ttfb_ms must be Some(_) when bytes flowed back:\n{captured}"
    );
}

#[skuld::test]
async fn silent_drop_records_zero_bytes_and_no_ttfb() {
    let captured = run_with_tap(Behavior::SilentDrop, |local| async move {
        let mut s = TcpStream::connect(local).await.unwrap();
        // No writes — let the stub close on us.
        let mut buf = [0u8; 1];
        let _ = s.read(&mut buf).await; // returns 0 (EOF)
    })
    .await;

    assert!(
        captured.contains("plugin tap: closed"),
        "missing close line:\n{captured}"
    );
    assert!(
        captured.contains("bytes_to_plugin=0") && captured.contains("bytes_from_plugin=0"),
        "expected zero byte counts:\n{captured}"
    );
    assert!(
        captured.contains("ttfb_ms=None"),
        "ttfb_ms must be None when no upstream bytes ever read:\n{captured}"
    );
}

#[skuld::test]
async fn silent_after_read_matches_248_shape() {
    // The #248 shape: client writes some bytes, upstream reads them,
    // upstream NEVER replies, then closes. Tap must record bytes_to=N,
    // bytes_from=0, ttfb=None.
    let captured = run_with_tap(
        Behavior::SilentAfterRead {
            read_bytes: 16,
            delay: Duration::from_millis(50),
        },
        |local| async move {
            let mut s = TcpStream::connect(local).await.unwrap();
            s.write_all(b"silent-after-rd1").await.unwrap();
            s.flush().await.unwrap();
            let mut buf = [0u8; 1];
            let _ = s.read(&mut buf).await; // returns 0 once stub drops
        },
    )
    .await;

    assert!(
        captured.contains("plugin tap: closed"),
        "missing close line:\n{captured}"
    );
    assert!(
        captured.contains("bytes_to_plugin=16"),
        "want bytes_to_plugin=16:\n{captured}"
    );
    assert!(
        captured.contains("bytes_from_plugin=0"),
        "want bytes_from_plugin=0:\n{captured}"
    );
    assert!(
        captured.contains("ttfb_ms=None"),
        "ttfb_ms must be None for the #248 silent-then-FIN shape:\n{captured}"
    );
}

#[skuld::test]
async fn rst_close_classified_as_rst_with_os_errno() {
    let captured = run_with_tap(Behavior::Reset, |local| async move {
        let mut s = TcpStream::connect(local).await.unwrap();
        // Touch the connection so the kernel actually accepts it before
        // SO_LINGER+drop fires the RST.
        let _ = s.write_all(b"x").await;
        let _ = s.flush().await;
        // Drain whatever the kernel surfaces (likely ConnectionReset).
        let mut buf = [0u8; 1];
        let _ = s.read(&mut buf).await;
    })
    .await;

    assert!(
        captured.contains("plugin tap: closed"),
        "missing close line:\n{captured}"
    );
    let close_ok = captured.contains("close_kind=rst") || captured.contains("close_kind=broken_pipe");
    assert!(
        close_ok,
        "expected close_kind=rst (or broken_pipe on platforms that surface RST as such):\n{captured}"
    );
    // os_errno is platform-dependent; just assert it's recorded as Some(_).
    assert!(
        captured.contains("os_errno=Some("),
        "os_errno must be Some(_) for RST-class close:\n{captured}"
    );
}

#[skuld::test]
async fn shutdown_cancels_in_flight_connection_without_panic() {
    let (subscriber, writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let local = pick_local().await;
    let remote = unused_remote();
    let shutdown = CancellationToken::new();

    // Echo plugin so the connection stays open while client holds it.
    let inner = Box::new(StubPlugin {
        behavior: Behavior::Echo { read_bytes: 4096 },
    }) as Box<dyn ChainPlugin>;
    let tap = Box::new(TapPlugin::wrap(inner));

    let ready_rx = writer.wait_for("plugin tap: ready");

    let plugin_shutdown = shutdown.clone();
    // These tests synchronize on the "plugin tap: ready" tracing event rather
    // than the readiness channel, so a throwaway oneshot is passed for the
    // unused `ready` param.
    let (ready_tx, _ready_rx) = tokio::sync::oneshot::channel();
    let plugin_handle = tokio::spawn(async move { tap.run(local, remote, plugin_shutdown, ready_tx).await });

    // Park until tap signals ready via tracing event. Deterministic.
    tokio::task::spawn_blocking(move || ready_rx.recv().expect("tap never signaled ready"))
        .await
        .unwrap();

    // Open a connection that the echo plugin will hold (waiting on
    // read_exact for 4096 bytes — we send only 1).
    let _client = TcpStream::connect(local).await.unwrap();

    // Cancel shutdown and await the plugin exit. The plugin's own
    // shutdown bookkeeping bounds time; if it hangs the test
    // framework's timeout surfaces a clear failure.
    shutdown.cancel();
    plugin_handle
        .await
        .expect("plugin task panicked")
        .expect("plugin returned error");
}

#[skuld::test]
async fn cross_check_inbound_and_upstream_counters_match() {
    // Sanity invariant: on a clean roundtrip, inbound.read == upstream.written
    // and inbound.written == upstream.read. Catches future tap regressions
    // where one direction's counter wires up wrong.
    let captured = run_with_tap(Behavior::Echo { read_bytes: 7 }, |local| async move {
        let mut s = TcpStream::connect(local).await.unwrap();
        s.write_all(b"abcdefg").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 7];
        s.read_exact(&mut buf).await.unwrap();
        let _ = s.shutdown().await;
    })
    .await;

    assert!(captured.contains("bytes_to_plugin=7"), "to_plugin=7:\n{captured}");
    assert!(captured.contains("bytes_from_plugin=7"), "from_plugin=7:\n{captured}");
    assert!(captured.contains("bytes_inbound_read=7"), "inbound_read=7:\n{captured}");
    assert!(
        captured.contains("bytes_inbound_written=7"),
        "inbound_written=7:\n{captured}"
    );
}

// When the inner exits cleanly and silently — never sending anything on its
// own readiness channel — the tap has NOTHING to recover beyond what it
// already knows: which plugin, wrapped by which tap, didn't bind. So it
// reports a name-bearing `Fatal` directly rather than the bare
// `ExitedBeforeReady` placeholder — a caller that later joins the whole
// chain's own driving task for more detail (bridge's `recover_exit_detail`)
// would find only the same already-resolved clean exit and recover nothing
// better, so deferring to it here would only lose the plugin name for free.
#[skuld::test]
async fn tap_reports_a_name_bearing_fatal_when_inner_exits_cleanly_and_silently() {
    let local = pick_local().await;
    let remote = unused_remote();
    let shutdown = CancellationToken::new();
    let inner = Box::new(ExitsBeforeReadyPlugin) as Box<dyn ChainPlugin>;
    let tap = Box::new(TapPlugin::wrap(inner));

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let _ = tap.run(local, remote, shutdown, ready_tx).await;

    let outcome = ready_rx
        .await
        .expect("tap must report something on its own ready channel");
    match outcome {
        Err(crate::sitrep::StartError::Fatal { detail, errno: None }) => {
            assert!(
                detail.contains("exits-before-ready") && detail.contains("inner exited before becoming ready"),
                "expected the plugin name and reason in the detail, got {detail:?}"
            );
        }
        other => panic!("expected a name-bearing Fatal, got {other:?}"),
    }
}

// When the inner returns a SPECIFIC `Err` from `run()` itself (e.g. a
// malformed-options error `BinaryPlugin::run` returns before ever touching
// `ready`) without ever sending on its own readiness channel, the tap must
// forward that text, not the generic "inner exited before becoming ready"
// placeholder. Losing it here is worse than the clean-silent-exit case:
// bridge's `spawn_plugin_runner_at` treats a `Fatal` as already-as-specific-
// as-it-gets and does not join the handle for more detail, so a `Fatal`
// without this text would discard the real reason permanently, not just
// defer recovering it.
#[skuld::test]
async fn tap_forwards_the_inner_runs_own_specific_error_when_it_exits_silently() {
    let local = pick_local().await;
    let remote = unused_remote();
    let shutdown = CancellationToken::new();
    let inner = Box::new(ExitsWithASpecificErrorPlugin) as Box<dyn ChainPlugin>;
    let tap = Box::new(TapPlugin::wrap(inner));

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let _ = tap.run(local, remote, shutdown, ready_tx).await;

    let outcome = ready_rx
        .await
        .expect("tap must report something on its own ready channel");
    match outcome {
        Err(crate::sitrep::StartError::Fatal { detail, errno: None }) => {
            assert!(
                detail.contains("exits-with-a-specific-error")
                    && detail.contains("malformed SS_PLUGIN_OPTIONS")
                    && detail.contains("unpaired backslash"),
                "expected the plugin name and the inner's own specific reason in the detail, got {detail:?}"
            );
        }
        other => panic!("expected a Fatal carrying the inner's specific reason, got {other:?}"),
    }
}

// A specific `StartError` the inner delivered on its own readiness channel
// before exiting must survive the tap's inner-exit race, not collapse to
// the generic `ExitedBeforeReady` placeholder — `BindConflict` is the only
// retryable class, so losing it here turns a transient port collision into
// a hard failure.
#[skuld::test]
async fn tap_forwards_a_specific_bind_conflict_the_inner_delivered_before_exiting() {
    let local = pick_local().await;
    let remote = unused_remote();
    let shutdown = CancellationToken::new();
    let inner = Box::new(BindConflictPlugin) as Box<dyn ChainPlugin>;
    let tap = Box::new(TapPlugin::wrap(inner));

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let _ = tap.run(local, remote, shutdown, ready_tx).await;

    let outcome = ready_rx
        .await
        .expect("tap must report something on its own ready channel");
    assert!(
        matches!(outcome, Err(crate::sitrep::StartError::BindConflict { .. })),
        "expected the inner's BindConflict to survive the tap, got {outcome:?}"
    );
}

// `BinaryPlugin::run` hands its readiness sender to a spawned reader task
// it only best-effort-joins (a short grace window) before returning — so
// `inner_handle` completing does NOT mean the sender has resolved yet. A
// plain `try_recv` snapshot at that point would see `Empty` and lose a
// `BindConflict` sent moments later. This pins that the tap's `join` arm
// recovers it anyway (via `drain_for_delivered_error`, not
// `scan_for_delivered_error`).
#[skuld::test]
async fn tap_forwards_a_bind_conflict_delivered_by_a_detached_task_after_inner_run_returns() {
    let local = pick_local().await;
    let remote = unused_remote();
    let shutdown = CancellationToken::new();
    let inner = Box::new(DetachedSenderPlugin) as Box<dyn ChainPlugin>;
    let tap = Box::new(TapPlugin::wrap(inner));

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let _ = tap.run(local, remote, shutdown, ready_tx).await;

    let outcome = ready_rx
        .await
        .expect("tap must report something on its own ready channel");
    assert!(
        matches!(
            outcome,
            Err(crate::sitrep::StartError::BindConflict { errno: 10048, .. })
        ),
        "expected the detached task's BindConflict, delivered after inner.run() returned, to survive, got {outcome:?}"
    );
}

// CountingStream sanity (delegated to its own test module, kept here as a smoke check).
#[skuld::test]
async fn counting_stream_smoke() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"abc").await.unwrap();
        s.flush().await.unwrap();
    });
    let raw = TcpStream::connect(addr).await.unwrap();
    let mut counted = CountingStream::new(raw);
    let counters = counted.counters();
    let mut buf = [0u8; 3];
    counted.read_exact(&mut buf).await.unwrap();
    assert_eq!(counters.read(), 3);
    server.await.unwrap();
}
