//! A tap whose start fails stops its inner, within a failure bound, before it reports.
//!
//! The paused clock makes the bounds exact; every wait on the inner is raced against a virtual hang, so a tap that
//! waits for an inner that ignores its token fails these tests instead of hanging them.

// `CancellationToken::new` is the cancel-test harness root; `allocate_ports` is the chain's TCP-only allocator.
#![allow(clippy::disallowed_methods)]

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::chain::{allocate_ports, ChainRunner};
use crate::plugin::ChainPlugin;
use crate::sitrep::StartError;
use crate::tap::TapPlugin;
use crate::tap_tests::{
    addr, announce, failed_start_of, loopback, make_debug_subscriber, scripted, unused_remote, Prelude, Ready,
};
use crate::tracing_test::set_default_in_current_thread;

/// Stands in for a runaway test: a paused runtime that goes idle jumps the clock, so a wait that never ends fails here
/// instead of hanging.
const VIRTUAL_HANG: Duration = Duration::from_secs(24 * 3600);

/// The bound on the wait for a stopped inner, written out so a change to it fails here: a `BinaryPlugin` inner's own
/// take-down (5 s of grace, 5 s of output) and a second of headroom over it.
const STOP_BOUND: Duration = Duration::from_secs(11);

const READINESS_BOUND: Duration = Duration::from_secs(30);

/// Sends when dropped; the receiver says the inner's future is gone.
struct DropSignal(Option<oneshot::Sender<()>>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}

fn drop_signal() -> (DropSignal, oneshot::Receiver<()>) {
    let (tx, rx) = oneshot::channel();
    (DropSignal(Some(tx)), rx)
}

/// Does its prelude, then ignores its token: only an abort ends it.
struct IgnoresStop {
    prelude: Prelude,
    torn_down: DropSignal,
}

#[async_trait::async_trait]
impl ChainPlugin for IgnoresStop {
    fn name(&self) -> &str {
        "ignores-stop-stub"
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: oneshot::Sender<Ready>,
    ) -> crate::Result<()> {
        let _torn_down = self.torn_down;
        let _held_ready = announce(self.prelude, local, ready);
        std::future::pending().await
    }
}

/// Does its prelude, waits to be stopped, then ends as `ends_with` says.
struct EndsWhenStopped {
    prelude: Prelude,
    ends_with: EndsWith,
    stopped: Arc<AtomicBool>,
}

#[derive(Clone, Copy)]
enum EndsWith {
    Ok,
    Exit,
    Panic,
}

#[async_trait::async_trait]
impl ChainPlugin for EndsWhenStopped {
    fn name(&self) -> &str {
        "ends-when-stopped-stub"
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Ready>,
    ) -> crate::Result<()> {
        let _held_ready = announce(self.prelude, local, ready);
        shutdown.cancelled().await;
        self.stopped.store(true, Ordering::SeqCst);
        match self.ends_with {
            EndsWith::Ok => Ok(()),
            EndsWith::Exit => Err(crate::Error::PluginExit {
                name: "ends-when-stopped-stub".into(),
                code: 3,
            }),
            EndsWith::Panic => panic!("the inner broke while stopping"),
        }
    }
}

fn holder() -> (std::net::TcpListener, SocketAddr) {
    let holder = std::net::TcpListener::bind(loopback()).unwrap();
    let public = holder.local_addr().unwrap();
    (holder, public)
}

// A failed start aborts an inner that ignores its token ---------------------------------------------------------------

/// Every way the start fails after the inner is running: the readiness bound, a listener outside the given address, the
/// inner's own typed failure, the public bind. An inner that does not stop when its token fires is warned about by
/// plugin name and aborted at the bound, and the failure is then reported.
#[skuld::test]
async fn a_failed_start_aborts_an_inner_that_ignores_its_token_at_the_bound() {
    tokio::time::pause();
    let (subscriber, writer) = make_debug_subscriber();
    let _g = set_default_in_current_thread(subscriber);
    let (public_holder, taken) = holder();

    let mut rows = 0;
    for (prelude, public, ready_cost) in [
        (Prelude::Silent, loopback(), READINESS_BOUND),
        (Prelude::ForeignListen, loopback(), Duration::ZERO),
        (Prelude::TypedFatal, loopback(), Duration::ZERO),
        (Prelude::Ready, taken, Duration::ZERO),
    ] {
        let label = match prelude {
            Prelude::Silent => "readiness bound",
            Prelude::ForeignListen => "foreign listener",
            Prelude::TypedFatal => "typed failure",
            Prelude::Ready => "public bind",
        };
        let (signal, torn_down) = drop_signal();
        let inner = Box::new(IgnoresStop {
            prelude,
            torn_down: signal,
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let probe = scripted(vec![Ok(addr(5001))], &calls);
        let tap = TapPlugin::wrap_with_probe(inner, Box::new(probe));
        let started = tokio::time::Instant::now();

        let (ready, result) = tokio::time::timeout(VIRTUAL_HANG, failed_start_of(tap, public, unused_remote()))
            .await
            .unwrap_or_else(|_| {
                panic!("{label}: the start never ended: the tap waits for an inner that ignores its token")
            });

        rows += 1;
        assert!(
            matches!(ready, Ok(Err(_))),
            "{label}: want a reported failure, got {ready:?}"
        );
        assert!(result.is_err(), "{label}: run must fail, got {result:?}");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= ready_cost + STOP_BOUND,
            "{label}: failed after {elapsed:?}, before the stop bound"
        );
        tokio::time::timeout(VIRTUAL_HANG, torn_down)
            .await
            .unwrap_or_else(|_| panic!("{label}: the inner was not aborted"))
            .ok();
        let log = writer.snapshot();
        let warned = log
            .lines()
            .filter(|l| l.contains("WARN") && l.contains("ignores-stop-stub") && l.contains("did not stop"))
            .count();
        assert_eq!(
            warned, rows,
            "{label}: want one warning naming the plugin per row:\n{log}"
        );
    }
    drop(public_holder);
}

/// The same through a chain: a start that fails over an inner that ignores its token ends the chain at the bounds, not
/// never, and the caller hears the failure.
#[skuld::test]
async fn a_chain_over_an_inner_that_ignores_its_token_ends_at_the_bounds() {
    tokio::time::pause();
    let (signal, _torn_down) = drop_signal();
    let (ready_tx, ready_rx) = oneshot::channel();
    let runner = ChainRunner::new()
        .add(Box::new(TapPlugin::wrap(Box::new(IgnoresStop {
            prelude: Prelude::Silent,
            torn_down: signal,
        }))))
        .on_ready(ready_tx);
    let mut env = crate::chain_tests::test_env();
    env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();
    let started = tokio::time::Instant::now();
    let handle = tokio::spawn(runner.run(env));

    let heard = tokio::time::timeout(VIRTUAL_HANG, ready_rx)
        .await
        .expect("the chain never reported: the tap waits for an inner that ignores its token");
    assert!(
        matches!(&heard, Ok(Err(StartError::Fatal { detail, .. })) if detail.contains("did not bind")),
        "want the readiness-bound Fatal, got {heard:?}"
    );
    assert!(started.elapsed() >= READINESS_BOUND + STOP_BOUND);
    let result = tokio::time::timeout(VIRTUAL_HANG, handle)
        .await
        .expect("the chain never ended")
        .unwrap();
    assert!(result.is_err(), "the chain must fail, got {result:?}");
}

// An accept failure stops the inner -----------------------------------------------------------------------------------

/// A listener that fails to accept leaves the tap with nothing to serve: it stops its inner, which would otherwise run
/// on unobserved, and fails with an error that names the accept failure.
#[skuld::test]
async fn an_accept_failure_stops_the_inner_and_fails_the_tap_naming_it() {
    tokio::time::pause();
    for cooperates in [true, false] {
        let label = format!("cooperating inner: {cooperates}");
        let stopped = Arc::new(AtomicBool::new(false));
        let (signal, torn_down) = drop_signal();
        let inner: Box<dyn ChainPlugin> = if cooperates {
            Box::new(EndsWhenStopped {
                prelude: Prelude::Ready,
                ends_with: EndsWith::Ok,
                stopped: stopped.clone(),
            })
        } else {
            Box::new(IgnoresStop {
                prelude: Prelude::Ready,
                torn_down: signal,
            })
        };
        let tap = Box::new(TapPlugin::wrap_with_accept_failure(
            inner,
            io::Error::other("scripted accept failure"),
        ));
        // Never cancelled: the tap ends the inner itself.
        let shutdown = CancellationToken::new();
        let (ready_tx, ready_rx) = oneshot::channel();
        let started = tokio::time::Instant::now();
        let handle = tokio::spawn(async move { tap.run(loopback(), unused_remote(), shutdown, ready_tx).await });

        assert!(
            matches!(ready_rx.await, Ok(Ok(_))),
            "{label}: the tap must have readied first"
        );
        let result = tokio::time::timeout(VIRTUAL_HANG, handle)
            .await
            .unwrap_or_else(|_| panic!("{label}: the tap never ended: it did not stop its inner"))
            .expect("tap task panicked");

        let error = result.expect_err("an accept failure fails the tap").to_string();
        assert!(
            error.contains("accept") && error.contains("scripted accept failure"),
            "{label}: the error must name the accept failure, got {error}"
        );
        if cooperates {
            assert!(
                stopped.load(Ordering::SeqCst),
                "{label}: the inner was not told to stop"
            );
        } else {
            assert!(started.elapsed() >= STOP_BOUND, "{label}: ended before the stop bound");
            tokio::time::timeout(VIRTUAL_HANG, torn_down)
                .await
                .unwrap_or_else(|_| panic!("{label}: the inner was not aborted"))
                .ok();
        }
    }
}

// The inner is never left running -------------------------------------------------------------------------------------

/// A tap whose task is aborted (the chain's drain bound expired) takes its inner with it: the inner is its child and
/// has nobody else to be stopped by.
#[skuld::test]
async fn an_aborted_tap_aborts_its_inner() {
    tokio::time::pause();
    let (signal, torn_down) = drop_signal();
    let tap = Box::new(TapPlugin::wrap(Box::new(IgnoresStop {
        prelude: Prelude::Ready,
        torn_down: signal,
    })));
    let (ready_tx, ready_rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        tap.run(loopback(), unused_remote(), CancellationToken::new(), ready_tx)
            .await
    });
    assert!(matches!(ready_rx.await, Ok(Ok(_))), "the tap must have readied");

    handle.abort();
    let _ = handle.await;

    tokio::time::timeout(VIRTUAL_HANG, torn_down)
        .await
        .expect("the inner outlived the aborted tap")
        .ok();
}

// What stopping the inner found ---------------------------------------------------------------------------------------

/// The failure being reported is the tap's, but how the inner ended is not lost: an exit status goes to the debug log,
/// a panic to the warn log, each naming the plugin.
#[skuld::test]
async fn how_a_stopped_inner_ended_is_logged() {
    let (subscriber, writer) = make_debug_subscriber();
    let _g = set_default_in_current_thread(subscriber);
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    for (ends_with, level, text) in [
        (EndsWith::Exit, "DEBUG", "code 3"),
        (EndsWith::Panic, "WARN", "panicked"),
    ] {
        let inner = Box::new(EndsWhenStopped {
            prelude: Prelude::TypedFatal,
            ends_with,
            stopped: Arc::new(AtomicBool::new(false)),
        });
        let (ready, result) = failed_start_of(TapPlugin::wrap(inner), loopback(), unused_remote()).await;

        assert!(matches!(ready, Ok(Err(StartError::Fatal { .. }))), "{ready:?}");
        assert!(result.is_err(), "{result:?}");
        let log = writer.snapshot();
        assert!(
            log.lines()
                .any(|l| l.contains(level) && l.contains("ends-when-stopped-stub") && l.contains(text)),
            "{level} line naming the plugin and {text:?} is missing:\n{log}"
        );
    }
    std::panic::set_hook(previous);

    // A clean end adds nothing.
    let before = writer.snapshot().lines().count();
    let inner = Box::new(EndsWhenStopped {
        prelude: Prelude::TypedFatal,
        ends_with: EndsWith::Ok,
        stopped: Arc::new(AtomicBool::new(false)),
    });
    let _ = failed_start_of(TapPlugin::wrap(inner), loopback(), unused_remote()).await;
    let log = writer.snapshot();
    assert!(
        log.lines().skip(before).all(|l| !l.contains("the inner ended")),
        "a clean end of the inner was logged:\n{log}"
    );
}

// A reported start failure is an error --------------------------------------------------------------------------------

/// An inner that returns `Ok` before it is ready has failed the start: the tap reports `Fatal` on `ready`, and `run`
/// returns an error too, so a runner that registered no `on_ready` does not see a clean end.
struct ExitsOkBeforeReady {
    /// Another task keeps the readiness sender, as a probe would, instead of the inner dropping it.
    detached_holder: bool,
}

#[async_trait::async_trait]
impl ChainPlugin for ExitsOkBeforeReady {
    fn name(&self) -> &str {
        "exits-ok-stub"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Ready>,
    ) -> crate::Result<()> {
        if self.detached_holder {
            tokio::spawn(async move {
                shutdown.cancelled().await;
                drop(ready);
            });
        }
        Ok(())
    }
}

#[skuld::test]
async fn an_inner_that_returns_ok_before_ready_fails_the_start_and_the_tap() {
    for detached_holder in [false, true] {
        let tap = TapPlugin::wrap(Box::new(ExitsOkBeforeReady { detached_holder }));
        let (ready, result) = failed_start_of(tap, loopback(), unused_remote()).await;

        assert!(
            matches!(&ready, Ok(Err(StartError::Fatal { detail, .. })) if detail.contains("exited before becoming ready")),
            "detached_holder={detached_holder}: want Fatal, got {ready:?}"
        );
        let error = result.expect_err("a reported start failure fails the tap").to_string();
        assert!(
            error.contains("exits-ok-stub") && error.contains("before becoming ready"),
            "detached_holder={detached_holder}: {error}"
        );
    }
}

// A start failure decided before a shutdown ---------------------------------------------------------------------------

/// Announces it is running, waits for its token, then delivers a typed start failure and ends: the order a
/// `BinaryPlugin` has, which delivers a failure it decided only at the end of its take-down.
struct DeliversAfterStop {
    error: StartError,
    running: oneshot::Sender<()>,
}

#[async_trait::async_trait]
impl ChainPlugin for DeliversAfterStop {
    fn name(&self) -> &str {
        "delivers-after-stop-stub"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Ready>,
    ) -> crate::Result<()> {
        let _ = self.running.send(());
        shutdown.cancelled().await;
        // On a current-thread runtime this puts the delivery behind the tap, already woken by the same cancel.
        tokio::task::yield_now().await;
        let _ = ready.send(Err(self.error));
        Err(crate::Error::Chain("the stub decided its start failed".into()))
    }
}

/// What a chain over `plugin` tells `on_ready` when its token is cancelled once `plugin` is running, and what `run`
/// returns.
async fn cancelled_chain_of(
    plugin: Box<dyn ChainPlugin>,
    running: oneshot::Receiver<()>,
) -> (
    Result<Result<crate::chain::ChainReady, StartError>, oneshot::error::RecvError>,
    crate::Result<()>,
) {
    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = oneshot::channel();
    let runner = ChainRunner::new()
        .add(plugin)
        .on_ready(ready_tx)
        .cancel_token(cancel.clone());
    let mut env = crate::chain_tests::test_env();
    env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();
    let handle = tokio::spawn(runner.run(env));
    running.await.expect("the stub never ran");
    cancel.cancel();
    let heard = ready_rx.await;
    (heard, handle.await.unwrap())
}

/// A start failure the inner decided before the chain's shutdown reaches `on_ready` typed, tapped or not.
#[skuld::test]
async fn a_start_failure_the_inner_delivers_while_the_tap_drains_it_is_still_reported() {
    let errors = [
        StartError::Fatal {
            detail: "decided earlier".into(),
            errno: None,
        },
        StartError::BindConflict {
            errno: 98,
            addr: loopback(),
        },
    ];
    for error in errors {
        for tapped in [false, true] {
            let (running_tx, running_rx) = oneshot::channel();
            let inner = Box::new(DeliversAfterStop {
                error: error.clone(),
                running: running_tx,
            });
            let plugin: Box<dyn ChainPlugin> = if tapped {
                Box::new(TapPlugin::wrap(inner))
            } else {
                inner
            };
            let (heard, result) = cancelled_chain_of(plugin, running_rx).await;
            let label = format!("{error:?}, tapped={tapped}");
            let typed = match (&heard, &error) {
                (Ok(Err(StartError::Fatal { detail, .. })), StartError::Fatal { detail: want, .. }) => detail == want,
                (Ok(Err(StartError::BindConflict { errno, addr })), StartError::BindConflict { errno: e, addr: a }) => {
                    errno == e && addr == a
                }
                _ => false,
            };
            assert!(typed, "{label}: want the inner's own failure, got {heard:?}");
            assert!(
                result.is_err(),
                "{label}: a failed start fails the chain, got {result:?}"
            );
        }
    }
}
