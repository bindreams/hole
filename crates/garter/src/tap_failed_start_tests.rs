//! A tap whose start fails stops its inner, within a failure bound, before it reports.
//!
//! The paused clock makes the bounds exact; every wait on the inner is raced against a virtual hang, so a tap that
//! waits for an inner that ignores its token fails these tests instead of hanging them.

// `CancellationToken::new` is the cancel-test harness root.
#![allow(clippy::disallowed_methods)]

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::chain::ChainRunner;
use crate::once::Once;
use crate::plugin::ChainPlugin;
use crate::port::free_loopback_port;
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
    torn_down: Once<DropSignal>,
}

#[async_trait::async_trait]
impl ChainPlugin for IgnoresStop {
    fn name(&self) -> &str {
        "ignores-stop-stub"
    }

    async fn run(
        &self,
        local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: oneshot::Sender<Ready>,
    ) -> crate::Result<()> {
        let _torn_down = self.torn_down.take();
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
    /// A stop that could not be confirmed, as a `BinaryPlugin` whose root kill was refused returns.
    Unconfirmed,
    /// A refused pid sink, whose plugin was taken down and confirmed stopped.
    PidSink,
}

#[async_trait::async_trait]
impl ChainPlugin for EndsWhenStopped {
    fn name(&self) -> &str {
        "ends-when-stopped-stub"
    }

    async fn run(
        &self,
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
            EndsWith::Unconfirmed => Err(crate::Error::StopUnconfirmed {
                plugins: vec!["ends-when-stopped-stub".into()],
                cause: "test: the root kill was refused".into(),
            }),
            EndsWith::PidSink => Err(crate::Error::PidSink {
                plugin: "ends-when-stopped-stub".into(),
                cause: "test: the sink said no".into(),
            }),
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
            torn_down: Once::new(signal),
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
        assert!(
            matches!(&result, Err(crate::Error::StopUnconfirmed { plugins, .. }) if plugins == &["ignores-stop-stub"]),
            "{label}: an aborted inner is an unconfirmed stop, got {result:?}"
        );
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
            torn_down: Once::new(signal),
        }))))
        .on_ready(ready_tx);
    let mut env = crate::chain_tests::test_env();
    env.local_port = free_loopback_port().port();
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
    assert!(
        matches!(&result, Err(crate::Error::StopUnconfirmed { plugins, .. }) if plugins == &["ignores-stop-stub"]),
        "the chain must fail with the aborted inner unconfirmed, got {result:?}"
    );
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
                torn_down: Once::new(signal),
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

        let error = result.expect_err("an accept failure fails the tap");
        if cooperates {
            match &error {
                crate::Error::Tap { plugin, step, cause } => {
                    assert_eq!(plugin, "ends-when-stopped-stub", "{label}");
                    assert_eq!(*step, crate::TapStep::AcceptConnection, "{label}");
                    assert_eq!(cause.to_string(), "scripted accept failure", "{label}");
                }
                other => panic!("{label}: the error must be the tap's accept failure, got {other:?}"),
            }
            assert_eq!(
                error.to_string(),
                "the tap of plugin 'ends-when-stopped-stub' could not accept a connection",
                "{label}"
            );
            assert!(
                stopped.load(Ordering::SeqCst),
                "{label}: the inner was not told to stop"
            );
        } else {
            assert!(
                matches!(&error, crate::Error::StopUnconfirmed { plugins, .. } if plugins == &["ignores-stop-stub"]),
                "{label}: an aborted inner outranks the accept failure, got {error:?}"
            );
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
        torn_down: Once::new(signal),
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

/// The failure being reported is the tap's, but how the inner ended is not lost: an exit status and a panic go to the
/// warn log, each naming the plugin.
#[skuld::test]
async fn how_a_stopped_inner_ended_is_logged() {
    let (subscriber, writer) = make_debug_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    for (ends_with, level, text) in [
        (EndsWith::Exit, "WARN", "code 3"),
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

/// An inner whose stop could not be confirmed, or that panicked, may still be running: the tap returns that, ahead of
/// its own failure, whichever way the start fails and whichever way the tap ends.
#[skuld::test]
async fn an_inner_that_cannot_confirm_its_stop_makes_the_taps_stop_unconfirmed() {
    for ends_with in [EndsWith::Unconfirmed, EndsWith::Panic] {
        let label = if matches!(ends_with, EndsWith::Panic) {
            "panic"
        } else {
            "unconfirmed"
        };
        let inner = |prelude| {
            Box::new(EndsWhenStopped {
                prelude,
                ends_with,
                stopped: Arc::new(AtomicBool::new(false)),
            })
        };

        // The start fails and the tap stops its inner.
        let (ready, result) =
            failed_start_of(TapPlugin::wrap(inner(Prelude::TypedFatal)), loopback(), unused_remote()).await;
        assert!(matches!(ready, Ok(Err(StartError::Fatal { .. }))), "{label}: {ready:?}");
        assert_stop_unconfirmed(label, "start failure", result, ends_with);

        // The tap is running and is shut down.
        let shutdown = CancellationToken::new();
        let (ready_tx, ready_rx) = oneshot::channel();
        let tap = Box::new(TapPlugin::wrap(inner(Prelude::Ready)));
        let token = shutdown.clone();
        let handle = tokio::spawn(async move { tap.run(loopback(), unused_remote(), token, ready_tx).await });
        assert!(
            matches!(ready_rx.await, Ok(Ok(_))),
            "{label}: the tap must have readied"
        );
        shutdown.cancel();
        assert_stop_unconfirmed(label, "shutdown", handle.await.unwrap(), ends_with);
    }
}

/// A refused pid sink that the inner returns while it is stopped outranks the tap's own failure, though its stop was
/// confirmed: the ranking is `Error::then`'s alone, not whether the stop was confirmed.
#[skuld::test]
async fn an_inner_that_ends_with_a_refused_pid_sink_outranks_the_taps_own_failure() {
    let inner = Box::new(EndsWhenStopped {
        prelude: Prelude::TypedFatal,
        ends_with: EndsWith::PidSink,
        stopped: Arc::new(AtomicBool::new(false)),
    });

    let (ready, result) = failed_start_of(TapPlugin::wrap(inner), loopback(), unused_remote()).await;

    assert!(matches!(ready, Ok(Err(StartError::Fatal { .. }))), "{ready:?}");
    assert!(
        matches!(&result, Err(crate::Error::PidSink { plugin, .. }) if plugin == "ends-when-stopped-stub"),
        "got {result:?}"
    );
}

fn assert_stop_unconfirmed(label: &str, when: &str, result: crate::Result<()>, ends_with: EndsWith) {
    let cause_is_the_inners = |cause: &(dyn std::error::Error + Send + Sync + 'static)| match ends_with {
        EndsWith::Panic => cause
            .downcast_ref::<tokio::task::JoinError>()
            .is_some_and(tokio::task::JoinError::is_panic),
        EndsWith::Unconfirmed => cause.to_string() == "test: the root kill was refused",
        EndsWith::Ok | EndsWith::Exit | EndsWith::PidSink => unreachable!(),
    };
    match &result {
        Err(crate::Error::StopUnconfirmed { plugins, cause }) => {
            assert_eq!(plugins, &["ends-when-stopped-stub"], "{label} at {when}");
            assert!(
                cause_is_the_inners(&**cause),
                "{label} at {when}: the cause is {cause:?}"
            );
        }
        other => panic!("{label} at {when}: want an unconfirmed stop, got {other:?}"),
    }
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
        &self,
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
    running: Once<oneshot::Sender<()>>,
}

#[async_trait::async_trait]
impl ChainPlugin for DeliversAfterStop {
    fn name(&self) -> &str {
        "delivers-after-stop-stub"
    }

    async fn run(
        &self,
        _local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Ready>,
    ) -> crate::Result<()> {
        let _ = self.running.take().send(());
        shutdown.cancelled().await;
        // On a current-thread runtime this puts the delivery behind the tap, already woken by the same cancel.
        tokio::task::yield_now().await;
        let _ = ready.send(Err(self.error.clone()));
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
    env.local_port = free_loopback_port().port();
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
                running: Once::new(running_tx),
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

// A typed start failure is reported on every path that ends the start -------------------------------------------------

/// When a [`Delivers`] stub hands its typed failure to `ready`.
#[derive(Clone, Copy, Debug)]
enum DeliversWhen {
    /// After its token fires, as a `BinaryPlugin` does at the end of its take-down.
    AfterStop,
    /// At once, then it ends.
    ThenExits,
    /// At once, then it runs on until its token fires.
    ThenWaits,
}

/// Announces it is running, then delivers `error` on `ready` as `when` says, and ends with an error.
struct Delivers {
    error: StartError,
    when: DeliversWhen,
    running: Once<oneshot::Sender<()>>,
}

#[async_trait::async_trait]
impl ChainPlugin for Delivers {
    fn name(&self) -> &str {
        "delivers-stub"
    }

    async fn run(
        &self,
        _local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Ready>,
    ) -> crate::Result<()> {
        let _ = self.running.take().send(());
        match self.when {
            DeliversWhen::AfterStop => {
                shutdown.cancelled().await;
                tokio::task::yield_now().await;
                let _ = ready.send(Err(self.error.clone()));
            }
            DeliversWhen::ThenExits => {
                let _ = ready.send(Err(self.error.clone()));
            }
            DeliversWhen::ThenWaits => {
                let _ = ready.send(Err(self.error.clone()));
                shutdown.cancelled().await;
            }
        }
        Err(crate::Error::Chain("the stub decided its start failed".into()))
    }
}

/// Whatever ends a start decides the error the caller gets, so the typed failure an inner delivers is the one reported
/// on every path, whichever of them stops or drains the inner: the readiness bound, a shutdown before ready, the inner
/// exiting on its own, and a failure it reports while running.
///
/// Paths that start from an inner that already reported (a listener outside the given address, the public bind, an
/// accept failure) have consumed its one readiness message: the inner cannot deliver a second, and the tap's own
/// failure is the only one, which `a_failed_start_aborts_an_inner_that_ignores_its_token_at_the_bound` covers.
#[skuld::test]
async fn a_typed_start_failure_the_inner_delivers_is_reported_on_every_path_that_ends_the_start() {
    tokio::time::pause();
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
    // (path, when the inner delivers, whether the caller shuts down once the inner runs)
    let paths = [
        ("readiness bound", DeliversWhen::AfterStop, false),
        ("shutdown before ready", DeliversWhen::AfterStop, true),
        ("inner exits on its own", DeliversWhen::ThenExits, false),
        ("failure reported while running", DeliversWhen::ThenWaits, false),
    ];
    let mut wrong = Vec::new();
    for error in errors {
        for (path, when, shuts_down) in paths {
            let label = format!("{path}, {error:?}");
            let (running_tx, running_rx) = oneshot::channel();
            let inner = Box::new(Delivers {
                error: error.clone(),
                when,
                running: Once::new(running_tx),
            });
            let calls = Arc::new(AtomicUsize::new(0));
            let tap = Box::new(TapPlugin::wrap_with_probe(
                inner,
                Box::new(scripted(vec![Ok(addr(5001))], &calls)),
            ));
            let shutdown = CancellationToken::new();
            let plugin_shutdown = shutdown.clone();
            let (ready_tx, ready_rx) = oneshot::channel();
            let handle =
                tokio::spawn(async move { tap.run(loopback(), unused_remote(), plugin_shutdown, ready_tx).await });
            if shuts_down {
                running_rx.await.expect("the stub never ran");
                shutdown.cancel();
            }

            let heard = tokio::time::timeout(VIRTUAL_HANG, ready_rx)
                .await
                .unwrap_or_else(|_| panic!("{label}: the start never ended"));
            let result = handle.await.expect("tap task panicked");
            let want = format!(
                "{:?}",
                Ok::<_, oneshot::error::RecvError>(Err::<crate::sitrep::PluginReady, _>(error.clone()))
            );
            if format!("{heard:?}") != want {
                wrong.push(format!("{label}: want the inner's own failure, got {heard:?}"));
            }
            if result.is_ok() {
                wrong.push(format!("{label}: a failed start fails the tap, got {result:?}"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "paths that lose the inner's failure:
{}",
        wrong.join(
            "
"
        )
    );
}

// An inner the runtime cancelled --------------------------------------------------------------------------------------

/// A task cancelled from outside the tap, as a runtime dropped mid-drain cancels it: the handle the tap awaits and the
/// cancel the tap did not issue.
fn an_inner_cancelled_from_outside() -> tokio_util::task::AbortOnDropHandle<crate::Result<()>> {
    let task = tokio::spawn(std::future::pending::<crate::Result<()>>());
    task.abort_handle().abort();
    tokio_util::task::AbortOnDropHandle::new(task)
}

fn is_a_cancel(cause: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    cause
        .downcast_ref::<tokio::task::JoinError>()
        .is_some_and(tokio::task::JoinError::is_cancelled)
}

/// An inner task the runtime cancelled was dropped, not stopped: its child may still run. The tap reports that, and
/// does not panic, when it stops the inner.
#[skuld::test]
async fn an_inner_cancelled_by_the_runtime_is_an_unconfirmed_stop_when_the_tap_stops_it() {
    let inner = an_inner_cancelled_from_outside();

    let stopped = crate::tap::stop_inner("cancelled-stub", &CancellationToken::new(), inner).await;

    match stopped {
        Some(crate::Error::StopUnconfirmed { plugins, cause }) => {
            assert_eq!(plugins, ["cancelled-stub"]);
            assert!(is_a_cancel(&*cause), "{cause:?}");
        }
        other => panic!("want an unconfirmed stop, got {other:?}"),
    }
}

/// The same inner, met while the tap awaits it for its result.
#[skuld::test]
async fn an_inner_cancelled_by_the_runtime_is_an_unconfirmed_stop_when_the_tap_awaits_it() {
    let joined = an_inner_cancelled_from_outside().await;

    let result = crate::tap::join_result("cancelled-stub", joined);

    match result {
        Err(crate::Error::StopUnconfirmed { plugins, cause }) => {
            assert_eq!(plugins, ["cancelled-stub"]);
            assert!(is_a_cancel(&*cause), "{cause:?}");
        }
        other => panic!("want an unconfirmed stop, got {other:?}"),
    }
}

/// The tap's own abort of an inner that ignores its stop is still the drain-bound error, not a runtime cancel.
#[skuld::test]
async fn an_inner_the_tap_aborts_keeps_the_stop_bound_as_its_cause() {
    tokio::time::pause();
    let inner = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(std::future::pending::<crate::Result<()>>()));

    let stopped = crate::tap::stop_inner("ignores-stop-stub", &CancellationToken::new(), inner).await;

    match stopped {
        Some(crate::Error::StopUnconfirmed { plugins, cause }) => {
            assert_eq!(plugins, ["ignores-stop-stub"]);
            assert!(cause.to_string().contains("did not stop within"), "{cause}");
        }
        other => panic!("want an unconfirmed stop, got {other:?}"),
    }
}

// A start failure the inner's error outranks --------------------------------------------------------------------------

/// The tap's own failure is the one error nobody else has logged: it is logged when the inner's error outranks it, and
/// not when it is the one returned (the chain logs that).
#[skuld::test]
fn the_taps_own_failure_is_logged_only_when_the_inners_error_outranks_it() {
    let (subscriber, writer) = make_debug_subscriber();
    let _g = set_default_in_current_thread(subscriber);
    let refused = || crate::Error::PidSink {
        plugin: "inner".into(),
        cause: "no".into(),
    };

    let kept = crate::tap::after_stop(crate::Error::Chain("own-lost-nothing".into()), None);
    let kept_over_ordinary = crate::tap::after_stop(
        crate::Error::Chain("own-stands".into()),
        Some(crate::Error::PluginKilled { name: "inner".into() }),
    );
    assert!(matches!(kept, crate::Error::Chain(_)) && matches!(kept_over_ordinary, crate::Error::Chain(_)));
    assert_eq!(writer.snapshot(), "");

    let outranked = crate::tap::after_stop(crate::Error::Chain("own-outranked".into()), Some(refused()));
    assert!(matches!(outranked, crate::Error::PidSink { .. }), "{outranked:?}");
    let log = writer.snapshot();
    assert!(
        log.lines().any(|l| l.contains("WARN") && l.contains("own-outranked")),
        "the outranked failure was not logged:\n{log}"
    );
}

/// An equal rank does not outrank: the tap's own error stands, so it is not logged as outranked.
#[skuld::test]
fn an_inner_of_equal_rank_does_not_outrank_the_taps_own_failure() {
    let (subscriber, writer) = make_debug_subscriber();
    let _g = set_default_in_current_thread(subscriber);
    let refused = |plugin: &str| crate::Error::PidSink {
        plugin: plugin.into(),
        cause: "no".into(),
    };

    let kept = crate::tap::after_stop(refused("own"), Some(refused("inner")));

    assert!(
        matches!(&kept, crate::Error::PidSink { plugin, .. } if plugin == "own"),
        "{kept:?}"
    );
    assert_eq!(writer.snapshot(), "");
}

/// The error an inner ends with while the tap reports its own failure is dropped when it does not outrank, so it is
/// logged where it is taken, at a level the default filter shows.
#[skuld::test]
async fn an_inner_error_the_tap_takes_is_logged_at_warn() {
    let (subscriber, writer) = make_debug_subscriber();
    let _g = set_default_in_current_thread(subscriber);
    let inner = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async {
        Err::<(), _>(crate::Error::Chain("inner-ended-marker".into()))
    }));

    let stopped = crate::tap::stop_inner("inner-stub", &CancellationToken::new(), inner).await;

    assert!(stopped.is_some());
    let log = writer.snapshot();
    assert!(
        log.lines()
            .any(|l| l.contains("WARN") && l.contains("inner-ended-marker")),
        "the inner's error was not logged at warn:
{log}"
    );
}
