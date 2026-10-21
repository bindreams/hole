// `CancellationToken::new` is the test harness's gate, never a bridge cancel scope.
#![allow(clippy::disallowed_methods)]

// What `ChainRunner::run` returns when a start failed -----------------------------------------------------------------
//
// `run` errs whenever any hop failed to start, and cancels the chain for it, whether or not the caller registered
// `on_ready`. The error is the typed failure, so a caller with no callback can still match it.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::chain::ChainRunner;
use crate::chain_tests::test_env;
use crate::once::Once;
use crate::plugin::ChainPlugin;
use crate::port::free_loopback_port;
use crate::sitrep::{PluginReady, StartError, Transports};
use crate::ChainReady;

type Ready = oneshot::Sender<Result<PluginReady, StartError>>;

/// How the failing member's start fails.
#[derive(Clone, Copy, Debug)]
enum Failure {
    /// Reports a typed `Fatal`.
    Fatal,
    /// Reports a bind conflict. The chain re-runs a hop that loses an intermediate port, so this one is always the
    /// public hop.
    PublicBindConflict,
    /// Drops `ready` unsent.
    Dropped,
}

/// What the failing member does after it reported.
#[derive(Clone, Copy, Debug)]
enum Ends {
    /// Returns an error.
    ReturnsErr,
    /// Returns `Ok(())`.
    ReturnsOk,
    /// Runs until it is stopped, then returns `Ok(())`.
    KeepsRunning,
}

/// Where the failing member starts.
#[derive(Clone, Copy, Debug)]
enum Position {
    /// First. A bind conflict is the public hop's, so that chain is the failing member alone; the others have a member
    /// behind it that must never start.
    First,
    /// After a member that is ready and running, as the public hop.
    Later,
}

struct Fails {
    failure: Failure,
    ends: Ends,
}

#[async_trait::async_trait]
impl ChainPlugin for Fails {
    fn name(&self) -> &str {
        "failing"
    }

    async fn run(
        &self,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: Ready,
    ) -> crate::Result<()> {
        match self.failure {
            Failure::Fatal => {
                let _ = ready.send(Err(StartError::Fatal {
                    detail: "member broke".into(),
                    errno: Some(7),
                }));
            }
            Failure::PublicBindConflict => {
                let _ = ready.send(Err(StartError::BindConflict { errno: 98, addr: local }));
            }
            Failure::Dropped => drop(ready),
        }
        match self.ends {
            Ends::ReturnsErr => Err(crate::Error::PluginExit {
                name: "failing".into(),
                code: 3,
            }),
            Ends::ReturnsOk => Ok(()),
            Ends::KeepsRunning => {
                shutdown.cancelled().await;
                Ok(())
            }
        }
    }
}

/// Ready and running; records that it was told to stop.
struct Healthy {
    stopped: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ChainPlugin for Healthy {
    fn name(&self) -> &str {
        "healthy"
    }

    async fn run(
        &self,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: Ready,
    ) -> crate::Result<()> {
        let _ = ready.send(Ok(PluginReady {
            listen: local,
            transports: Transports::TCP,
        }));
        shutdown.cancelled().await;
        self.stopped.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// Records that it was started.
struct Unstarted {
    entered: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ChainPlugin for Unstarted {
    fn name(&self) -> &str {
        "unstarted"
    }

    async fn run(&self, _: SocketAddr, _: SocketAddr, _: CancellationToken, _: Ready) -> crate::Result<()> {
        self.entered.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// What a run of one chain left behind.
struct Outcome {
    result: crate::Result<()>,
    /// What `on_ready` got, when one was registered.
    heard: Option<Result<Result<ChainReady, StartError>, oneshot::error::RecvError>>,
    /// The running member behind the failing one was told to stop.
    healthy_stopped: Option<bool>,
    /// The member behind the failing one was started.
    unstarted_entered: Option<bool>,
}

/// Runs a client-mode chain around a failing member and reads what it left.
async fn run_chain(failure: Failure, position: Position, ends: Ends, on_ready: bool) -> Outcome {
    let healthy_stopped = Arc::new(AtomicBool::new(false));
    let unstarted_entered = Arc::new(AtomicBool::new(false));
    let failing: Box<dyn ChainPlugin> = Box::new(Fails { failure, ends });
    // In plugin order; a client-mode chain starts the last one first.
    let (members, healthy, unstarted): (Vec<Box<dyn ChainPlugin>>, bool, bool) = match (position, failure) {
        (Position::First, Failure::PublicBindConflict) => (vec![failing], false, false),
        (Position::First, _) => (
            vec![
                Box::new(Unstarted {
                    entered: unstarted_entered.clone(),
                }),
                failing,
            ],
            false,
            true,
        ),
        (Position::Later, _) => (
            vec![
                failing,
                Box::new(Healthy {
                    stopped: healthy_stopped.clone(),
                }),
            ],
            true,
            false,
        ),
    };
    let mut runner = ChainRunner::new();
    for member in members {
        runner = runner.add(member);
    }
    let ready_rx = on_ready.then(|| {
        let (tx, rx) = oneshot::channel();
        runner = std::mem::take(&mut runner).on_ready(tx);
        rx
    });
    let mut env = test_env();
    env.local_port = free_loopback_port().port();

    let result = runner.run(env).await;
    let heard = match ready_rx {
        Some(rx) => Some(rx.await),
        None => None,
    };
    Outcome {
        result,
        heard,
        healthy_stopped: healthy.then(|| healthy_stopped.load(Ordering::SeqCst)),
        unstarted_entered: unstarted.then(|| unstarted_entered.load(Ordering::SeqCst)),
    }
}

/// Whether `cause` is what `failure` reports, as the spec words it: a typed failure as sent, and an exit without a
/// report as the chain's "exited before becoming ready".
fn is_reported(failure: Failure, cause: &StartError) -> bool {
    match (failure, cause) {
        (Failure::Fatal, StartError::Fatal { detail, errno: Some(7) }) => detail == "member broke",
        (Failure::PublicBindConflict, StartError::BindConflict { errno: 98, .. }) => true,
        (Failure::Dropped, StartError::Fatal { detail, .. }) => detail.contains("exited before becoming ready"),
        _ => false,
    }
}

/// `Err` names the first thing wrong with a run, so a table reports every failing row.
fn check(failure: Failure, outcome: &Outcome) -> Result<(), String> {
    match &outcome.result {
        Err(crate::Error::StartFailed { plugin, cause }) if plugin == "failing" && is_reported(failure, cause) => {}
        other => return Err(format!("run returned {other:?}")),
    }
    if let Some(heard) = &outcome.heard {
        if !matches!(heard, Ok(Err(cause)) if is_reported(failure, cause)) {
            return Err(format!("on_ready got {heard:?}"));
        }
    }
    if outcome.healthy_stopped == Some(false) {
        return Err("the running member was never told to stop".into());
    }
    if outcome.unstarted_entered == Some(true) {
        return Err("the member behind the failing one was started".into());
    }
    Ok(())
}

fn rows(ends: Ends, on_ready: &[bool]) -> Vec<(Failure, Position, Ends, bool)> {
    let mut rows = Vec::new();
    for failure in [Failure::Fatal, Failure::PublicBindConflict, Failure::Dropped] {
        for position in [Position::First, Position::Later] {
            for &on_ready in on_ready {
                rows.push((failure, position, ends, on_ready));
            }
        }
    }
    rows
}

async fn assert_every_row_errs(rows: Vec<(Failure, Position, Ends, bool)>) {
    let mut failures = Vec::new();
    for (failure, position, ends, on_ready) in rows {
        let outcome = run_chain(failure, position, ends, on_ready).await;
        if let Err(why) = check(failure, &outcome) {
            failures.push(format!("{failure:?} {position:?} {ends:?} on_ready={on_ready}: {why}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} rows failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The table: `run` returns the typed failure, the others were cancelled, and a registered callback got the same one.
#[skuld::test]
async fn run_returns_the_start_failure_whichever_hop_failed_and_however_the_caller_listens() {
    assert_every_row_errs(rows(Ends::ReturnsErr, &[true, false])).await;
}

/// A member that reports a failure and then returns `Ok(())` still fails `run`: the failure is the member's report,
/// not its exit.
#[skuld::test]
async fn a_start_failure_from_a_member_that_returns_ok_still_fails_run() {
    assert_every_row_errs(rows(Ends::ReturnsOk, &[true, false])).await;
}

/// With no `on_ready` to read the failure, the chain is still cancelled for it: a member that reports and then keeps
/// running does not leave the chain up.
#[skuld::test]
async fn a_member_that_sends_err_and_keeps_running_is_cancelled_without_on_ready() {
    assert_every_row_errs(rows(Ends::KeepsRunning, &[false])).await;
}

/// A hop that never readies and returns when the caller cancels did not fail to start.
#[skuld::test]
async fn a_shutdown_before_ready_is_not_a_failure() {
    struct Holds {
        running: Once<oneshot::Sender<()>>,
    }

    #[async_trait::async_trait]
    impl ChainPlugin for Holds {
        fn name(&self) -> &str {
            "holds"
        }

        async fn run(
            &self,
            _: SocketAddr,
            _: SocketAddr,
            shutdown: CancellationToken,
            _ready: Ready,
        ) -> crate::Result<()> {
            let _ = self.running.take().send(());
            shutdown.cancelled().await;
            Ok(())
        }
    }

    for on_ready in [true, false] {
        let (running_tx, running_rx) = oneshot::channel();
        let cancel = CancellationToken::new();
        let mut runner = ChainRunner::new()
            .add(Box::new(Holds {
                running: Once::new(running_tx),
            }))
            .cancel_token(cancel.clone());
        let ready_rx = on_ready.then(|| {
            let (tx, rx) = oneshot::channel();
            runner = std::mem::take(&mut runner).on_ready(tx);
            rx
        });
        let mut env = test_env();
        env.local_port = free_loopback_port().port();
        let handle = tokio::spawn(runner.run(env));

        running_rx.await.expect("the member ran");
        cancel.cancel();

        let result = handle.await.unwrap();
        assert!(
            result.is_ok(),
            "on_ready={on_ready}: a cancel before ready is no failure: {result:?}"
        );
        if let Some(ready_rx) = ready_rx {
            assert!(ready_rx.await.is_err(), "on_ready={on_ready}: nothing to report");
        }
    }
}
