// `CancellationToken::new` is the test harness's gate, never a bridge cancel scope.
#![allow(clippy::disallowed_methods)]

// A start failure a member has decided reaches the caller as that failure ---------------------------------------------
//
// Every way the chain can end while a member still holds the failure it decided: what the caller's `ready` receives
// is the typed failure, and only after every member has returned. A `BinaryPlugin` holds its failure through its own
// take-down (grace, tree kill, output drain), so the chain's end can land inside that window.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::chain::{allocate_ports, ChainRunner};
use crate::chain_tests::{test_env, DRAIN, IDLE};
use crate::plugin::ChainPlugin;
use crate::sitrep::{PluginReady, StartError, Transports};

type Ready = oneshot::Sender<Result<PluginReady, StartError>>;

fn bind_conflict() -> StartError {
    StartError::BindConflict {
        errno: 98,
        addr: "127.0.0.1:1080".parse().unwrap(),
    }
}

/// Sends `error` on `ready` when dropped, which is what a `BinaryPlugin`'s held failure does whenever the plugin's end
/// comes: it returns, unwinds, or its task is aborted.
struct Held {
    ready: Option<Ready>,
    error: Option<StartError>,
}

impl Drop for Held {
    fn drop(&mut self) {
        if let (Some(ready), Some(error)) = (self.ready.take(), self.error.take()) {
            let _ = ready.send(Err(error));
        }
    }
}

/// How a [`HoldsFailure`] member ends.
#[derive(Clone)]
enum Finish {
    /// Returns an error once the gate opens.
    Returns(CancellationToken),
    /// Panics once the gate opens.
    Panics(CancellationToken),
    /// Never ends by itself and ignores `shutdown`: only an abort ends it.
    Never,
}

/// A member whose start failed. It has decided the failure and holds the report until it ends.
struct HoldsFailure {
    finish: Finish,
}

#[async_trait::async_trait]
impl ChainPlugin for HoldsFailure {
    fn name(&self) -> &str {
        "holds-failure"
    }

    async fn run(
        self: Box<Self>,
        _local: SocketAddr,
        _remote: SocketAddr,
        _shutdown: CancellationToken,
        ready: Ready,
    ) -> crate::Result<()> {
        let _held = Held {
            ready: Some(ready),
            error: Some(bind_conflict()),
        };
        match self.finish {
            Finish::Returns(gate) => {
                gate.cancelled().await;
                Err(crate::Error::PluginExit {
                    name: "holds-failure".into(),
                    code: 4,
                })
            }
            Finish::Panics(gate) => {
                gate.cancelled().await;
                panic!("the holder panicked");
            }
            Finish::Never => std::future::pending().await,
        }
    }
}

/// What ends the chain from a sibling, or from outside.
#[derive(Clone, Copy, Debug)]
enum Cause {
    /// A sibling returns `Ok(())`.
    SiblingExits,
    /// A sibling returns an error.
    SiblingFails,
    /// A sibling panics.
    SiblingPanics,
    /// The caller's cancel token fires.
    ExternalCancel,
}

struct CauseMember {
    cause: Cause,
    /// The aggregator awaits members in order: a member in front of the holder must have readied.
    ready_first: bool,
}

#[async_trait::async_trait]
impl ChainPlugin for CauseMember {
    fn name(&self) -> &str {
        "cause"
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        ready: Ready,
    ) -> crate::Result<()> {
        if self.ready_first {
            let _ = ready.send(Ok(PluginReady {
                listen: local,
                transports: Transports::TCP,
            }));
        }
        match self.cause {
            Cause::SiblingExits => Ok(()),
            Cause::SiblingFails => Err(crate::Error::PluginExit {
                name: "cause".into(),
                code: 3,
            }),
            Cause::SiblingPanics => panic!("the sibling panicked"),
            Cause::ExternalCancel => {
                shutdown.cancelled().await;
                Ok(())
            }
        }
    }
}

/// A healthy member that, once stopped, holds a last line back until `gate` opens.
struct Drainer {
    gate: CancellationToken,
    stopped: oneshot::Sender<()>,
    relayed: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ChainPlugin for Drainer {
    fn name(&self) -> &str {
        "drainer"
    }

    async fn run(
        self: Box<Self>,
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
        let _ = self.stopped.send(());
        self.gate.cancelled().await;
        self.relayed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn start(
    members: Vec<Box<dyn ChainPlugin>>,
    cancel: CancellationToken,
) -> (
    oneshot::Receiver<Result<crate::ChainReady, StartError>>,
    tokio::task::JoinHandle<crate::Result<()>>,
) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let mut runner = ChainRunner::new();
    for member in members {
        runner = runner.add(member);
    }
    let runner = runner.cancel_token(cancel).drain_timeout(DRAIN).on_ready(ready_tx);
    let mut env = test_env();
    env.local_port = allocate_ports(1).unwrap().pop().unwrap().port();
    (ready_rx, tokio::spawn(runner.run(env)))
}

/// How the holder ends, as a row of the table below.
#[derive(Clone, Copy, Debug)]
enum HolderEnd {
    /// Returns an error once the drainer's gate opens.
    Returns,
    /// Panics once the gate opens.
    Panics,
    /// Never ends by itself: only the drain bound aborts it.
    Aborted,
}

/// One end of a chain that holds a decided failure: where the holder sits, what ends the chain, how the holder ends.
#[derive(Clone, Copy, Debug)]
struct Row {
    holder_at: usize,
    cause: Cause,
    holder_ends: HolderEnd,
}

/// Runs a chain of the holder, the cause and a [`Drainer`] and checks what the caller's `ready` gets. `Err` names the
/// first thing that went wrong, so the table reports every failing row, not the first.
async fn run_row(row: Row) -> Result<(), String> {
    let Row {
        holder_at,
        cause,
        holder_ends,
    } = row;
    let gate = CancellationToken::new();
    let cancel = CancellationToken::new();
    let (stopped_tx, mut stopped_rx) = oneshot::channel();
    let relayed = Arc::new(AtomicBool::new(false));
    let finish = match holder_ends {
        HolderEnd::Returns => Finish::Returns(gate.clone()),
        HolderEnd::Panics => Finish::Panics(gate.clone()),
        HolderEnd::Aborted => Finish::Never,
    };
    let holder: Box<dyn ChainPlugin> = Box::new(HoldsFailure { finish });
    let causer: Box<dyn ChainPlugin> = Box::new(CauseMember {
        cause,
        ready_first: holder_at == 1,
    });
    let mut members = if holder_at == 0 {
        vec![holder, causer]
    } else {
        vec![causer, holder]
    };
    // A holder that is aborted at the drain bound has no gate to wait for, so no drainer either.
    let drains = !matches!(holder_ends, HolderEnd::Aborted);
    if drains {
        members.push(Box::new(Drainer {
            gate: gate.clone(),
            stopped: stopped_tx,
            relayed: relayed.clone(),
        }));
    }
    let (mut ready_rx, handle) = start(members, cancel.clone());
    if matches!(cause, Cause::ExternalCancel) {
        cancel.cancel();
    }

    if drains {
        tokio::select! {
            biased;
            r = &mut ready_rx => return Err(format!("the caller was told ({r:?}) before the drainer was stopped")),
            _ = &mut stopped_rx => {}
        }
        tokio::select! {
            biased;
            r = &mut ready_rx => return Err(format!("the caller was told ({r:?}) while the drainer held its last line")),
            () = tokio::time::sleep(IDLE) => {}
        }
        gate.cancel();
    }
    let reported = ready_rx.await;
    if !matches!(&reported, Ok(Err(StartError::BindConflict { errno: 98, .. }))) {
        return Err(format!("the decided failure was lost: {reported:?}"));
    }
    if drains && !relayed.load(Ordering::SeqCst) {
        return Err("told before the drainer relayed its last line".into());
    }
    let result = handle.await.map_err(|e| format!("the chain task panicked: {e}"))?;
    match (holder_ends, result) {
        (HolderEnd::Aborted, Err(crate::Error::Chain(m))) if m.contains("drain timeout") => Ok(()),
        (HolderEnd::Aborted, other) => Err(format!("run must end at the drain bound: {other:?}")),
        (_, Err(_)) => Ok(()),
        (_, Ok(())) => Err("run returned Ok for a chain whose holder failed".into()),
    }
}

/// Every end of a chain that holds a decided failure: the caller's `ready` gets the typed failure, after every other
/// member has returned.
#[skuld::test]
async fn a_decided_failure_reaches_the_caller_whichever_way_the_chain_ends() {
    tokio::time::pause();
    let mut rows = Vec::new();
    for holder_at in [0, 1] {
        for cause in [
            Cause::SiblingExits,
            Cause::SiblingFails,
            Cause::SiblingPanics,
            Cause::ExternalCancel,
        ] {
            rows.push(Row {
                holder_at,
                cause,
                holder_ends: HolderEnd::Returns,
            });
        }
        // The holder's own end is the other way a chain ends with the failure undelivered: unwinding, or the abort at
        // `drain_timeout`; the sibling's exit is what cancels the chain.
        for holder_ends in [HolderEnd::Panics, HolderEnd::Aborted] {
            rows.push(Row {
                holder_at,
                cause: Cause::SiblingExits,
                holder_ends,
            });
        }
    }

    let mut failures = Vec::new();
    for row in rows {
        if let Err(why) = run_row(row).await {
            failures.push(format!("{row:?}: {why}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} rows failed:
{}",
        failures.len(),
        failures.join(
            "
"
        )
    );
}
