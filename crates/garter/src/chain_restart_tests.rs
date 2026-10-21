//! A hop that loses its intermediate port is run again, alone, on a fresh port.

// `CancellationToken::new` is the cancel-test harness root.
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{oneshot, Notify};
use tokio_util::sync::CancellationToken;

use crate::chain::{ChainReady, ChainRunner};
use crate::plugin::ChainPlugin;
use crate::port::{os_probe, Probe};
use crate::sip003::PluginEnv;
use crate::sitrep::{PluginReady, StartError, Transports};
use crate::tap::TapPlugin;
use crate::tap_tests::addr;

const SS_LOCAL: u16 = 41000;
const SS_REMOTE: u16 = 41999;
/// The first port the probe hands out; each pick after it is the next one up.
const FIRST_PICK: u16 = 42001;

/// What a hop or the probe did, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Picked(u16),
    Entered(&'static str),
    Conflicted(&'static str),
    Stopped(&'static str),
    ReadySent(&'static str),
}

/// What one run of a hop does.
#[derive(Clone)]
enum Attempt {
    /// Readies and runs until it is stopped.
    Ready,
    /// Reports a bind conflict (on `addr`, or on its own listen address) and returns.
    Conflict { addr: Option<SocketAddr> },
    /// Reports a bind conflict, keeps running until it is stopped, and notes that it stopped.
    ConflictThenLinger,
    /// Returns, and sends its bind conflict while it is being dropped, as a `BinaryPlugin` does at the end of its
    /// take-down.
    ConflictFromDrop,
    /// Reports a fatal failure and returns.
    Fatal,
    /// Binds its listen address for real: readies if it binds, reports the OS's bind conflict if the port is taken.
    RealBind,
}

/// One run of a hop.
struct Run {
    local: SocketAddr,
    remote: SocketAddr,
    token: CancellationToken,
}

#[derive(Default)]
struct Rig {
    trace: Mutex<Vec<Event>>,
    runs: Mutex<HashMap<&'static str, Vec<Run>>>,
}

impl Rig {
    fn new() -> Arc<Self> {
        Arc::default()
    }

    fn push(&self, event: Event) {
        self.trace.lock().unwrap().push(event);
    }

    fn trace(&self) -> Vec<Event> {
        self.trace.lock().unwrap().clone()
    }

    /// The `(local, remote)` of each run of `name`, in order.
    fn wiring(&self, name: &'static str) -> Vec<(SocketAddr, SocketAddr)> {
        let runs = self.runs.lock().unwrap();
        runs.get(name)
            .map(|runs| runs.iter().map(|run| (run.local, run.remote)).collect())
            .unwrap_or_default()
    }

    fn tokens(&self, name: &'static str) -> Vec<CancellationToken> {
        let runs = self.runs.lock().unwrap();
        runs.get(name)
            .map(|runs| runs.iter().map(|run| run.token.clone()).collect())
            .unwrap_or_default()
    }

    /// A hop that behaves as `behave` says for its n-th run (counting from 0).
    fn hop(
        self: &Arc<Self>,
        name: &'static str,
        behave: impl Fn(usize) -> Attempt + Send + Sync + 'static,
    ) -> Box<dyn ChainPlugin> {
        Box::new(Hop {
            name,
            behave: Box::new(behave),
            rig: self.clone(),
        })
    }

    /// A hop that readies on every run.
    fn steady(self: &Arc<Self>, name: &'static str) -> Box<dyn ChainPlugin> {
        self.hop(name, |_| Attempt::Ready)
    }

    /// A hop whose first `runs.len()` runs are `runs` and whose later ones ready.
    fn hop_that_starts_with(self: &Arc<Self>, name: &'static str, runs: Vec<Attempt>) -> Box<dyn ChainPlugin> {
        self.hop(name, move |n| runs.get(n).cloned().unwrap_or(Attempt::Ready))
    }

    /// A probe that hands out `FIRST_PICK`, `FIRST_PICK + 1`, and so on, and logs each pick in the trace.
    fn probe(self: &Arc<Self>) -> Probe {
        let rig = self.clone();
        let mut next = FIRST_PICK;
        Box::new(move || {
            rig.push(Event::Picked(next));
            next += 1;
            Ok(addr(next - 1))
        })
    }
}

struct Hop {
    name: &'static str,
    behave: Box<dyn Fn(usize) -> Attempt + Send + Sync>,
    rig: Arc<Rig>,
}

/// Sends `outcome` on `ready` when it is dropped.
struct SendOnDrop {
    ready: Option<oneshot::Sender<Result<PluginReady, StartError>>>,
    outcome: Option<StartError>,
}

impl Drop for SendOnDrop {
    fn drop(&mut self) {
        let _ = self.ready.take().unwrap().send(Err(self.outcome.take().unwrap()));
    }
}

fn bind_conflict(addr: SocketAddr) -> StartError {
    StartError::BindConflict { errno: 98, addr }
}

#[async_trait::async_trait]
impl ChainPlugin for Hop {
    fn name(&self) -> &str {
        self.name
    }

    async fn run(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let n = {
            let mut runs = self.rig.runs.lock().unwrap();
            let runs = runs.entry(self.name).or_default();
            runs.push(Run {
                local,
                remote,
                token: shutdown.clone(),
            });
            runs.len() - 1
        };
        self.rig.push(Event::Entered(self.name));
        let report = PluginReady {
            listen: local,
            transports: Transports::TCP,
        };
        match (self.behave)(n) {
            Attempt::Ready => {
                self.rig.push(Event::ReadySent(self.name));
                let _ = ready.send(Ok(report));
                shutdown.cancelled().await;
            }
            Attempt::Conflict { addr } => {
                self.rig.push(Event::Conflicted(self.name));
                let _ = ready.send(Err(bind_conflict(addr.unwrap_or(local))));
            }
            Attempt::ConflictThenLinger => {
                self.rig.push(Event::Conflicted(self.name));
                let _ = ready.send(Err(bind_conflict(local)));
                shutdown.cancelled().await;
                // A take-down takes a scheduler turn, so a restart that does not wait for it shows in the trace.
                tokio::task::yield_now().await;
                self.rig.push(Event::Stopped(self.name));
            }
            Attempt::ConflictFromDrop => {
                self.rig.push(Event::Conflicted(self.name));
                let _guard = SendOnDrop {
                    ready: Some(ready),
                    outcome: Some(bind_conflict(local)),
                };
            }
            Attempt::Fatal => {
                let _ = ready.send(Err(StartError::Fatal {
                    detail: "injected".into(),
                    errno: None,
                }));
            }
            Attempt::RealBind => match std::net::TcpListener::bind(local) {
                Ok(_listener) => {
                    self.rig.push(Event::ReadySent(self.name));
                    let _ = ready.send(Ok(report));
                    shutdown.cancelled().await;
                }
                // A fresh port can fail `PermissionDenied` on Windows; the product restarts on that too.
                Err(e) if crate::port::is_port_race(&e) => {
                    self.rig.push(Event::Conflicted(self.name));
                    let errno = e.raw_os_error().expect("a bind failure carries an errno");
                    let _ = ready.send(Err(StartError::BindConflict { errno, addr: local }));
                }
                Err(e) => panic!("the bind failed for a reason that is not a conflict: {e}"),
            },
        }
        Ok(())
    }
}

fn env() -> PluginEnv {
    PluginEnv {
        local_host: "127.0.0.1".parse().unwrap(),
        local_port: SS_LOCAL,
        remote_host: "127.0.0.1".into(),
        remote_port: SS_REMOTE,
        plugin_options: None,
    }
}

/// A chain that was started and is reporting through `ready`.
struct Launched {
    ready: oneshot::Receiver<Result<ChainReady, StartError>>,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<crate::Result<()>>,
}

fn launch(runner: ChainRunner) -> Launched {
    let (ready_tx, ready) = oneshot::channel();
    let cancel = CancellationToken::new();
    let runner = runner.on_ready(ready_tx).cancel_token(cancel.clone());
    Launched {
        ready,
        cancel,
        handle: tokio::spawn(runner.run(env())),
    }
}

impl Launched {
    /// Waits for the caller's verdict, stops the chain, and returns the verdict and what `run` returned.
    async fn finish(self) -> (Result<ChainReady, StartError>, crate::Result<()>) {
        let told = self.ready.await.expect("the chain closed `on_ready` without a verdict");
        self.cancel.cancel();
        (told, self.handle.await.expect("the chain task panicked"))
    }
}

#[skuld::test]
async fn a_hop_that_loses_its_intermediate_port_is_restarted_on_a_fresh_port() {
    tokio::time::pause();
    let rig = Rig::new();
    let conflicts = vec![Attempt::Conflict { addr: None }; 5];
    let runner = ChainRunner::new()
        .add(rig.steady("A"))
        .add(rig.hop_that_starts_with("B", conflicts))
        .with_probe(rig.probe());

    let (told, result) = launch(runner).finish().await;

    told.expect("the chain readies once B finds a port");
    result.expect("a stop is a clean end");
    let picks: Vec<u16> = (FIRST_PICK..FIRST_PICK + 6).collect();
    assert_eq!(
        rig.wiring("B"),
        picks
            .iter()
            .map(|&port| (addr(port), addr(SS_REMOTE)))
            .collect::<Vec<_>>(),
        "B ran six times, on a fresh port each time, forwarding to the destination"
    );
    assert_eq!(
        rig.wiring("A"),
        [(addr(SS_LOCAL), addr(FIRST_PICK + 5))],
        "A ran once, forwarding to the port B finally got"
    );
}

/// The conflict is the OS's own: the port the first pick returned is held by someone else. The second pick comes from
/// the chain's own OS probe, so another process taking it is one more retry, not a failure of the test.
#[skuld::test]
async fn a_real_os_conflict_is_retried() {
    tokio::time::pause();
    let rig = Rig::new();
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let held_addr = held.local_addr().unwrap();
    let mut first = Some(held_addr);
    let mut os = os_probe(Ipv4Addr::LOCALHOST.into());
    let probe: Probe = Box::new(move || match first.take() {
        Some(held) => Ok(held),
        None => os(),
    });
    let runner = ChainRunner::new()
        .add(rig.steady("A"))
        .add(rig.hop("B", |_| Attempt::RealBind))
        .with_probe(probe);

    let (told, _) = launch(runner).finish().await;

    told.expect("the chain readies on a port nobody holds");
    let b = rig.wiring("B").into_iter().map(|(local, _)| local).collect::<Vec<_>>();
    assert_eq!(b[0], held_addr, "B was first given the held port");
    let last = *b.last().unwrap();
    assert_ne!(last, held_addr, "B readied on another port");
    assert_eq!(rig.wiring("A")[0].1, last, "A forwards to the port B finally got");
    drop(held);
}

#[skuld::test]
async fn only_the_hop_that_lost_its_port_is_restarted() {
    tokio::time::pause();
    let rig = Rig::new();
    let runner = ChainRunner::new()
        .add(rig.steady("A"))
        .add(rig.hop_that_starts_with("B", vec![Attempt::ConflictThenLinger]))
        .add(rig.steady("C"))
        .with_probe(rig.probe());
    let launched = launch(runner);

    let told = launched.ready.await.expect("a verdict");
    told.expect("the chain readies");

    assert_eq!(
        rig.trace(),
        [
            Event::Picked(FIRST_PICK),
            Event::Entered("C"),
            Event::ReadySent("C"),
            Event::Picked(FIRST_PICK + 1),
            Event::Entered("B"),
            Event::Conflicted("B"),
            Event::Stopped("B"),
            Event::Picked(FIRST_PICK + 2),
            Event::Entered("B"),
            Event::ReadySent("B"),
            Event::Entered("A"),
            Event::ReadySent("A"),
        ],
        "A starts only after B's final ready"
    );
    let c = rig.tokens("C");
    assert_eq!(c.len(), 1, "C ran once");
    assert!(!c[0].is_cancelled(), "C was never stopped");
    assert_eq!(rig.wiring("A").len(), 1, "A ran once");
    let b = rig.tokens("B");
    assert_eq!(b.len(), 2, "B ran twice");
    assert!(b[0].is_cancelled(), "the failed attempt was stopped");
    assert!(!b[1].is_cancelled(), "the live attempt was not");

    launched.cancel.cancel();
    launched.handle.await.unwrap().expect("a stop is a clean end");
}

/// The tap reports the conflict of its inner plugin's port, which is not the address the chain gave the tap.
#[skuld::test]
async fn a_conflict_reported_for_another_address_is_still_retried() {
    tokio::time::pause();
    let rig = Rig::new();
    let elsewhere = addr(43000);
    let runner = ChainRunner::new()
        .add(rig.steady("A"))
        .add(rig.hop_that_starts_with("B", vec![Attempt::Conflict { addr: Some(elsewhere) }]))
        .with_probe(rig.probe());

    let (told, _) = launch(runner).finish().await;

    told.expect("the chain readies");
    assert_eq!(rig.wiring("B").len(), 2, "B was restarted");
}

/// The production intermediate hop is a `TapPlugin` around the real plugin, and one `TapPlugin` value runs again after
/// its inner reported a conflict. The inner's conflict must reach the chain as the tap's own, and the second run must
/// start from scratch.
///
/// The tap binds a port the chain's OS probe picked, so another process taking it is one more restart of the tap, and
/// the inner runs once more. The assertions hold whatever the number of those.
#[skuld::test]
async fn a_tap_hop_whose_inner_loses_its_port_is_restarted_and_runs_again() {
    let rig = Rig::new();
    let runner = ChainRunner::new().add(rig.steady("A")).add(Box::new(TapPlugin::wrap(
        rig.hop_that_starts_with("B", vec![Attempt::Conflict { addr: None }]),
    )));

    let launched = launch(runner);
    let told = launched.ready.await.expect("a verdict");
    let ready = told.expect("the chain readies once the tap's inner finds a port");

    let trace = rig.trace();
    assert_eq!(
        trace[..2],
        [Event::Entered("B"), Event::Conflicted("B")],
        "the inner's conflict is the first thing that happens: {trace:?}"
    );
    let a_starts = trace.iter().position(|e| *e == Event::Entered("A")).expect("A started");
    assert_eq!(
        trace[a_starts..],
        [Event::Entered("A"), Event::ReadySent("A")],
        "nothing runs after A readies: {trace:?}"
    );
    assert_eq!(
        trace[a_starts - 1],
        Event::ReadySent("B"),
        "A started only after the tap's last run readied: {trace:?}"
    );
    let inner = rig.wiring("B");
    assert!(
        inner.len() >= 2,
        "the same tap value ran its inner again after the conflict: {inner:?}"
    );
    assert!(
        inner.iter().all(|&(_, remote)| remote == addr(SS_REMOTE)),
        "the inner forwards to the destination on every run: {inner:?}"
    );
    let a = rig.wiring("A");
    assert_eq!(a.len(), 1, "A ran once");
    let tap_listens = a[0].1;
    assert!(
        inner.iter().all(|&(local, _)| local != tap_listens),
        "A forwards to the tap's listener, not to its inner"
    );
    assert_eq!(ready.listen, addr(SS_LOCAL), "A is the public hop");
    tokio::net::TcpStream::connect(tap_listens)
        .await
        .expect("the tap's last run is listening where A forwards");

    launched.cancel.cancel();
    launched.handle.await.unwrap().expect("a stop is a clean end");
}

#[skuld::test]
async fn a_conflict_on_the_public_hop_is_reported_not_retried() {
    tokio::time::pause();
    let rig = Rig::new();
    let runner = ChainRunner::new()
        .add(rig.hop_that_starts_with("A", vec![Attempt::Conflict { addr: None }]))
        .add(rig.steady("B"))
        .with_probe(rig.probe());
    let launched = launch(runner);

    let told = launched.ready.await.expect("a verdict");
    // The chain ends itself on a start failure; this stops one that wrongly started.
    launched.cancel.cancel();
    let _ = launched.handle.await.expect("the chain task panicked");

    assert!(
        matches!(told, Err(StartError::BindConflict { .. })),
        "the caller owns the public port: {told:?}"
    );
    assert_eq!(rig.wiring("A").len(), 1, "the public hop ran once");
    assert_eq!(rig.wiring("B").len(), 1);
    assert!(rig.tokens("B")[0].is_cancelled(), "the chain was cancelled");
}

#[skuld::test]
async fn a_fatal_on_an_intermediate_hop_is_not_retried() {
    tokio::time::pause();
    let rig = Rig::new();
    let runner = ChainRunner::new()
        .add(rig.steady("A"))
        .add(rig.hop_that_starts_with("B", vec![Attempt::Fatal]))
        .with_probe(rig.probe());
    let launched = launch(runner);

    let told = launched.ready.await.expect("a verdict");
    launched.cancel.cancel();
    let _ = launched.handle.await.expect("the chain task panicked");

    assert!(matches!(told, Err(StartError::Fatal { .. })), "{told:?}");
    assert_eq!(rig.wiring("B").len(), 1, "a fatal start is not retried");
    assert_eq!(rig.wiring("A").len(), 0, "the hop behind it never started");
}

/// A `BinaryPlugin` holds its failure through its take-down and delivers it last.
#[skuld::test]
async fn a_failure_delivered_while_the_attempt_stops_is_read_before_the_exit() {
    tokio::time::pause();
    let rig = Rig::new();
    let runner = ChainRunner::new()
        .add(rig.steady("A"))
        .add(rig.hop_that_starts_with("B", vec![Attempt::ConflictFromDrop]))
        .with_probe(rig.probe());

    let (told, _) = launch(runner).finish().await;

    told.expect("the chain readies");
    assert_eq!(rig.wiring("B").len(), 2, "B was restarted, not reported");
}

#[skuld::test]
async fn a_failed_attempt_has_returned_before_the_hop_is_restarted() {
    tokio::time::pause();
    let rig = Rig::new();
    let runner = ChainRunner::new()
        .add(rig.steady("A"))
        .add(rig.hop_that_starts_with("B", vec![Attempt::ConflictThenLinger]))
        .with_probe(rig.probe());

    let (told, _) = launch(runner).finish().await;

    told.expect("the chain readies");
    assert_eq!(
        rig.trace(),
        [
            Event::Picked(FIRST_PICK),
            Event::Entered("B"),
            Event::Conflicted("B"),
            Event::Stopped("B"),
            Event::Picked(FIRST_PICK + 1),
            Event::Entered("B"),
            Event::ReadySent("B"),
            Event::Entered("A"),
            Event::ReadySent("A"),
        ]
    );
}

#[skuld::test]
async fn a_shutdown_ends_the_restart_loop() {
    tokio::time::pause();
    let rig = Rig::new();
    let third_run = Arc::new(Notify::new());
    let runs = Arc::new(AtomicUsize::new(0));
    let b = {
        let third_run = third_run.clone();
        let runs = runs.clone();
        rig.hop("B", move |n| {
            runs.fetch_add(1, Ordering::SeqCst);
            if n == 2 {
                third_run.notify_one();
            }
            Attempt::Conflict { addr: None }
        })
    };
    let runner = ChainRunner::new().add(rig.steady("A")).add(b).with_probe(rig.probe());
    let launched = launch(runner);

    third_run.notified().await;
    launched.cancel.cancel();

    launched
        .handle
        .await
        .expect("the chain task panicked")
        .expect("a shutdown is a clean end, however far the start got");
    assert!(
        launched.ready.await.is_err(),
        "a shutdown before ready tells the caller nothing, least of all a failure"
    );
    assert!(runs.load(Ordering::SeqCst) >= 3);
    assert_eq!(rig.wiring("A").len(), 0, "A never started");
}
