//! The order a chain starts its hops in, the addresses each is given, and how an intermediate port is picked.

// `CancellationToken::new` is the cancel-test harness root.
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{oneshot, Notify};
use tokio_util::sync::CancellationToken;

use crate::chain::{ChainReady, ChainRunner, Mode};
use crate::once::Once;
use crate::plugin::ChainPlugin;
use crate::port::Probe;
use crate::sip003::PluginEnv;
use crate::sitrep::{PluginReady, StartError, Transports};
use crate::tap_tests::{addr, err, scripted};

const SS_LOCAL: u16 = 41000;
const SS_REMOTE: u16 = 41999;
const P1: u16 = 42001;
const P2: u16 = 42002;

/// What a hop or the probe did, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Picked(u16),
    Entered(&'static str),
    ReadySent(&'static str),
}

type Trace = Arc<Mutex<Vec<Event>>>;

/// The `(local, remote)` each hop was run with.
type Wiring = Arc<Mutex<HashMap<&'static str, (SocketAddr, SocketAddr)>>>;

/// A hop that logs its start, records its wiring, readies, and runs until it is stopped.
struct Hop {
    name: &'static str,
    trace: Trace,
    wiring: Wiring,
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
        self.trace.lock().unwrap().push(Event::Entered(self.name));
        self.wiring.lock().unwrap().insert(self.name, (local, remote));
        // Takes a scheduler turn to ready, so hops started at once interleave in the trace.
        tokio::task::yield_now().await;
        self.trace.lock().unwrap().push(Event::ReadySent(self.name));
        let _ = ready.send(Ok(PluginReady {
            listen: local,
            transports: Transports::TCP,
        }));
        shutdown.cancelled().await;
        Ok(())
    }
}

/// A hop that signals it is running and never readies.
struct Unready {
    entered: Once<oneshot::Sender<()>>,
}

#[async_trait::async_trait]
impl ChainPlugin for Unready {
    fn name(&self) -> &str {
        "unready"
    }

    async fn run(
        &self,
        _local: SocketAddr,
        _remote: SocketAddr,
        shutdown: CancellationToken,
        _ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let _ = self.entered.take().send(());
        shutdown.cancelled().await;
        Ok(())
    }
}

struct Rig {
    trace: Trace,
    wiring: Wiring,
}

impl Rig {
    fn new() -> Self {
        Self {
            trace: Arc::default(),
            wiring: Arc::default(),
        }
    }

    fn hop(&self, name: &'static str) -> Box<dyn ChainPlugin> {
        Box::new(Hop {
            name,
            trace: self.trace.clone(),
            wiring: self.wiring.clone(),
        })
    }

    /// A probe that hands out `ports` in order.
    fn probe(&self, ports: &[u16]) -> Probe {
        let mut ports = Vec::from(ports).into_iter();
        Box::new(move || {
            Ok(addr(
                ports.next().expect("the probe was asked for more ports than it has"),
            ))
        })
    }

    /// Like [`Rig::probe`], and logs each pick in the trace.
    fn logging_probe(&self, ports: &[u16]) -> Probe {
        let trace = self.trace.clone();
        let mut ports = Vec::from(ports).into_iter();
        Box::new(move || {
            let port = ports.next().expect("the probe was asked for more ports than it has");
            trace.lock().unwrap().push(Event::Picked(port));
            Ok(addr(port))
        })
    }

    fn trace(&self) -> Vec<Event> {
        self.trace.lock().unwrap().clone()
    }

    fn wiring(&self, name: &'static str) -> (SocketAddr, SocketAddr) {
        self.wiring.lock().unwrap()[name]
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

/// Runs `runner` until it is ready, then stops it; returns what the caller was told and what `run` returned.
async fn run_until_ready(runner: ChainRunner, mode: Mode) -> (Result<ChainReady, StartError>, crate::Result<()>) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let cancel = CancellationToken::new();
    let runner = runner.mode(mode).on_ready(ready_tx).cancel_token(cancel.clone());
    let handle = tokio::spawn(runner.run(env()));
    let told = ready_rx.await.expect("the chain closed `on_ready` without a verdict");
    cancel.cancel();
    (told, handle.await.expect("the chain task panicked"))
}

/// The two ends of the chain as the SIP003 spec names them, `(public, destination)`. Client: the SS client's listener
/// `SS_LOCAL` is what the chain listens on. Server: `SS_REMOTE` is, and `SS_LOCAL` is what it forwards to.
fn ends(mode: Mode) -> (SocketAddr, SocketAddr) {
    match mode {
        Mode::Client => (addr(SS_LOCAL), addr(SS_REMOTE)),
        Mode::Server => (addr(SS_REMOTE), addr(SS_LOCAL)),
    }
}

#[skuld::test]
async fn hops_start_back_to_front_in_client_mode() {
    let rig = Rig::new();
    let runner = ChainRunner::new()
        .add(rig.hop("A"))
        .add(rig.hop("B"))
        .add(rig.hop("C"))
        .with_probe(rig.probe(&[P1, P2]));

    let (told, result) = run_until_ready(runner, Mode::Client).await;

    told.expect("the chain readies");
    result.expect("a stop is a clean end");
    assert_eq!(
        rig.trace(),
        [
            Event::Entered("C"),
            Event::ReadySent("C"),
            Event::Entered("B"),
            Event::ReadySent("B"),
            Event::Entered("A"),
            Event::ReadySent("A"),
        ]
    );
}

#[skuld::test]
async fn hops_start_front_to_back_in_server_mode() {
    let rig = Rig::new();
    let runner = ChainRunner::new()
        .add(rig.hop("A"))
        .add(rig.hop("B"))
        .add(rig.hop("C"))
        .with_probe(rig.probe(&[P1, P2]));

    let (told, result) = run_until_ready(runner, Mode::Server).await;

    told.expect("the chain readies");
    result.expect("a stop is a clean end");
    assert_eq!(
        rig.trace(),
        [
            Event::Entered("A"),
            Event::ReadySent("A"),
            Event::Entered("B"),
            Event::ReadySent("B"),
            Event::Entered("C"),
            Event::ReadySent("C"),
        ]
    );
}

/// Each hop forwards to the address the hop started before it was given, the first-started forwards to the
/// destination, and the last-started listens on the public end.
#[skuld::test]
async fn each_hop_forwards_to_the_address_the_next_started_hop_was_given() {
    for mode in [Mode::Client, Mode::Server] {
        let rig = Rig::new();
        let runner = ChainRunner::new()
            .add(rig.hop("A"))
            .add(rig.hop("B"))
            .add(rig.hop("C"))
            .with_probe(rig.probe(&[P1, P2]));

        let (told, _) = run_until_ready(runner, mode).await;
        let told = told.expect("the chain readies");

        let (public, destination) = ends(mode);
        // The first-started hop is given P1, the second P2.
        let expected = match mode {
            Mode::Client => [
                ("C", (addr(P1), destination)),
                ("B", (addr(P2), addr(P1))),
                ("A", (public, addr(P2))),
            ],
            Mode::Server => [
                ("A", (addr(P1), destination)),
                ("B", (addr(P2), addr(P1))),
                ("C", (public, addr(P2))),
            ],
        };
        for (name, wiring) in expected {
            assert_eq!(rig.wiring(name), wiring, "{mode:?}: hop {name}");
        }
        assert_eq!(
            told.listen, public,
            "{mode:?}: the chain reports the public hop's listen"
        );
    }
}

#[skuld::test]
async fn an_intermediate_port_is_picked_just_before_its_hop_starts() {
    let rig = Rig::new();
    let runner = ChainRunner::new()
        .add(rig.hop("A"))
        .add(rig.hop("B"))
        .add(rig.hop("C"))
        .with_probe(rig.logging_probe(&[P1, P2]));

    let (told, _) = run_until_ready(runner, Mode::Client).await;

    told.expect("the chain readies");
    assert_eq!(
        rig.trace(),
        [
            Event::Picked(P1),
            Event::Entered("C"),
            Event::ReadySent("C"),
            Event::Picked(P2),
            Event::Entered("B"),
            Event::ReadySent("B"),
            Event::Entered("A"),
            Event::ReadySent("A"),
        ]
    );
}

#[skuld::test]
async fn the_pick_skips_the_public_port() {
    tokio::time::pause();
    let rig = Rig::new();
    let runner = ChainRunner::new()
        .add(rig.hop("A"))
        .add(rig.hop("B"))
        .with_probe(rig.probe(&[SS_LOCAL, P1]));

    let (told, _) = run_until_ready(runner, Mode::Client).await;

    told.expect("the chain readies");
    assert_eq!(
        rig.wiring("B").0,
        addr(P1),
        "the public port is not an intermediate port"
    );
    assert_eq!(rig.wiring("A").1, addr(P1));
}

#[skuld::test]
async fn the_pick_skips_the_destination_port() {
    tokio::time::pause();
    let rig = Rig::new();
    let runner = ChainRunner::new()
        .add(rig.hop("A"))
        .add(rig.hop("B"))
        .with_probe(rig.probe(&[SS_REMOTE, P1]));

    let (told, _) = run_until_ready(runner, Mode::Client).await;

    told.expect("the chain readies");
    assert_eq!(
        rig.wiring("B").0,
        addr(P1),
        "the destination port is not an intermediate port"
    );
}

#[skuld::test]
async fn the_pick_skips_a_port_an_earlier_hop_was_given() {
    tokio::time::pause();
    let rig = Rig::new();
    let runner = ChainRunner::new()
        .add(rig.hop("A"))
        .add(rig.hop("B"))
        .add(rig.hop("C"))
        .with_probe(rig.probe(&[P1, P1, P2]));

    let (told, _) = run_until_ready(runner, Mode::Client).await;

    told.expect("the chain readies");
    assert_eq!(rig.wiring("C").0, addr(P1));
    assert_eq!(rig.wiring("B").0, addr(P2), "P1 belongs to C");
}

#[skuld::test]
async fn the_pick_is_not_capped() {
    tokio::time::pause();
    let rig = Rig::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut script: Vec<io::Result<SocketAddr>> = (0..10).map(|_| err(io::ErrorKind::AddrInUse)).collect();
    script.push(Ok(addr(P1)));
    let runner = ChainRunner::new()
        .add(rig.hop("A"))
        .add(rig.hop("B"))
        .with_probe(Box::new(scripted(script, &calls)));

    let (told, _) = run_until_ready(runner, Mode::Client).await;

    told.expect("the chain readies after ten lost races");
    assert_eq!(calls.load(Ordering::SeqCst), 11);
    assert_eq!(rig.wiring("B").0, addr(P1));
}

#[skuld::test]
async fn a_probe_error_that_is_a_race_before_the_first_answer_is_retried() {
    tokio::time::pause();
    let rig = Rig::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let script = vec![err(io::ErrorKind::PermissionDenied), Ok(addr(P1))];
    let runner = ChainRunner::new()
        .add(rig.hop("A"))
        .add(rig.hop("B"))
        .with_probe(Box::new(scripted(script, &calls)));

    let (told, _) = run_until_ready(runner, Mode::Client).await;

    told.expect("a WSAEACCES at the first probe is a race, not a refusal");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// An OS error that is not a port race, with a raw errno to carry: `EINVAL` / `WSAEINVAL`, both `InvalidInput`.
fn not_a_race() -> io::Error {
    let errno = if cfg!(windows) { 10022 } else { 22 };
    let error = io::Error::from_raw_os_error(errno);
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    error
}

#[skuld::test]
async fn a_probe_error_that_is_not_a_race_fails_the_start_and_starts_no_hop() {
    tokio::time::pause();
    let rig = Rig::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let errno = not_a_race().raw_os_error();
    let runner = ChainRunner::new()
        .add(rig.hop("A"))
        .add(rig.hop("B"))
        .with_probe(Box::new(scripted(vec![Err(not_a_race())], &calls)));

    let (told, result) = run_until_ready(runner, Mode::Client).await;

    match told {
        Err(StartError::Fatal { detail, errno: got }) => {
            assert!(detail.contains("picking a port for plugin 'B'"), "{detail}");
            assert_eq!(got, errno);
        }
        other => panic!("the caller must be told a Fatal start failure, got {other:?}"),
    }
    match result {
        Err(crate::Error::StartFailed {
            plugin,
            cause: StartError::Fatal { errno: got, .. },
        }) => {
            assert_eq!(plugin, "B");
            assert_eq!(got, errno);
        }
        other => panic!("run must return the start failure, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1, "a refusal is not picked again");
    assert!(rig.trace().is_empty(), "no hop started: {:?}", rig.trace());
}

#[skuld::test]
async fn a_cancel_during_the_pick_ends_run() {
    tokio::time::pause();
    let rig = Rig::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let second_call = Arc::new(Notify::new());
    let probe: Probe = {
        let calls = calls.clone();
        let second_call = second_call.clone();
        Box::new(move || {
            if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                second_call.notify_one();
            }
            err(io::ErrorKind::AddrInUse)
        })
    };
    let cancel = CancellationToken::new();
    let runner = ChainRunner::new()
        .add(rig.hop("A"))
        .add(rig.hop("B"))
        .with_probe(probe)
        .cancel_token(cancel.clone());
    let handle = tokio::spawn(runner.run(env()));

    second_call.notified().await;
    cancel.cancel();

    handle
        .await
        .expect("the chain task panicked")
        .expect("a cancel is a clean end, however far the start got");
    assert!(rig.trace().is_empty(), "no hop started: {:?}", rig.trace());
}

/// A hop that never readies holds the start: the hop behind it is not started, so it is not running to be stopped.
#[skuld::test]
async fn a_later_hop_is_not_started_while_an_earlier_one_is_unready() {
    let rig = Rig::new();
    let (entered_tx, entered_rx) = oneshot::channel();
    let cancel = CancellationToken::new();
    let runner = ChainRunner::new()
        .add(rig.hop("later"))
        .add(Box::new(Unready {
            entered: Once::new(entered_tx),
        }))
        .with_probe(rig.probe(&[P1]))
        .cancel_token(cancel.clone());
    let handle = tokio::spawn(runner.run(env()));

    entered_rx.await.expect("the unready hop ran");
    cancel.cancel();

    handle
        .await
        .expect("the chain task panicked")
        .expect("a cancel is a clean end");
    assert!(
        rig.trace().is_empty(),
        "the later hop was started behind a hop that never readied: {:?}",
        rig.trace()
    );
}
