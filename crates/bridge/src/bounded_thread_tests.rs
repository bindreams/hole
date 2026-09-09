//! Unit tests for [`super`]. Platform-neutral: the primitive is `std`
//! threads plus `std::sync::mpsc`, so these run on every target the bridge
//! builds for even though the only production consumer
//! (`diagnostics::etw`) is Windows-only.

use super::*;
use std::sync::mpsc;

/// The healthy path: a body that returns reports [`ThreadExit::Finished`],
/// and does so on the completion channel rather than by waiting `bound`
/// out. The bound here is deliberately far larger than any plausible
/// scheduling delay — if `wait` returned `Finished` by elapsing it instead
/// of by receiving, this test would take an hour, not milliseconds.
#[skuld::test]
fn a_body_that_returns_reports_finished() {
    let thread = spawn("bounded-thread-test-finished", || {}).expect("spawn");
    assert_eq!(thread.wait(Duration::from_secs(3600)), ThreadExit::Finished);
}

/// A body that cannot finish reports [`ThreadExit::Abandoned`] instead of
/// blocking forever — the whole point of the type. Deterministic, not a
/// race: the body is parked on a channel whose only sender this test holds,
/// so it provably cannot have finished when `wait` is called, whatever the
/// bound.
///
/// Test-of-timing: `bound` is the behaviour under test, so a small literal
/// here is the exception CONTRIBUTING.md sanctions, not a synchronisation
/// sleep.
#[skuld::test]
fn a_body_that_has_not_finished_is_abandoned() {
    let (gate_tx, gate_rx) = mpsc::channel::<()>();
    let (exited_tx, exited_rx) = mpsc::channel::<()>();
    let thread = spawn("bounded-thread-test-abandoned", move || {
        let _ = gate_rx.recv();
        let _ = exited_tx.send(());
    })
    .expect("spawn");

    assert_eq!(thread.wait(Duration::from_millis(50)), ThreadExit::Abandoned);

    // Reap the abandoned thread: release the gate, then block on its own
    // exit signal (an unbounded `recv`, a real rendezvous) so the test does
    // not return while its thread is still live.
    drop(gate_tx);
    exited_rx.recv().expect("abandoned thread exits once released");
}

/// An abandoned thread is abandoned, not killed: `wait` returning
/// [`ThreadExit::Abandoned`] must not stop the body from running to
/// completion afterwards. This is what makes abandonment safe on the ETW
/// teardown path — the processing thread keeps draining, it just stops
/// holding up the service's `Stopped` report.
#[skuld::test]
fn an_abandoned_body_still_runs_to_completion() {
    let (gate_tx, gate_rx) = mpsc::channel::<()>();
    let (exited_tx, exited_rx) = mpsc::channel::<bool>();
    let thread = spawn("bounded-thread-test-still-runs", move || {
        let released = gate_rx.recv().is_ok();
        let _ = exited_tx.send(released);
    })
    .expect("spawn");

    assert_eq!(thread.wait(Duration::from_millis(50)), ThreadExit::Abandoned);
    gate_tx.send(()).expect("abandoned body is still receiving");
    assert!(
        exited_rx.recv().expect("abandoned body still reaches its end"),
        "the abandoned body must observe the value sent after it was abandoned"
    );
}

/// An unwinding body reports [`ThreadExit::Panicked`], not `Finished` and
/// not `Abandoned`: a detached thread has no `JoinHandle` to carry the
/// payload, so the sender dropping mid-unwind is the only signal there is,
/// and the caller needs it to log the right thing.
#[skuld::test]
fn a_panicking_body_reports_panicked() {
    // The default panic hook prints the payload to stderr from the spawned
    // thread; that output is expected, and is this test's only noise.
    let thread = spawn("bounded-thread-test-panicked", || panic!("deliberate")).expect("spawn");
    assert_eq!(thread.wait(Duration::from_secs(3600)), ThreadExit::Panicked);
}
