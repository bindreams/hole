// `CancellationToken::new` roots the shutdown signal of the probes.
#![allow(clippy::disallowed_methods)]

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::binary::ReadinessProbes;
use crate::test_utils::WaitableWriter;
use crate::tracing_test::set_default_in_current_thread;

/// A probe holds the readiness sender while it polls: once `end` returns the sender is gone, so a chain reading the
/// receiver sees a plugin that dropped it, not one still deciding.
#[skuld::test]
async fn ending_the_probes_drops_the_sender_a_probe_held() {
    let shutdown = CancellationToken::new();
    let probes = ReadinessProbes::new("p", &shutdown);
    let (held_tx, mut held_rx) = oneshot::channel::<()>();
    let stop = probes.token();
    probes.spawn(async move {
        let _held = held_tx;
        stop.cancelled().await;
    });
    assert!(matches!(held_rx.try_recv(), Err(oneshot::error::TryRecvError::Empty)));

    probes.end().await;

    assert!(matches!(held_rx.try_recv(), Err(oneshot::error::TryRecvError::Closed)));
    assert!(!shutdown.is_cancelled(), "ending the probes is not a chain shutdown");
}

/// A probe the chain's shutdown stops needs no `end` to be stopped: the token a probe gets is a descendant of it.
#[skuld::test]
async fn the_chains_shutdown_stops_a_probe() {
    // A paused runtime that goes idle jumps the clock, so a probe the shutdown does not stop fails here, not hangs.
    tokio::time::pause();
    let shutdown = CancellationToken::new();
    let probes = ReadinessProbes::new("p", &shutdown);
    let stop = probes.token();

    shutdown.cancel();

    tokio::time::timeout(std::time::Duration::from_secs(24 * 3600), stop.cancelled())
        .await
        .expect("the chain's shutdown did not stop the probe");
}

/// A probe the readers start after the probes ended (an aborted reader that had not yet run) never runs.
#[skuld::test]
async fn a_probe_started_after_the_probes_ended_never_runs() {
    let probes = ReadinessProbes::new("p", &CancellationToken::new());
    probes.end().await;

    let (ran_tx, mut ran_rx) = oneshot::channel::<()>();
    probes.spawn(async move {
        let _ = ran_tx.send(());
    });
    // A spawned task runs once this one yields; a dropped one has dropped its sender by now.
    tokio::task::yield_now().await;

    assert!(
        matches!(ran_rx.try_recv(), Err(oneshot::error::TryRecvError::Closed)),
        "the probe ran after the probes ended"
    );
    // Ending again finds nothing to wait for.
    probes.end().await;
}

/// A probe that panics is a bug in the probe, not in the plugin; it is not lost.
#[skuld::test]
async fn a_probe_that_panics_is_warned_about_by_plugin_name() {
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let _g = set_default_in_current_thread(subscriber);
    let probes = ReadinessProbes::new("probed-plugin", &CancellationToken::new());
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    probes.spawn(async { panic!("probe broke") });

    probes.end().await;
    std::panic::set_hook(previous);

    let log = writer.snapshot();
    assert!(
        log.contains("WARN") && log.contains("probed-plugin") && log.contains("did not end normally"),
        "{log}"
    );
}
