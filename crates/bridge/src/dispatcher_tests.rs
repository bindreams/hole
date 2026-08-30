#![allow(clippy::disallowed_methods)] // fixtures build their own root CancellationToken; see clippy.toml

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::sync::oneshot;

use super::*;
use crate::drop_sink::LoggingDropSink;
use crate::endpoint::{InterfaceEndpoint, Socks5Endpoint};
use crate::filter::rules::RuleSet;
use crate::hole_router::HoleRouter;

/// Builds a `Dispatcher` without a TUN device, backed by a stand-in
/// "driver" task whose body the caller controls.
fn build_dispatcher(driver_body: impl Future<Output = ()> + Send + 'static) -> Dispatcher {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080);
    let router = Arc::new(HoleRouter::new(
        Socks5Endpoint::new(addr, None, false),
        InterfaceEndpoint::new(0, false),
        LoggingDropSink::new(),
        RuleSet::default(),
    ));
    let cancel = CancellationToken::new();
    let driver_handle = tokio::spawn(driver_body);
    let driver_abort = driver_handle.abort_handle();

    Dispatcher {
        router,
        cancel,
        driver_handle: Some(driver_handle),
        driver_abort,
        bomb: drop_bomb::DebugDropBomb::new("Dispatcher dropped without shutdown().await"),
        ipv6_assigned: None,
    }
}

// drain ===============================================================================================================

#[skuld::test]
async fn drain_reports_a_finished_driver_as_drained() {
    let mut handle = tokio::spawn(async {});
    assert_eq!(drain(&mut handle).await, DriverExit::Drained);
}

#[skuld::test]
async fn drain_reports_an_aborted_driver_as_aborted() {
    let (_tx, rx) = oneshot::channel::<()>();
    let mut handle = tokio::spawn(async move {
        let _ = rx.await;
    });
    handle.abort();

    assert_eq!(drain(&mut handle).await, DriverExit::Aborted);
}

#[skuld::test]
async fn drain_reports_a_panicking_driver_as_panicked() {
    let mut handle = tokio::spawn(async {
        panic!("boom");
    });

    assert_eq!(drain(&mut handle).await, DriverExit::Panicked);
}

#[skuld::test]
async fn drain_does_not_give_up_on_a_driver_that_is_still_running() {
    tokio::time::pause();
    let (tx, rx) = oneshot::channel::<()>();
    let mut handle = tokio::spawn(async move {
        let _ = rx.await;
    });

    let fut = drain(&mut handle);
    tokio::pin!(fut);

    // The absence of a timing bound is the behaviour under test; the
    // clock is virtual, so no wall-clock time passes.
    tokio::select! {
        biased;
        _ = &mut fut => panic!("drain resolved despite the driver still running"),
        () = tokio::time::advance(Duration::from_secs(3600)) => {}
    }

    tx.send(()).unwrap();
    assert_eq!(fut.await, DriverExit::Drained);
}

// Dispatcher ==========================================================================================================

#[skuld::test]
async fn a_cancelled_shutdown_leaves_the_driver_handle_for_drop() {
    let (tx, rx) = oneshot::channel::<()>();
    let mut dispatcher = build_dispatcher(async move {
        let _ = rx.await;
    });

    {
        let fut = dispatcher.shutdown();
        tokio::pin!(fut);

        tokio::select! {
            biased;
            _ = &mut fut => panic!("shutdown resolved despite the driver still running"),
            () = std::future::ready(()) => {}
        }
        // fut (and its &mut borrow of dispatcher) drops here, mid-drain.
    }

    assert!(dispatcher.driver_handle.is_some());

    tx.send(()).unwrap();
    assert_eq!(dispatcher.shutdown().await, DriverExit::Drained);
}

#[skuld::test]
async fn shutdown_of_an_already_drained_dispatcher_reports_already_drained() {
    let mut dispatcher = build_dispatcher(async {});

    assert_eq!(dispatcher.shutdown().await, DriverExit::Drained);
    assert_eq!(dispatcher.shutdown().await, DriverExit::AlreadyDrained);
}

#[skuld::test]
async fn shutdown_reports_a_panicking_driver_as_panicked() {
    let mut dispatcher = build_dispatcher(async {
        panic!("boom");
    });

    assert_eq!(dispatcher.shutdown().await, DriverExit::Panicked);
}

// build_or_cancel =====================================================================================================

/// Phase 5 can now wait on an OS interface-appearance notification, so a Cancel
/// arriving while the device build is parked must be observed without waiting
/// for the build: on a covered (auto-connect) start the user's whole host is
/// fail-closed for exactly that window. The build runs on a blocking thread, so
/// the wait also occupies no tokio worker.
#[skuld::test]
async fn cancel_during_phase_5_preempts_the_device_build() {
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let cancel = CancellationToken::new();

    let racing = tokio::spawn({
        let cancel = cancel.clone();
        async move {
            build_or_cancel(&cancel, move || {
                entered_tx.send(()).expect("the racing task still awaits the signal");
                release_rx.recv().expect("the test releases the parked build");
                "device"
            })
            .await
        }
    });

    // The build is provably parked before the cancel fires.
    entered_rx.await.expect("the device build never started");
    cancel.cancel();

    assert_eq!(
        racing.await.expect("the racing task panicked"),
        None,
        "a cancel arriving mid-build must return without awaiting the build"
    );

    // Let the detached blocking thread finish so the runtime can shut down.
    release_tx.send(()).expect("the parked build is still receiving");
}
