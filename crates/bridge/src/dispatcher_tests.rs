// `CancellationToken::new` is the test harness's root signal; module-level
// allow per clippy.toml's "Bridge cancellation contract" sanctioned-test-file
// exception.
#![allow(clippy::disallowed_methods)]

use super::*;

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
