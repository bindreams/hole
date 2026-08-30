//! Cancellation teardown, the live TUN read-error exit, and idle-sweep
//! eviction — pinned from outside the driver.

use std::io;
use std::time::Duration;

use super::super::driver_sim_test_support::{start, v4};
use crate::sim::{udp_packet, Dispatch};

#[skuld::test]
async fn cancelling_the_engine_ends_the_run_loop() {
    let mut h = start(|_| {});

    h.wire
        .inject(udp_packet(v4("10.255.0.2", 51000), v4("8.8.8.8", 443), b"x"))
        .await;
    h.dispatch.recv().await.expect("router never dispatched");

    let _ = h.shutdown().await;
}

#[skuld::test]
async fn cancelling_the_engine_closes_every_in_flight_flow() {
    let mut h = start(|_| {});

    h.wire
        .inject(udp_packet(v4("10.255.0.2", 51000), v4("8.8.8.8", 443), b"x"))
        .await;
    let Dispatch::Udp { mut flow, .. } = h.dispatch.recv().await.expect("router never dispatched") else {
        panic!("expected a UDP dispatch");
    };
    // Drain the injected datagram, which `handle_udp_packet` seeds into a
    // new flow — otherwise it is still buffered ahead of the check below.
    assert_eq!(flow.recv().await.as_deref(), Some(b"x".as_slice()));

    let _ = h.shutdown().await;

    // Edge: joining the cancelled engine is what orders this negative.
    // `run(mut self)` (`driver.rs`) consumes `self` when it returns, which
    // drops the flow's sender; `try_recv` (non-blocking, unlike `recv`)
    // turns a regression into an instant `Empty`, not a hang.
    assert_eq!(
        flow.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected),
        "the flow outlived the cancelled engine"
    );
}

#[skuld::test]
async fn a_tun_read_error_ends_the_run_loop() {
    let h = start(|_| {});
    h.wire.fail_next_read(io::ErrorKind::Other);

    // Rendezvous: joining IS the observable. This is the driver's live exit
    // path (`tun-0.8.13` never produces `Ok(0)`, only `Err`) — contrast
    // `dropping_the_wire_reports_eof_to_the_engine_side` in `wire_tests.rs`,
    // which pins only the simulator's own EOF contract.
    let _ = h.join().await;
}

#[skuld::test]
async fn the_driver_sweep_closes_a_flow_the_router_still_holds() {
    let mut h = start(|c| {
        c.udp_flow_idle_timeout = Duration::ZERO;
        c.idle_sweep_interval = Duration::ZERO;
    });

    h.wire
        .inject(udp_packet(v4("10.255.0.2", 51000), v4("8.8.8.8", 443), b"x"))
        .await;
    let Dispatch::Udp { mut flow, .. } = h.dispatch.recv().await.expect("router never dispatched") else {
        panic!("expected a UDP dispatch");
    };

    // Zero timeouts convert the sweep from a timing behaviour into an
    // ordering one: the flow is created and then the same loop iteration's
    // sweep evicts it immediately. This does not distinguish a correct
    // timeout-respecting sweep from an unconditional-clear one — that
    // distinction is `FlowTable`-level, pinned by
    // `udp_flow_tests.rs::sweep_keeps_active_flows`. It pins only that the
    // driver calls the sweep and that eviction reaches the router.
    //
    // No join edge exists ahead of either assert below — both observe the
    // live engine, before cancellation — so a regression here blocks
    // instead of failing; `.config/nextest.toml`'s `driver_sim_tests`
    // override bounds that.
    assert_eq!(flow.recv().await.as_deref(), Some(b"x".as_slice()));
    assert!(flow.recv().await.is_none(), "the swept flow was not closed");

    let _ = h.shutdown().await;
}
