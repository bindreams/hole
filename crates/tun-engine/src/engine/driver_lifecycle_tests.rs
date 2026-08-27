//! Cancellation teardown, the live TUN read-error exit, and idle-sweep
//! eviction — pinned from outside the driver.

#![allow(clippy::disallowed_methods)]
// This file's `CancellationToken::new()` is the test's own root — see
// `driver_udp_tests.rs`.

use std::io;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::device::MutDeviceConfig;
use crate::sim::{packet_pair, recording_router, udp_packet, Dispatch};
use crate::{DeviceConfig, Engine, MutEngineConfig};

fn device_config() -> DeviceConfig {
    MutDeviceConfig {
        tun_name: "sim0".into(),
        mtu: 1400,
        ipv4: Some("10.255.0.1/24".parse().unwrap()),
        ipv6: None,
    }
    .freeze()
}

#[skuld::test]
async fn cancelling_the_engine_ends_the_run_loop() {
    let (tun, wire) = packet_pair(64);
    let (router, mut dispatch) = recording_router();
    let cancel = CancellationToken::new();
    let engine = Engine::from_io(tun, device_config(), router, |c: &mut MutEngineConfig| {
        c.udp_flow_idle_timeout = Duration::from_secs(24 * 3600);
    })
    .expect("from_io with a valid DeviceConfig never fails");
    let handle = tokio::spawn(engine.run(cancel.clone()));

    wire.inject(udp_packet(
        "10.255.0.2:51000".parse().unwrap(),
        "8.8.8.8:443".parse().unwrap(),
        b"x",
    ))
    .await;
    dispatch.recv().await.expect("router never dispatched");

    cancel.cancel();
    handle.await.expect("engine task panicked");
}

#[skuld::test]
async fn cancelling_the_engine_closes_every_in_flight_flow() {
    let (tun, wire) = packet_pair(64);
    let (router, mut dispatch) = recording_router();
    let cancel = CancellationToken::new();
    let engine = Engine::from_io(tun, device_config(), router, |c: &mut MutEngineConfig| {
        c.udp_flow_idle_timeout = Duration::from_secs(24 * 3600);
    })
    .expect("from_io with a valid DeviceConfig never fails");
    let handle = tokio::spawn(engine.run(cancel.clone()));

    wire.inject(udp_packet(
        "10.255.0.2:51000".parse().unwrap(),
        "8.8.8.8:443".parse().unwrap(),
        b"x",
    ))
    .await;
    let Dispatch::Udp { mut flow, .. } = dispatch.recv().await.expect("router never dispatched") else {
        panic!("expected a UDP dispatch");
    };
    // Drain the injected datagram, which `handle_udp_packet` seeds into a
    // new flow — otherwise it is still buffered ahead of the `None` below.
    assert_eq!(flow.recv().await.as_deref(), Some(b"x".as_slice()));

    cancel.cancel();
    handle.await.expect("engine task panicked");

    // `run(mut self)` (`driver.rs`) consumes `self`, so this observable does
    // not distinguish an explicit `flow_table.clear()` from the driver
    // simply being dropped when `run` returns — both close every flow's
    // sender. This test pins the router-visible contract, not line coverage
    // of `flow_table.clear()`, which is redundant with the drop of `self`.
    assert!(flow.recv().await.is_none(), "the flow outlived the cancelled engine");
}

#[skuld::test]
async fn a_tun_read_error_ends_the_run_loop() {
    let (tun, wire) = packet_pair(64);
    let (router, _dispatch) = recording_router();
    let cancel = CancellationToken::new();
    let engine = Engine::from_io(tun, device_config(), router, |c: &mut MutEngineConfig| {
        c.udp_flow_idle_timeout = Duration::from_secs(24 * 3600);
    })
    .expect("from_io with a valid DeviceConfig never fails");
    let handle = tokio::spawn(engine.run(cancel));

    wire.fail_next_read(io::ErrorKind::Other);

    // Rendezvous: the handle joining IS the observable. This is the driver's
    // live exit path (`tun-0.8.14` never produces `Ok(0)`, only `Err`) —
    // contrast `dropping_the_wire_reports_eof_to_the_engine_side` in
    // `wire_tests.rs`, which pins only the simulator's own EOF contract.
    handle.await.expect("engine task panicked");
}

#[skuld::test]
async fn the_driver_sweep_closes_a_flow_the_router_still_holds() {
    let (tun, wire) = packet_pair(64);
    let (router, mut dispatch) = recording_router();
    let cancel = CancellationToken::new();
    let engine = Engine::from_io(tun, device_config(), router, |c: &mut MutEngineConfig| {
        c.udp_flow_idle_timeout = Duration::ZERO;
        c.idle_sweep_interval = Duration::ZERO;
    })
    .expect("from_io with a valid DeviceConfig never fails");
    let handle = tokio::spawn(engine.run(cancel.clone()));

    wire.inject(udp_packet(
        "10.255.0.2:51000".parse().unwrap(),
        "8.8.8.8:443".parse().unwrap(),
        b"x",
    ))
    .await;
    let Dispatch::Udp { mut flow, .. } = dispatch.recv().await.expect("router never dispatched") else {
        panic!("expected a UDP dispatch");
    };

    // Zero timeouts convert the sweep from a timing behaviour into an
    // ordering one: the flow is created and then the same loop iteration's
    // sweep evicts it immediately. This does not distinguish a correct
    // timeout-respecting sweep from an unconditional-clear one — that
    // distinction is `FlowTable`-level, pinned by
    // `udp_flow_tests.rs::sweep_keeps_active_flows`. It pins only that the
    // driver calls the sweep and that eviction reaches the router.
    assert_eq!(flow.recv().await.as_deref(), Some(b"x".as_slice()));
    assert!(flow.recv().await.is_none(), "the swept flow was not closed");

    cancel.cancel();
    handle.await.expect("engine task panicked");
}
