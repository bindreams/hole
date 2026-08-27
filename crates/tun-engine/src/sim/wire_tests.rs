//! Pins `SimTun`/`SimWire`'s framing contract — see the module doc.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

#[skuld::test]
async fn one_read_yields_exactly_one_injected_packet() {
    let (mut tun, wire) = packet_pair(4);
    wire.inject(vec![1, 2, 3]).await;
    wire.inject(vec![4, 5, 6, 7, 8]).await;

    let mut buf = vec![0u8; 64];
    let n = tun.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &[1, 2, 3]);

    let n = tun.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &[4, 5, 6, 7, 8]);
}

#[skuld::test]
async fn one_write_all_enqueues_exactly_one_egress_packet() {
    let (mut tun, mut wire) = packet_pair(4);
    let payload = vec![7u8; 900];

    tun.write_all(&payload).await.unwrap();

    let egress = wire.next_egress().await.expect("no egress packet");
    assert_eq!(egress.len(), 900);
    assert_eq!(egress, payload);
    assert!(
        wire.try_next_egress().is_none(),
        "a single write_all produced more than one egress packet"
    );
}

#[skuld::test]
async fn dropping_the_wire_reports_eof_to_the_engine_side() {
    // Pins the simulator's own contract. The product's live exit path is the
    // `Err` arm, covered by `a_tun_read_error_ends_the_run_loop` in
    // `driver_lifecycle_tests.rs`.
    let (mut tun, wire) = packet_pair(4);
    drop(wire);

    let mut buf = vec![0u8; 64];
    let n = tun.read(&mut buf).await.unwrap();
    assert_eq!(n, 0);
}

#[skuld::test]
async fn a_queued_read_error_is_surfaced_to_the_engine_side() {
    let (mut tun, wire) = packet_pair(4);
    wire.fail_next_read(io::ErrorKind::ConnectionReset);

    let mut buf = vec![0u8; 64];
    let err = tun.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
}

#[skuld::test(should_panic = "SimTun read buffer too small")]
async fn a_short_read_buffer_panics() {
    let (mut tun, wire) = packet_pair(4);
    wire.inject(vec![0u8; 100]).await;

    let mut buf = vec![0u8; 10];
    let _ = tun.read(&mut buf).await;
}

#[skuld::test]
async fn a_tap_observes_both_directions() {
    let (mut tun, mut wire) = packet_pair(4);
    let mut tap = wire.tap();

    wire.inject(vec![9, 9]).await;
    let (direction, packet) = tap.next().await.expect("tap saw nothing for the injected packet");
    assert_eq!(direction, Direction::ToEngine);
    assert_eq!(packet, vec![9, 9]);

    let mut buf = vec![0u8; 64];
    let n = tun.read(&mut buf).await.unwrap();
    tun.write_all(&buf[..n]).await.unwrap();
    let _ = wire.next_egress().await.expect("no egress packet");

    let (direction, packet) = tap.next().await.expect("tap saw nothing for the egress packet");
    assert_eq!(direction, Direction::FromEngine);
    assert_eq!(packet, vec![9, 9]);
}
