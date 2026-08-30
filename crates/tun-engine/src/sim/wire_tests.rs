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

#[skuld::test(should_panic = "engine already exited")]
async fn inject_after_the_engine_exited_names_the_engine_not_a_lifetime_bug() {
    let (tun, wire) = packet_pair(4);
    drop(tun); // ordinary post-teardown state, not a broken invariant

    wire.inject(vec![1]).await;
}

#[skuld::test(should_panic = "engine already exited")]
async fn fail_next_read_after_the_engine_exited_names_the_engine_not_capacity() {
    let (tun, wire) = packet_pair(4);
    drop(tun); // ordinary post-teardown state, not a full queue

    wire.fail_next_read(io::ErrorKind::Other);
}

#[skuld::test(should_panic = "ingress queue full")]
async fn fail_next_read_on_a_full_queue_names_capacity_not_the_engine() {
    let (_tun, wire) = packet_pair(1);
    wire.fail_next_read(io::ErrorKind::Other); // fills the one slot

    wire.fail_next_read(io::ErrorKind::Other);
}

#[skuld::test]
async fn a_tap_never_blocks_or_drops_past_the_old_64_slot_bound() {
    // Regression: a bounded tap channel made `inject`/`next_egress` deadlock
    // past 64 undrained records while `try_next_egress` silently dropped
    // them instead — two inconsistent overflow policies on the same
    // condition. The tap is unbounded, so 100 packets neither block nor
    // drop.
    let (_tun, mut wire) = packet_pair(200);
    let mut tap = wire.tap();

    for i in 0..100u8 {
        wire.inject(vec![i]).await;
    }

    for i in 0..100u8 {
        let (direction, packet) = tap.next().await.expect("tap dropped a record under load");
        assert_eq!(direction, Direction::ToEngine);
        assert_eq!(packet, vec![i]);
    }
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
