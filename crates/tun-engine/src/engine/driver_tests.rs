//! The driver's accept and disposal dispatch, over a real smoltcp stack.
//!
//! `decide_admission` and `decide_disposal` are covered as pure functions in
//! their own suites; covered here is the half that turns their verdicts into
//! [`SocketStack`] calls — arms whose bodies are interchangeable to the
//! compiler and to any suite that only re-invokes the decision. Each test
//! asserts on what the client sees (a segment, or its absence) and what the
//! driver keeps (a connection entry, a permit, a slot), never on the verdict.
//!
//! The stack is polled at explicit instants rather than through
//! `poll_smoltcp`, so no assertion here depends on the wall clock.

// A driver test owns the whole cancellation chain it builds; there is no
// caller-supplied token to propagate.
#![allow(clippy::disallowed_methods)]

use std::io;

use smoltcp::socket::tcp;
use smoltcp::wire::{TcpControl, TcpSeqNumber};
use tokio::io::{Empty, Join, Sink};

use super::super::tcp_test_support::*;
use super::super::udp_flow::UdpFlow;
use super::*;
use crate::engine::config::MutEngineConfig;

// Helpers =============================================================================================================

/// A router that never finishes a connection: these tests drive the socket
/// themselves, and the flow the driver handed it must stay open meanwhile.
struct HoldingRouter;

#[async_trait::async_trait]
impl Router for HoldingRouter {
    async fn route_tcp(&self, _meta: TcpMeta, _flow: TcpFlow) -> io::Result<()> {
        std::future::pending().await
    }

    async fn route_udp(&self, _meta: UdpMeta, _flow: UdpFlow) -> io::Result<()> {
        std::future::pending().await
    }
}

/// The driver under test. Its TUN reads EOF and discards writes: these tests
/// drive the smoltcp layer through `stack` and never call [`Driver::run`].
type TestDriver = Driver<Join<Empty, Sink>>;

fn driver(max_connections: usize) -> TestDriver {
    let config = MutEngineConfig {
        max_connections,
        ..MutEngineConfig::default()
    };

    Driver::new(
        tokio::io::join(tokio::io::empty(), tokio::io::sink()),
        device_config(),
        Arc::new(HoldingRouter),
        Arc::new(config.freeze()),
        CancellationToken::new(),
    )
}

/// Offer one client SYN to the accept dispatch, and return the verdict's
/// effect on the wire.
fn offer_syn(d: &mut TestDriver, src: SocketAddr, dst: SocketAddr, isn: u32, now: i64) -> (SocketHandle, Vec<Segment>) {
    d.stack.ensure_listener(dst.port());
    d.stack.enqueue_rx(syn(src, dst, isn));
    d.stack.poll(t(now));
    let handle = d.stack.listener(dst.port()).expect("a listener took the SYN");

    d.accept_tcp_connections();
    d.stack.poll(t(now + 1));
    (handle, tcp_out(&mut d.stack))
}

/// Drive one client SYN through the accept dispatch to an admitted connection
/// and its SYN-ACK. Returns the connection's handle and the sequence number
/// every later client segment must acknowledge.
fn admit_one(d: &mut TestDriver, src: SocketAddr, dst: SocketAddr, isn: u32, now: i64) -> (SocketHandle, u32) {
    let (handle, out) = offer_syn(d, src, dst, isn, now);
    assert!(d.connections.contains_key(&handle), "the connection was admitted");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].control, TcpControl::Syn);
    (handle, after(out[0].seq))
}

/// Free the lowest socket slot while a listener on `dest()` sits above it, so
/// that the listener `admit` re-arms `dest()` with lands *below* its own
/// connection. This is the routine case: every connection that finishes frees
/// a slot under the ones still open.
fn free_the_lowest_slot(d: &mut TestDriver) {
    d.stack.ensure_listener(other_dest().port());
    d.stack.ensure_listener(dest().port());

    let (spare, spare_seq) = admit_one(d, client(), other_dest(), 7000, 0);
    d.stack.enqueue_rx(rst(client(), other_dest(), 7001, spare_seq));
    d.stack.poll(t(2));
    d.cleanup_finished_connections();
    d.stack.poll(t(3));
    let _ = tcp_out(&mut d.stack);
    assert!(!d.stack.holds(spare), "the finished connection's slot is free");
}

// Accept dispatch =====================================================================================================

#[skuld::test]
async fn a_refused_handshake_is_answered_with_an_rst() {
    let mut d = driver(0);

    let (_, out) = offer_syn(&mut d, client(), dest(), 1000, 0);

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].control, TcpControl::Rst);
    assert_eq!((out[0].src, out[0].dst), (dest(), client()));
    assert!(d.connections.is_empty());
}

#[skuld::test]
async fn a_refused_port_still_serves_the_next_client() {
    let mut d = driver(0);
    let _ = offer_syn(&mut d, client(), dest(), 1000, 0);

    let (_, out) = offer_syn(&mut d, other_client(), dest(), 5000, 2);

    assert_eq!(out.len(), 1);
    assert_eq!(out[0].control, TcpControl::Rst);
    assert_eq!(out[0].dst, other_client());
}

#[skuld::test]
async fn a_peerless_handshake_is_discarded_without_a_packet() {
    let mut d = driver(1);
    d.stack.ensure_listener(dest().port());
    d.stack.enqueue_rx(syn(client(), dest(), 1000));
    d.stack.poll(t(0));

    // The peer goes away before the verdict: smoltcp has cleared the 4-tuple
    // and there is no address left to answer.
    let handle = d.stack.listener(dest().port()).expect("a listener took the SYN");
    d.stack.socket_mut(handle).abort();
    d.stack.poll(t(1));
    let _ = tcp_out(&mut d.stack);

    d.accept_tcp_connections();
    d.stack.poll(t(2));

    assert!(tcp_out(&mut d.stack).is_empty());
    assert!(d.connections.is_empty());
    assert_eq!(d.conn_semaphore.available_permits(), 1, "no permit was spent");
}

#[skuld::test]
async fn a_retransmitted_syn_buys_no_second_connection() {
    let mut d = driver(4);
    free_the_lowest_slot(&mut d);
    let (connection, _) = admit_one(&mut d, client(), dest(), 1000, 4);
    let permits = d.conn_semaphore.available_permits();

    // The replacement listener took the freed slot below the connection, so it
    // is what smoltcp hands the client's retransmitted SYN.
    d.stack.enqueue_rx(syn(client(), dest(), 1000));
    d.stack.poll(t(6));
    d.accept_tcp_connections();
    d.stack.poll(t(7));

    assert!(
        tcp_out(&mut d.stack).is_empty(),
        "the client is waiting on its own socket"
    );
    assert_eq!(d.connections.keys().copied().collect::<Vec<_>>(), vec![connection]);
    assert_eq!(d.conn_semaphore.available_permits(), permits);
    assert_eq!(d.stack.socket(connection).state(), tcp::State::SynReceived);
}

// Disposal dispatch ===================================================================================================

#[skuld::test]
async fn a_reverted_connection_socket_is_retired_and_stops_hijacking() {
    let mut d = driver(4);
    let (handle, synack_seq) = admit_one(&mut d, client(), dest(), 1000, 0);

    // The client answers the SYN-ACK with an RST, and smoltcp flips the socket
    // back to `Listen` still holding the port.
    d.stack.enqueue_rx(rst(client(), dest(), 1001, synack_seq));
    d.stack.poll(t(2));
    assert_eq!(d.stack.socket(handle).state(), tcp::State::Listen);

    d.cleanup_finished_connections();

    assert!(!d.connections.contains_key(&handle));
    assert!(d.stack.holds(handle), "a retired socket is parked until poll reaps it");
    d.stack.poll(t(3));

    let (_, out) = offer_syn(&mut d, other_client(), dest(), 5000, 4);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].control,
        TcpControl::Syn,
        "the next client is served, not swallowed"
    );
    assert_eq!(out[0].dst, other_client());
}

#[skuld::test]
async fn a_timewait_connection_socket_is_dropped_at_once() {
    let mut d = driver(4);
    let (handle, synack_seq) = admit_one(&mut d, client(), dest(), 1000, 0);
    d.stack.enqueue_rx(ack(client(), dest(), 1001, synack_seq));
    d.stack.poll(t(2));
    assert_eq!(d.stack.socket(handle).state(), tcp::State::Established);

    d.stack.socket_mut(handle).close();
    d.stack.poll(t(3));
    let our_fin = tcp_out(&mut d.stack);
    assert_eq!(our_fin.len(), 1);
    assert_eq!(our_fin[0].control, TcpControl::Fin);
    d.stack.enqueue_rx(ack(client(), dest(), 1001, after(our_fin[0].seq)));
    d.stack.enqueue_rx(fin(client(), dest(), 1001, after(our_fin[0].seq)));
    d.stack.poll(t(4));
    assert_eq!(d.stack.socket(handle).state(), tcp::State::TimeWait);

    d.cleanup_finished_connections();

    assert!(!d.connections.contains_key(&handle));
    assert!(
        !d.stack.holds(handle),
        "a TIME-WAIT socket is dropped at once, not parked for its close delay",
    );
}

/// Route A (F7a): `copy_bidirectional` calls `flow.shutdown()` on the
/// half that closes first and keeps relaying the other way, so the router
/// task is still alive and reading when the client's final bytes arrive.
/// This is the dominant path — every proxied TCP connection takes it.
#[skuld::test]
async fn a_half_closing_router_still_receives_the_clients_final_bytes() {
    let mut d = driver(4);
    let (handle, synack_seq) = admit_one(&mut d, client(), dest(), 1000, 0);
    d.stack.enqueue_rx(ack(client(), dest(), 1001, synack_seq));
    d.stack.poll(t(2));
    assert_eq!(d.stack.socket(handle).state(), tcp::State::Established);

    d.stack.socket_mut(handle).close();
    d.stack.poll(t(3));
    let our_fin = tcp_out(&mut d.stack);
    assert_eq!(our_fin.len(), 1);
    assert_eq!(our_fin[0].control, TcpControl::Fin);

    d.stack.enqueue_rx(ack(client(), dest(), 1001, after(our_fin[0].seq)));
    d.stack.poll(t(4));
    assert_eq!(d.stack.socket(handle).state(), tcp::State::FinWait2);

    let payload = vec![7u8; 100];
    d.stack
        .enqueue_rx(data_fin(client(), dest(), 1001, after(our_fin[0].seq), &payload));
    d.stack.poll(t(5));
    assert_eq!(d.stack.socket(handle).state(), tcp::State::TimeWait);
    assert_eq!(d.stack.socket(handle).recv_queue(), 100);

    d.relay_tcp_data();
    assert_eq!(
        d.stack.socket(handle).recv_queue(),
        0,
        "the router — still holding its flow open — received the client's final bytes"
    );

    d.cleanup_finished_connections();
    assert!(!d.connections.contains_key(&handle));

    let out = tcp_out(&mut d.stack);
    assert_eq!(
        out.len(),
        1,
        "the ACK covering the payload and the FIN reached the wire before removal"
    );
    assert_eq!(out[0].ack, Some(TcpSeqNumber(1001 + 100 + 1)));
}

/// Route B (F7a): the router task ended and dropped its flow, so nothing
/// can be delivered. Confined to this route is F7b's remaining downside —
/// bytes still in `rx_buffer` at removal are now acknowledged and then
/// dropped — which is #923's to close, not this plan's.
///
/// A live spawned router cannot be observed reaching this state without a
/// sleep or a poll-with-timeout, both forbidden here (see the plan's F8/Task
/// 2 Step 1b note). This closes the driver's own `to_handler` directly
/// instead of dropping a router's `TcpFlow` — the test is about what the
/// driver does once that channel is closed, not about how it got closed, so
/// it does not demonstrate that a dropped router causes the closure.
#[skuld::test]
async fn a_dropped_router_leaves_the_clients_final_bytes_undelivered() {
    let mut d = driver(4);
    let (handle, synack_seq) = admit_one(&mut d, client(), dest(), 1000, 0);
    d.stack.enqueue_rx(ack(client(), dest(), 1001, synack_seq));
    d.stack.poll(t(2));
    assert_eq!(d.stack.socket(handle).state(), tcp::State::Established);

    d.stack.socket_mut(handle).close();
    d.stack.poll(t(3));
    let our_fin = tcp_out(&mut d.stack);
    assert_eq!(our_fin.len(), 1);

    d.stack.enqueue_rx(ack(client(), dest(), 1001, after(our_fin[0].seq)));
    d.stack.poll(t(4));
    assert_eq!(d.stack.socket(handle).state(), tcp::State::FinWait2);

    let payload = vec![7u8; 100];
    d.stack
        .enqueue_rx(data_fin(client(), dest(), 1001, after(our_fin[0].seq), &payload));
    d.stack.poll(t(5));
    assert_eq!(d.stack.socket(handle).state(), tcp::State::TimeWait);
    assert_eq!(d.stack.socket(handle).recv_queue(), 100);

    let (dead_tx, dead_rx) = mpsc::channel(1);
    drop(dead_rx);
    d.connections.get_mut(&handle).unwrap().to_handler = dead_tx;

    d.relay_tcp_data();
    assert_eq!(
        d.stack.socket(handle).recv_queue(),
        100,
        "nothing can be delivered once the router is gone"
    );

    d.cleanup_finished_connections();
    let out = tcp_out(&mut d.stack);
    assert_eq!(
        out.len(),
        1,
        "the ACK still leaves — this fix's remaining cost, confined to route B"
    );
    assert_eq!(out[0].ack, Some(TcpSeqNumber(1001 + 100 + 1)));
}

/// Reaches Task 2's conclusion through `Driver`'s own methods instead of
/// `SocketStack`'s. The phase sequence below is a copy of
/// `Driver::run`'s (`driver.rs:153-159`), substituting `stack.poll(t(..))`
/// for `poll_smoltcp()` because the fixture drives time explicitly — it is
/// not a read of that order, and no assertion here would catch it changing.
/// Its RED sibling is Task 2's
/// `a_fin_carrying_data_is_acknowledged_before_the_socket_can_be_removed`,
/// which fails without the fix at the layer the fix lives in.
#[skuld::test]
async fn the_last_ack_reaches_the_wire_before_the_connection_is_reaped() {
    let mut d = driver(4);
    let (handle, synack_seq) = admit_one(&mut d, client(), dest(), 1000, 0);
    d.stack.enqueue_rx(ack(client(), dest(), 1001, synack_seq));
    d.stack.poll(t(2));
    assert_eq!(d.stack.socket(handle).state(), tcp::State::Established);

    d.stack.socket_mut(handle).close();
    d.stack.poll(t(3));
    let our_fin = tcp_out(&mut d.stack);
    assert_eq!(our_fin.len(), 1);

    d.stack.enqueue_rx(ack(client(), dest(), 1001, after(our_fin[0].seq)));
    d.stack.poll(t(4));
    assert_eq!(d.stack.socket(handle).state(), tcp::State::FinWait2);

    let payload = vec![7u8; 100];
    d.stack
        .enqueue_rx(data_fin(client(), dest(), 1001, after(our_fin[0].seq), &payload));

    d.stack.poll(t(5));
    d.accept_tcp_connections();
    d.relay_tcp_data();
    d.cleanup_finished_connections();
    d.process_udp_replies();
    d.stack.poll(t(6));

    let out = tcp_out(&mut d.stack);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].ack, Some(TcpSeqNumber(1001 + 100 + 1)));
    assert!(!d.connections.contains_key(&handle));
}

#[skuld::test]
async fn a_connection_whose_client_never_answers_is_reclaimed() {
    let mut d = driver(1);
    let (handle, _) = admit_one(&mut d, client(), dest(), 1000, 0);

    // The client vanishes between its SYN and the SYN-ACK. Nothing it does
    // reclaims the connection; only the bound on its silence.
    d.cleanup_finished_connections();
    assert!(d.connections.contains_key(&handle));

    d.stack
        .poll(t(MutEngineConfig::default().tcp_peer_timeout.as_millis() as i64 + 1));
    d.cleanup_finished_connections();

    assert!(!d.connections.contains_key(&handle), "the stalled connection is gone");
}
