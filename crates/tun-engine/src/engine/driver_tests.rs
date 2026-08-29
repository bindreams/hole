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
//! `Driver::smoltcp_now`, so no assertion here depends on the wall clock.

// A driver test owns the whole cancellation chain it builds; there is no
// caller-supplied token to propagate.
#![allow(clippy::disallowed_methods)]

use std::io;
use std::net::SocketAddr;

use smoltcp::socket::tcp;
use smoltcp::wire::TcpControl;
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
/// effect on the wire. Checksumless, like every real inbound SYN — this suite
/// drives `Driver::settle_packet`, the real production entry point, and
/// [`checksumless_syn`] is the shape it actually receives.
fn offer_syn(d: &mut TestDriver, src: SocketAddr, dst: SocketAddr, isn: u32, now: i64) -> (SocketHandle, Vec<Segment>) {
    d.stack.ensure_listener(dst.port());
    d.stack.enqueue_rx(checksumless_syn(src, dst, isn));
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

/// The correction to the steal (RFC 9293 §3.10.7.4): a second SYN on the same
/// tuple with a *different* ISN is a new connection, not the client's own
/// retransmit. The stale owner is torn down — its channels closed, its socket
/// gone — and the new SYN is admitted in its place.
#[skuld::test]
async fn a_syn_with_a_different_isn_tears_down_the_stale_owner_and_admits_the_new_one() {
    let mut d = driver(4);
    free_the_lowest_slot(&mut d);
    let (stale, _) = admit_one(&mut d, client(), dest(), 1000, 4);
    let permits_before = d.conn_semaphore.available_permits();

    // The replacement listener took the freed slot below the connection, so
    // it is what smoltcp hands this second SYN.
    d.stack.enqueue_rx(syn(client(), dest(), 2000));
    d.stack.poll(t(6));
    d.accept_tcp_connections();
    d.stack.poll(t(7));

    // Not `d.stack.holds(stale)`: `remove` frees the slot, and the fresh
    // listener `admit` re-arms can refill it, so the slot being occupied
    // again proves nothing about `stale`'s own socket.
    assert_eq!(d.connections.len(), 1, "the new SYN takes the stale connection's place");
    let new_handle = *d.connections.keys().next().unwrap();
    assert_ne!(new_handle, stale, "a fresh socket admits the new connection");
    assert_eq!(
        d.conn_semaphore.available_permits(),
        permits_before - 1,
        "the new connection spent a fresh permit"
    );
    assert_eq!(d.stack.socket(new_handle).state(), tcp::State::SynReceived);

    let out = tcp_out(&mut d.stack);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].control,
        TcpControl::Syn,
        "the new connection is admitted, not refused"
    );
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

// settle_packet ordering ==============================================================================================

/// The invariant behind #911's fix, proven against the call `Driver::run`
/// actually makes — not a hand-sequenced stand-in for it. `settle_packet` is
/// the one production entry point for a TUN packet; enqueue, both polls,
/// admission and retirement never straddle two calls, so a socket
/// mid-retirement can never intercept the next packet's SYN regardless of how
/// many packets a future `run()` reads per iteration.
///
/// A hijacked SYN is not silent on the wire — the reverted socket kept the
/// SYN-ACK unpaused from its earlier admission, so it answers anyway. The
/// defect is that `take_handshakes` never sees the hijacking socket (it left
/// `self.listeners` at its first admission), so `accept_tcp_connections` never
/// runs for it: no `TcpConn`, no Router task, no permit — a connection that is
/// alive on the wire and dead everywhere the driver would relay for it. That
/// is what this test asserts on, not the wire.
#[skuld::test]
async fn a_reverting_rst_and_a_later_syn_never_straddle_one_settle() {
    let mut d = driver(4);
    let (handle, synack_seq) = admit_one(&mut d, client(), dest(), 1000, 0);

    d.settle_packet(Some(&rst(client(), dest(), 1001, synack_seq)), t(2));
    d.settle_packet(Some(&checksumless_syn(other_client(), dest(), 5000)), t(3));

    assert!(!d.connections.contains_key(&handle), "the reverted connection is gone");
    assert_eq!(
        d.connections.len(),
        1,
        "the next client's SYN is admitted through the tracked accept path, not just answered on the wire"
    );
}
