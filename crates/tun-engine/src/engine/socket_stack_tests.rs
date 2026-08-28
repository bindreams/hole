//! Packet-level tests over a real smoltcp `Interface` + `VirtualTunDevice`.
//!
//! The segment builders and egress parsing live in
//! [`tcp_test_support`](super::super::tcp_test_support), which documents the
//! properties of theirs that tests here depend on.

use smoltcp::wire::{TcpControl, TcpSeqNumber};

use super::super::tcp_test_support::*;
use super::*;
use crate::engine::config::MutEngineConfig;

// Helpers =============================================================================================================

fn stack() -> SocketStack {
    SocketStack::new(&device_config(), &MutEngineConfig::default().freeze())
}

/// Milliseconds from a `MutEngineConfig` field. The timeout tests are about the
/// shipped bounds, so they read them rather than restate them.
fn config_ms(field: impl FnOnce(&MutEngineConfig) -> std::time::Duration) -> i64 {
    field(&MutEngineConfig::default()).as_millis() as i64
}

/// Every socket in the set holding the 4-tuple `src` -> `dst`. The invariant
/// the duplicate check exists to keep is that this is never longer than one.
fn owners_of(stack: &SocketStack, src: SocketAddr, dst: SocketAddr) -> Vec<SocketHandle> {
    stack
        .sockets
        .iter()
        .filter_map(|(handle, socket)| {
            let smoltcp::socket::Socket::Tcp(socket) = socket else {
                return None;
            };
            let local = socket.local_endpoint()?;
            let remote = socket.remote_endpoint()?;
            let holds = SocketAddr::new(smoltcp_to_std_ip(remote.addr), remote.port) == src
                && SocketAddr::new(smoltcp_to_std_ip(local.addr), local.port) == dst;
            holds.then_some(handle)
        })
        .collect()
}

/// The one handshake in `handshakes`.
fn one(handshakes: Vec<Handshake>) -> Handshake {
    assert_eq!(handshakes.len(), 1, "expected exactly one handshake");
    handshakes.into_iter().next().unwrap()
}

fn kind(handshake: &Handshake) -> &'static str {
    match handshake {
        Handshake::Pending { .. } => "pending",
        Handshake::Duplicate { .. } => "duplicate",
    }
}

/// The one non-superseding `Pending` handshake in `handshakes`, destructured.
/// Panics if it supersedes a stale owner — callers expecting that should use
/// [`one_superseding_pending`] instead, which asserts the opposite.
fn one_pending(handshakes: Vec<Handshake>) -> (SocketHandle, u16, SocketAddr, SocketAddr) {
    match one(handshakes) {
        Handshake::Pending {
            handle,
            port,
            src,
            dst,
            supersedes,
        } => {
            assert_eq!(
                supersedes, None,
                "expected a fresh handshake, not one superseding a stale owner"
            );
            (handle, port, src, dst)
        }
        other => panic!("expected a pending handshake, got a {} one", kind(&other)),
    }
}

/// The one superseding `Pending` handshake in `handshakes`, destructured,
/// including the stale owner it supersedes.
fn one_superseding_pending(handshakes: Vec<Handshake>) -> (SocketHandle, u16, SocketAddr, SocketAddr, SocketHandle) {
    match one(handshakes) {
        Handshake::Pending {
            handle,
            port,
            src,
            dst,
            supersedes: Some(owner),
        } => (handle, port, src, dst, owner),
        Handshake::Pending { supersedes: None, .. } => panic!("expected a superseding handshake, got a fresh one"),
        other => panic!("expected a pending handshake, got a {} one", kind(&other)),
    }
}

/// The one `Duplicate` handshake in `handshakes`, destructured.
fn one_duplicate(handshakes: Vec<Handshake>) -> (SocketHandle, u16) {
    match one(handshakes) {
        Handshake::Duplicate { handle, port } => (handle, port),
        other => panic!("expected a duplicate handshake, got a {} one", kind(&other)),
    }
}

/// Drive a listener on port 80 to `SynReceived` and return its handle. The tx
/// queue is left untouched — the caller decides what it should hold.
/// A listener is created paused, so nothing has been emitted yet.
fn half_open(stack: &mut SocketStack, isn: u32) -> SocketHandle {
    stack.ensure_listener(80);
    stack.enqueue_rx(syn(client(), dest(), isn));
    stack.poll(t(0));
    let (handle, port, src, dst) = one_pending(stack.take_handshakes());
    assert_eq!((port, src, dst), (80, client(), dest()));
    handle
}

/// Drive an admitted connection to the zombie state: the client answers the
/// SYN|ACK with an RST, and smoltcp flips the socket back to `Listen` without
/// clearing the listen endpoint that makes it accept on port alone.
fn revert_to_listen(stack: &mut SocketStack) -> SocketHandle {
    let isn = 1000u32;
    let handle = half_open(stack, isn);
    stack.admit(handle, 80);
    stack.poll(t(1));

    let synack = tcp_out(stack);
    assert_eq!(synack.len(), 1);
    assert_eq!(synack[0].control, TcpControl::Syn);

    stack.enqueue_rx(rst(client(), dest(), isn + 1, after(synack[0].seq)));
    stack.poll(t(2));
    handle
}

/// The instant of the client's ACK in [`established`] — the last thing the
/// client says, and so where its silence starts being measured.
const ESTABLISHED_AT: i64 = 2;

/// Drive a listener on port 80 through `admit` and the client's ACK to
/// `Established`. Returns the connection's handle and the sequence number the
/// client last acknowledged, which every later client segment must carry.
fn established(stack: &mut SocketStack, isn: u32) -> (SocketHandle, u32) {
    let handle = half_open(stack, isn);
    stack.admit(handle, 80);
    stack.poll(t(1));

    let synack = tcp_out(stack);
    assert_eq!(synack.len(), 1);
    assert_eq!(synack[0].control, TcpControl::Syn);
    stack.enqueue_rx(ack(client(), dest(), isn + 1, after(synack[0].seq)));
    stack.poll(t(2));
    assert_eq!(stack.socket(handle).state(), tcp::State::Established);
    (handle, after(synack[0].seq))
}

/// Drive an admitted connection through a clean close to `TimeWait`: we send
/// the FIN, the client acknowledges it and sends its own.
fn time_wait(stack: &mut SocketStack) -> SocketHandle {
    let isn = 1000u32;
    let (handle, _) = established(stack, isn);

    stack.socket_mut(handle).close();
    stack.poll(t(3));
    let our_fin = tcp_out(stack);
    assert_eq!(our_fin.len(), 1);
    assert_eq!(our_fin[0].control, TcpControl::Fin);

    stack.enqueue_rx(ack(client(), dest(), isn + 1, after(our_fin[0].seq)));
    stack.poll(t(4));
    assert_eq!(stack.socket(handle).state(), tcp::State::FinWait2);

    stack.enqueue_rx(fin(client(), dest(), isn + 1, after(our_fin[0].seq)));
    stack.poll(t(5));
    assert_eq!(stack.socket(handle).state(), tcp::State::TimeWait);
    let _ = tcp_out(stack);
    handle
}

/// Reproduce the slot-ordering steal, then feed a second SYN — with ISN
/// `second_isn` — onto the same tuple. `SocketSet::add` fills the lowest free
/// slot, so the listener `admit` re-arms the port with can land *below* its own
/// connection; smoltcp hands a packet to the first socket that `accepts()` it,
/// and a `Listen` socket accepts a bare SYN on port alone. The second SYN
/// therefore lands on the replacement listener instead of on the connection it
/// would otherwise belong to. Returns the connection's handle.
fn steal_a_syn(stack: &mut SocketStack, second_isn: u32) -> SocketHandle {
    let isn = 1000u32;

    // Occupy the lowest slot with a connection on another port, then free it:
    // the replacement listener needs a slot below the port-80 connection.
    stack.ensure_listener(other_dest().port());
    stack.ensure_listener(dest().port());
    stack.enqueue_rx(syn(client(), other_dest(), 7000));
    stack.poll(t(0));
    let (spare, spare_port, ..) = one_pending(stack.take_handshakes());
    stack.refuse(spare, spare_port);
    stack.poll(t(1));
    let _ = tcp_out(stack);
    assert!(!stack.sockets.iter().any(|(h, _)| h == spare), "the low slot is free");

    // The connection this reproduction is about.
    stack.enqueue_rx(syn(client(), dest(), isn));
    stack.poll(t(2));
    let (handle, port, ..) = one_pending(stack.take_handshakes());
    stack.admit(handle, port);
    stack.poll(t(3));
    let synack = tcp_out(stack);
    assert_eq!(synack.len(), 1);
    assert_eq!(synack[0].control, TcpControl::Syn);

    let slot = |target: SocketHandle| stack.sockets.iter().position(|(h, _)| h == target).unwrap();
    let listener = stack.listeners.iter().find(|l| l.port == dest().port()).unwrap().handle;
    assert!(
        slot(listener) < slot(handle),
        "the replacement listener must outrank the connection for this to reproduce",
    );

    stack.enqueue_rx(syn(client(), dest(), second_isn));
    stack.poll(t(4));
    assert_eq!(
        stack.socket(listener).state(),
        tcp::State::SynReceived,
        "the replacement listener took the second SYN",
    );
    assert_eq!(
        owners_of(stack, client(), dest()).len(),
        2,
        "two sockets now hold one client's 4-tuple",
    );
    handle
}

/// [`steal_a_syn`] with a genuine retransmit — the same ISN as the original.
fn steal_a_retransmitted_syn(stack: &mut SocketStack) -> SocketHandle {
    steal_a_syn(stack, 1000)
}

// Tests ===============================================================================================================

#[skuld::test]
fn ensure_listener_is_idempotent_per_port() {
    let mut stack = stack();
    stack.ensure_listener(80);
    stack.ensure_listener(80);
    assert_eq!(stack.sockets.iter().count(), 1);
}

#[skuld::test]
fn a_listener_holds_the_synack_until_admitted() {
    let mut stack = stack();
    let handle = half_open(&mut stack, 1000);
    assert!(tcp_out(&mut stack).is_empty());

    stack.admit(handle, 80);
    stack.poll(t(1));

    let out = tcp_out(&mut stack);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].control, TcpControl::Syn);
    assert!(out[0].ack.is_some());
    assert!(out[0].payload.is_empty());
}

#[skuld::test]
fn take_handshakes_reports_the_peer_tuple() {
    let mut stack = stack();
    stack.ensure_listener(80);
    stack.enqueue_rx(syn(client(), dest(), 1000));
    stack.poll(t(0));

    let (_, port, src, dst) = one_pending(stack.take_handshakes());
    assert_eq!(port, 80);
    assert_eq!(src, client());
    assert_eq!(dst, dest());
}

#[skuld::test]
fn take_handshakes_is_empty_without_a_syn() {
    let mut stack = stack();
    stack.ensure_listener(80);
    stack.poll(t(0));
    assert!(stack.take_handshakes().is_empty());
}

#[skuld::test]
fn refuse_emits_an_rst() {
    let mut stack = stack();
    let handle = half_open(&mut stack, 1000);
    assert!(tcp_out(&mut stack).is_empty());

    stack.refuse(handle, 80);
    stack.poll(t(1));

    let out = tcp_out(&mut stack);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].control, TcpControl::Rst);
    assert!(out[0].payload.is_empty());
}

#[skuld::test]
fn the_refusal_rst_acknowledges_the_clients_syn() {
    let isn = 1000u32;
    let mut stack = stack();
    let handle = half_open(&mut stack, isn);

    stack.refuse(handle, 80);
    stack.poll(t(1));

    let out = tcp_out(&mut stack);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].ack, Some(TcpSeqNumber(isn as i32 + 1)));
}

#[skuld::test]
fn the_refusal_rst_is_addressed_from_the_original_destination() {
    let mut stack = stack();
    let handle = half_open(&mut stack, 1000);

    stack.refuse(handle, 80);
    stack.poll(t(1));

    let out = tcp_out(&mut stack);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].src, dest());
    assert_eq!(out[0].dst, client());
}

#[skuld::test]
fn a_refused_socket_is_reaped_only_after_its_rst_is_sent() {
    let mut stack = stack();
    let handle = half_open(&mut stack, 1000);

    stack.refuse(handle, 80);
    assert_eq!(stack.sockets.iter().count(), 2);
    assert_eq!(stack.retiring, vec![handle]);

    stack.poll(t(1));
    assert_eq!(stack.sockets.iter().count(), 1);
    assert!(stack.retiring.is_empty());
}

/// Distinguishes reaping on smoltcp's completion signal from an unconditional
/// end-of-poll drain: this socket is parked but its peer is still live.
#[skuld::test]
fn a_parked_socket_with_a_live_peer_is_not_reaped() {
    let isn = 1000u32;
    let mut stack = stack();
    let handle = half_open(&mut stack, isn);
    stack.admit(handle, 80);
    stack.poll(t(1));

    let synack = tcp_out(&mut stack);
    assert_eq!(synack.len(), 1);
    stack.enqueue_rx(ack(client(), dest(), isn + 1, after(synack[0].seq)));
    stack.poll(t(2));
    assert_eq!(stack.socket(handle).state(), tcp::State::Established);

    stack.retire(handle);
    stack.poll(t(3));

    assert!(stack.sockets.iter().any(|(h, _)| h == handle));
    assert_eq!(stack.retiring, vec![handle]);
}

#[skuld::test]
fn a_refused_socket_does_not_intercept_a_retry() {
    let mut stack = stack();
    let refused = half_open(&mut stack, 1000);
    stack.refuse(refused, 80);

    // The refused socket outranks the re-armed listener in slot order, so the
    // interface reaches it first and its `Closed` early return is what keeps
    // the port serving.
    let order: Vec<SocketHandle> = stack.sockets.iter().map(|(handle, _)| handle).collect();
    assert_eq!(order.len(), 2);
    assert_eq!(order[0], refused);

    stack.enqueue_rx(syn(client(), dest(), 1000));
    stack.poll(t(1));

    let (handle, port, src, dst) = one_pending(stack.take_handshakes());
    assert_ne!(handle, refused);
    assert_eq!((port, src, dst), (80, client(), dest()));
}

/// Guards that pausing the SYN|ACK did not break the accepted path.
#[skuld::test]
fn an_admitted_connection_reaches_established() {
    let isn = 1000u32;
    let mut stack = stack();
    let handle = half_open(&mut stack, isn);
    stack.admit(handle, 80);
    stack.poll(t(1));

    let synack = tcp_out(&mut stack);
    assert_eq!(synack.len(), 1);
    assert_eq!(synack[0].control, TcpControl::Syn);

    stack.enqueue_rx(ack(client(), dest(), isn + 1, after(synack[0].seq)));
    stack.poll(t(2));

    assert_eq!(stack.socket(handle).state(), tcp::State::Established);
}

#[skuld::test]
fn refuse_rearms_the_listener() {
    let mut stack = stack();
    let handle = half_open(&mut stack, 1000);

    stack.refuse(handle, 80);
    stack.poll(t(1));
    let _ = tcp_out(&mut stack);

    stack.enqueue_rx(syn(client(), dest(), 1000));
    stack.poll(t(2));

    let (_, port, src, dst) = one_pending(stack.take_handshakes());
    assert_eq!((port, src, dst), (80, client(), dest()));
}

#[skuld::test]
fn a_client_rst_after_the_synack_reverts_the_socket_to_listen() {
    let mut stack = stack();
    let handle = revert_to_listen(&mut stack);

    assert_eq!(stack.socket(handle).state(), tcp::State::Listen);
    assert!(stack.socket(handle).remote_endpoint().is_none());
}

/// The defect, stated as a test: the reverted socket outranks the re-armed
/// listener and swallows the next client's SYN, which no accept path can see.
#[skuld::test]
fn a_reverted_socket_would_hijack_a_later_syn() {
    let mut stack = stack();
    let reverted = revert_to_listen(&mut stack);

    let order: Vec<SocketHandle> = stack.sockets.iter().map(|(handle, _)| handle).collect();
    assert_eq!(order.len(), 2);
    assert_eq!(order[0], reverted);

    stack.enqueue_rx(syn(other_client(), dest(), 5000));
    stack.poll(t(3));

    assert!(stack.take_handshakes().is_empty());
}

#[skuld::test]
fn a_reverted_socket_is_retired_and_stops_hijacking() {
    let mut stack = stack();
    let reverted = revert_to_listen(&mut stack);

    stack.retire(reverted);
    stack.poll(t(3));
    assert!(!stack.sockets.iter().any(|(handle, _)| handle == reverted));

    stack.enqueue_rx(syn(other_client(), dest(), 5000));
    stack.poll(t(4));

    let (_, port, src, dst) = one_pending(stack.take_handshakes());
    assert_eq!((port, src, dst), (80, other_client(), dest()));
}

#[skuld::test]
fn decide_disposal_retires_closed_and_listen_but_removes_timewait() {
    assert_eq!(decide_disposal(tcp::State::Closed), Some(Disposal::Retire));
    assert_eq!(decide_disposal(tcp::State::Listen), Some(Disposal::Retire));
    assert_eq!(decide_disposal(tcp::State::TimeWait), Some(Disposal::Remove));

    for state in [
        tcp::State::SynSent,
        tcp::State::SynReceived,
        tcp::State::Established,
        tcp::State::FinWait1,
        tcp::State::FinWait2,
        tcp::State::Closing,
        tcp::State::CloseWait,
        tcp::State::LastAck,
    ] {
        assert_eq!(decide_disposal(state), None, "{state} still has a peer");
    }
}

/// Why `TimeWait` is the one finished state that is removed rather than
/// retired: its tuple lives on for smoltcp's `CLOSE_DELAY`, so retiring it
/// would park the socket and both its buffers for that whole window.
#[skuld::test]
fn retiring_a_timewait_socket_would_hold_it_but_removing_does_not() {
    let mut parked = stack();
    let handle = time_wait(&mut parked);
    assert!(parked.socket(handle).remote_endpoint().is_some());

    parked.retire(handle);
    parked.poll(t(6));
    assert!(
        parked.sockets.iter().any(|(h, _)| h == handle),
        "retiring parks a TIME-WAIT socket instead of freeing it"
    );

    let mut dropped = stack();
    let handle = time_wait(&mut dropped);
    dropped.remove(handle);
    assert!(!dropped.sockets.iter().any(|(h, _)| h == handle));
}

/// The defect, stated as a test: the stolen SYN belongs to a connection the
/// driver already owns, so offering it as a new one would buy a second permit,
/// a second connection entry and a second upstream dial for one client socket.
#[skuld::test]
fn a_stolen_retransmit_is_not_offered_as_a_new_connection() {
    let mut stack = stack();
    let connection = steal_a_retransmitted_syn(&mut stack);

    let (handle, port) = one_duplicate(stack.take_handshakes());

    assert_eq!(port, dest().port());
    assert_ne!(handle, connection, "the owner of the tuple is untouched");
    assert_eq!(stack.socket(connection).state(), tcp::State::SynReceived);
}

#[skuld::test]
fn a_dropped_duplicate_answers_nothing_and_leaves_its_port_armed() {
    let mut stack = stack();
    let connection = steal_a_retransmitted_syn(&mut stack);
    let _ = tcp_out(&mut stack);
    let (handle, port) = one_duplicate(stack.take_handshakes());

    stack.drop_duplicate(handle, port);
    stack.poll(t(5));

    assert!(
        tcp_out(&mut stack).is_empty(),
        "the client is waiting on the tuple's owner"
    );
    assert_eq!(owners_of(&stack, client(), dest()), vec![connection]);
    assert_eq!(stack.socket(connection).state(), tcp::State::SynReceived);

    stack.enqueue_rx(syn(other_client(), dest(), 5000));
    stack.poll(t(6));
    let (_, _, src, dst) = one_pending(stack.take_handshakes());
    assert_eq!((src, dst), (other_client(), dest()));
}

/// The correction to the steal: a SYN carrying a *different* ISN on a tuple
/// the datapath still owns is not a retransmit (RFC 9293 §3.10.7.4). It is
/// classified `Pending` with `supersedes` naming the stale owner, not dropped
/// as a `Duplicate`.
#[skuld::test]
fn a_syn_with_a_different_isn_supersedes_its_tuples_owner() {
    let mut stack = stack();
    let connection = steal_a_syn(&mut stack, 2000);

    let (handle, port, src, dst, owner) = one_superseding_pending(stack.take_handshakes());

    assert_eq!((port, src, dst), (dest().port(), client(), dest()));
    assert_eq!(owner, connection);
    assert_ne!(handle, connection);
}

/// Tearing down the superseded owner and admitting the new SYN leaves exactly
/// one socket holding the tuple — the primitive composition the driver relies
/// on when it acts on `supersedes`.
#[skuld::test]
fn superseding_and_removing_the_stale_owner_leaves_one_socket_on_the_tuple() {
    let mut stack = stack();
    let connection = steal_a_syn(&mut stack, 2000);
    let (handle, port, ..) = one_superseding_pending(stack.take_handshakes());

    stack.remove(connection);
    stack.admit(handle, port);
    stack.poll(t(5));

    assert_eq!(owners_of(&stack, client(), dest()), vec![handle]);
    assert_eq!(stack.socket(handle).state(), tcp::State::SynReceived);
}

/// The defensive fallback: if this stack could not read the SYN's ISN off the
/// wire, a same-tuple owner is never assumed superseded — the
/// historically-safe `Duplicate` wins over guessing at a new connection.
#[skuld::test]
fn an_unreadable_isn_falls_back_to_duplicate_rather_than_superseding() {
    let mut stack = stack();
    let connection = steal_a_syn(&mut stack, 2000);
    stack.pending_syn = None; // simulate an ISN this stack could not read off the wire

    let (handle, port) = one_duplicate(stack.take_handshakes());

    assert_ne!(handle, connection);
    assert_eq!(port, dest().port());
}

#[skuld::test]
fn an_admitted_connection_whose_client_never_answers_is_closed() {
    let mut stack = stack();
    let handle = half_open(&mut stack, 1000);
    stack.admit(handle, 80);
    stack.poll(t(1));
    let _ = tcp_out(&mut stack);

    stack.poll(t(config_ms(|c| c.tcp_peer_timeout) + 1));

    assert_eq!(stack.socket(handle).state(), tcp::State::Closed);
}

#[skuld::test]
fn an_idle_connection_probes_its_client() {
    let mut stack = stack();
    let (handle, _) = established(&mut stack, 1000);
    let _ = tcp_out(&mut stack);

    stack.poll(t(120_000));

    let out = tcp_out(&mut stack);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].payload, b"\0",
        "a keep-alive carries one garbage octet (RFC 1122)"
    );
    assert_eq!(stack.socket(handle).state(), tcp::State::Established);
}

#[skuld::test]
fn an_idle_connection_whose_client_answers_the_probe_outlives_the_peer_timeout() {
    let mut stack = stack();
    let (handle, server_seq) = established(&mut stack, 1000);
    let _ = tcp_out(&mut stack);

    let probed_at = 2 * config_ms(|c| c.tcp_keep_alive_interval);
    stack.poll(t(probed_at));
    assert_eq!(tcp_out(&mut stack).len(), 1, "the idle connection is probed");
    stack.enqueue_rx(ack(client(), dest(), 1001, server_seq));
    stack.poll(t(probed_at + 1));

    // Past the bound measured from admission, but not from the answered probe.
    stack.poll(t(config_ms(|c| c.tcp_peer_timeout) + 2));

    assert_eq!(stack.socket(handle).state(), tcp::State::Established);
}

#[skuld::test]
fn an_idle_connection_whose_client_stops_answering_is_closed() {
    let mut stack = stack();
    let (handle, _) = established(&mut stack, 1000);

    stack.poll(t(ESTABLISHED_AT + config_ms(|c| c.tcp_peer_timeout)));

    assert_eq!(stack.socket(handle).state(), tcp::State::Closed);
}
