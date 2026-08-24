//! Packet-level tests over a real smoltcp `Interface` + `VirtualTunDevice`.
//!
//! Four properties of the helpers below are load-bearing:
//!
//! 1. [`stack`] supplies a real MTU. `MutDeviceConfig::default()` leaves `mtu`
//!    at 0, and smoltcp computes `ip_mtu() - ip_header_len - TCP_HEADER_LEN`,
//!    which underflows and panics on the first poll after any SYN.
//! 2. [`tcp_out`] owns its bytes. `TcpRepr` borrows its payload, so [`Segment`]
//!    copies out every field a test asserts on, payload included.
//! 3. [`tcp_out`] is destructive — `dequeue_tx` is the only thing that empties
//!    the queue, so every tx assertion is relative to the last drain.
//! 4. Sequence numbers are randomised by smoltcp. Assert relations to the
//!    client's own ISN, never absolute values.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{IpProtocol, Ipv4Cidr, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber};

use super::*;
use crate::device::MutDeviceConfig;
use crate::engine::config::MutEngineConfig;

// Helpers =============================================================================================================

/// One segment drained from the virtual device, owned.
struct Segment {
    src: SocketAddr,
    dst: SocketAddr,
    control: TcpControl,
    seq: TcpSeqNumber,
    ack: Option<TcpSeqNumber>,
    payload: Vec<u8>,
}

/// The client dialling through the tunnel.
fn client() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 40000)
}

/// The address the client dialled, outside the tunnel's own subnet.
fn dest() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80)
}

fn stack() -> SocketStack {
    let device_config = MutDeviceConfig {
        tun_name: "hole-test".into(),
        mtu: 1400,
        ipv4: Some(Ipv4Cidr::new(Ipv4Addr::new(10, 255, 0, 1), 24)),
        ipv6: None,
    }
    .freeze();
    SocketStack::new(&device_config, &MutEngineConfig::default().freeze())
}

fn t(ms: i64) -> SmoltcpInstant {
    SmoltcpInstant::from_millis(ms)
}

/// The sequence number one past `seq`, in the wire form the builders take.
fn after(seq: TcpSeqNumber) -> u32 {
    (seq.0 as u32).wrapping_add(1)
}

fn segment(src: SocketAddr, dst: SocketAddr, control: TcpControl, seq: u32, ack: Option<u32>) -> Vec<u8> {
    let (src_v4, dst_v4) = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
        _ => panic!("these helpers build IPv4 segments only"),
    };
    let checksums = ChecksumCapabilities::default();

    let tcp_repr = TcpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
        control,
        seq_number: TcpSeqNumber(seq as i32),
        ack_number: ack.map(|a| TcpSeqNumber(a as i32)),
        window_len: 65535,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };
    let ip_repr = Ipv4Repr {
        src_addr: src_v4,
        dst_addr: dst_v4,
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    };

    let header_len = ip_repr.buffer_len();
    let mut buf = vec![0u8; header_len + tcp_repr.buffer_len()];
    ip_repr.emit(&mut Ipv4Packet::new_unchecked(&mut buf), &checksums);
    tcp_repr.emit(
        &mut TcpPacket::new_unchecked(&mut buf[header_len..]),
        &IpAddress::Ipv4(src_v4),
        &IpAddress::Ipv4(dst_v4),
        &checksums,
    );
    buf
}

fn syn(src: SocketAddr, dst: SocketAddr, seq: u32) -> Vec<u8> {
    segment(src, dst, TcpControl::Syn, seq, None)
}

fn ack(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32) -> Vec<u8> {
    segment(src, dst, TcpControl::None, seq, Some(ack))
}

/// Drain and parse everything the stack has queued for the TUN.
fn tcp_out(stack: &mut SocketStack) -> Vec<Segment> {
    stack.dequeue_tx().iter().map(|packet| parse_segment(packet)).collect()
}

fn parse_segment(packet: &[u8]) -> Segment {
    let checksums = ChecksumCapabilities::default();
    let ip_packet = Ipv4Packet::new_checked(packet).expect("egress packet is IPv4");
    let ip_repr = Ipv4Repr::parse(&ip_packet, &checksums).expect("egress IPv4 header parses");
    let tcp_packet = TcpPacket::new_checked(ip_packet.payload()).expect("egress payload is TCP");
    let tcp_repr = TcpRepr::parse(
        &tcp_packet,
        &IpAddress::Ipv4(ip_repr.src_addr),
        &IpAddress::Ipv4(ip_repr.dst_addr),
        &checksums,
    )
    .expect("egress TCP header parses");

    Segment {
        src: SocketAddr::new(IpAddr::V4(ip_repr.src_addr), tcp_repr.src_port),
        dst: SocketAddr::new(IpAddr::V4(ip_repr.dst_addr), tcp_repr.dst_port),
        control: tcp_repr.control,
        seq: tcp_repr.seq_number,
        ack: tcp_repr.ack_number,
        payload: tcp_repr.payload.to_vec(),
    }
}

/// The one `Pending` handshake in `handshakes`, destructured.
fn one_pending(handshakes: Vec<Handshake>) -> (SocketHandle, u16, SocketAddr, SocketAddr) {
    assert_eq!(handshakes.len(), 1, "expected exactly one handshake");
    match handshakes.into_iter().next().unwrap() {
        Handshake::Pending { handle, port, src, dst } => (handle, port, src, dst),
        Handshake::Stale { port, .. } => panic!("expected a pending handshake on port {port}, got a stale one"),
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
