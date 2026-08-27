//! Segment builders and egress parsing shared by the packet-level tests.
//!
//! Registered from `engine.rs` under `#[cfg(test)]` instead of as a `*_tests.rs`
//! sibling: it has no business-logic counterpart, and both
//! `socket_stack_tests.rs` and `driver_tests.rs` drive a real smoltcp
//! `Interface` over a [`VirtualTunDevice`](super::virtual_device::VirtualTunDevice).
//!
//! Four properties are load-bearing:
//!
//! 1. [`device_config`] supplies a real MTU. `MutDeviceConfig::default()` leaves
//!    `mtu` at 0, and smoltcp computes `ip_mtu() - ip_header_len -
//!    TCP_HEADER_LEN`, which underflows and panics on the first poll after any
//!    SYN.
//! 2. [`tcp_out`] owns its bytes. `TcpRepr` borrows its payload, so [`Segment`]
//!    copies out every field a test asserts on, payload included.
//! 3. [`tcp_out`] is destructive — `dequeue_tx` is the only thing that empties
//!    the queue, so every tx assertion is relative to the last drain.
//! 4. Sequence numbers are randomised by smoltcp. Assert relations to the
//!    client's own ISN, never absolute values.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Cidr, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};

use super::socket_stack::SocketStack;
use crate::device::{DeviceConfig, MutDeviceConfig};

/// One segment drained from the virtual device, owned.
pub(crate) struct Segment {
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) control: TcpControl,
    pub(crate) seq: TcpSeqNumber,
    pub(crate) ack: Option<TcpSeqNumber>,
    pub(crate) payload: Vec<u8>,
}

/// The client dialling through the tunnel.
pub(crate) fn client() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 40000)
}

/// A second client dialling the same destination.
pub(crate) fn other_client() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 41000)
}

/// The address the client dialled, outside the tunnel's own subnet.
pub(crate) fn dest() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80)
}

/// A second destination, on another port.
pub(crate) fn other_dest() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 53)
}

pub(crate) fn device_config() -> DeviceConfig {
    MutDeviceConfig {
        tun_name: "hole-test".into(),
        mtu: 1400,
        ipv4: Some(Ipv4Cidr::new(Ipv4Addr::new(10, 255, 0, 1), 24)),
        ipv6: None,
    }
    .freeze()
}

pub(crate) fn t(ms: i64) -> SmoltcpInstant {
    SmoltcpInstant::from_millis(ms)
}

/// The sequence number one past `seq`, in the wire form the builders take.
pub(crate) fn after(seq: TcpSeqNumber) -> u32 {
    (seq.0 as u32).wrapping_add(1)
}

pub(crate) fn segment(src: SocketAddr, dst: SocketAddr, control: TcpControl, seq: u32, ack: Option<u32>) -> Vec<u8> {
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

pub(crate) fn syn(src: SocketAddr, dst: SocketAddr, seq: u32) -> Vec<u8> {
    segment(src, dst, TcpControl::Syn, seq, None)
}

pub(crate) fn ack(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32) -> Vec<u8> {
    segment(src, dst, TcpControl::None, seq, Some(ack))
}

pub(crate) fn rst(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32) -> Vec<u8> {
    segment(src, dst, TcpControl::Rst, seq, Some(ack))
}

pub(crate) fn fin(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32) -> Vec<u8> {
    segment(src, dst, TcpControl::Fin, seq, Some(ack))
}

/// Drain and parse everything the stack has queued for the TUN.
pub(crate) fn tcp_out(stack: &mut SocketStack) -> Vec<Segment> {
    stack.dequeue_tx().iter().map(|packet| parse_segment(packet)).collect()
}

pub(crate) fn parse_segment(packet: &[u8]) -> Segment {
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
