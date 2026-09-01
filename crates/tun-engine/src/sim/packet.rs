//! Synthetic packet builders for injecting traffic onto a [`super::SimWire`].

use std::net::SocketAddr;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};

use crate::engine::emit::build_udp_packet;

/// Build a raw IP+UDP packet. Delegates to the engine's own emitter so the
/// simulator can never drift from what the engine itself builds for a UDP
/// reply.
pub fn udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    build_udp_packet(src, dst, payload)
}

/// Build a raw IP+TCP SYN packet with no payload and no options, requesting
/// `dst` from `src` with initial sequence number `seq`.
pub fn tcp_syn(src: SocketAddr, dst: SocketAddr, seq: u32) -> Vec<u8> {
    let tcp_repr = TcpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(seq as i32),
        ack_number: None,
        window_len: 65535,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let checksums = ChecksumCapabilities::default();
    let tcp_len = tcp_repr.buffer_len();

    match (src.ip(), dst.ip()) {
        (std::net::IpAddr::V4(s), std::net::IpAddr::V4(d)) => {
            let ip_repr = Ipv4Repr {
                src_addr: s,
                dst_addr: d,
                next_header: IpProtocol::Tcp,
                payload_len: tcp_len,
                hop_limit: 64,
            };
            let total = ip_repr.buffer_len() + tcp_len;
            let mut buf = vec![0u8; total];
            let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf);
            ip_repr.emit(&mut ip_pkt, &checksums);
            let ip_hdr_len = ip_repr.buffer_len();
            let mut tcp_pkt = TcpPacket::new_unchecked(&mut buf[ip_hdr_len..]);
            tcp_repr.emit(&mut tcp_pkt, &IpAddress::Ipv4(s), &IpAddress::Ipv4(d), &checksums);
            buf
        }
        (std::net::IpAddr::V6(s), std::net::IpAddr::V6(d)) => {
            let ip_repr = Ipv6Repr {
                src_addr: s,
                dst_addr: d,
                next_header: IpProtocol::Tcp,
                payload_len: tcp_len,
                hop_limit: 64,
            };
            let total = ip_repr.buffer_len() + tcp_len;
            let mut buf = vec![0u8; total];
            let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf);
            ip_repr.emit(&mut ip_pkt);
            let ip_hdr_len = ip_repr.buffer_len();
            let mut tcp_pkt = TcpPacket::new_unchecked(&mut buf[ip_hdr_len..]);
            tcp_repr.emit(&mut tcp_pkt, &IpAddress::Ipv6(s), &IpAddress::Ipv6(d), &checksums);
            buf
        }
        _ => unreachable!("tcp_syn: src/dst IP family mismatch ({src} / {dst})"),
    }
}

#[cfg(test)]
#[path = "packet_tests.rs"]
mod packet_tests;
