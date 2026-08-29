//! Reply packet construction — raw IP+UDP frames written back to the TUN.

use std::net::{IpAddr, SocketAddr};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, UdpPacket, UdpRepr};
use tracing::debug;

/// Build a raw IP+UDP packet from the given fields, with correct checksums.
pub(crate) fn build_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    debug_assert!(src.is_ipv4() == dst.is_ipv4(), "src/dst IP family mismatch");

    let udp_len = 8 + payload.len();
    let checksums = ChecksumCapabilities::default();
    let src_port = src.port();
    let dst_port = dst.port();

    match (src.ip(), dst.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let ip_repr = Ipv4Repr {
                src_addr: src,
                dst_addr: dst,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let total = ip_repr.buffer_len() + udp_len;
            let mut buf = vec![0u8; total];

            let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf);
            ip_repr.emit(&mut ip_pkt, &checksums);

            let ip_hdr_len = ip_repr.buffer_len();
            let mut udp_pkt = UdpPacket::new_unchecked(&mut buf[ip_hdr_len..]);
            let udp_repr = UdpRepr { src_port, dst_port };
            udp_repr.emit(
                &mut udp_pkt,
                &IpAddress::Ipv4(src),
                &IpAddress::Ipv4(dst),
                payload.len(),
                |buf| buf.copy_from_slice(payload),
                &checksums,
            );

            buf
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let ip_repr = Ipv6Repr {
                src_addr: src,
                dst_addr: dst,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let total = ip_repr.buffer_len() + udp_len;
            let mut buf = vec![0u8; total];

            let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf);
            ip_repr.emit(&mut ip_pkt);

            let ip_hdr_len = ip_repr.buffer_len();
            let mut udp_pkt = UdpPacket::new_unchecked(&mut buf[ip_hdr_len..]);
            let udp_repr = UdpRepr { src_port, dst_port };
            udp_repr.emit(
                &mut udp_pkt,
                &IpAddress::Ipv6(src),
                &IpAddress::Ipv6(dst),
                payload.len(),
                |buf| buf.copy_from_slice(payload),
                &checksums,
            );

            buf
        }
        _ => {
            debug!("mismatched IP versions in UDP reply");
            Vec::new()
        }
    }
}

pub(crate) fn smoltcp_to_std_ip(addr: IpAddress) -> IpAddr {
    match addr {
        IpAddress::Ipv4(v4) => IpAddr::V4(v4),
        IpAddress::Ipv6(v6) => IpAddr::V6(v6),
    }
}
