//! Packet parsing — flow keys and payload from a raw IP packet.
//!
//! Every packet the TUN delivers passes through here before the driver
//! loop does anything else with it, so these functions are hostile-input
//! surface. Header fields are read through smoltcp's checked wire types
//! (`Ipv4Packet::new_checked` and friends), which reject a packet whose
//! declared lengths don't fit the buffer before any accessor is allowed to
//! run — so `ParsedPacket::payload` is bounded by construction, not by a
//! check a caller has to remember to add.

use std::net::{IpAddr, SocketAddr};

use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};

/// Minimum IPv4 header length, and the minimum legal value of the IHL field
/// scaled to bytes. A smaller IHL puts the L4 header inside the IP header.
const IPV4_MIN_HEADER: usize = 20;
/// Fixed IPv6 header length; extension headers are not walked.
const IPV6_HEADER: usize = 40;

pub(crate) fn parse_ip_dst(packet: &[u8]) -> Option<(u16, IpProto)> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => parse_ipv4_dst(packet),
        6 => parse_ipv6_dst(packet),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpProto {
    Tcp,
    Udp,
}

fn parse_ipv4_dst(packet: &[u8]) -> Option<(u16, IpProto)> {
    if packet.len() < IPV4_MIN_HEADER {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < IPV4_MIN_HEADER {
        return None;
    }
    let flags_frag_offset = u16::from_be_bytes([packet[6], packet[7]]);
    let more_frags = flags_frag_offset & 0x2000 != 0;
    let frag_offset = flags_frag_offset & 0x1fff;
    if more_frags || frag_offset != 0 {
        return None;
    }
    let protocol = packet[9];
    if packet.len() < ihl + 4 {
        return None;
    }
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    match protocol {
        6 => Some((dst_port, IpProto::Tcp)),
        17 => Some((dst_port, IpProto::Udp)),
        _ => None,
    }
}

fn parse_ipv6_dst(packet: &[u8]) -> Option<(u16, IpProto)> {
    if packet.len() < IPV6_HEADER + 4 {
        return None;
    }
    let next_header = packet[6];
    let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
    match next_header {
        6 => Some((dst_port, IpProto::Tcp)),
        17 => Some((dst_port, IpProto::Udp)),
        _ => None,
    }
}

/// A parsed packet's flow key and L4 payload.
pub(crate) struct ParsedPacket<'a> {
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) proto: IpProto,
    pub(crate) payload: &'a [u8],
}

pub(crate) fn parse_ip_packet_full(packet: &[u8]) -> Option<ParsedPacket<'_>> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => parse_ipv4_full(packet),
        6 => parse_ipv6_full(packet),
        _ => None,
    }
}

fn parse_ipv4_full(packet: &[u8]) -> Option<ParsedPacket<'_>> {
    let ip = Ipv4Packet::new_checked(packet).ok()?;
    // `new_checked` bounds-checks lengths but does not inspect fragmentation;
    // an L4 header is only present in the first fragment, and this driver
    // does not reassemble, so any fragment must be rejected rather than
    // parsed as if its bytes were an L4 header (or L4 payload mistaken for
    // one). See issue #951 for reassembly.
    if ip.more_frags() || ip.frag_offset() != 0 {
        return None;
    }
    let src_ip = IpAddr::V4(ip.src_addr());
    let dst_ip = IpAddr::V4(ip.dst_addr());
    let proto = ip.next_header();
    parse_l4(proto, src_ip, dst_ip, ip.payload())
}

fn parse_ipv6_full(packet: &[u8]) -> Option<ParsedPacket<'_>> {
    let ip = Ipv6Packet::new_checked(packet).ok()?;
    let src_ip = IpAddr::V6(ip.src_addr());
    let dst_ip = IpAddr::V6(ip.dst_addr());
    let proto = ip.next_header();
    parse_l4(proto, src_ip, dst_ip, ip.payload())
}

/// Parse the TCP/UDP header out of an IP payload already bounded to the IP
/// header's own declared length (`Ipv4Packet`/`Ipv6Packet::payload()`).
fn parse_l4(proto: IpProtocol, src_ip: IpAddr, dst_ip: IpAddr, l4: &[u8]) -> Option<ParsedPacket<'_>> {
    let (proto, src_port, dst_port, payload) = match proto {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(l4).ok()?;
            (IpProto::Tcp, tcp.src_port(), tcp.dst_port(), tcp.payload())
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(l4).ok()?;
            (IpProto::Udp, udp.src_port(), udp.dst_port(), udp.payload())
        }
        _ => return None,
    };

    Some(ParsedPacket {
        src: SocketAddr::new(src_ip, src_port),
        dst: SocketAddr::new(dst_ip, dst_port),
        proto,
        payload,
    })
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod parse_tests;
