//! Packet parsing — flow keys and payload extents from a raw IP packet.
//!
//! Every packet the TUN delivers passes through here before the driver
//! loop does anything else with it, so these functions are hostile-input
//! surface: an out-of-bounds read panics the driver task and silently
//! stops the tunnel.

use std::net::{IpAddr, SocketAddr};

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
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
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
    if packet.len() < 40 + 4 {
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

pub(crate) struct ParsedPacket {
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) proto: IpProto,
    pub(crate) payload_offset: usize,
    pub(crate) payload_len: usize,
}

pub(crate) fn parse_ip_packet_full(packet: &[u8]) -> Option<ParsedPacket> {
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

fn parse_ipv4_full(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.len() < 20 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    let protocol = packet[9];
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;

    if packet.len() < ihl + 8 || total_len < ihl + 8 {
        return None;
    }

    let proto = match protocol {
        6 => IpProto::Tcp,
        17 => IpProto::Udp,
        _ => return None,
    };

    let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
    let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);

    let (payload_offset, payload_len) = if proto == IpProto::Udp {
        let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
        let hdr = 8;
        (ihl + hdr, udp_len.saturating_sub(hdr))
    } else {
        let data_offset = ((packet[ihl + 12] >> 4) as usize) * 4;
        let tcp_payload = total_len.saturating_sub(ihl + data_offset);
        (ihl + data_offset, tcp_payload)
    };

    Some(ParsedPacket {
        src: SocketAddr::new(src_ip, src_port),
        dst: SocketAddr::new(dst_ip, dst_port),
        proto,
        payload_offset,
        payload_len,
    })
}

fn parse_ipv6_full(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.len() < 48 {
        return None;
    }
    let next_header = packet[6];
    let payload_length = u16::from_be_bytes([packet[4], packet[5]]) as usize;

    let proto = match next_header {
        6 => IpProto::Tcp,
        17 => IpProto::Udp,
        _ => return None,
    };

    let mut src_octets = [0u8; 16];
    src_octets.copy_from_slice(&packet[8..24]);
    let mut dst_octets = [0u8; 16];
    dst_octets.copy_from_slice(&packet[24..40]);

    let src_ip = IpAddr::V6(std::net::Ipv6Addr::from(src_octets));
    let dst_ip = IpAddr::V6(std::net::Ipv6Addr::from(dst_octets));

    let l4_start = 40;
    let src_port = u16::from_be_bytes([packet[l4_start], packet[l4_start + 1]]);
    let dst_port = u16::from_be_bytes([packet[l4_start + 2], packet[l4_start + 3]]);

    let (payload_offset, payload_len) = if proto == IpProto::Udp {
        let udp_len = u16::from_be_bytes([packet[l4_start + 4], packet[l4_start + 5]]) as usize;
        let hdr = 8;
        (l4_start + hdr, udp_len.saturating_sub(hdr))
    } else {
        let data_offset = ((packet[l4_start + 12] >> 4) as usize) * 4;
        let tcp_payload = payload_length.saturating_sub(data_offset);
        (l4_start + data_offset, tcp_payload)
    };

    Some(ParsedPacket {
        src: SocketAddr::new(src_ip, src_port),
        dst: SocketAddr::new(dst_ip, dst_port),
        proto,
        payload_offset,
        payload_len,
    })
}
