use std::net::{Ipv4Addr, Ipv6Addr};

use super::*;

const SRC_V4: Ipv4Addr = Ipv4Addr::new(10, 255, 0, 2);
const DST_V4: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const SRC_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xff00, 2);
const DST_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946);
const SRC_PORT: u16 = 51000;
const DST_PORT: u16 = 443;
const PAYLOAD: &[u8] = b"hello parser";

/// Minimum TCP header length, mirroring `smoltcp::wire::TCP_HEADER_LEN`.
const TCP_MIN_HEADER: usize = 20;
/// Offset of the data-offset/reserved byte within the TCP header.
const TCP_DATA_OFFSET_BYTE: usize = 12;

// Packet builders =====================================================================================================

/// An IPv4 header of `ihl_bytes` bytes; option bytes (past 20) are left zero.
fn ipv4_header(protocol: u8, ihl_bytes: usize, total_len: usize) -> Vec<u8> {
    let mut h = vec![0u8; ihl_bytes];
    h[0] = 0x40 | (ihl_bytes / 4) as u8;
    h[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    h[8] = 64; // TTL
    h[9] = protocol;
    h[12..16].copy_from_slice(&SRC_V4.octets());
    h[16..20].copy_from_slice(&DST_V4.octets());
    h
}

fn ipv6_header(next_header: u8, payload_length: usize) -> Vec<u8> {
    let mut h = vec![0u8; 40];
    h[0] = 0x60;
    h[4..6].copy_from_slice(&(payload_length as u16).to_be_bytes());
    h[6] = next_header;
    h[7] = 64; // hop limit
    h[8..24].copy_from_slice(&SRC_V6.octets());
    h[24..40].copy_from_slice(&DST_V6.octets());
    h
}

/// A TCP header of `data_offset_bytes` bytes; option bytes (past 20) are left zero.
fn tcp_header(data_offset_bytes: usize) -> Vec<u8> {
    let mut h = vec![0u8; data_offset_bytes];
    h[0..2].copy_from_slice(&SRC_PORT.to_be_bytes());
    h[2..4].copy_from_slice(&DST_PORT.to_be_bytes());
    h[12] = ((data_offset_bytes / 4) as u8) << 4;
    h
}

fn udp_header(payload_len: usize) -> Vec<u8> {
    let mut h = vec![0u8; 8];
    h[0..2].copy_from_slice(&SRC_PORT.to_be_bytes());
    h[2..4].copy_from_slice(&DST_PORT.to_be_bytes());
    h[4..6].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    h
}

fn ipv4_tcp(ihl_bytes: usize) -> Vec<u8> {
    ipv4_tcp_with_offset(ihl_bytes, 20)
}

/// An IPv4/TCP packet whose TCP header carries `data_offset_bytes` of header
/// (20 plus options).
fn ipv4_tcp_with_offset(ihl_bytes: usize, data_offset_bytes: usize) -> Vec<u8> {
    let total = ihl_bytes + data_offset_bytes + PAYLOAD.len();
    let mut p = ipv4_header(6, ihl_bytes, total);
    p.extend_from_slice(&tcp_header(data_offset_bytes));
    p.extend_from_slice(PAYLOAD);
    p
}

fn ipv4_udp(ihl_bytes: usize) -> Vec<u8> {
    let total = ihl_bytes + 8 + PAYLOAD.len();
    let mut p = ipv4_header(17, ihl_bytes, total);
    p.extend_from_slice(&udp_header(PAYLOAD.len()));
    p.extend_from_slice(PAYLOAD);
    p
}

fn ipv6_tcp() -> Vec<u8> {
    ipv6_tcp_with_offset(20)
}

/// An IPv6/TCP packet whose TCP header carries `data_offset_bytes` of header
/// (20 plus options).
fn ipv6_tcp_with_offset(data_offset_bytes: usize) -> Vec<u8> {
    let mut p = ipv6_header(6, data_offset_bytes + PAYLOAD.len());
    p.extend_from_slice(&tcp_header(data_offset_bytes));
    p.extend_from_slice(PAYLOAD);
    p
}

fn ipv6_udp() -> Vec<u8> {
    let mut p = ipv6_header(17, 8 + PAYLOAD.len());
    p.extend_from_slice(&udp_header(PAYLOAD.len()));
    p.extend_from_slice(PAYLOAD);
    p
}

/// The four well-formed shapes, each with a name for assertion messages.
fn well_formed() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("ipv4/tcp", ipv4_tcp(20)),
        ("ipv4/udp", ipv4_udp(20)),
        ("ipv6/tcp", ipv6_tcp()),
        ("ipv6/udp", ipv6_udp()),
    ]
}

// Length sweep ========================================================================================================

#[skuld::test]
fn parse_never_panics_on_any_prefix() {
    for (name, packet) in well_formed() {
        for len in 0..=packet.len() {
            let prefix = &packet[..len];
            // Returning at all is the assertion: an out-of-bounds index here
            // panics the driver task and silently stops the tunnel.
            let _ = parse_ip_packet_full(prefix);
            let _ = parse_ip_dst(prefix);
        }
        // Guard against a parser that satisfies the sweep by rejecting everything.
        assert!(
            parse_ip_packet_full(&packet).is_some(),
            "{name}: the full packet must still parse"
        );
        assert!(
            parse_ip_dst(&packet).is_some(),
            "{name}: the full packet must still parse"
        );
    }
}

#[skuld::test]
fn truncated_ipv4_tcp_header_is_rejected() {
    // 28 bytes: a 20-byte IPv4 header plus 8 of the TCP header's 20.
    let packet = ipv4_header(6, 20, 28);
    let packet = [packet, vec![0u8; 8]].concat();
    assert_eq!(packet.len(), 28);
    assert!(parse_ip_packet_full(&packet).is_none());
}

#[skuld::test]
fn truncated_ipv6_tcp_header_is_rejected() {
    // 48 bytes: a 40-byte IPv6 header plus 8 of the TCP header's 20.
    let packet = [ipv6_header(6, 8), vec![0u8; 8]].concat();
    assert_eq!(packet.len(), 48);
    assert!(parse_ip_packet_full(&packet).is_none());
}

#[skuld::test]
fn ipv4_header_length_below_the_minimum_is_rejected() {
    // Version/IHL byte 0x40 claims a zero-length IPv4 header, which would put
    // the L4 header on top of the IP header's own version and TOS bytes.
    let mut packet = ipv4_tcp(20);
    packet[0] = 0x40;
    assert!(parse_ip_packet_full(&packet).is_none());
    assert!(parse_ip_dst(&packet).is_none());
}

#[skuld::test]
fn a_partial_tcp_header_is_rejected() {
    // Reaching the data-offset byte takes 13 bytes of TCP header; the parser
    // requires the full 20, so every partial header is rejected outright.
    let v4 = ipv4_tcp(20);
    for l4_bytes in 0..TCP_MIN_HEADER {
        let len = IPV4_MIN_HEADER + l4_bytes;
        assert!(parse_ip_packet_full(&v4[..len]).is_none(), "ipv4 length {len}");
    }
    let v6 = ipv6_tcp();
    for l4_bytes in 0..TCP_MIN_HEADER {
        let len = IPV6_HEADER + l4_bytes;
        assert!(parse_ip_packet_full(&v6[..len]).is_none(), "ipv6 length {len}");
    }
}

#[skuld::test]
fn tcp_data_offset_below_the_minimum_is_rejected() {
    // A data offset under five words would put the payload inside the TCP header.
    let mut v4 = ipv4_tcp(20);
    v4[IPV4_MIN_HEADER + TCP_DATA_OFFSET_BYTE] = 4 << 4;
    assert!(parse_ip_packet_full(&v4).is_none());

    let mut v6 = ipv6_tcp();
    v6[IPV6_HEADER + TCP_DATA_OFFSET_BYTE] = 4 << 4;
    assert!(parse_ip_packet_full(&v6).is_none());
}

#[skuld::test]
fn tcp_data_offset_beyond_the_packet_is_rejected() {
    // A data-offset nibble of 0xF claims a 60-byte TCP header on packets that
    // have nowhere near that much room; the extent it implies must not be
    // handed back as a successful parse.
    let mut v4 = ipv4_tcp(20);
    v4[IPV4_MIN_HEADER + TCP_DATA_OFFSET_BYTE] = 0xF << 4;
    assert!(parse_ip_packet_full(&v4).is_none());

    let mut v6 = ipv6_tcp();
    v6[IPV6_HEADER + TCP_DATA_OFFSET_BYTE] = 0xF << 4;
    assert!(parse_ip_packet_full(&v6).is_none());
}

#[skuld::test]
fn udp_len_exceeding_the_packet_is_rejected() {
    let mut v4 = ipv4_udp(20);
    v4[IPV4_MIN_HEADER + 4..IPV4_MIN_HEADER + 6].copy_from_slice(&0xFFFFu16.to_be_bytes());
    assert!(parse_ip_packet_full(&v4).is_none());

    let mut v6 = ipv6_udp();
    v6[IPV6_HEADER + 4..IPV6_HEADER + 6].copy_from_slice(&0xFFFFu16.to_be_bytes());
    assert!(parse_ip_packet_full(&v6).is_none());
}

#[skuld::test]
fn total_len_smaller_than_the_l4_header_is_rejected() {
    // Physically a full IPv4/TCP packet, but the header's own total_len
    // claims less than ihl + a full TCP header.
    let mut v4 = ipv4_tcp(20);
    v4[2..4].copy_from_slice(&30u16.to_be_bytes());
    assert!(parse_ip_packet_full(&v4).is_none());
}

// Field fidelity ======================================================================================================

#[skuld::test]
fn parsed_fields_match_a_well_formed_packet() {
    for (name, packet) in well_formed() {
        let parsed = parse_ip_packet_full(&packet).unwrap_or_else(|| panic!("{name}: expected a parse"));
        let (src_ip, dst_ip) = if name.starts_with("ipv4") {
            (IpAddr::V4(SRC_V4), IpAddr::V4(DST_V4))
        } else {
            (IpAddr::V6(SRC_V6), IpAddr::V6(DST_V6))
        };
        let proto = if name.ends_with("tcp") {
            IpProto::Tcp
        } else {
            IpProto::Udp
        };

        assert_eq!(parsed.src, SocketAddr::new(src_ip, SRC_PORT), "{name}");
        assert_eq!(parsed.dst, SocketAddr::new(dst_ip, DST_PORT), "{name}");
        assert_eq!(parsed.proto, proto, "{name}");
        assert_eq!(parsed.payload, PAYLOAD, "{name}");

        assert_eq!(parse_ip_dst(&packet), Some((DST_PORT, proto)), "{name}");
    }
}

#[skuld::test]
fn ipv4_options_are_skipped() {
    let with_options = ipv4_udp(24); // IHL=6: four option bytes
    let parsed = parse_ip_packet_full(&with_options).unwrap();
    assert_eq!(parsed.payload, PAYLOAD);
    assert_eq!(parse_ip_dst(&with_options), Some((DST_PORT, IpProto::Udp)));
}

#[skuld::test]
fn tcp_options_are_skipped() {
    let with_options = ipv4_tcp_with_offset(20, 24); // data offset 6 words: four option bytes
    let parsed = parse_ip_packet_full(&with_options).unwrap();
    assert_eq!(parsed.payload, PAYLOAD);
    assert_eq!(parse_ip_dst(&with_options), Some((DST_PORT, IpProto::Tcp)));

    let with_options = ipv6_tcp_with_offset(24);
    let parsed = parse_ip_packet_full(&with_options).unwrap();
    assert_eq!(parsed.payload, PAYLOAD);
    assert_eq!(parse_ip_dst(&with_options), Some((DST_PORT, IpProto::Tcp)));
}
