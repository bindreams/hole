// Driver tests require a real TUN device (elevated privileges).
// Unit tests for parse_ip_dst are feasible and placed here.

use super::{build_udp_packet, parse_ip_dst, parse_ip_packet_full, IpProto};
use smoltcp::wire::{IpAddress, Ipv4Packet, Ipv6Packet, UdpPacket};

#[skuld::test]
fn parse_ipv4_tcp_syn() {
    // Minimal IPv4 header (20 bytes) + TCP header start (4 bytes for ports).
    let mut packet = [0u8; 24];
    packet[0] = 0x45; // version=4, IHL=5 (20 bytes)
    packet[9] = 6; // protocol = TCP
                   // Destination port at offset IHL+2..IHL+4 = 22..24
    packet[22] = 0x01;
    packet[23] = 0xBB; // port 443
    let result = parse_ip_dst(&packet);
    assert_eq!(result, Some((443, IpProto::Tcp)));
}

#[skuld::test]
fn parse_ipv4_udp() {
    let mut packet = [0u8; 24];
    packet[0] = 0x45;
    packet[9] = 17; // protocol = UDP
    packet[22] = 0x00;
    packet[23] = 0x35; // port 53
    let result = parse_ip_dst(&packet);
    assert_eq!(result, Some((53, IpProto::Udp)));
}

#[skuld::test]
fn parse_ipv6_tcp() {
    // IPv6 header (40 bytes) + TCP header start (4 bytes for ports).
    let mut packet = [0u8; 44];
    packet[0] = 0x60; // version=6
    packet[6] = 6; // next header = TCP
                   // Destination port at offset 42..44
    packet[42] = 0x00;
    packet[43] = 0x50; // port 80
    let result = parse_ip_dst(&packet);
    assert_eq!(result, Some((80, IpProto::Tcp)));
}

#[skuld::test]
fn parse_empty_packet_returns_none() {
    assert_eq!(parse_ip_dst(&[]), None);
}

#[skuld::test]
fn parse_truncated_ipv4_returns_none() {
    // Only 10 bytes — not enough for an IPv4 header.
    let packet = [0x45u8; 10];
    assert_eq!(parse_ip_dst(&packet), None);
}

#[skuld::test]
fn parse_unknown_protocol_returns_none() {
    let mut packet = [0u8; 24];
    packet[0] = 0x45;
    packet[9] = 1; // ICMP
    assert_eq!(parse_ip_dst(&packet), None);
}

// parse_ip_packet_full tests ==========================================================================================

#[skuld::test]
fn parse_full_ipv4_udp() {
    // Build a minimal IPv4+UDP packet via build_udp_packet, then parse it back.
    let src: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let dst: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();
    let payload = b"hello";
    let packet = build_udp_packet(src.into(), 12345, dst.into(), 53, payload);

    let parsed = parse_ip_packet_full(&packet).unwrap();
    assert_eq!(parsed.proto, IpProto::Udp);
    assert_eq!(parsed.src_ip, std::net::IpAddr::V4(src));
    assert_eq!(parsed.dst_ip, std::net::IpAddr::V4(dst));
    assert_eq!(parsed.src_port, 12345);
    assert_eq!(parsed.dst_port, 53);
    assert_eq!(parsed.payload_len, payload.len());
    assert_eq!(
        &packet[parsed.payload_offset..parsed.payload_offset + parsed.payload_len],
        payload
    );
}

#[skuld::test]
fn parse_full_ipv6_udp() {
    let src: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let dst: std::net::Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
    let payload = b"world";
    let packet = build_udp_packet(src.into(), 54321, dst.into(), 443, payload);

    let parsed = parse_ip_packet_full(&packet).unwrap();
    assert_eq!(parsed.proto, IpProto::Udp);
    assert_eq!(parsed.src_ip, std::net::IpAddr::V6(src));
    assert_eq!(parsed.dst_ip, std::net::IpAddr::V6(dst));
    assert_eq!(parsed.src_port, 54321);
    assert_eq!(parsed.dst_port, 443);
    assert_eq!(parsed.payload_len, payload.len());
    assert_eq!(
        &packet[parsed.payload_offset..parsed.payload_offset + parsed.payload_len],
        payload
    );
}

// build_udp_packet tests ==============================================================================================

#[skuld::test]
fn build_ipv4_udp_roundtrip() {
    let src: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();
    let dst: std::net::Ipv4Addr = "10.0.0.2".parse().unwrap();
    let payload = b"test payload data";

    let packet = build_udp_packet(src.into(), 1234, dst.into(), 5678, payload);

    // Parse with smoltcp to verify correctness.
    let ip_pkt = Ipv4Packet::new_checked(&packet).unwrap();
    assert_eq!(ip_pkt.src_addr(), src);
    assert_eq!(ip_pkt.dst_addr(), dst);
    assert_eq!(ip_pkt.next_header(), smoltcp::wire::IpProtocol::Udp);
    assert!(ip_pkt.verify_checksum(), "IPv4 header checksum mismatch");

    let ip_hdr_len = ip_pkt.header_len() as usize;
    let udp_pkt = UdpPacket::new_checked(&packet[ip_hdr_len..]).unwrap();
    assert_eq!(udp_pkt.src_port(), 1234);
    assert_eq!(udp_pkt.dst_port(), 5678);
    assert_eq!(udp_pkt.payload(), payload);

    // Verify UDP checksum.
    udp_pkt
        .verify_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst))
        .then_some(())
        .expect("UDP checksum mismatch");
}

#[skuld::test]
fn build_ipv6_udp_roundtrip() {
    let src: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let dst: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
    let payload = b"ipv6 test data";

    let packet = build_udp_packet(src.into(), 9999, dst.into(), 8080, payload);

    // Parse with smoltcp.
    let ip_pkt = Ipv6Packet::new_checked(&packet).unwrap();
    assert_eq!(ip_pkt.src_addr(), src);
    assert_eq!(ip_pkt.dst_addr(), dst);
    assert_eq!(ip_pkt.next_header(), smoltcp::wire::IpProtocol::Udp);

    let ip_hdr_len = 40; // fixed IPv6 header
    let udp_pkt = UdpPacket::new_checked(&packet[ip_hdr_len..]).unwrap();
    assert_eq!(udp_pkt.src_port(), 9999);
    assert_eq!(udp_pkt.dst_port(), 8080);
    assert_eq!(udp_pkt.payload(), payload);

    udp_pkt
        .verify_checksum(&IpAddress::Ipv6(src), &IpAddress::Ipv6(dst))
        .then_some(())
        .expect("UDP checksum mismatch");
}

#[skuld::test]
fn build_udp_mismatched_ip_versions_returns_empty() {
    let src: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let dst: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let packet = build_udp_packet(src.into(), 1234, dst.into(), 5678, b"data");
    assert!(packet.is_empty());
}

#[skuld::test]
fn build_udp_empty_payload() {
    let src: std::net::Ipv4Addr = "10.0.0.1".parse().unwrap();
    let dst: std::net::Ipv4Addr = "10.0.0.2".parse().unwrap();
    let packet = build_udp_packet(src.into(), 100, dst.into(), 200, b"");

    let ip_pkt = Ipv4Packet::new_checked(&packet).unwrap();
    let ip_hdr_len = ip_pkt.header_len() as usize;
    let udp_pkt = UdpPacket::new_checked(&packet[ip_hdr_len..]).unwrap();
    assert_eq!(udp_pkt.payload().len(), 0);
    assert_eq!(udp_pkt.src_port(), 100);
    assert_eq!(udp_pkt.dst_port(), 200);
}
