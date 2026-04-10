// Driver tests require a real TUN device (elevated privileges).
// Unit tests for parse_ip_dst are feasible and placed here.

use super::{parse_ip_dst, IpProto};

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
