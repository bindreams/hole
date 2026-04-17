use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

#[skuld::test]
fn encode_decode_roundtrip_ipv4() {
    let dst_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let dst_port = 443;
    let payload = b"hello world";

    let encoded = encode_socks5_udp(dst_ip, dst_port, None, payload);
    let (ip, port, header_len) = decode_socks5_udp(&encoded).expect("decode should succeed");

    assert_eq!(ip, dst_ip);
    assert_eq!(port, dst_port);
    assert_eq!(&encoded[header_len..], payload);
}

#[skuld::test]
fn encode_decode_roundtrip_ipv6() {
    let dst_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let dst_port = 8080;
    let payload = b"ipv6 test";

    let encoded = encode_socks5_udp(dst_ip, dst_port, None, payload);
    let (ip, port, header_len) = decode_socks5_udp(&encoded).expect("decode should succeed");

    assert_eq!(ip, dst_ip);
    assert_eq!(port, dst_port);
    assert_eq!(&encoded[header_len..], payload);
}

#[skuld::test]
fn encode_domain_decodes_as_unspecified_ip() {
    let dst_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let dst_port = 53;
    let payload = b"dns query";
    let domain = "example.com";

    let encoded = encode_socks5_udp(dst_ip, dst_port, Some(domain), payload);

    // ATYP should be 0x03 (domain).
    assert_eq!(encoded[3], 0x03);

    let (ip, port, header_len) = decode_socks5_udp(&encoded).expect("decode should succeed");
    // Domain-type decode returns 0.0.0.0 as the IP.
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(port, dst_port);
    assert_eq!(&encoded[header_len..], payload);
}

#[skuld::test]
fn frag_nonzero_returns_none() {
    let mut encoded = encode_socks5_udp(IpAddr::V4(Ipv4Addr::LOCALHOST), 80, None, b"data");
    // Set FRAG byte to non-zero.
    encoded[2] = 0x01;
    assert!(decode_socks5_udp(&encoded).is_none());
}

#[skuld::test]
fn truncated_packet_returns_none() {
    // Too short to contain even a minimal header.
    assert!(decode_socks5_udp(&[0x00, 0x00, 0x00, 0x01, 0x01]).is_none());
}

#[skuld::test]
fn unknown_atyp_returns_none() {
    let mut encoded = encode_socks5_udp(IpAddr::V4(Ipv4Addr::LOCALHOST), 80, None, b"data");
    // Replace ATYP with an invalid value.
    encoded[3] = 0x05;
    assert!(decode_socks5_udp(&encoded).is_none());
}
