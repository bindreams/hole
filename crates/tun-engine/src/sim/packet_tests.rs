//! Asserts through smoltcp's own accessors, not the crate's `parse.rs`
//! logic, so a shared bug in that logic cannot mask itself here.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use smoltcp::wire::{IpAddress, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};

use super::*;

fn v4(a: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(a.into(), port)
}

fn v6(a: Ipv6Addr, port: u16) -> SocketAddr {
    SocketAddr::new(a.into(), port)
}

#[skuld::test]
fn built_udp_packet_parses_back_v4() {
    let src = v4(Ipv4Addr::new(10, 255, 0, 2), 51000);
    let dst = v4(Ipv4Addr::new(8, 8, 8, 8), 53);
    let pkt = udp_packet(src, dst, b"payload");

    let ip = Ipv4Packet::new_checked(&pkt).expect("not a valid IPv4 packet");
    assert_eq!(ip.src_addr(), Ipv4Addr::new(10, 255, 0, 2));
    assert_eq!(ip.dst_addr(), Ipv4Addr::new(8, 8, 8, 8));

    let udp = UdpPacket::new_checked(ip.payload()).expect("not a valid UDP packet");
    assert_eq!(udp.src_port(), 51000);
    assert_eq!(udp.dst_port(), 53);
    assert_eq!(udp.payload(), b"payload");
    assert!(udp.verify_checksum(&IpAddress::Ipv4(ip.src_addr()), &IpAddress::Ipv4(ip.dst_addr())));
}

#[skuld::test]
fn built_udp_packet_parses_back_v6() {
    let src = v6("fd00::ff00:2".parse().unwrap(), 51000);
    let dst = v6("2001:db8::1".parse().unwrap(), 443);
    let pkt = udp_packet(src, dst, b"payload6");

    let ip = Ipv6Packet::new_checked(&pkt).expect("not a valid IPv6 packet");
    assert_eq!(ip.src_addr(), "fd00::ff00:2".parse::<Ipv6Addr>().unwrap());
    assert_eq!(ip.dst_addr(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());

    let udp = UdpPacket::new_checked(ip.payload()).expect("not a valid UDP packet");
    assert_eq!(udp.src_port(), 51000);
    assert_eq!(udp.dst_port(), 443);
    assert_eq!(udp.payload(), b"payload6");
    assert!(udp.verify_checksum(&IpAddress::Ipv6(ip.src_addr()), &IpAddress::Ipv6(ip.dst_addr())));
}

#[skuld::test]
fn built_tcp_syn_parses_back_v4() {
    let src = v4(Ipv4Addr::new(10, 255, 0, 2), 51000);
    let dst = v4(Ipv4Addr::new(93, 184, 216, 34), 80);
    let pkt = tcp_syn(src, dst, 1000);

    let ip = Ipv4Packet::new_checked(&pkt).expect("not a valid IPv4 packet");
    assert_eq!(ip.src_addr(), Ipv4Addr::new(10, 255, 0, 2));
    assert_eq!(ip.dst_addr(), Ipv4Addr::new(93, 184, 216, 34));

    let tcp = TcpPacket::new_checked(ip.payload()).expect("not a valid TCP packet");
    assert_eq!(tcp.src_port(), 51000);
    assert_eq!(tcp.dst_port(), 80);
    assert!(tcp.syn());
    assert!(!tcp.ack());
    assert_eq!(tcp.seq_number().0 as u32, 1000);
    assert!(tcp.verify_checksum(&IpAddress::Ipv4(ip.src_addr()), &IpAddress::Ipv4(ip.dst_addr())));
}

#[skuld::test]
fn built_tcp_syn_parses_back_v6() {
    let src = v6("fd00::ff00:2".parse().unwrap(), 51000);
    let dst = v6("2001:db8::1".parse().unwrap(), 443);
    let pkt = tcp_syn(src, dst, 2000);

    let ip = Ipv6Packet::new_checked(&pkt).expect("not a valid IPv6 packet");
    let tcp = TcpPacket::new_checked(ip.payload()).expect("not a valid TCP packet");
    assert_eq!(tcp.src_port(), 51000);
    assert_eq!(tcp.dst_port(), 443);
    assert!(tcp.syn());
    assert_eq!(tcp.seq_number().0 as u32, 2000);
    assert!(tcp.verify_checksum(&IpAddress::Ipv6(ip.src_addr()), &IpAddress::Ipv6(ip.dst_addr())));
}
