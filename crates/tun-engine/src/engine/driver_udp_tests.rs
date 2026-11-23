//! UDP dispatch fidelity: the driver reaches the router with the packet's
//! 5-tuple, reuses an existing flow rather than opening a second one, and
//! frames a router-originated reply back onto the wire with a checksum that
//! verifies.
//!
//! Every test drives `Engine::from_io` over a `sim::packet_pair` wire and a
//! `sim::recording_router` — no real socket, proxy or bypass mechanism is
//! involved.

use smoltcp::wire::{IpAddress, Ipv4Cidr, Ipv4Packet, Ipv6Packet, UdpPacket};

use super::super::driver_sim_test_support::{start, v4, v6};
use super::is_addressed_to_the_link;
use crate::sim::{udp_packet, Dispatch};

#[skuld::test]
async fn a_udp_datagram_reaches_the_router_with_its_five_tuple() {
    let mut h = start(|_| {});
    let src = v4("10.255.0.2", 51000);
    let dst = v4("8.8.8.8", 443);

    h.wire.inject(udp_packet(src, dst, b"hello")).await;

    let dispatch = h.dispatch.recv().await.expect("router never dispatched");
    let Dispatch::Udp { meta, .. } = dispatch else {
        panic!("expected a UDP dispatch");
    };
    assert_eq!(meta.src, src);
    assert_eq!(meta.dst, dst);

    h.shutdown().await;
}

#[skuld::test]
async fn the_first_datagram_is_seeded_into_the_new_flow() {
    let mut h = start(|_| {});
    let src = v4("10.255.0.2", 51000);
    let dst = v4("8.8.8.8", 443);

    h.wire.inject(udp_packet(src, dst, b"hello")).await;

    let Dispatch::Udp { mut flow, .. } = h.dispatch.recv().await.expect("router never dispatched") else {
        panic!("expected a UDP dispatch");
    };
    assert_eq!(flow.recv().await.as_deref(), Some(b"hello".as_slice()));

    h.shutdown().await;
}

#[skuld::test]
async fn a_second_datagram_on_the_same_five_tuple_reuses_the_flow() {
    let mut h = start(|_| {});
    let src = v4("10.255.0.2", 51000);
    let dst = v4("8.8.8.8", 443);

    h.wire.inject(udp_packet(src, dst, b"first")).await;
    let Dispatch::Udp { mut flow, .. } = h.dispatch.recv().await.expect("router never dispatched") else {
        panic!("expected a UDP dispatch");
    };
    assert_eq!(flow.recv().await.as_deref(), Some(b"first".as_slice()));

    h.wire.inject(udp_packet(src, dst, b"second")).await;
    assert_eq!(flow.recv().await.as_deref(), Some(b"second".as_slice()));

    // Rendezvous: a reply sent back through the same flow. The driver only
    // writes it to the wire in `flush_to_tun`, called once `handle_udp_packet`
    // has fully returned for "second" — i.e. strictly after any dispatch a
    // duplicate-flow bug would have spawned while handling it. `flow.recv()`
    // above does not give this: its wake fires from `try_send`, which
    // precedes any such spawn in the same synchronous stretch, not after it.
    flow.send(b"ack").await.expect("engine is still running");
    h.wire.next_egress().await.expect("no reply reached the wire");

    // Edge: joining the cancelled engine (see `Harness::shutdown`) is what
    // orders this negative — the payload arriving on the reused flow does
    // not, since a second `Dispatch` is decided by a separately spawned
    // task racing this one, not by anything on `flow`'s channel.
    let mut dispatch = h.shutdown().await;
    assert!(
        dispatch.recv().await.is_none(),
        "a second flow was opened for the same 5-tuple"
    );
}

#[skuld::test]
async fn a_datagram_with_a_different_source_port_opens_a_second_flow() {
    let mut h = start(|_| {});
    let dst = v4("8.8.8.8", 443);

    h.wire.inject(udp_packet(v4("10.255.0.2", 51000), dst, b"a")).await;
    let first = h.dispatch.recv().await.expect("router never dispatched the first flow");
    assert!(matches!(first, Dispatch::Udp { .. }));

    h.wire.inject(udp_packet(v4("10.255.0.2", 51001), dst, b"b")).await;
    let second = h
        .dispatch
        .recv()
        .await
        .expect("router never dispatched the second flow");
    assert!(matches!(second, Dispatch::Udp { .. }));

    h.shutdown().await;
}

#[skuld::test]
async fn a_router_reply_is_written_to_the_tun_with_the_five_tuple_swapped() {
    let mut h = start(|_| {});
    let src = v4("10.255.0.2", 51000);
    let dst = v4("8.8.8.8", 443);

    h.wire.inject(udp_packet(src, dst, b"query")).await;
    let Dispatch::Udp { flow, .. } = h.dispatch.recv().await.expect("router never dispatched") else {
        panic!("expected a UDP dispatch");
    };
    flow.send(b"reply").await.expect("engine is still running");

    let egress = h.wire.next_egress().await.expect("no reply reached the wire");
    let ip = Ipv4Packet::new_checked(&egress).expect("egress is not a valid IPv4 packet");
    assert_eq!(ip.src_addr(), "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap());
    assert_eq!(ip.dst_addr(), "10.255.0.2".parse::<std::net::Ipv4Addr>().unwrap());
    let udp = UdpPacket::new_checked(ip.payload()).expect("egress payload is not valid UDP");
    assert_eq!(udp.src_port(), 443);
    assert_eq!(udp.dst_port(), 51000);
    assert_eq!(udp.payload(), b"reply");
    assert!(
        udp.verify_checksum(&IpAddress::Ipv4(ip.src_addr()), &IpAddress::Ipv4(ip.dst_addr())),
        "UDP checksum does not verify"
    );

    h.shutdown().await;
}

#[skuld::test]
async fn an_ipv6_udp_datagram_round_trips() {
    let mut h = start(|_| {});
    let src = v6("fd00::ff00:2", 51000);
    let dst = v6("2001:db8::1", 443);

    h.wire.inject(udp_packet(src, dst, b"v6")).await;
    let Dispatch::Udp { meta, flow, .. } = h.dispatch.recv().await.expect("router never dispatched") else {
        panic!("expected a UDP dispatch");
    };
    assert_eq!(meta.src, src);
    assert_eq!(meta.dst, dst);

    flow.send(b"v6-reply").await.expect("engine is still running");
    let egress = h.wire.next_egress().await.expect("no reply reached the wire");
    let ip = Ipv6Packet::new_checked(&egress).expect("egress is not a valid IPv6 packet");
    assert_eq!(ip.src_addr(), "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap());
    assert_eq!(ip.dst_addr(), "fd00::ff00:2".parse::<std::net::Ipv6Addr>().unwrap());
    let udp = UdpPacket::new_checked(ip.payload()).expect("egress payload is not valid UDP");
    assert_eq!(udp.payload(), b"v6-reply");
    assert!(udp.verify_checksum(&IpAddress::Ipv6(ip.src_addr()), &IpAddress::Ipv6(ip.dst_addr())));

    h.shutdown().await;
}

// Datagrams addressed to the link =====================================================================================

/// Windows sends LLMNR, mDNS and NetBIOS lookups out of the TUN as it does out
/// of every adapter. Each is addressed to a group or to the link, which no
/// proxy can deliver to, so none may become a flow. The datagrams that must
/// still be carried sit next to the ones that must not, and the carried ones
/// are the sign that the dispatch path ran. The harness's TUN is
/// `10.255.0.1/24`, so its directed broadcast is `10.255.0.255`.
#[skuld::test]
async fn datagrams_addressed_to_a_group_or_to_the_link_open_no_flow() {
    let mut h = start(|_| {});
    let src4 = v4("10.255.0.2", 51000);
    let src6 = v6("fd00::ff00:2", 51000);

    let dropped = [
        v4("224.0.0.252", 5355),
        v4("224.0.0.251", 5353),
        v4("239.255.255.250", 1900),
        v4("255.255.255.255", 67),
        v4("10.255.0.255", 137),
        v6("ff02::1:3", 5355),
        v6("ff02::fb", 5353),
        v6("ff0e::1", 9),
    ];
    let carried = [
        v4("223.255.255.255", 53000),
        v4("10.255.0.254", 137),
        v4("10.255.1.255", 137),
        v4("8.8.8.8", 443),
        v6("fe80::1", 5355),
        v6("2001:db8::1", 443),
    ];

    for dst in dropped {
        let src = if dst.is_ipv4() { src4 } else { src6 };
        h.wire.inject(udp_packet(src, dst, b"x")).await;
    }
    for dst in carried {
        let src = if dst.is_ipv4() { src4 } else { src6 };
        h.wire.inject(udp_packet(src, dst, b"x")).await;
    }

    let mut dispatched = Vec::new();
    for _ in carried {
        let Dispatch::Udp { meta, .. } = h.dispatch.recv().await.expect("router never dispatched") else {
            panic!("expected a UDP dispatch");
        };
        dispatched.push(meta.dst);
    }
    dispatched.sort();
    let mut expected = carried.to_vec();
    expected.sort();
    assert_eq!(
        dispatched, expected,
        "the flows opened are not exactly the unicast ones"
    );

    // Joining the cancelled engine is what orders this negative (see `Harness::shutdown`).
    let mut rest = h.shutdown().await;
    assert!(
        rest.recv().await.is_none(),
        "a datagram to the link opened a further flow"
    );
}

/// The directed broadcast address follows the TUN's own prefix, and a /31, a /32 or an IPv6-only TUN has none.
#[skuld::test]
fn the_directed_broadcast_address_is_the_tuns_own() {
    let cidr = |s: &str| Some(s.parse::<Ipv4Cidr>().unwrap());
    let to = |tun: Option<Ipv4Cidr>, dst: &str| is_addressed_to_the_link(dst.parse().unwrap(), tun);

    assert!(to(cidr("10.255.0.1/22"), "10.255.3.255"));
    assert!(!to(cidr("10.255.0.1/22"), "10.255.0.255"));
    assert!(!to(cidr("10.255.0.1/22"), "10.255.2.255"));
    assert!(!to(cidr("10.255.0.1/24"), "10.255.0.0"));
    assert!(to(cidr("192.168.7.9/16"), "192.168.255.255"));
    assert!(!to(cidr("10.255.0.1/31"), "10.255.0.1"));
    assert!(!to(cidr("10.255.0.1/32"), "10.255.0.1"));
    assert!(!to(None, "10.255.0.255"));
    // Unicast neighbours of the addresses above stay carried.
    let tun = cidr("10.255.0.1/24");
    for dst in [
        "223.255.255.255",
        "10.255.0.254",
        "10.255.1.255",
        "8.8.8.8",
        "fe80::1",
        "2001:db8::1",
    ] {
        assert!(!to(tun, dst), "{dst} is not addressed to the link");
    }
    // Not tied to the TUN: multicast and the limited broadcast are addressed to the link whatever the prefix.
    assert!(to(None, "224.0.0.252"));
    assert!(to(None, "255.255.255.255"));
    assert!(to(None, "ff02::1:3"));
}
