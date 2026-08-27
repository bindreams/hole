//! UDP dispatch fidelity: the driver reaches the router with the packet's
//! 5-tuple, reuses an existing flow rather than opening a second one, and
//! frames a router-originated reply back onto the wire with a checksum that
//! verifies.
//!
//! Every test drives `Engine::from_io` over a `sim::packet_pair` wire and a
//! `sim::recording_router` — no real socket, proxy or bypass mechanism is
//! involved.

#![allow(clippy::disallowed_methods)]
// This file's `CancellationToken::new()` is the test's own root — an
// unprivileged `Engine::run` driven directly has no cooperative-cancel chain
// to shadow (that rule is about `crates/bridge/src/`). See clippy.toml.

use std::net::SocketAddr;
use std::time::Duration;

use smoltcp::wire::{IpAddress, Ipv4Packet, Ipv6Packet, UdpPacket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::device::MutDeviceConfig;
use crate::sim::{packet_pair, recording_router, udp_packet, Dispatch, SimWire};
use crate::{DeviceConfig, Engine, MutEngineConfig};

fn device_config() -> DeviceConfig {
    MutDeviceConfig {
        tun_name: "sim0".into(),
        mtu: 1400,
        ipv4: Some("10.255.0.1/24".parse().unwrap()),
        ipv6: Some("fd00::ff00:1/64".parse().unwrap()),
    }
    .freeze()
}

fn v4(s: &str, port: u16) -> SocketAddr {
    format!("{s}:{port}").parse().unwrap()
}

fn v6(s: &str, port: u16) -> SocketAddr {
    format!("[{s}]:{port}").parse().unwrap()
}

/// Every test's shape: an `Engine::from_io` over an in-memory wire and a
/// recording router, run on its own task, with `udp_flow_idle_timeout` set
/// to a day so the sweep can never structurally fire inside a test.
struct Harness {
    wire: SimWire,
    dispatch: mpsc::Receiver<Dispatch>,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

fn start() -> Harness {
    let (tun, wire) = packet_pair(64);
    let (router, dispatch) = recording_router();
    let cancel = CancellationToken::new();
    let engine = Engine::from_io(tun, device_config(), router, |c: &mut MutEngineConfig| {
        c.udp_flow_idle_timeout = Duration::from_secs(24 * 3600);
    })
    .expect("from_io with a valid DeviceConfig never fails");
    let handle = tokio::spawn(engine.run(cancel.clone()));
    Harness {
        wire,
        dispatch,
        cancel,
        handle,
    }
}

impl Harness {
    async fn shutdown(self) {
        self.cancel.cancel();
        self.handle.await.expect("engine task panicked");
    }
}

#[skuld::test]
async fn a_udp_datagram_reaches_the_router_with_its_five_tuple() {
    let mut h = start();
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
    let mut h = start();
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
    let mut h = start();
    let src = v4("10.255.0.2", 51000);
    let dst = v4("8.8.8.8", 443);

    h.wire.inject(udp_packet(src, dst, b"first")).await;
    let Dispatch::Udp { mut flow, .. } = h.dispatch.recv().await.expect("router never dispatched") else {
        panic!("expected a UDP dispatch");
    };
    assert_eq!(flow.recv().await.as_deref(), Some(b"first".as_slice()));

    h.wire.inject(udp_packet(src, dst, b"second")).await;
    // Edge: the second payload arriving on the same flow orders the negative
    // below — a second `Dispatch` would only ever have preceded it.
    assert_eq!(flow.recv().await.as_deref(), Some(b"second".as_slice()));
    assert!(
        h.dispatch.try_recv().is_err(),
        "a second flow was opened for the same 5-tuple"
    );

    h.shutdown().await;
}

#[skuld::test]
async fn a_datagram_with_a_different_source_port_opens_a_second_flow() {
    let mut h = start();
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
    let mut h = start();
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
    let mut h = start();
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
