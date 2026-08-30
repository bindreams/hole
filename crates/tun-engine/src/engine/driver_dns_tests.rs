//! The `DnsInterceptor` hook.
//!
//! This is generic `tun-engine` API — **Hole registers no `DnsInterceptor`**
//! (`crates/bridge/src/dispatcher.rs` builds the engine with the default
//! `dns_interceptor: None`). Hole's own UDP/53 divert is `HoleRouter`'s
//! `local_dns` slot, proved unprivileged in `hole_router_dispatch_tests.rs`.
//! Without this paragraph, a green file named
//! `driver_dns_tests` would read as coverage of Hole's DNS path — it is not.
//! What it pins is the hook itself, for any future `tun-engine` consumer
//! that registers one.

use std::sync::Arc;

use async_trait::async_trait;
use smoltcp::wire::{IpAddress, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};
use tokio::sync::{mpsc, Mutex};

use super::super::driver_sim_test_support::{start as start_sim, v4, v6, Harness};
use super::DnsInterceptor;
use crate::sim::{tcp_syn, udp_packet, Dispatch};

/// A `DnsInterceptor` double: reports every intercepted request on an mpsc
/// and answers with a fixed, configurable reply.
struct RecordingInterceptor {
    reports: mpsc::Sender<Vec<u8>>,
    answer: Mutex<Option<Vec<u8>>>,
}

#[async_trait]
impl DnsInterceptor for RecordingInterceptor {
    async fn intercept(&self, request: &[u8]) -> Option<Vec<u8>> {
        let _ = self.reports.send(request.to_vec()).await;
        self.answer.lock().await.clone()
    }
}

fn interceptor(answer: Option<Vec<u8>>) -> (Arc<dyn DnsInterceptor>, mpsc::Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel(8);
    (
        Arc::new(RecordingInterceptor {
            reports: tx,
            answer: Mutex::new(answer),
        }),
        rx,
    )
}

fn start(dns_interceptor: Arc<dyn DnsInterceptor>) -> Harness {
    start_sim(|c| c.dns_interceptor = Some(dns_interceptor))
}

#[skuld::test]
async fn a_port_53_datagram_reaches_the_interceptor() {
    let (interceptor, mut reports) = interceptor(Some(b"answer".to_vec()));
    let mut h = start(interceptor);
    let src = v4("10.255.0.2", 51000);
    let dst = v4("8.8.8.8", 53);

    h.wire.inject(udp_packet(src, dst, b"query")).await;

    let got = reports.recv().await.expect("interceptor was never called");
    assert_eq!(got, b"query");

    // Rendezvous: the reply reaching the wire happens strictly after
    // `handle_udp_packet` has fully processed this datagram — including any
    // (buggy) dispatch spawn, which happens earlier in the same synchronous
    // stretch. Waiting for it here, before cancelling, is what lets a
    // wrongly-spawned route task actually get polled and enqueue its
    // `Dispatch` ahead of the join below, instead of racing cancellation
    // and never running at all — the failure mode a bare `try_recv` (and,
    // it turns out, an immediate `shutdown` with nothing in between) shares.
    h.wire.next_egress().await.expect("no reply reached the wire");

    // Edge: joining the cancelled engine (see `Harness::shutdown`) is what
    // orders this negative — the interceptor's report on `reports` does not,
    // since that report is sent from inside `intercept` itself, strictly
    // before the driver has decided whether to dispatch.
    let mut dispatch = h.shutdown().await;
    assert!(
        dispatch.recv().await.is_none(),
        "the recording router received a Dispatch despite the interceptor answering"
    );
}

#[skuld::test]
async fn an_intercepted_reply_is_written_to_the_tun_with_the_five_tuple_swapped() {
    let (interceptor, mut reports) = interceptor(Some(b"answer".to_vec()));
    let mut h = start(interceptor);
    let src = v4("10.255.0.2", 51000);
    let dst = v4("8.8.8.8", 53);

    h.wire.inject(udp_packet(src, dst, b"query")).await;
    reports.recv().await.expect("interceptor was never called");

    let egress = h.wire.next_egress().await.expect("no reply reached the wire");
    let ip = Ipv4Packet::new_checked(&egress).expect("egress is not a valid IPv4 packet");
    assert_eq!(ip.src_addr(), "8.8.8.8".parse::<std::net::Ipv4Addr>().unwrap());
    assert_eq!(ip.dst_addr(), "10.255.0.2".parse::<std::net::Ipv4Addr>().unwrap());
    let udp = UdpPacket::new_checked(ip.payload()).expect("egress payload is not valid UDP");
    assert_eq!(udp.src_port(), 53);
    assert_eq!(udp.dst_port(), 51000);
    assert_eq!(udp.payload(), b"answer");
    assert!(udp.verify_checksum(&IpAddress::Ipv4(ip.src_addr()), &IpAddress::Ipv4(ip.dst_addr())));

    h.shutdown().await;
}

#[skuld::test]
async fn an_interceptor_returning_none_falls_through_to_the_router() {
    let (interceptor, mut reports) = interceptor(None);
    let mut h = start(interceptor);
    let src = v4("10.255.0.2", 51000);
    let dst = v4("8.8.8.8", 53);

    h.wire.inject(udp_packet(src, dst, b"query")).await;
    reports.recv().await.expect("interceptor was never called");

    let dispatch = h.dispatch.recv().await.expect("router never dispatched");
    let Dispatch::Udp { mut flow, .. } = dispatch else {
        panic!("expected a UDP dispatch");
    };
    assert_eq!(flow.recv().await.as_deref(), Some(b"query".as_slice()));

    h.shutdown().await;
}

#[skuld::test]
async fn a_non_53_datagram_never_reaches_the_interceptor() {
    let (interceptor, mut reports) = interceptor(None);
    let mut h = start(interceptor);
    let src = v4("10.255.0.2", 51000);
    let dst = v4("8.8.8.8", 443);

    h.wire.inject(udp_packet(src, dst, b"not dns")).await;

    // Edge: the router's dispatch for this flow orders the interceptor
    // negative — the same synchronous `handle_udp_packet` call that decided
    // not to touch the interceptor is what produced this Dispatch, so
    // observing the Dispatch means that decision already happened.
    let dispatch = h.dispatch.recv().await.expect("router never dispatched");
    assert!(matches!(dispatch, Dispatch::Udp { .. }));
    assert!(reports.try_recv().is_err(), "a non-53 datagram reached the interceptor");

    h.shutdown().await;
}

#[skuld::test]
async fn tcp_to_port_53_never_reaches_the_interceptor() {
    let (interceptor, mut reports) = interceptor(None);
    let mut h = start(interceptor);
    let src = v4("10.255.0.2", 51000);
    let dst = v4("8.8.8.8", 53);

    h.wire.inject(tcp_syn(src, dst, 1000)).await;

    // Edge: the SYN-ACK reaching the wire orders the interceptor negative —
    // there is no TCP interceptor hook, so any port-53 detection here would
    // be a UDP-only-path bug leaking across protocols.
    let egress = h.wire.next_egress().await.expect("no SYN-ACK reached the wire");
    let ip = Ipv4Packet::new_checked(&egress).expect("egress is not a valid IPv4 packet");
    let tcp = TcpPacket::new_checked(ip.payload()).expect("egress payload is not valid TCP");
    assert!(tcp.syn() && tcp.ack());
    assert!(
        reports.try_recv().is_err(),
        "a TCP SYN to port 53 reached the DNS interceptor"
    );

    h.shutdown().await;
}

#[skuld::test]
async fn an_ipv6_port_53_datagram_reaches_the_interceptor_and_its_reply_is_framed_correctly() {
    let (interceptor, mut reports) = interceptor(Some(b"v6-answer".to_vec()));
    let mut h = start(interceptor);
    let src = v6("fd00::ff00:2", 51000);
    let dst = v6("2001:db8::1", 53);

    h.wire.inject(udp_packet(src, dst, b"v6-query")).await;

    let got = reports.recv().await.expect("interceptor was never called");
    assert_eq!(got, b"v6-query");

    let egress = h.wire.next_egress().await.expect("no reply reached the wire");
    let ip = Ipv6Packet::new_checked(&egress).expect("egress is not a valid IPv6 packet");
    assert_eq!(ip.src_addr(), "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap());
    assert_eq!(ip.dst_addr(), "fd00::ff00:2".parse::<std::net::Ipv6Addr>().unwrap());
    let udp = UdpPacket::new_checked(ip.payload()).expect("egress payload is not valid UDP");
    assert_eq!(udp.src_port(), 53);
    assert_eq!(udp.dst_port(), 51000);
    assert_eq!(udp.payload(), b"v6-answer");
    assert!(udp.verify_checksum(&IpAddress::Ipv6(ip.src_addr()), &IpAddress::Ipv6(ip.dst_addr())));

    // Edge: joining the cancelled engine (see `Harness::shutdown`) orders
    // this negative — see `a_port_53_datagram_reaches_the_interceptor` for
    // why a bare `try_recv` cannot.
    let mut dispatch = h.shutdown().await;
    assert!(
        dispatch.recv().await.is_none(),
        "the recording router received a Dispatch despite the interceptor answering"
    );
}

#[skuld::test]
async fn an_ipv6_interceptor_returning_none_falls_through_to_the_router() {
    let (interceptor, mut reports) = interceptor(None);
    let mut h = start(interceptor);
    let src = v6("fd00::ff00:2", 51000);
    let dst = v6("2001:db8::1", 53);

    h.wire.inject(udp_packet(src, dst, b"v6-query")).await;
    reports.recv().await.expect("interceptor was never called");

    let dispatch = h.dispatch.recv().await.expect("router never dispatched");
    let Dispatch::Udp { meta, mut flow, .. } = dispatch else {
        panic!("expected a UDP dispatch");
    };
    assert_eq!(meta.src, src);
    assert_eq!(meta.dst, dst);
    assert_eq!(flow.recv().await.as_deref(), Some(b"v6-query".as_slice()));

    h.shutdown().await;
}
