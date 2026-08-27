//! The `DnsInterceptor` hook.
//!
//! This is generic `tun-engine` API — **Hole registers no `DnsInterceptor`**
//! (`crates/bridge/src/dispatcher.rs` builds the engine with the default
//! `dns_interceptor: None`). Hole's own UDP/53 divert is `HoleRouter`'s
//! `local_dns` slot, proved unprivileged in `hole_router_dispatch_tests.rs`
//! (bindreams/hole#892, Unit B). Without this paragraph, a green file named
//! `driver_dns_tests` would read as coverage of Hole's DNS path — it is not.
//! What it pins is the hook itself, for any future `tun-engine` consumer
//! that registers one.

#![allow(clippy::disallowed_methods)]
// This file's `CancellationToken::new()` is the test's own root — see
// `driver_udp_tests.rs`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use smoltcp::wire::{IpAddress, Ipv4Packet, TcpPacket, UdpPacket};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::DnsInterceptor;
use crate::device::MutDeviceConfig;
use crate::sim::{packet_pair, recording_router, tcp_syn, udp_packet, Dispatch, SimWire};
use crate::{DeviceConfig, Engine, MutEngineConfig};

fn device_config() -> DeviceConfig {
    MutDeviceConfig {
        tun_name: "sim0".into(),
        mtu: 1400,
        ipv4: Some("10.255.0.1/24".parse().unwrap()),
        ipv6: None,
    }
    .freeze()
}

fn v4(s: &str, port: u16) -> SocketAddr {
    format!("{s}:{port}").parse().unwrap()
}

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

struct Harness {
    wire: SimWire,
    dispatch: mpsc::Receiver<Dispatch>,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

fn start(dns_interceptor: Arc<dyn DnsInterceptor>) -> Harness {
    let (tun, wire) = packet_pair(64);
    let (router, dispatch) = recording_router();
    let cancel = CancellationToken::new();
    let engine = Engine::from_io(tun, device_config(), router, |c: &mut MutEngineConfig| {
        c.udp_flow_idle_timeout = Duration::from_secs(24 * 3600);
        c.dns_interceptor = Some(dns_interceptor);
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
async fn a_port_53_datagram_reaches_the_interceptor() {
    let (interceptor, mut reports) = interceptor(Some(b"answer".to_vec()));
    let mut h = start(interceptor);
    let src = v4("10.255.0.2", 51000);
    let dst = v4("8.8.8.8", 53);

    h.wire.inject(udp_packet(src, dst, b"query")).await;

    let got = reports.recv().await.expect("interceptor was never called");
    assert_eq!(got, b"query");
    // Edge: the interceptor's report on `reports` orders this negative — a
    // `Some`-returning interceptor short-circuits the cascade.
    assert!(
        h.dispatch.try_recv().is_err(),
        "the recording router received a Dispatch despite the interceptor answering"
    );

    h.shutdown().await;
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
    // negative.
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
