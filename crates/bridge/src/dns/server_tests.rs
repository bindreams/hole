use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hole_common::config::{DnsConfig, DnsProtocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use super::*;
use crate::dns::connector::DirectConnector;

// Ladder ==============================================================================================================

#[skuld::test]
fn ladder_first_is_127_0_0_1() {
    let list = ladder_candidates();
    assert_eq!(list[0], SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53));
}

#[skuld::test]
fn ladder_sweeps_127_53_0_1_through_254() {
    let list = ladder_candidates();
    assert_eq!(list.len(), 1 + 254);
    assert_eq!(list[1].ip(), IpAddr::V4(Ipv4Addr::new(127, 53, 0, 1)));
    assert_eq!(list.last().unwrap().ip(), IpAddr::V4(Ipv4Addr::new(127, 53, 0, 254)));
    for addr in &list {
        assert_eq!(addr.port(), 53, "every ladder candidate uses port 53");
    }
}

// End-to-end with stub upstream =======================================================================================

/// Spin up a stub UDP DNS upstream on an ephemeral port. Replies with a
/// minimal well-formed response.
async fn start_stub_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let h = tokio::spawn(async move {
        loop {
            let mut buf = [0u8; 1500];
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            // Build a reply: copy id, set QR/RA, zero counts, include question verbatim.
            let mut r = Vec::with_capacity(n + 16);
            r.extend_from_slice(&buf[..2]); // id
            r.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1
            r.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
            r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            if n > 12 {
                r.extend_from_slice(&buf[12..n]);
            }
            let _ = sock.send_to(&r, peer).await;
        }
    });
    (addr, h)
}

fn sample_query(tx_id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&tx_id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    q.push(7);
    q.extend_from_slice(b"example");
    q.push(3);
    q.extend_from_slice(b"com");
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x01]);
    q
}

/// Build a forwarder + start a DnsServer on 127.0.0.1:0 (ephemeral).
/// Returns the bound server, its address, and the stub upstream task
/// handle so the test can keep it alive.
async fn start_server_with_stub() -> (LocalDnsServer, SocketAddr, tokio::task::JoinHandle<()>) {
    let (upstream, up_task) = start_stub_upstream().await;

    // Direct-connector forwarder targeting the stub UDP upstream via the
    // forwarder's `forward_on_port` wouldn't fit the real API; instead we
    // pass the upstream IP as the forwarder's server, but the forwarder
    // hard-codes DNS_PORT_PLAIN=53. The stub is on an ephemeral port, so
    // direct-connector UDP would not reach it. Work around by running the
    // whole thing through the forwarder's public `forward` with an
    // upstream on :53 — but we have no privilege to bind :53 in CI.
    //
    // Instead: use a forwarder with a *broken* server list and rely on
    // SERVFAIL being a well-formed reply for the server-layer tests.
    // (Separate forwarder-layer tests already cover upstream wiring.)
    let _ = upstream; // kept alive via `up_task`
    let cfg = DnsConfig {
        enabled: true,
        servers: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))], // TEST-NET-1, unroutable
        protocol: DnsProtocol::PlainUdp,
        intercept_udp53: true,
    };
    let fwd = Arc::new(DnsForwarder::new(cfg, Arc::new(DirectConnector), true));
    let srv = LocalDnsServer::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), fwd)
        .await
        .expect("bind ephemeral");
    let addr = srv.addr();
    (srv, addr, up_task)
}

#[skuld::test]
async fn udp_end_to_end_returns_servfail_on_dead_upstream() {
    let (_srv, addr, _up) = start_server_with_stub().await;

    // Send a UDP query from a loopback socket.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(addr).await.unwrap();
    let q = sample_query(0xFEED);
    client.send(&q).await.unwrap();
    let mut rbuf = [0u8; 1500];
    let n = timeout(Duration::from_secs(10), client.recv(&mut rbuf))
        .await
        .expect("forwarder responded in time")
        .unwrap();
    let reply = &rbuf[..n];
    assert_eq!(&reply[..2], &[0xFE, 0xED], "tx id preserved");
    assert_eq!(reply[3] & 0x0F, 2, "RCODE=SERVFAIL (no upstream reachable)");
}

#[skuld::test]
async fn tcp_end_to_end_returns_servfail_on_dead_upstream() {
    let (_srv, addr, _up) = start_server_with_stub().await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let q = sample_query(0xBEEF);
    let len = (q.len() as u16).to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(&q).await.unwrap();
    let mut len_buf = [0u8; 2];
    timeout(Duration::from_secs(10), stream.read_exact(&mut len_buf))
        .await
        .expect("TCP reply framing arrived")
        .unwrap();
    let reply_len = u16::from_be_bytes(len_buf) as usize;
    let mut reply = vec![0u8; reply_len];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..2], &[0xBE, 0xEF]);
    assert_eq!(reply[3] & 0x0F, 2, "RCODE=SERVFAIL");
}

#[skuld::test]
async fn drop_releases_udp_and_tcp_ports() {
    let cfg = DnsConfig {
        enabled: true,
        servers: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
        protocol: DnsProtocol::PlainUdp,
        intercept_udp53: true,
    };
    let fwd = Arc::new(DnsForwarder::new(cfg, Arc::new(DirectConnector), true));
    let srv = LocalDnsServer::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), fwd)
        .await
        .unwrap();
    let addr = srv.addr();
    drop(srv);
    // Give the runtime a tick to process the abort/close.
    tokio::task::yield_now().await;
    // The port should be rebindable after drop.
    let rebind = UdpSocket::bind(addr).await;
    assert!(rebind.is_ok(), "UDP port released after server drop: {rebind:?}");
    let rebind_tcp = tokio::net::TcpListener::bind(addr).await;
    assert!(rebind_tcp.is_ok(), "TCP port released after server drop");
}

#[skuld::test]
async fn bind_fails_when_port_in_use_on_preferred_ip() {
    // Hold 127.0.0.1:<ephemeral> hostage and try to bind the same addr.
    let hostage_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let busy_addr = hostage_udp.local_addr().unwrap();
    let cfg = DnsConfig {
        enabled: true,
        servers: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
        protocol: DnsProtocol::PlainUdp,
        intercept_udp53: true,
    };
    let fwd = Arc::new(DnsForwarder::new(cfg, Arc::new(DirectConnector), true));
    let res = LocalDnsServer::bind(busy_addr, fwd).await;
    assert!(res.is_err(), "bind should fail on busy port");
}
