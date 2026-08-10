use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

// Wire-format helpers =================================================================================================

#[skuld::test]
fn socks5_udp_header_v4_shape() {
    let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let h = socks5_udp_header(addr);
    assert_eq!(h[0..3], [0, 0, 0], "RSV=0 FRAG=0");
    assert_eq!(h[3], SOCKS5_ATYP_IPV4);
    assert_eq!(&h[4..8], &[8, 8, 8, 8]);
    assert_eq!(&h[8..10], &53_u16.to_be_bytes());
}

#[skuld::test]
fn socks5_udp_header_v6_shape() {
    let addr: SocketAddr = "[2001:db8::1]:853".parse().unwrap();
    let h = socks5_udp_header(addr);
    assert_eq!(h[0..3], [0, 0, 0]);
    assert_eq!(h[3], SOCKS5_ATYP_IPV6);
    assert_eq!(h.len(), 3 + 1 + 16 + 2);
}

#[skuld::test]
fn parse_socks5_udp_header_v4() {
    // Server replies with source 1.2.3.4:5353 + 5 bytes of payload.
    let mut buf = vec![0u8, 0, 0, SOCKS5_ATYP_IPV4, 1, 2, 3, 4, 0x14, 0xE9];
    buf.extend_from_slice(b"hello");
    let (off, src) = parse_socks5_udp_header(&buf).unwrap();
    assert_eq!(off, 10);
    assert_eq!(src, SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0x14E9));
}

#[skuld::test]
fn parse_socks5_udp_header_v6() {
    let mut buf = vec![0u8, 0, 0, SOCKS5_ATYP_IPV6];
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    buf.extend_from_slice(&v6.octets());
    buf.extend_from_slice(&53_u16.to_be_bytes());
    buf.extend_from_slice(b"p");
    let (off, src) = parse_socks5_udp_header(&buf).unwrap();
    assert_eq!(off, 3 + 1 + 16 + 2);
    assert_eq!(src.ip(), IpAddr::V6(v6));
    assert_eq!(src.port(), 53);
}

#[skuld::test]
fn parse_socks5_udp_header_rejects_fragmented() {
    let buf = [0u8, 0, 1, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    assert!(parse_socks5_udp_header(&buf).is_err());
}

#[skuld::test]
fn parse_socks5_udp_header_rejects_too_short() {
    let buf = [0u8, 0, 0, SOCKS5_ATYP_IPV4, 0, 0, 0]; // 7 bytes
    assert!(parse_socks5_udp_header(&buf).is_err());
}

#[skuld::test]
fn parse_socks5_udp_header_rejects_unknown_atyp() {
    let buf = [0u8, 0, 0, 0x7F, 0, 0, 0, 0, 0, 0];
    assert!(parse_socks5_udp_header(&buf).is_err());
}

// Protocol negotiation ================================================================================================

/// Start a fake SOCKS5 proxy that rejects UDP ASSOCIATE (simulating a
/// TCP-only shadowsocks plugin). Returns the proxy's listen address.
async fn start_udp_rejecting_proxy() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        // Expect greeting: VER | NMETHODS | METHOD...
        let mut greeting = [0u8; 3];
        let _ = sock.read_exact(&mut greeting).await;
        let _ = sock.write_all(&[SOCKS5_VER, SOCKS5_NO_AUTH]).await;
        // Expect request: VER | CMD | RSV | ATYP | ... (v4: 4 more bytes + port 2)
        let mut head = [0u8; 4];
        let _ = sock.read_exact(&mut head).await;
        // Consume addr(4) + port(2) for v4
        let mut addr_tail = [0u8; 6];
        let _ = sock.read_exact(&mut addr_tail).await;
        // Reply with REP=7 (Command not supported), signaling a TCP-only plugin.
        let _ = sock
            .write_all(&[SOCKS5_VER, 7, 0, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await;
    });
    addr
}

#[skuld::test]
async fn udp_associate_rejected_for_tcp_only_plugin() {
    let proxy = start_udp_rejecting_proxy().await;
    let err = udp_associate(proxy).await.expect_err("expected rejection");
    let s = format!("{err}");
    assert!(s.contains("ASSOCIATE rejected"), "error msg includes reason: {s}");
}

/// Start a fake SOCKS5 proxy that accepts UDP ASSOCIATE and advertises a
/// relay on 127.0.0.1 at a preset port. Returns the proxy's listen
/// address; the relay port it advertises is the `relay_port` argument.
async fn start_udp_accepting_proxy(relay_port: u16) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        let _ = sock.read_exact(&mut greeting).await;
        let _ = sock.write_all(&[SOCKS5_VER, SOCKS5_NO_AUTH]).await;
        let mut req = [0u8; 10];
        let _ = sock.read_exact(&mut req).await;
        let mut reply = vec![SOCKS5_VER, 0, 0, SOCKS5_ATYP_IPV4, 127, 0, 0, 1];
        reply.extend_from_slice(&relay_port.to_be_bytes());
        let _ = sock.write_all(&reply).await;
        // Hold the control connection open.
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    });
    addr
}

#[skuld::test]
async fn udp_associate_returns_relay_address_from_reply() {
    let proxy = start_udp_accepting_proxy(65300).await;
    let (_ctl, _udp, relay) = udp_associate(proxy).await.unwrap();
    assert_eq!(relay, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 65300));
}

// Wire-level byte accounting ==========================================================================================

/// A reply that arrives and then fails to parse is still proof something came
/// back. The DNS self-test gate reads these counters to decide exactly that, so
/// the wire read must be counted BEFORE the SOCKS5 header is interpreted —
/// counting the parsed payload instead would report a tunnel that answered as
/// silent.
#[skuld::test]
async fn a_reply_that_fails_to_parse_is_still_counted_as_read() {
    // A relay that answers every datagram with a FRAG != 0 frame, which
    // `parse_socks5_udp_header` rejects.
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_port = relay.local_addr().unwrap().port();
    let (got_tx, got_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (_n, peer) = relay.recv_from(&mut buf).await.unwrap();
        let frame = [SOCKS5_VER, 0, 1, SOCKS5_ATYP_IPV4, 1, 2, 3, 4, 0, 53, 0xAA, 0xBB];
        relay.send_to(&frame, peer).await.unwrap();
        let _ = got_tx.send(frame.len() as u64);
    });

    let proxy = start_udp_accepting_proxy(relay_port).await;
    let socket = Socks5Connector::new(proxy)
        .connect_udp("8.8.8.8:53".parse().unwrap())
        .await
        .expect("the stub proxy accepts ASSOCIATE");
    let counters = socket.counters();

    socket.send(b"query").await.expect("send");
    let sent = got_rx.await.expect("the relay answered");
    let mut buf = [0u8; 512];
    let err = socket.recv(&mut buf).await.expect_err("the frame is fragmented");
    assert!(format!("{err}").contains("ragmented"), "got: {err}");

    assert_eq!(
        counters.read(),
        sent,
        "the wire read must be counted even though the frame did not parse"
    );
    assert!(counters.written() > 0, "the query went out; got {}", counters.written());
}
