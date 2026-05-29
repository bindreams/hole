// `CancellationToken::new` is the cancel-test harness root for the E2E relay
// tests; module-level allow per the workspace clippy.toml's sanctioned
// test-file exception (mirrors garter's tap_tests.rs).
#![allow(clippy::disallowed_methods)]

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use garter::test_utils::WaitableWriter;
use garter::tracing_test::set_default_in_current_thread;

use crate::yamux::{
    deframe_udp_datagram, frame_udp_datagram, parse_udp_timeout, run_client, run_server, FrameAccumulator, StreamTag,
    DEFAULT_UDP_TIMEOUT,
};
// Only the Windows-gated CONNRESET regression test uses this.
#[cfg(windows)]
use crate::yamux::bind_udp;

#[skuld::test]
fn stream_tag_tcp_roundtrip() {
    assert_eq!(StreamTag::Tcp.to_byte(), 0x01);
    assert_eq!(StreamTag::from_byte(0x01).unwrap(), StreamTag::Tcp);
}

#[skuld::test]
fn stream_tag_udp_roundtrip() {
    assert_eq!(StreamTag::Udp.to_byte(), 0x02);
    assert_eq!(StreamTag::from_byte(0x02).unwrap(), StreamTag::Udp);
}

#[skuld::test]
fn stream_tag_invalid() {
    assert!(StreamTag::from_byte(0x00).is_none());
    assert!(StreamTag::from_byte(0xFF).is_none());
}

#[skuld::test]
fn udp_frame_roundtrip() {
    let payload = b"hello udp";
    let framed = frame_udp_datagram(payload);
    assert_eq!(framed.len(), 2 + payload.len());
    let (decoded, rest) = deframe_udp_datagram(&framed).unwrap();
    assert_eq!(decoded, payload);
    assert!(rest.is_empty());
}

#[skuld::test]
fn udp_frame_max_size() {
    let payload = vec![0xABu8; 65535];
    let framed = frame_udp_datagram(&payload);
    let (decoded, _) = deframe_udp_datagram(&framed).unwrap();
    assert_eq!(decoded.len(), 65535);
}

// FrameAccumulator (Defect C) -----------------------------------------------------------------------------------------

/// Helper: collect every frame currently available from the accumulator.
fn drain_all(acc: &mut FrameAccumulator) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(frame) = acc.next_frame() {
        out.push(frame);
    }
    out
}

#[skuld::test]
fn accumulator_single_frame_in_one_push() {
    let mut acc = FrameAccumulator::new();
    acc.push(&frame_udp_datagram(b"hello"));
    assert_eq!(drain_all(&mut acc), vec![b"hello".to_vec()]);
}

#[skuld::test]
fn accumulator_two_coalesced_frames_in_one_push() {
    // The bug: a single read returning two frames must yield BOTH payloads,
    // not just the first.
    let mut buf = frame_udp_datagram(b"first");
    buf.extend_from_slice(&frame_udp_datagram(b"second"));
    let mut acc = FrameAccumulator::new();
    acc.push(&buf);
    assert_eq!(drain_all(&mut acc), vec![b"first".to_vec(), b"second".to_vec()]);
}

#[skuld::test]
fn accumulator_frame_split_across_pushes() {
    // The bug: a frame split across two reads must reassemble, not corrupt.
    let framed = frame_udp_datagram(b"split me up");
    let (head, tail) = framed.split_at(4);
    let mut acc = FrameAccumulator::new();
    acc.push(head);
    assert!(acc.next_frame().is_none(), "partial frame must not yield");
    acc.push(tail);
    assert_eq!(drain_all(&mut acc), vec![b"split me up".to_vec()]);
}

#[skuld::test]
fn accumulator_one_byte_at_a_time() {
    let framed = frame_udp_datagram(b"drip");
    let mut acc = FrameAccumulator::new();
    for (i, byte) in framed.iter().enumerate() {
        acc.push(&[*byte]);
        // Only the final byte completes the frame.
        if i + 1 < framed.len() {
            assert!(acc.next_frame().is_none());
        }
    }
    assert_eq!(drain_all(&mut acc), vec![b"drip".to_vec()]);
}

#[skuld::test]
fn accumulator_length_prefix_split() {
    // Split in the middle of the 2-byte length prefix.
    let framed = frame_udp_datagram(b"x");
    let mut acc = FrameAccumulator::new();
    acc.push(&framed[..1]);
    assert!(acc.next_frame().is_none());
    acc.push(&framed[1..]);
    assert_eq!(drain_all(&mut acc), vec![b"x".to_vec()]);
}

#[skuld::test]
fn accumulator_one_and_a_half_frames() {
    // One complete frame plus the start of a second: yields the first, keeps
    // the partial, then completes the second on the next push.
    let mut buf = frame_udp_datagram(b"whole");
    let second = frame_udp_datagram(b"partial then rest");
    buf.extend_from_slice(&second[..3]);
    let mut acc = FrameAccumulator::new();
    acc.push(&buf);
    assert_eq!(drain_all(&mut acc), vec![b"whole".to_vec()]);
    acc.push(&second[3..]);
    assert_eq!(drain_all(&mut acc), vec![b"partial then rest".to_vec()]);
}

#[skuld::test]
fn accumulator_empty_payload_frame() {
    // A zero-length datagram is a valid frame (2-byte length == 0).
    let mut acc = FrameAccumulator::new();
    acc.push(&frame_udp_datagram(b""));
    assert_eq!(drain_all(&mut acc), vec![Vec::<u8>::new()]);
}

// parse_udp_timeout (#415) --------------------------------------------------------------------------------------------

#[skuld::test]
fn udp_timeout_defaults_when_absent() {
    assert_eq!(parse_udp_timeout(None).unwrap(), DEFAULT_UDP_TIMEOUT);
    assert_eq!(parse_udp_timeout(Some("server")).unwrap(), DEFAULT_UDP_TIMEOUT);
    assert_eq!(
        parse_udp_timeout(Some("mode=quic;host=cdn")).unwrap(),
        DEFAULT_UDP_TIMEOUT
    );
}

#[skuld::test]
fn udp_timeout_parsed_value() {
    assert_eq!(
        parse_udp_timeout(Some("udp_timeout=10")).unwrap(),
        Duration::from_secs(10)
    );
    // Coexists with other (v2ray) keys.
    assert_eq!(
        parse_udp_timeout(Some("server;udp_timeout=42;mode=quic")).unwrap(),
        Duration::from_secs(42)
    );
}

#[skuld::test]
fn udp_timeout_last_occurrence_wins() {
    assert_eq!(
        parse_udp_timeout(Some("udp_timeout=5;udp_timeout=20")).unwrap(),
        Duration::from_secs(20)
    );
}

#[skuld::test]
fn udp_timeout_invalid_is_error() {
    assert!(parse_udp_timeout(Some("udp_timeout=abc")).is_err());
    assert!(parse_udp_timeout(Some("udp_timeout=")).is_err());
    // 0 would evict every association immediately — rejected.
    assert!(parse_udp_timeout(Some("udp_timeout=0")).is_err());
    assert!(parse_udp_timeout(Some("udp_timeout=-1")).is_err());
}

// End-to-end UDP relay (#415) -----------------------------------------------------------------------------------------

/// Spawn a UDP echo server bound on `ip:0`; returns its bound address. The task
/// echoes every datagram back to its sender and lives until the runtime drops.
async fn spawn_udp_echo(ip: IpAddr) -> SocketAddr {
    let sock = UdpSocket::bind(SocketAddr::new(ip, 0)).await.expect("bind echo");
    let addr = sock.local_addr().expect("echo local_addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

/// Stand up a client+server yamux relay whose upstream is a UDP echo server
/// bound on `echo_ip`. Returns the client's local UDP address (where a test
/// "app" socket sends) and the shutdown token.
///
/// No artificial delay orders startup: `run_server`/`run_client` report their
/// bound address via the readiness oneshot, and we await each before using it.
async fn setup_relay(echo_ip: IpAddr, udp_timeout: Duration) -> (SocketAddr, CancellationToken) {
    let echo_addr = spawn_udp_echo(echo_ip).await;
    let shutdown = CancellationToken::new();
    let loopback_v4: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let (srv_tx, srv_rx) = oneshot::channel();
    tokio::spawn(run_server(
        ::yamux::Config::default(),
        loopback_v4,
        echo_addr,
        shutdown.clone(),
        Some(srv_tx),
    ));
    let server_addr = srv_rx.await.expect("server bound");

    let (cli_tx, cli_rx) = oneshot::channel();
    tokio::spawn(run_client(
        ::yamux::Config::default(),
        loopback_v4,
        server_addr,
        udp_timeout,
        shutdown.clone(),
        Some(cli_tx),
    ));
    let client_udp_addr = cli_rx.await.expect("client bound");

    (client_udp_addr, shutdown)
}

/// Send one datagram from `app` to the client's local UDP port and await the
/// echoed reply. A reply that never arrives (the pre-#415 bug) hangs until the
/// test-framework timeout — the sanctioned "external event" failure bound.
async fn round_trip(app: &UdpSocket, client_addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    app.send_to(payload, client_addr).await.expect("app send");
    let mut buf = [0u8; 65536];
    let (n, _from) = app.recv_from(&mut buf).await.expect("app recv");
    buf[..n].to_vec()
}

#[skuld::test]
async fn udp_reply_delivered() {
    let (client_addr, shutdown) = setup_relay("127.0.0.1".parse().unwrap(), DEFAULT_UDP_TIMEOUT).await;
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(round_trip(&app, client_addr, b"ping").await, b"ping");
    shutdown.cancel();
}

#[skuld::test]
async fn udp_multiple_datagrams_one_association() {
    let (client_addr, shutdown) = setup_relay("127.0.0.1".parse().unwrap(), DEFAULT_UDP_TIMEOUT).await;
    // Reuse one app socket so all datagrams share a single NAT association /
    // yamux stream; every reply must still route back.
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for msg in [b"one".as_slice(), b"two", b"three", b"four"] {
        assert_eq!(round_trip(&app, client_addr, msg).await, msg);
    }
    shutdown.cancel();
}

#[skuld::test]
async fn udp_distinct_peers_isolated() {
    let (client_addr, shutdown) = setup_relay("127.0.0.1".parse().unwrap(), DEFAULT_UDP_TIMEOUT).await;
    let app_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let app_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    app_a.send_to(b"aaaa", client_addr).await.unwrap();
    app_b.send_to(b"bbbb", client_addr).await.unwrap();

    let mut buf = [0u8; 64];
    let (na, _) = app_a.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..na], b"aaaa", "peer A must receive its own echo");
    let (nb, _) = app_b.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..nb], b"bbbb", "peer B must receive its own echo");
    shutdown.cancel();
}

#[skuld::test]
async fn udp_ipv6_remote() {
    // Defect B: the server relay must bind a UDP socket in the remote's address
    // family. An IPv6 upstream fails the pre-#415 hardcoded IPv4 bind.
    let (client_addr, shutdown) = setup_relay("::1".parse().unwrap(), DEFAULT_UDP_TIMEOUT).await;
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(round_trip(&app, client_addr, b"over-v6").await, b"over-v6");
    shutdown.cancel();
}

#[cfg(windows)]
#[skuld::test]
async fn bind_udp_send_to_dead_peer_does_not_poison_recv() {
    // Windows-only regression for #415: a UDP send to a loopback peer with no
    // listener must NOT surface a phantom WSAECONNRESET on the socket's next
    // recv. With SIO_UDP_CONNRESET left enabled (tokio/mio default) the recv
    // below would return Err(ConnectionReset) instead of the self-datagram,
    // which in run_client would tear down the whole tunnel. `bind_udp` disables
    // it.
    let sock = bind_udp("127.0.0.1:0".parse().unwrap()).expect("bind_udp");
    let me = sock.local_addr().unwrap();

    // Send to a dead loopback port (no listener) — would poison the next recv.
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    sock.send_to(b"into the void", dead).await.unwrap();

    // Then exercise the socket normally; recv must succeed, not ConnectionReset.
    sock.send_to(b"still alive", me).await.unwrap();
    let mut buf = [0u8; 32];
    let (n, _) = sock.recv_from(&mut buf).await.expect("recv must not be poisoned");
    assert_eq!(&buf[..n], b"still alive");
}

#[skuld::test]
async fn udp_idle_eviction_and_recreation() {
    // The short idle timeout IS the behavior under test (NAT idle eviction);
    // we park on the deterministic "udp association closed" log event, never on
    // a sleep. 500ms gives a comfortable margin over a loopback round-trip so
    // the first exchange can never race the eviction. See #415 / #383.
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let _g = set_default_in_current_thread(subscriber);

    let (client_addr, shutdown) = setup_relay("127.0.0.1".parse().unwrap(), Duration::from_millis(500)).await;
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // First exchange establishes the association.
    assert_eq!(round_trip(&app, client_addr, b"first").await, b"first");

    // The now-idle association is evicted; park on the close event.
    let closed = writer.wait_for("udp association closed");
    tokio::task::spawn_blocking(move || closed.recv().expect("association never evicted"))
        .await
        .unwrap();

    // A datagram from the same peer transparently re-creates the association.
    assert_eq!(round_trip(&app, client_addr, b"second").await, b"second");
    shutdown.cancel();
}
