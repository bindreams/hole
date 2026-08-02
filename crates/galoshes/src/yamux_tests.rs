// `CancellationToken::new` is the cancel-test harness root for the E2E relay
// tests; module-level allow per the workspace clippy.toml's sanctioned
// test-file exception (mirrors garter's tap_tests.rs).
#![allow(clippy::disallowed_methods)]

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::TokioAsyncReadCompatExt as _;
use tokio_util::sync::CancellationToken;

use garter::test_utils::WaitableWriter;
use garter::tracing_test::set_default_in_current_thread;

use crate::yamux::{
    connect_delay, connect_retrying, deframe_udp_datagram, drive_connection, driver_panicked, frame_udp_datagram,
    next_failures, open_probe, parse_udp_timeout, run_client, run_keepalive, run_server, session_reconnect_backoff,
    ClientBoundAddrs, FrameAccumulator, OpenStreamReply, StreamTag, TransportLivenessTap, DEFAULT_UDP_TIMEOUT,
    KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT, LOOPBACK_CONNECT_RETRY, REMOTE_BACKOFF_BASE, REMOTE_BACKOFF_MAX,
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
fn stream_tag_keepalive_roundtrip() {
    assert_eq!(StreamTag::Keepalive.to_byte(), 0x03);
    assert_eq!(StreamTag::from_byte(0x03).unwrap(), StreamTag::Keepalive);
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

/// Stand up a client+server yamux relay pointed at `upstream`, returning the
/// client's bound listener addresses and the shutdown token.
///
/// No artificial delay orders startup: `run_server`/`run_client` report their
/// bound address via the readiness oneshot, and we await each before using it.
async fn setup_relay_inner(upstream: SocketAddr, udp_timeout: Duration) -> (ClientBoundAddrs, CancellationToken) {
    let shutdown = CancellationToken::new();
    let loopback_v4: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let (srv_tx, srv_rx) = oneshot::channel();
    tokio::spawn(run_server(
        ::yamux::Config::default(),
        loopback_v4,
        upstream,
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
        None,
    ));
    let addrs = cli_rx.await.expect("client bound");

    (addrs, shutdown)
}

/// [`setup_relay_inner`] fronted by a UDP echo server bound on `echo_ip`.
/// Returns the client's local UDP address (where a test "app" socket sends).
async fn setup_relay(echo_ip: IpAddr, udp_timeout: Duration) -> (SocketAddr, CancellationToken) {
    let echo_addr = spawn_udp_echo(echo_ip).await;
    let (addrs, shutdown) = setup_relay_inner(echo_addr, udp_timeout).await;
    (addrs.udp, shutdown)
}

/// Send one datagram from `app` to the client's local UDP port and await the
/// echoed reply. A reply that never arrives hangs until the test-framework
/// timeout — the sanctioned external-event failure bound.
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
    // The server relay must bind its upstream UDP socket in the remote's address
    // family; an IPv6 upstream must work.
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
    // the first exchange can never race the eviction.
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

// End-to-end TCP relay (half-close) -----------------------------------------------------------------------------------

/// Spawn a TCP "upstream" (stands in for the ss-server side). On each accepted
/// connection it drains the request, writes `response`, then half-closes its
/// write side (FIN) — what an HTTP/1.0 `Connection: close` target does.
async fn spawn_tcp_responder(response: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp responder");
    let addr = listener.local_addr().expect("responder local_addr");
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let response = response.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await; // drain (part of) the request
                let _ = sock.write_all(&response).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

/// [`setup_relay_inner`] pointed at the TCP responder at `upstream`. Returns the
/// client's local TCP listener address (where a test "app" connects).
async fn setup_tcp_relay(upstream: SocketAddr) -> (SocketAddr, CancellationToken) {
    let (addrs, shutdown) = setup_relay_inner(upstream, DEFAULT_UDP_TIMEOUT).await;
    (addrs.tcp, shutdown)
}

#[skuld::test]
async fn tcp_full_response_survives_client_half_close() {
    // The app half-closes its write side right after the request (a legitimate
    // `Connection: close` client), then reads the response to EOF. The request
    // reaches the relay before any response round-trips, so the old
    // `select!{copy;copy}` relay completed its request-direction copy first and
    // dropped the still-live response-direction copy — truncating the response.
    // The ordering is causal (the FIN follows the request on the same direction;
    // the response can only arrive after a full round-trip), so the assertion is
    // deterministic, not timing-dependent. `copy_bidirectional` instead FINs the
    // peer and keeps draining the response to completion.
    const RESPONSE: &[u8] = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    let upstream = spawn_tcp_responder(RESPONSE.to_vec()).await;
    let (client_tcp, shutdown) = setup_tcp_relay(upstream).await;

    let mut app = TcpStream::connect(client_tcp).await.expect("connect client TCP");
    app.write_all(b"GET / HTTP/1.0\r\n\r\n").await.expect("write request");
    app.shutdown().await.expect("half-close write"); // FIN; keep reading

    let mut got = Vec::new();
    app.read_to_end(&mut got).await.expect("read response to EOF");
    assert_eq!(got, RESPONSE, "the full response must survive a client half-close");

    shutdown.cancel();
}

// Connect-cadence policy (#550) ---------------------------------------------------------------------------------------

#[skuld::test]
fn connect_delay_is_tight_and_constant_for_a_loopback_peer() {
    // A loopback peer is a co-located hop that comes up within startup; every
    // attempt polls on the same tight cadence, so nothing is stalled behind a
    // grown backoff once it binds.
    for addr in ["127.0.0.1:9000", "[::1]:9000"] {
        let remote: SocketAddr = addr.parse().unwrap();
        for attempt in [0u32, 1, 5, 20, 1000] {
            assert_eq!(
                connect_delay(remote, attempt),
                LOOPBACK_CONNECT_RETRY,
                "{addr} @ {attempt}"
            );
        }
    }
}

#[skuld::test]
fn connect_delay_backs_off_exponentially_for_a_routable_remote() {
    // Golden literals, independent of the impl's formula: 100 ms doubling,
    // capped at 30 s.
    let remote: SocketAddr = "203.0.113.7:443".parse().unwrap();
    let expected_ms = [
        100u64, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 30000, 30000, 30000,
    ];
    for (attempt, ms) in expected_ms.iter().enumerate() {
        assert_eq!(
            connect_delay(remote, attempt as u32),
            Duration::from_millis(*ms),
            "@ {attempt}"
        );
    }
    // Saturates at the cap for huge attempt counts (no overflow panic).
    assert_eq!(connect_delay(remote, u32::MAX), REMOTE_BACKOFF_MAX);
}

#[skuld::test]
async fn connect_retrying_returns_the_stream_when_the_peer_is_up() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    assert!(connect_retrying(addr, &shutdown).await.is_some());
}

#[skuld::test]
async fn connect_retrying_returns_none_when_shutdown_fires() {
    // Bound-but-not-listening: connects are refused (so the loop is in its
    // retry path) and the port can't be stolen by a parallel test. A
    // pre-cancelled token makes the loop take its shutdown branch — no clock.
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = sock.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    assert!(connect_retrying(addr, &shutdown).await.is_none());
}

#[skuld::test]
async fn connect_retrying_retries_until_the_peer_listens() {
    // Reserve the port bound-but-not-listening so early connects refuse (and
    // no parallel test can steal it), then `listen` to bring the peer up. The
    // client must retry across the gap and connect — a real event rendezvous
    // (await the task), never a timed guess.
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = sock.local_addr().unwrap();

    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    let handle = tokio::spawn(async move { connect_retrying(addr, &token).await });

    tokio::task::yield_now().await; // bias the first attempt to fail before listen
    let _listener = sock.listen(1024).unwrap();

    assert!(
        handle.await.unwrap().is_some(),
        "must connect once the peer starts listening"
    );
    shutdown.cancel();
}

// Reconnect backoff ---------------------------------------------------------------------------------------------------

#[skuld::test]
fn next_failures_resets_on_productive_and_increments_otherwise() {
    assert_eq!(next_failures(0, true), 0);
    assert_eq!(next_failures(5, true), 0);
    assert_eq!(next_failures(0, false), 1);
    assert_eq!(next_failures(3, false), 4);
    assert_eq!(next_failures(u32::MAX, false), u32::MAX);
}

#[skuld::test]
fn session_reconnect_backoff_schedule() {
    // Contract properties (independent of any literal table): a floor at the base,
    // doubling per failure, capped at the max.
    assert_eq!(session_reconnect_backoff(0), REMOTE_BACKOFF_BASE);
    assert_eq!(session_reconnect_backoff(1), REMOTE_BACKOFF_BASE);
    for n in 1..14u32 {
        assert_eq!(
            session_reconnect_backoff(n + 1),
            (session_reconnect_backoff(n) * 2).min(REMOTE_BACKOFF_MAX),
            "doubling @ {n}"
        );
    }
    assert_eq!(session_reconnect_backoff(u32::MAX), REMOTE_BACKOFF_MAX);

    // Golden literals as a readable cross-check (mirrors the connect_delay tests).
    let expected_ms = [100u64, 100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 30000, 30000];
    for (failures, ms) in expected_ms.iter().enumerate() {
        assert_eq!(
            session_reconnect_backoff(failures as u32),
            Duration::from_millis(*ms),
            "@ {failures}"
        );
    }
}

// TransportLivenessTap ------------------------------------------------------------------------------------------------

#[skuld::test]
async fn transport_tap_counts_inbound_reads() {
    use futures::AsyncReadExt as _;
    let reads = Arc::new(AtomicU64::new(0));
    let mut tap = TransportLivenessTap::new(futures::io::Cursor::new(b"datadata".to_vec()), Arc::clone(&reads));
    let mut buf = [0u8; 4];
    assert_eq!(tap.read(&mut buf).await.unwrap(), 4);
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    assert_eq!(tap.read(&mut buf).await.unwrap(), 4);
    assert_eq!(reads.load(Ordering::Relaxed), 2, "each non-empty read must be counted");
}

#[skuld::test]
async fn transport_tap_silent_on_eof() {
    use futures::AsyncReadExt as _;
    let reads = Arc::new(AtomicU64::new(0));
    let mut tap = TransportLivenessTap::new(futures::io::Cursor::new(Vec::new()), Arc::clone(&reads));
    let mut buf = [0u8; 8];
    assert_eq!(tap.read(&mut buf).await.unwrap(), 0);
    assert_eq!(reads.load(Ordering::Relaxed), 0);
}

#[skuld::test]
async fn transport_tap_delegates_writes() {
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    let reads = Arc::new(AtomicU64::new(0));
    let (a, b) = tokio::io::duplex(64);
    let mut tap = TransportLivenessTap::new(a.compat(), Arc::clone(&reads));
    tap.write_all(b"ping").await.unwrap();
    tap.flush().await.unwrap();
    let mut b = b.compat();
    let mut buf = [0u8; 4];
    b.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    assert_eq!(reads.load(Ordering::Relaxed), 0, "writes are never inbound liveness");
}

// Transport-reset reconnect -------------------------------------------------------------------------------------------

/// Fire a one-shot reset on a relay connection.
struct ResetHandle {
    tx: Option<oneshot::Sender<()>>,
}
impl ResetHandle {
    fn trigger(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

/// A TCP relay in front of `upstream`. Its first `immediate_closes` connections
/// are closed with a graceful FIN right after accept (before any yamux frame, so
/// the client establishes an unproductive session that then dies); the next
/// connection is armed with the returned `ResetHandle` (RST on `trigger()`);
/// later connections pass through.
///
/// The immediate closes are a FIN, not an RST, on purpose. An RST on accept
/// races the client's `connect()` on loopback and, on Linux/macOS, makes the
/// connect itself fail with `ECONNRESET` (nondeterministically); `connect_retrying`
/// then retries silently, so no *session* death occurs and the reconnect these
/// tests await never fires — the test hangs. A FIN never fails a completed
/// connect, so the client always establishes, then deterministically observes
/// transport death on every platform.
async fn spawn_controllable_relay(upstream: SocketAddr, immediate_closes: usize) -> (SocketAddr, ResetHandle) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
    let addr = listener.local_addr().expect("relay addr");
    let (reset_tx, reset_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut seen = 0usize;
        let mut trigger = Some(reset_rx);
        while let Ok((client_conn, _)) = listener.accept().await {
            if seen < immediate_closes {
                seen += 1;
                drop(client_conn); // graceful FIN, no upstream → unproductive session death
                continue;
            }
            let server_conn = match TcpStream::connect(upstream).await {
                Ok(s) => s,
                Err(_) => continue,
            };
            tokio::spawn(pump_with_optional_reset(client_conn, server_conn, trigger.take()));
        }
    });
    (addr, ResetHandle { tx: Some(reset_tx) })
}

/// Pump both ways; if `reset` fires first, RST both sockets.
// `set_linger` is deprecated in favour of blocking-on-drop with a nonzero
// timeout; a zero timeout is the opposite — an immediate abortive close (RST),
// no blocking — which is exactly the reset this path needs, not the case the
// deprecation warns about.
#[allow(deprecated)]
async fn pump_with_optional_reset(mut client: TcpStream, mut server: TcpStream, reset: Option<oneshot::Receiver<()>>) {
    match reset {
        Some(rx) => {
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                _ = rx => {
                    let _ = client.set_linger(Some(Duration::ZERO));
                    let _ = server.set_linger(Some(Duration::ZERO));
                }
            }
        }
        None => {
            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
        }
    }
}

async fn spawn_yamux_server(upstream: SocketAddr, shutdown: CancellationToken) -> SocketAddr {
    let (srv_tx, srv_rx) = oneshot::channel();
    tokio::spawn(run_server(
        ::yamux::Config::default(),
        "127.0.0.1:0".parse().unwrap(),
        upstream,
        shutdown,
        Some(srv_tx),
    ));
    srv_rx.await.expect("server bound")
}

/// Spawn a yamux client pointed at `remote`, with a typed reconnect observer.
/// Returns the client's local addresses and the observer receiver.
async fn spawn_yamux_client(
    remote: SocketAddr,
    udp_timeout: Duration,
    shutdown: CancellationToken,
) -> (ClientBoundAddrs, mpsc::UnboundedReceiver<(u32, bool)>) {
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let (cli_tx, cli_rx) = oneshot::channel();
    tokio::spawn(run_client(
        ::yamux::Config::default(),
        "127.0.0.1:0".parse().unwrap(),
        remote,
        udp_timeout,
        shutdown,
        Some(cli_tx),
        Some(events_tx),
    ));
    (cli_rx.await.expect("client bound"), events_rx)
}

/// One TCP request/response through the client's local listener.
async fn tcp_round_trip(client_tcp: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut app = TcpStream::connect(client_tcp).await.expect("connect client TCP");
    app.write_all(request).await.expect("write request");
    app.shutdown().await.expect("half-close write");
    let mut got = Vec::new();
    app.read_to_end(&mut got).await.expect("read to EOF");
    got
}

const HTTP_RESPONSE: &[u8] = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc";

#[skuld::test]
async fn tcp_transport_reset_reconnects() {
    let upstream = spawn_tcp_responder(HTTP_RESPONSE.to_vec()).await;
    let shutdown = CancellationToken::new();
    let server_addr = spawn_yamux_server(upstream, shutdown.clone()).await;
    let (relay_addr, mut reset) = spawn_controllable_relay(server_addr, 0).await;
    let (addrs, mut events) = spawn_yamux_client(relay_addr, DEFAULT_UDP_TIMEOUT, shutdown.clone()).await;

    // #1 proves the tunnel works and (via the transport tap) marks it productive.
    assert_eq!(
        tcp_round_trip(addrs.tcp, b"GET /1 HTTP/1.0\r\n\r\n").await,
        HTTP_RESPONSE
    );

    reset.trigger();
    // Rendezvous: the client observed transport death and is reconnecting. The
    // session was productive, so it resets to the floor.
    assert_eq!(events.recv().await.unwrap(), (0, true));

    // #2 must succeed on the reconnected session.
    assert_eq!(
        tcp_round_trip(addrs.tcp, b"GET /2 HTTP/1.0\r\n\r\n").await,
        HTTP_RESPONSE
    );

    shutdown.cancel();
}

#[skuld::test]
async fn udp_transport_reset_reconnects() {
    let echo = spawn_udp_echo("127.0.0.1".parse().unwrap()).await;
    let shutdown = CancellationToken::new();
    let server_addr = spawn_yamux_server(echo, shutdown.clone()).await;
    let (relay_addr, mut reset) = spawn_controllable_relay(server_addr, 0).await;
    let (addrs, mut events) = spawn_yamux_client(relay_addr, DEFAULT_UDP_TIMEOUT, shutdown.clone()).await;
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    assert_eq!(round_trip(&app, addrs.udp, b"one").await, b"one");

    reset.trigger();
    assert_eq!(events.recv().await.unwrap(), (0, true));

    assert_eq!(round_trip(&app, addrs.udp, b"two").await, b"two");

    shutdown.cancel();
}

#[skuld::test]
async fn backoff_escalates_then_resets_on_productive() {
    // Two immediate closes escalate failures 1→2 (unproductive), then a
    // passthrough session round-trips (productive), then a triggered reset resets
    // failures to 0 — proving both escalation and the productive reset.
    let upstream = spawn_tcp_responder(HTTP_RESPONSE.to_vec()).await;
    let shutdown = CancellationToken::new();
    let server_addr = spawn_yamux_server(upstream, shutdown.clone()).await;
    let (relay_addr, mut reset) = spawn_controllable_relay(server_addr, 2).await;
    let (addrs, mut events) = spawn_yamux_client(relay_addr, DEFAULT_UDP_TIMEOUT, shutdown.clone()).await;

    assert_eq!(events.recv().await.unwrap(), (1, false)); // close #1 (unproductive)
    assert_eq!(events.recv().await.unwrap(), (2, false)); // close #2 (unproductive)

    // The 3rd connection passes through; a round trip makes it productive.
    assert_eq!(
        tcp_round_trip(addrs.tcp, b"GET / HTTP/1.0\r\n\r\n").await,
        HTTP_RESPONSE
    );
    reset.trigger();
    assert_eq!(events.recv().await.unwrap(), (0, true)); // productive → reset to floor

    shutdown.cancel();
}

// Remaining branch coverage -------------------------------------------------------------------------------------------

/// Install a per-test tracing subscriber that captures log lines for
/// [`wait_for_log`] rendezvous, plus the `DefaultGuard` keeping it active.
fn capture_logs() -> (WaitableWriter, tracing::subscriber::DefaultGuard) {
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let guard = set_default_in_current_thread(subscriber);
    (writer, guard)
}

/// Park until a log line containing `needle` is captured — a real event
/// rendezvous, not a timed guess.
async fn wait_for_log(writer: &WaitableWriter, needle: &str) {
    let rx = writer.wait_for(needle);
    tokio::task::spawn_blocking(move || rx.recv().expect("log event never arrived"))
        .await
        .unwrap();
}

/// Strip the 1-byte stream tag, then echo everything else back.
async fn echo_yamux_stream(mut stream: yamux::Stream) {
    use futures::AsyncReadExt as _;
    let mut tag = [0u8; 1];
    if stream.read_exact(&mut tag).await.is_err() {
        return;
    }
    echo_yamux_stream_body(stream).await;
}

/// Echo every byte back until the peer goes away. Any stream tag must already
/// have been consumed.
async fn echo_yamux_stream_body(mut stream: yamux::Stream) {
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut buf = vec![0u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                let _ = stream.flush().await;
            }
        }
    }
    let _ = stream.close().await;
}

#[skuld::test]
async fn server_initiated_stream_dropped_client_keeps_serving() {
    let (writer, _g) = capture_logs();
    let srv_shutdown = CancellationToken::new();
    let srv_shutdown2 = srv_shutdown.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let conn = ::yamux::Connection::new(tcp.compat(), ::yamux::Config::default(), ::yamux::Mode::Server);
        let (open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<yamux::Stream>(16);
        tokio::spawn(drive_connection(conn, open_rx, inbound_tx));
        // A server-initiated stream (protocol violation on the client).
        let (tx, rx) = oneshot::channel();
        let _ = open_tx.send(tx).await;
        if let Ok(Ok(mut s)) = rx.await {
            use futures::AsyncWriteExt as _;
            let _ = s.write_all(&[0xFF]).await;
            let _ = s.flush().await;
        }
        // Echo client-initiated streams so a normal round trip works.
        loop {
            tokio::select! {
                _ = srv_shutdown2.cancelled() => break,
                s = inbound_rx.recv() => match s {
                    Some(stream) => { tokio::spawn(echo_yamux_stream(stream)); }
                    None => break,
                },
            }
        }
    });

    let client_shutdown = CancellationToken::new();
    let (addrs, _events) = spawn_yamux_client(server_addr, DEFAULT_UDP_TIMEOUT, client_shutdown.clone()).await;

    // The bogus stream is warned-and-dropped...
    wait_for_log(&writer, "unexpected server-initiated yamux stream").await;
    // ...and the client keeps serving: a normal TCP round trip still echoes.
    assert_eq!(tcp_round_trip(addrs.tcp, b"still here").await, b"still here");

    client_shutdown.cancel();
    srv_shutdown.cancel();
}

#[skuld::test]
async fn driver_panicked_detects_panic_not_cancel() {
    // Normal completion (the ordinary TransportDied reconnect path) → not a panic.
    let h = tokio::spawn(async {});
    assert!(!driver_panicked(h.await));

    // Our own abort → cancelled JoinError → not a panic.
    let h = tokio::spawn(std::future::pending::<()>());
    h.abort();
    assert!(!driver_panicked(h.await));

    // A real panic → panic JoinError → detected (and logged as a side effect).
    let h = tokio::spawn(async { panic!("boom") });
    assert!(driver_panicked(h.await));
}

#[skuld::test]
async fn shutdown_during_backoff_exits_promptly() {
    let upstream = spawn_tcp_responder(HTTP_RESPONSE.to_vec()).await;
    let shutdown = CancellationToken::new();
    let server_addr = spawn_yamux_server(upstream, shutdown.clone()).await;
    let (relay_addr, _reset) = spawn_controllable_relay(server_addr, 1).await; // one unproductive close
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let (cli_tx, cli_rx) = oneshot::channel();
    let client = tokio::spawn(run_client(
        ::yamux::Config::default(),
        "127.0.0.1:0".parse().unwrap(),
        relay_addr,
        DEFAULT_UDP_TIMEOUT,
        shutdown.clone(),
        Some(cli_tx),
        Some(events_tx),
    ));
    let _ = cli_rx.await.unwrap();

    // Rendezvous (not the assertion): the observer event means the client has
    // reached the reconnect decision and is entering the backoff sleep.
    assert_eq!(events_rx.recv().await.unwrap(), (1, false));

    // Freeze only the backoff window. Pausing for the whole test would put the
    // session's keepalive timers inside an auto-advancing clock while real
    // socket traffic is still in flight, and a spurious verdict would change
    // which reconnect event the rendezvous above yields.
    tokio::time::pause();

    // The external assertion: shutdown must win the paused sleep, so the client
    // task returns `Ok` promptly. Without the select! shutdown branch the paused
    // sleep never elapses and this `await` hangs → framework timeout.
    shutdown.cancel();
    client.await.unwrap().unwrap();
}

// Keepalive -----------------------------------------------------------------------------------------------------------

/// Open one substream through `open_tx`. Panics if the connection is gone.
async fn open_test_stream(open_tx: &mpsc::Sender<OpenStreamReply>) -> yamux::Stream {
    let (tx, rx) = oneshot::channel();
    open_tx.send(tx).await.expect("driver alive");
    rx.await.expect("open reply").expect("stream opened")
}

/// Write `payload` to `stream` and read exactly `expect_len` bytes back.
async fn write_and_read(stream: &mut yamux::Stream, payload: &[u8], expect_len: usize) -> Option<Vec<u8>> {
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    stream.write_all(payload).await.ok()?;
    stream.flush().await.ok()?;
    let mut echo = vec![0u8; expect_len];
    stream.read_exact(&mut echo).await.ok().map(|()| echo)
}

/// A raw yamux client over a real TCP connection, kept alive so a test can send
/// several substreams — and several messages per substream — down the *same*
/// session.
struct RawYamuxClient {
    open_tx: mpsc::Sender<OpenStreamReply>,
    _inbound_rx: mpsc::Receiver<yamux::Stream>,
    driver: tokio::task::JoinHandle<()>,
}

impl RawYamuxClient {
    async fn connect(server_addr: SocketAddr) -> Self {
        let tcp = TcpStream::connect(server_addr).await.expect("connect yamux server");
        let conn = ::yamux::Connection::new(tcp.compat(), ::yamux::Config::default(), ::yamux::Mode::Client);
        let (open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(4);
        let (inbound_tx, _inbound_rx) = mpsc::channel::<yamux::Stream>(4);
        let driver = tokio::spawn(drive_connection(conn, open_rx, inbound_tx));
        Self {
            open_tx,
            _inbound_rx,
            driver,
        }
    }

    /// Open a fresh substream and write its leading `tag` byte.
    async fn open_tagged(&self, tag: u8) -> yamux::Stream {
        use futures::AsyncWriteExt as _;
        let mut stream = open_test_stream(&self.open_tx).await;
        stream.write_all(&[tag]).await.expect("write tag");
        stream.flush().await.expect("flush tag");
        stream
    }

    /// Send `tag` + `payload` on a fresh substream and read `expect_len` bytes
    /// back. `None` if the peer ended the substream first.
    async fn exchange(&self, tag: u8, payload: &[u8], expect_len: usize) -> Option<Vec<u8>> {
        let mut stream = self.open_tagged(tag).await;
        write_and_read(&mut stream, payload, expect_len).await
    }
}

impl Drop for RawYamuxClient {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[skuld::test]
async fn the_server_echoes_every_nonce_on_one_keepalive_substream() {
    // The client holds a single keepalive substream for the whole session, so
    // the server must keep echoing on it rather than answering once and closing.
    let upstream = spawn_tcp_responder(HTTP_RESPONSE.to_vec()).await;
    let shutdown = CancellationToken::new();
    let server_addr = spawn_yamux_server(upstream, shutdown.clone()).await;

    let client = RawYamuxClient::connect(server_addr).await;
    let mut probe = client.open_tagged(0x03).await;
    for nonce in [1u64, 2, 3] {
        assert_eq!(
            write_and_read(&mut probe, &nonce.to_be_bytes(), 8).await,
            Some(nonce.to_be_bytes().to_vec()),
            "nonce {nonce} must come back verbatim on the same substream"
        );
    }

    shutdown.cancel();
}

#[skuld::test]
async fn an_unknown_stream_tag_costs_one_substream_not_the_session() {
    // The compatibility property in mirror image, asserted on the SAME session:
    // the server rejects the substream and keeps serving the connection. This is
    // exactly what an un-upgraded server does to a keepalive probe.
    let upstream = spawn_tcp_responder(HTTP_RESPONSE.to_vec()).await;
    let shutdown = CancellationToken::new();
    let server_addr = spawn_yamux_server(upstream, shutdown.clone()).await;

    let client = RawYamuxClient::connect(server_addr).await;
    assert_eq!(
        client.exchange(0x7F, b"whatever", 1).await,
        None,
        "unknown tag rejected"
    );
    assert_eq!(
        client
            .exchange(0x01, b"GET / HTTP/1.0\r\n\r\n", HTTP_RESPONSE.len())
            .await,
        Some(HTTP_RESPONSE.to_vec()),
        "the session must survive a rejected substream"
    );

    shutdown.cancel();
}

/// One registered wait: the substring, how many occurrences it needs, and the
/// sender that fires when it has them.
type LogWait = (String, usize, tokio::sync::oneshot::Sender<()>);

/// A `MakeWriter` that fires a **tokio** oneshot the first time a registered
/// substring is written.
///
/// `garter`'s `WaitableWriter` hands back a `std::sync::mpsc::Receiver`, which a
/// test can only await through `spawn_blocking` — and on a current-thread
/// runtime built with `test-util`, spawning a blocking task calls
/// `Clock::inhibit_auto_advance` for that task's whole lifetime. Under
/// `tokio::time::pause()` the clock then never advances, the awaited line is
/// never written, the blocking task never ends, and the wait deadlocks. This
/// receiver is awaited on the runtime instead, so the runtime still parks and
/// the clock still advances.
#[derive(Clone, Default)]
struct LogWaiter {
    text: Arc<std::sync::Mutex<String>>,
    waiters: Arc<std::sync::Mutex<Vec<LogWait>>>,
}

impl LogWaiter {
    /// Fires the first time the accumulated log contains `needle`; fires
    /// immediately if it already does, so a caller cannot race a past write.
    fn wait_for(&self, needle: &str) -> tokio::sync::oneshot::Receiver<()> {
        self.wait_for_nth(needle, 1)
    }

    /// Fires once `needle` has been written at least `nth` times. Lets a test
    /// wait for an occurrence that provably post-dates a snapshot, which
    /// `wait_for` cannot: a needle already present fires it immediately.
    fn wait_for_nth(&self, needle: &str, nth: usize) -> tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        // Hold both locks across the check-and-register so a write landing
        // between them cannot be lost.
        let text = self.text.lock().unwrap();
        let mut waiters = self.waiters.lock().unwrap();
        if text.matches(needle).count() >= nth {
            let _ = tx.send(());
        } else {
            waiters.push((needle.to_string(), nth, tx));
        }
        rx
    }

    fn count(&self, needle: &str) -> usize {
        self.text.lock().unwrap().matches(needle).count()
    }

    fn contains(&self, needle: &str) -> bool {
        self.count(needle) > 0
    }
}

impl std::io::Write for LogWaiter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut text = self.text.lock().unwrap();
        text.push_str(&String::from_utf8_lossy(buf));
        // Scan the whole accumulated text, not just this write: tracing's
        // formatter splits a line's header and body across calls.
        let mut waiters = self.waiters.lock().unwrap();
        let mut i = 0;
        while i < waiters.len() {
            if text.matches(waiters[i].0.as_str()).count() >= waiters[i].1 {
                let (_, _, tx) = waiters.swap_remove(i);
                let _ = tx.send(());
            } else {
                i += 1;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWaiter {
    type Writer = LogWaiter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Install a per-test subscriber whose waits are awaitable on the runtime.
fn capture_logs_awaitable() -> (LogWaiter, tracing::subscriber::DefaultGuard) {
    let writer = LogWaiter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let guard = set_default_in_current_thread(subscriber);
    (writer, guard)
}

/// How a stub peer treats the client's keepalive substream. Non-keepalive
/// substreams are always echoed, so a test can generate ordinary traffic.
#[derive(Clone, Copy)]
enum StubPeer {
    /// Echoes every nonce, like the production server.
    Echo,
    /// What a pre-keepalive galoshes server does: the tag is unknown, the
    /// handler errors, the substream is dropped — which yamux turns into a reset
    /// the client will read.
    RejectTag,
    /// Answers, but with bytes that are not the nonce.
    Corrupt,
    /// Reads every nonce and never answers any of them, holding the substream
    /// open. Models a busy-but-alive peer whose probe stalls.
    StallProbe,
    /// Answers one nonce, then half-closes the substream. A FIN leaves the
    /// client's side writable (`State::RecvClosed`), so the read side ending is
    /// the only signal that it is spent.
    FinAfterFirstProbe,
    /// Answers one nonce, then *resets* the substream. The reset lands between
    /// cycles, so the client's next write is the thing that discovers it.
    ResetAfterFirstProbe,
    /// A raw byte sink: reads and discards, never writes a single byte. NOT a
    /// yamux peer — a real `Connection` would answer yamux's own pings and so
    /// could not model a black hole.
    Blackhole,
}

/// A live yamux client whose transport is an in-process pipe to `peer`.
///
/// Every stub except `Blackhole` runs a real `yamux::Connection`, whose first RTT
/// ping is due immediately — so the peer pongs during setup and the tap has
/// already moved before the keepalive's first cycle. That cycle is therefore
/// skipped by the idle gate and probes start at cycle 2. `PING_INTERVAL` is 10 s
/// of *real* time, which a virtual clock does not move, so no further pong
/// arrives during a test.
struct PipedClient {
    open_tx: mpsc::Sender<OpenStreamReply>,
    inbound_reads: Arc<AtomicU64>,
    /// One item per keepalive nonce the peer read.
    probes: mpsc::UnboundedReceiver<()>,
    /// One item per inbound substream the peer accepted, of any kind.
    substreams: mpsc::UnboundedReceiver<()>,
    _client_driver: tokio::task::JoinHandle<()>,
    _client_inbound: mpsc::Receiver<yamux::Stream>,
    _peer: tokio::task::JoinHandle<()>,
}

async fn piped_client(peer: StubPeer) -> PipedClient {
    piped_client_with_max_streams(peer, 512).await
}

async fn piped_client_with_max_streams(peer: StubPeer, max_streams: usize) -> PipedClient {
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};

    let (client_io, peer_io) = tokio::io::duplex(256 * 1024);

    let mut config = ::yamux::Config::default();
    config.set_max_num_streams(max_streams);

    let inbound_reads = Arc::new(AtomicU64::new(0));
    let tapped = TransportLivenessTap::new(client_io.compat(), Arc::clone(&inbound_reads));
    let conn = ::yamux::Connection::new(tapped, config, ::yamux::Mode::Client);
    let (open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(32);
    let (inbound_tx, client_inbound) = mpsc::channel::<yamux::Stream>(32);
    let client_driver = tokio::spawn(drive_connection(conn, open_rx, inbound_tx));

    let (probe_tx, probes) = mpsc::unbounded_channel();
    let (substream_tx, substreams) = mpsc::unbounded_channel();
    let peer_task = tokio::spawn(async move {
        if let StubPeer::Blackhole = peer {
            let mut sink = peer_io;
            let mut buf = [0u8; 4096];
            while matches!(tokio::io::AsyncReadExt::read(&mut sink, &mut buf).await, Ok(n) if n > 0) {}
            return;
        }

        let conn = ::yamux::Connection::new(peer_io.compat(), ::yamux::Config::default(), ::yamux::Mode::Server);
        let (_open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<yamux::Stream>(32);
        tokio::spawn(drive_connection(conn, open_rx, inbound_tx));

        while let Some(mut stream) = inbound_rx.recv().await {
            let _ = substream_tx.send(());
            let probe_tx = probe_tx.clone();
            tokio::spawn(async move {
                let mut tag = [0u8; 1];
                if stream.read_exact(&mut tag).await.is_err() {
                    return;
                }
                if tag[0] != StreamTag::Keepalive.to_byte() {
                    echo_yamux_stream_body(stream).await;
                    return;
                }
                if let StubPeer::RejectTag = peer {
                    return; // drops the substream -> reset
                }
                let mut nonce = [0u8; 8];
                let mut answered = 0u32;
                while stream.read_exact(&mut nonce).await.is_ok() {
                    let _ = probe_tx.send(());
                    if let StubPeer::StallProbe = peer {
                        continue;
                    }
                    if let StubPeer::Corrupt = peer {
                        nonce.iter_mut().for_each(|b| *b ^= 0xFF);
                    }
                    if stream.write_all(&nonce).await.is_err() || stream.flush().await.is_err() {
                        return;
                    }
                    answered += 1;
                    match peer {
                        StubPeer::FinAfterFirstProbe if answered == 1 => {
                            let _ = stream.close().await;
                            return;
                        }
                        StubPeer::ResetAfterFirstProbe if answered == 1 => return, // drop -> reset
                        _ => {}
                    }
                }
            });
        }
    });

    PipedClient {
        open_tx,
        inbound_reads,
        probes,
        substreams,
        _client_driver: client_driver,
        _client_inbound: client_inbound,
        _peer: peer_task,
    }
}

/// Await `count` nonces read by the peer. An in-runtime rendezvous, so a paused
/// clock only advances between cycles and never mid-exchange.
async fn expect_probes(client: &mut PipedClient, count: usize) {
    for probe in 1..=count {
        client
            .probes
            .recv()
            .await
            .unwrap_or_else(|| panic!("probe {probe} never reached the peer"));
    }
}

/// Drive one echoed round trip on an ordinary substream. Used where the point is
/// that a real substream still works, not to time inbound traffic against a
/// keepalive cycle.
async fn chatter(open_tx: &mpsc::Sender<OpenStreamReply>) {
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = open_test_stream(open_tx).await;
    stream.write_all(&[StreamTag::Tcp.to_byte()]).await.unwrap();
    stream.write_all(b"still here").await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = [0u8; 10];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"still here");
}

#[skuld::test]
async fn a_refused_probe_open_ends_the_whole_yamux_connection() {
    // Pins yamux's actual behavior, which is harsher than "the open failed":
    // `Connection::poll_new_outbound` hands any open error to `cleanup`, which
    // drops every substream. So exhausting the budget does not cost one probe,
    // it costs the connection — and the keepalive must report it as such rather
    // than treat it as a survivable, transport-alive event.
    use futures::AsyncWriteExt as _;

    let (writer, _g) = capture_logs_awaitable();
    let client = piped_client_with_max_streams(StubPeer::Echo, 1).await;
    let mut hog = open_test_stream(&client.open_tx).await;
    assert!(open_probe(&client.open_tx, 1).await.is_none());
    assert!(
        writer.contains("keepalive substream open ended the yamux connection"),
        "a refused open must be reported as fatal to the connection"
    );

    // The driver ends outright — an in-runtime rendezvous on it dropping the
    // open channel, no polling.
    client.open_tx.closed().await;
    // And the pre-existing substream is collateral, not merely idle.
    assert!(hog.write_all(b"x").await.is_err(), "the held substream is gone too");
}

#[skuld::test]
async fn opening_a_probe_fails_when_the_connection_is_gone() {
    let (open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(1);
    drop(open_rx);
    assert!(open_probe(&open_tx, 1).await.is_none());
}

#[skuld::test]
async fn opening_a_probe_tags_it_and_delivers_the_first_nonce() {
    let mut client = piped_client(StubPeer::Echo).await;
    let probe = open_probe(&client.open_tx, 7).await;
    assert!(probe.is_some(), "a healthy connection must yield a probe substream");
    expect_probes(&mut client, 1).await;
}

#[skuld::test]
async fn the_driver_opens_no_substream_for_a_departed_requester() {
    // The keepalive cancels an open whenever its deadline beats the transport.
    // Answering a request already known to be cancelled would open a substream
    // nobody reads, which yamux immediately resets — a wasted SYN/RST pair and a
    // stream-table slot.
    //
    // `try_send` is fully synchronous, so no other task can run between the send
    // and the drop: the driver is guaranteed to see a request that is already
    // abandoned. (`send().await` would not do — it goes through
    // `batch_semaphore.rs`'s `poll_proceed`, which yields on an exhausted coop
    // budget even when the channel has room.)
    let (writer, _g) = capture_logs_awaitable();
    let mut client = piped_client(StubPeer::Echo).await;
    let (tx, rx) = oneshot::channel();
    client.open_tx.try_send(tx).expect("driver alive");
    drop(rx);

    // Assert the discard branch itself ran, not just its side effect: that line
    // is written only there. It covers requests abandoned before the driver's
    // poll, which is what this test constructs; one abandoned later is caught by
    // `reply.send` failing instead.
    writer
        .wait_for("discarding an open request whose requester is gone")
        .await
        .expect("the driver must discard the cancelled request, not answer it");

    // And the observable consequence: a real substream afterwards works, and its
    // round trip gives the peer time to report every substream it accepted.
    chatter(&client.open_tx).await;
    assert!(client.substreams.recv().await.is_some(), "the chatter substream");
    assert!(
        matches!(client.substreams.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "the cancelled request must not have opened a substream of its own"
    );
}

#[skuld::test]
async fn keepalive_keeps_probing_a_healthy_peer() {
    // Three delivered probes prove the loop took the non-fatal path twice and
    // came back for more, which a fatal verdict would have prevented.
    let mut client = piped_client(StubPeer::Echo).await;
    tokio::time::pause();
    let keepalive = tokio::spawn(run_keepalive(client.open_tx.clone(), Arc::clone(&client.inbound_reads)));
    expect_probes(&mut client, 3).await;
    assert!(!keepalive.is_finished(), "a healthy peer must never be declared dead");
    keepalive.abort();
}

#[skuld::test]
async fn keepalive_survives_a_peer_that_rejects_the_tag() {
    // An un-upgraded server. Its reset is inbound traffic read inside the same
    // window, so the cycle ends non-fatally — which only the post-window line
    // can report.
    let (writer, _g) = capture_logs_awaitable();
    let client = piped_client(StubPeer::RejectTag).await;
    tokio::time::pause();
    let keepalive = tokio::spawn(run_keepalive(client.open_tx.clone(), Arc::clone(&client.inbound_reads)));
    writer
        .wait_for("transport answered inside the keepalive deadline")
        .await
        .expect("the rejected probe must close its window non-fatally");
    assert!(
        !keepalive.is_finished(),
        "an un-upgraded peer must never be declared dead"
    );
    keepalive.abort();
}

#[skuld::test]
async fn keepalive_replaces_a_probe_substream_the_peer_half_closed() {
    // A FIN leaves the client's substream writable, so a write cannot detect it.
    // The read side ending is the signal; the next cycle must open a fresh
    // substream, which the peer sees as a second one carrying a second nonce.
    let mut client = piped_client(StubPeer::FinAfterFirstProbe).await;
    tokio::time::pause();
    let keepalive = tokio::spawn(run_keepalive(client.open_tx.clone(), Arc::clone(&client.inbound_reads)));
    expect_probes(&mut client, 2).await;
    assert!(
        !keepalive.is_finished(),
        "a half-closed probe substream is not a dead transport"
    );
    keepalive.abort();
}

#[skuld::test]
async fn keepalive_replaces_a_probe_substream_the_peer_reset_between_cycles() {
    // The write-failure path: the peer answers, then resets while the client is
    // *not* reading it. The cached substream is discovered dead by a later
    // cycle's write, which must retry on a fresh substream rather than lose the
    // cycle. A second delivered nonce is proof it did.
    let mut client = piped_client(StubPeer::ResetAfterFirstProbe).await;
    tokio::time::pause();
    let keepalive = tokio::spawn(run_keepalive(client.open_tx.clone(), Arc::clone(&client.inbound_reads)));
    expect_probes(&mut client, 2).await;
    assert!(
        !keepalive.is_finished(),
        "a reset probe substream costs a re-open, not a session"
    );
    keepalive.abort();
}

#[skuld::test]
async fn keepalive_survives_a_peer_that_garbles_the_echo() {
    let mut client = piped_client(StubPeer::Corrupt).await;
    tokio::time::pause();
    let keepalive = tokio::spawn(run_keepalive(client.open_tx.clone(), Arc::clone(&client.inbound_reads)));
    expect_probes(&mut client, 3).await;
    assert!(
        !keepalive.is_finished(),
        "a peer that answers with the wrong bytes is still a live transport"
    );
    keepalive.abort();
}

#[skuld::test]
async fn a_stalled_probe_survives_on_other_traffic_then_dies_on_silence() {
    // One test, both halves of the stalled-probe contract. The peer holds the
    // substream open and answers nothing, so nothing ever makes it unusable and
    // it is reused across cycles.
    //
    // Cycle A: probe #1 stalls, but the transport delivers a frame on some other
    // substream, so the window closes non-fatally — proved by cycle B happening
    // at all. Cycle B: probe #2 goes out on that same retained substream and
    // nothing answers it, so silence wins.
    //
    // The other-traffic frame is injected straight into the tap rather than
    // relayed for real. The tap counter IS the keepalive's input, and driving it
    // directly is what makes the ordering exact: real traffic has to be produced
    // between two cycle boundaries, and a paused clock auto-advances on any park
    // inside that exchange.
    let mut client = piped_client(StubPeer::StallProbe).await;
    tokio::time::pause();
    let keepalive = tokio::spawn(run_keepalive(client.open_tx.clone(), Arc::clone(&client.inbound_reads)));

    expect_probes(&mut client, 1).await;
    client.inbound_reads.fetch_add(1, Ordering::Relaxed);

    // A second nonce can only exist if cycle A ended non-fatally, and it travels
    // the retained substream because nothing has invalidated it.
    expect_probes(&mut client, 1).await;
    keepalive.await.expect("silence must end the loop, not hang it");
}

#[skuld::test]
async fn keepalive_skips_the_probe_while_the_transport_is_busy() {
    // A transport that delivered something has already answered the question a
    // probe asks, so those cycles send nothing at all.
    //
    // The traffic is injected into the tap on its own cadence rather than
    // relayed for real: the tap counter is the keepalive's input, and a
    // stand-in that ticks three times per keepalive interval guarantees every
    // gate check sees movement. Real traffic would have to be produced between
    // two cycle boundaries, which a paused clock can auto-advance straight past.
    // The interval here IS the behavior being modelled (a busy transport), not
    // synchronization between test steps.
    let (writer, _g) = capture_logs_awaitable();
    let mut client = piped_client(StubPeer::Echo).await;
    let reads = Arc::clone(&client.inbound_reads);
    tokio::time::pause();
    let busy = tokio::spawn(async move {
        loop {
            tokio::time::sleep(KEEPALIVE_INTERVAL / 3).await;
            reads.fetch_add(1, Ordering::Relaxed);
        }
    });
    let keepalive = tokio::spawn(run_keepalive(client.open_tx.clone(), Arc::clone(&client.inbound_reads)));

    // Three skipped cycles, or the first probe — whichever comes first. A
    // keepalive with no idle gate probes immediately and loses this race, so the
    // regression fails fast instead of hanging.
    const SKIP: &str = "transport still active; skipping the keepalive probe";
    tokio::select! {
        r = writer.wait_for_nth(SKIP, 3) => r.expect("skips observed"),
        _ = client.probes.recv() => panic!("a busy transport must not be probed"),
    }

    assert!(!keepalive.is_finished(), "a skipped cycle is never a fatal one");
    keepalive.abort();
    busy.abort();
}

#[skuld::test]
async fn keepalive_declares_a_silent_transport_dead() {
    // The peer swallows everything and answers nothing, with no reset and no
    // FIN. Only timers can make progress, so the paused clock advances
    // deterministically to the verdict; if it never came, this would hang to the
    // framework timeout.
    let client = piped_client(StubPeer::Blackhole).await;
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    run_keepalive(client.open_tx.clone(), Arc::clone(&client.inbound_reads)).await;
    assert_eq!(
        client.inbound_reads.load(Ordering::Relaxed),
        0,
        "nothing came back — that silence is what made the verdict fatal"
    );
    assert!(
        tokio::time::Instant::now() - started >= KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT,
        "the verdict must wait out a whole interval and a whole deadline"
    );
}

#[skuld::test]
async fn keepalive_declares_a_transport_dead_when_it_cannot_even_open_a_probe() {
    // A refused open plus a whole silent window is, at this layer,
    // observationally identical to a dead transport: substreams that delivered
    // nothing. Reconnecting is the fail-safe reading — but only after the full
    // window, never on the open failure alone.
    let client = piped_client_with_max_streams(StubPeer::Blackhole, 1).await;
    let _hog = open_test_stream(&client.open_tx).await;
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    run_keepalive(client.open_tx.clone(), Arc::clone(&client.inbound_reads)).await;
    assert_eq!(client.inbound_reads.load(Ordering::Relaxed), 0);
    assert!(
        tokio::time::Instant::now() - started >= KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT,
        "a refused open must not short-circuit the window"
    );
}

#[skuld::test]
async fn server_shutdown_is_prompt_while_client_connected() {
    // A connected client keeps the driver live; shutdown must still complete
    // promptly (the driver is aborted, not awaited-to-natural-close).
    let (writer, _g) = capture_logs();
    let upstream = spawn_tcp_responder(b"hi".to_vec()).await;
    let shutdown = CancellationToken::new();
    let (srv_tx, srv_rx) = oneshot::channel();
    let server = tokio::spawn(run_server(
        ::yamux::Config::default(),
        "127.0.0.1:0".parse().unwrap(),
        upstream,
        shutdown.clone(),
        Some(srv_tx),
    ));
    let server_addr = srv_rx.await.expect("server bound");

    let _conn = TcpStream::connect(server_addr).await.expect("connect server");
    wait_for_log(&writer, "accepted underlying connection").await;

    shutdown.cancel();
    server.await.expect("server task joined").expect("run_server ok");
}

/// Fire a one-shot silent black hole on a relay connection.
struct BlackholeHandle {
    tx: Option<oneshot::Sender<()>>,
}
impl BlackholeHandle {
    fn trigger(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

/// A TCP relay in front of `upstream` whose first connection can be silently
/// black-holed: on `trigger()` it stops forwarding both ways but holds both
/// sockets open forever, so neither peer sees a FIN or an RST and neither peer's
/// TCP stack times out (the relay's kernel keeps ACKing). That is strictly
/// harsher than the field condition, where the client's retransmits do
/// eventually abort.
async fn spawn_blackholing_relay(upstream: SocketAddr) -> (SocketAddr, BlackholeHandle) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
    let addr = listener.local_addr().expect("relay addr");
    let (hole_tx, hole_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut trigger = Some(hole_rx);
        while let Ok((client_conn, _)) = listener.accept().await {
            let server_conn = match TcpStream::connect(upstream).await {
                Ok(s) => s,
                Err(_) => continue,
            };
            tokio::spawn(pump_with_optional_blackhole(client_conn, server_conn, trigger.take()));
        }
    });
    (addr, BlackholeHandle { tx: Some(hole_tx) })
}

async fn pump_with_optional_blackhole(
    mut client: TcpStream,
    mut server: TcpStream,
    hole: Option<oneshot::Receiver<()>>,
) {
    match hole {
        Some(rx) => {
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                // `client` and `server` stay alive in this frame, so both
                // sockets stay open: a true silent black hole.
                _ = rx => std::future::pending::<()>().await,
            }
        }
        None => {
            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
        }
    }
}

#[skuld::test]
async fn a_silently_blackholed_session_is_declared_dead() {
    let (writer, _g) = capture_logs_awaitable();
    let upstream = spawn_tcp_responder(HTTP_RESPONSE.to_vec()).await;
    let shutdown = CancellationToken::new();
    let server_addr = spawn_yamux_server(upstream, shutdown.clone()).await;
    let (relay_addr, mut hole) = spawn_blackholing_relay(server_addr).await;
    let (addrs, mut events) = spawn_yamux_client(relay_addr, DEFAULT_UDP_TIMEOUT, shutdown.clone()).await;

    // #1 proves the tunnel works and marks the session productive.
    assert_eq!(
        tcp_round_trip(addrs.tcp, b"GET /1 HTTP/1.0\r\n\r\n").await,
        HTTP_RESPONSE
    );

    hole.trigger();
    // From here nothing but a timer can make progress, so the clock
    // auto-advances to the verdict (see `LogWaiter` for why the rendezvous
    // below must stay in-runtime).
    tokio::time::pause();

    // Productive before the hole, so failures reset to the floor. `run_client`
    // emits this before any backoff or reconnect, so nothing else has started.
    assert_eq!(events.recv().await.unwrap(), (0, true));
    tokio::time::resume();

    // Naming the mechanism: the fatal line is written by `run_keepalive`, which
    // returns before `run_client_session` returns and therefore before the event
    // above — same task, so the ordering is program order, not a race.
    assert!(
        writer.contains("transport silent across the keepalive deadline"),
        "the reconnect must have been caused by the keepalive, not by anything else"
    );

    shutdown.cancel();
}
