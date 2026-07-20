// `CancellationToken::new` is the cancel-test harness root for the E2E relay
// tests; module-level allow per the workspace clippy.toml's sanctioned
// test-file exception (mirrors garter's tap_tests.rs).
#![allow(clippy::disallowed_methods)]

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
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
    next_failures, parse_udp_timeout, run_client, run_server, session_reconnect_backoff, ClientBoundAddrs,
    FrameAccumulator, OpenStreamReply, StreamTag, TransportLivenessTap, DEFAULT_UDP_TIMEOUT, LOOPBACK_CONNECT_RETRY,
    REMOTE_BACKOFF_BASE, REMOTE_BACKOFF_MAX,
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
async fn transport_tap_sets_on_inbound_bytes() {
    use futures::AsyncReadExt as _;
    let productive = Arc::new(AtomicBool::new(false));
    let mut tap = TransportLivenessTap::new(futures::io::Cursor::new(b"data".to_vec()), Arc::clone(&productive));
    let mut buf = [0u8; 8];
    assert_eq!(tap.read(&mut buf).await.unwrap(), 4);
    assert!(productive.load(Ordering::Relaxed));
}

#[skuld::test]
async fn transport_tap_silent_on_eof() {
    use futures::AsyncReadExt as _;
    let productive = Arc::new(AtomicBool::new(false));
    let mut tap = TransportLivenessTap::new(futures::io::Cursor::new(Vec::new()), Arc::clone(&productive));
    let mut buf = [0u8; 8];
    assert_eq!(tap.read(&mut buf).await.unwrap(), 0);
    assert!(!productive.load(Ordering::Relaxed));
}

#[skuld::test]
async fn transport_tap_delegates_writes() {
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    let productive = Arc::new(AtomicBool::new(false));
    let (a, b) = tokio::io::duplex(64);
    let mut tap = TransportLivenessTap::new(a.compat(), Arc::clone(&productive));
    tap.write_all(b"ping").await.unwrap();
    tap.flush().await.unwrap();
    let mut b = b.compat();
    let mut buf = [0u8; 4];
    b.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    assert!(!productive.load(Ordering::Relaxed), "writes never set productive");
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
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut tag = [0u8; 1];
    if stream.read_exact(&mut tag).await.is_err() {
        return;
    }
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
    tokio::time::pause();
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

    // The external assertion: shutdown must win the paused sleep, so the client
    // task returns `Ok` promptly. Without the select! shutdown branch the paused
    // sleep never elapses and this `await` hangs → framework timeout.
    shutdown.cancel();
    client.await.unwrap().unwrap();
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
