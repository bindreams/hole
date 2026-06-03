use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hole_common::config::{DnsConfig, DnsProtocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use super::*;
use crate::dns::connector::DirectConnector;

// SelfTestProbe mocks =================================================================================================

/// Probe that always returns `Ok(())` — skips the post-bind round-trip
/// for tests that want to focus on the rest of `bind_once_with_probe`.
struct AlwaysOkProbe;

#[async_trait]
impl SelfTestProbe for AlwaysOkProbe {
    async fn probe(&self, _socket: &UdpSocket) -> std::io::Result<()> {
        Ok(())
    }
}

/// Probe that always returns `Err` — simulates a loopback hijack so the
/// test can assert that `bind_once_with_probe` propagates the failure.
struct AlwaysFailProbe;

#[async_trait]
impl SelfTestProbe for AlwaysFailProbe {
    async fn probe(&self, _socket: &UdpSocket) -> std::io::Result<()> {
        Err(std::io::Error::other("simulated self-test hijack"))
    }
}

/// Probe that returns `Err` on its first invocation and `Ok` thereafter.
/// Verifies composition: probe `Err` propagates through `bind_once_with_probe`
/// so `bind_ladder` would walk; a subsequent attempt on a different addr
/// succeeds.
struct FailFirstThenOkProbe {
    calls: AtomicUsize,
}

impl FailFirstThenOkProbe {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl SelfTestProbe for FailFirstThenOkProbe {
    async fn probe(&self, _socket: &UdpSocket) -> std::io::Result<()> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            Err(std::io::Error::other("first-call simulated hijack"))
        } else {
            Ok(())
        }
    }
}

fn dummy_forwarder() -> Arc<DnsForwarder> {
    let cfg = DnsConfig {
        enabled: true,
        servers: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))], // TEST-NET-1, unroutable
        protocol: DnsProtocol::PlainUdp,
        intercept_udp53: true,
    };
    Arc::new(DnsForwarder::new(cfg, Arc::new(DirectConnector), true))
}

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

    // The forwarder hard-codes DNS port 53, which CI can't reach without
    // privilege, so this helper points it at an unroutable upstream
    // (TEST-NET-1). Server-layer tests assert on the well-formed SERVFAIL
    // reply; forwarder-layer upstream wiring is covered in forwarder_tests.
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

// SelfTestProbe seam ==================================================================================================

#[skuld::test]
async fn bind_with_probe_returns_err_when_probe_fails() {
    let res = LocalDnsServer::bind_once_with_probe(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        dummy_forwarder(),
        &AlwaysFailProbe,
    )
    .await;
    assert!(res.is_err(), "probe Err must propagate; bind_ladder walks on any Err");
}

#[skuld::test]
async fn bind_with_probe_succeeds_when_probe_returns_ok() {
    let srv = LocalDnsServer::bind_once_with_probe(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        dummy_forwarder(),
        &AlwaysOkProbe,
    )
    .await
    .expect("probe Ok → bind Ok");
    // Round-trip a query through the live listener loop to prove both
    // UDP and TCP are alive after the probe-Ok path.
    let addr = srv.addr();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(addr).await.unwrap();
    let q = sample_query(0xABCD);
    client.send(&q).await.unwrap();
    let mut rbuf = [0u8; 1500];
    let n = timeout(Duration::from_secs(10), client.recv(&mut rbuf))
        .await
        .expect("forwarder responded in time")
        .unwrap();
    assert_eq!(&rbuf[..2], &[0xAB, 0xCD], "tx id preserved");
    assert_eq!(rbuf[3] & 0x0F, 2, "RCODE=SERVFAIL (no upstream reachable)");
    drop(srv);
    let _ = n;
}

#[skuld::test]
async fn probe_invoked_once_per_bind_with_probe_call() {
    // Composition test: probe Err on first invocation, Ok on second.
    // Exercises (1) probe Err propagates through `bind_once_with_probe`
    // (so a real `bind_ladder` would walk), AND (2) probe is called
    // exactly once per `bind_once_with_probe` invocation.
    //
    // Note: this is NOT a test of `bind_ladder`'s walker — that path is
    // not reachable here because `bind_ladder` hardcodes `DefaultProbe`
    // and operates on `127.53.0.X:53` (requires elevation). The walker's
    // info!-vs-debug! log routing predicate is exercised in production
    // through the `SelfTestError` typed downcast (see
    // `crates/bridge/src/dns/server.rs::bind_ladder`).
    let probe = FailFirstThenOkProbe::new();
    let first = LocalDnsServer::bind_once_with_probe(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        dummy_forwarder(),
        &probe,
    )
    .await;
    assert!(first.is_err(), "first probe call returned Err → bind must propagate");
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        1,
        "probe invoked once after first bind"
    );
    let second = LocalDnsServer::bind_once_with_probe(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        dummy_forwarder(),
        &probe,
    )
    .await
    .expect("second probe call returned Ok → bind must succeed");
    drop(second);
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        2,
        "probe invoked once after second bind"
    );
}

// Direct tests for `loopback_udp_self_test` and `build_sentinel` ======================================================

#[skuld::test]
async fn loopback_udp_self_test_succeeds_on_clean_socket() {
    // Healthy path: bind an ephemeral UDP socket on loopback with no
    // contention; the production self-test should succeed in ~microseconds.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let result = loopback_udp_self_test(&socket).await;
    assert!(
        result.is_ok(),
        "self-test must succeed on clean loopback socket: {result:?}"
    );
}

#[skuld::test]
fn build_sentinel_format_has_magic_prefix_and_zero_pad() {
    let s = build_sentinel(0);
    assert_eq!(&s[..4], b"HOLE", "magic prefix");
    assert_eq!(&s[4..8], &[0u8; 4], "must-be-zero pad (DNS-malformed marker)");
}

#[skuld::test]
fn build_sentinel_nonce_distinct_per_attempt() {
    // The nonce mixes wall-clock nanos with the attempt index via
    // rotate_left + XOR. Even when nanos repeat (extremely fast
    // back-to-back calls), the per-attempt mixing must differ. Three
    // attempts back-to-back is the maximum the retry loop uses.
    let s0 = build_sentinel(0);
    let s1 = build_sentinel(1);
    let s2 = build_sentinel(2);
    assert_ne!(s0[8..16], s1[8..16], "attempt 0 vs 1 nonce");
    assert_ne!(s1[8..16], s2[8..16], "attempt 1 vs 2 nonce");
    assert_ne!(s0[8..16], s2[8..16], "attempt 0 vs 2 nonce");
}

#[skuld::test]
async fn self_test_error_downcastable_to_typed_marker() {
    // `bind_ladder`'s info!-vs-debug! routing relies on downcasting the
    // io::Error's source via `e.get_ref().is::<SelfTestError>()`. Verify
    // the production probe's errors actually expose that typed source.
    let probe_err = LocalDnsServer::bind_once_with_probe(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        dummy_forwarder(),
        &AlwaysFailProbe,
    )
    .await;
    let err = match probe_err {
        Err(e) => e,
        Ok(_) => panic!("AlwaysFailProbe must propagate Err"),
    };
    // AlwaysFailProbe uses `io::Error::other("simulated self-test hijack")`
    // — NOT a SelfTestError; this assertion shows the typed downcast is
    // selective (test mock isn't a false positive).
    assert!(
        err.get_ref().and_then(|s| s.downcast_ref::<SelfTestError>()).is_none(),
        "AlwaysFailProbe's untyped Err must NOT downcast to SelfTestError"
    );
    // The production self_test_error helper DOES produce typed errors.
    let typed = self_test_error("test message");
    assert!(
        typed
            .get_ref()
            .and_then(|s| s.downcast_ref::<SelfTestError>())
            .is_some(),
        "self_test_error() must produce a downcastable SelfTestError"
    );
}

// Wildcard-holder coverage note:
//
// A vanilla `SO_REUSEADDR` wildcard bind on `0.0.0.0:P/UDP` does NOT
// reproduce the inbound-routing hijack: per MSDN's Winsock matrix,
// `SO_EXCLUSIVEADDRUSE` on a specific-address bind coexists with a
// `SO_REUSEADDR` wildcard holder (different addresses), so
// `LocalDnsServer::bind(127.0.0.1:P)` returns `Ok`. The hijack (a
// wildcard holder winning inbound routing on `127.0.0.1:53` despite
// Hole's specific bind) comes from kernel-level routing override, not
// the documented matrix. The load-bearing defense is the post-bind
// self-test (verified by `bind_with_probe_returns_err_when_probe_fails`
// + `probe_invoked_once_per_bind_with_probe_call`): the sentinel
// datagram doesn't come back, so `bind_ladder` walks to `127.53.0.X:53`.
// `SO_EXCLUSIVEADDRUSE` is kept as forward-looking defense against a
// FUTURE `SO_REUSEADDR` binder stealing already-bound traffic.
