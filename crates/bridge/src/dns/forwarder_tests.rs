use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use hole_common::config::{DnsConfig, DnsProtocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use super::*;
use crate::dns::connector::DirectConnector;
use crate::test_support::refusing_connector::{RefusingConnector, SilentConnector};

// Helpers =============================================================================================================

/// Build a minimal well-formed DNS query for the name `example.com.` A.
/// Wire format:
///   [id:2][flags:2 = 0x0100][qdcount:2 = 1][an=0][ns=0][ar=0]
///   name: 7 "example" 3 "com" 0
///   qtype=A(1), qclass=IN(1)
fn sample_query(tx_id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&tx_id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    q.push(7);
    q.extend_from_slice(b"example");
    q.push(3);
    q.extend_from_slice(b"com");
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    q
}

/// Build a DNS reply that echoes the query's id + question and adds a
/// single A record pointing at 93.184.216.34 (the historical example.com).
fn sample_reply(query: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(64);
    r.extend_from_slice(&query[..2]); // id
    r.extend_from_slice(&[0x81, 0x80]); // flags: QR=1, RD=1, RA=1
    r.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    r.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // echo question from byte 12 onwards
    r.extend_from_slice(&query[12..]);
    // answer: name pointer to offset 12, type A, class IN, TTL 60, rdlen 4, IP
    r.extend_from_slice(&[0xc0, 0x0c]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&60_u32.to_be_bytes());
    r.extend_from_slice(&[0x00, 0x04]);
    r.extend_from_slice(&[93, 184, 216, 34]);
    r
}

async fn start_udp_stub(reply_bytes: Option<Vec<u8>>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
            return;
        };
        if let Some(reply) = reply_bytes {
            let _ = sock.send_to(&reply, peer).await;
        } else {
            // emulate "dead" server: echo answer shape based on query
            let reply = sample_reply(&buf[..n]);
            let _ = sock.send_to(&reply, peer).await;
        }
    });
    (addr, h)
}

async fn start_tcp_stub(reply: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return;
        }
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut q = vec![0u8; n];
        if stream.read_exact(&mut q).await.is_err() {
            return;
        }
        let reply = if reply.is_empty() { sample_reply(&q) } else { reply };
        let len = (reply.len() as u16).to_be_bytes();
        let _ = stream.write_all(&len).await;
        let _ = stream.write_all(&reply).await;
    });
    (addr, h)
}

/// Loopback address for a server the [`RefusingConnector`] will reject. The
/// port is never dialled, so any value works; distinct values keep multi-server
/// configs readable.
fn dead_addr(n: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000 + n)
}

fn build_cfg(protocol: DnsProtocol, servers: Vec<IpAddr>) -> DnsConfig {
    DnsConfig {
        enabled: true,
        servers,
        protocol,
        allow_insecure_bootstrap: false,
    }
}

// SERVFAIL synthesis ==================================================================================================

#[skuld::test]
fn servfail_preserves_transaction_id() {
    let q = sample_query(0xABCD);
    let r = synthesize_servfail(&q);
    assert_eq!(&r[..2], &[0xAB, 0xCD]);
}

#[skuld::test]
fn servfail_sets_qr_ra_and_rcode() {
    let q = sample_query(0x0001);
    let r = synthesize_servfail(&q);
    assert_eq!(r[2] & 0x80, 0x80, "QR bit set");
    assert_eq!(r[3] & 0x80, 0x80, "RA bit set");
    assert_eq!(r[3] & 0x0F, 2, "RCODE = SERVFAIL");
}

#[skuld::test]
fn servfail_zeroes_answer_authority_additional_counts() {
    let q = sample_query(0x0001);
    let r = synthesize_servfail(&q);
    assert_eq!(&r[6..8], &[0, 0]);
    assert_eq!(&r[8..10], &[0, 0]);
    assert_eq!(&r[10..12], &[0, 0]);
}

#[skuld::test]
fn servfail_preserves_question_section() {
    let q = sample_query(0x1234);
    let r = synthesize_servfail(&q);
    // Header(12) + question echoed verbatim.
    assert_eq!(&r[12..], &q[12..]);
}

#[skuld::test]
fn servfail_handles_short_input() {
    let short = b"\x12\x34"; // only the tx id
    let r = synthesize_servfail(short);
    assert!(r.len() >= 12);
    assert_eq!(&r[..2], &[0x12, 0x34]);
    assert_eq!(r[3] & 0x0F, 2);
}

// Forward: UDP ========================================================================================================

#[skuld::test]
async fn plain_udp_primary_succeeds() {
    let q = sample_query(0x0042);
    let (addr, _h) = start_udp_stub(None).await;
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainUdp, vec![addr.ip()]),
        Arc::new(DirectConnector),
        true,
        vec![addr.port()],
    );
    let reply = fwd.forward(&q).await;
    assert_eq!(&reply[..2], &[0x00, 0x42], "tx id echoed");
    assert_eq!(reply[2] & 0x80, 0x80, "QR set (real reply, not SERVFAIL)");
    assert_ne!(reply[3] & 0x0F, 2, "RCODE is not SERVFAIL");
}

#[skuld::test]
async fn primary_fails_secondary_succeeds() {
    // Failover is in `try_forward`'s server loop, not in any one transport.
    // The primary is refused by the connector rather than by the OS, so the
    // premise cannot drift with the platform; the secondary is a real stub.
    let q = sample_query(0x0001);
    let dead_addr = dead_addr(0);
    let (live_addr, _h) = start_tcp_stub(Vec::new()).await;
    // The refuse list matches by exact SocketAddr and the stub's port is
    // kernel-assigned, so pin the premise: a collision would refuse the
    // secondary too and read as a failover regression.
    assert_ne!(
        live_addr, dead_addr,
        "the refuse list must not swallow the live secondary"
    );

    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainTcp, vec![dead_addr.ip(), live_addr.ip()]),
        RefusingConnector::only(vec![dead_addr]),
        true,
        vec![dead_addr.port(), live_addr.port()],
    );
    let reply = fwd.forward(&q).await;
    assert_eq!(&reply[..2], &[0x00, 0x01], "tx id echoed by the secondary");
    assert_ne!(reply[3] & 0x0F, 2, "secondary succeeded, not SERVFAIL");
    // Both servers are 127.0.0.1, so one throttle entry — and it exists only
    // because an attempt FAILED. Pins the premise: the primary really did fail.
    let map = fwd.failure_throttle.lock().unwrap();
    let state = map.get(&dead_addr.ip()).expect("the primary must have failed");
    assert!(state.logged >= 1, "the primary must have failed");
}

#[skuld::test]
async fn all_servers_fail_returns_servfail() {
    let q = sample_query(0x5678);
    let s1 = dead_addr(0);
    let s2 = dead_addr(1);
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainTcp, vec![s1.ip(), s2.ip()]),
        RefusingConnector::all(),
        true,
        vec![s1.port(), s2.port()],
    );
    let reply = fwd.forward(&q).await;
    assert_eq!(reply[3] & 0x0F, 2, "RCODE=SERVFAIL");
    assert_eq!(&reply[..2], &[0x56, 0x78]);
}

#[skuld::test]
async fn try_forward_reports_unreachable_when_every_server_refuses() {
    let q = sample_query(0x5678);
    let s1 = dead_addr(0);
    let s2 = dead_addr(1);
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainTcp, vec![s1.ip(), s2.ip()]),
        RefusingConnector::all(),
        true,
        vec![s1.port(), s2.port()],
    );
    assert_eq!(
        fwd.try_forward(&q, UPSTREAM_TIMEOUT).await,
        Err(ForwardFailure::Upstream(UpstreamCause::Unreachable))
    );
}

#[skuld::test]
fn attempted_upstreams_counts_only_the_servers_a_walk_will_dial() {
    // A caller sizing a per-upstream budget from a total must divide by the
    // width the walk ACTUALLY dials. Counting skipped IPv6 entries would shrink
    // every surviving upstream's budget and leave part of the total unused.
    let v4: IpAddr = "1.1.1.1".parse().unwrap();
    let v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();

    let cfg = |servers: Vec<IpAddr>| build_cfg(DnsProtocol::Https, servers);
    let width = |servers: Vec<IpAddr>, v6_ok: bool| {
        DnsForwarder::new(cfg(servers), RefusingConnector::all(), v6_ok).attempted_upstreams()
    };

    assert_eq!(width(vec![v4, v6], false), 1, "the IPv6 entry is skipped");
    assert_eq!(width(vec![v4, v6], true), 2, "with a bypass both are dialled");
    assert_eq!(width(vec![v6], false), 0, "an all-IPv6 config dials nothing");
    assert_eq!(width(vec![v4, v4], false), 2, "duplicates are separate attempts");
}

#[skuld::test]
async fn try_forward_reports_malformed_query_and_no_upstream() {
    let (addr, _h) = start_udp_stub(None).await;
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainUdp, vec![addr.ip()]),
        Arc::new(DirectConnector),
        true,
        vec![addr.port()],
    );
    assert_eq!(
        fwd.try_forward(b"abc", UPSTREAM_TIMEOUT).await,
        Err(ForwardFailure::MalformedQuery)
    );

    // Every configured server skipped (IPv6 with no IPv6 bypass) — nothing was
    // attempted, which is not the same as an upstream failing.
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let none = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainUdp, vec![v6]),
        Arc::new(DirectConnector),
        false,
        vec![0],
    );
    assert_eq!(
        none.try_forward(&sample_query(1), UPSTREAM_TIMEOUT).await,
        Err(ForwardFailure::NoUpstream)
    );
}

#[skuld::test]
async fn try_forward_reports_tls_failed_when_the_peer_closes_mid_handshake() {
    // Accept, then close gracefully (FIN, not RST — an RST races connect() on
    // Linux/macOS loopback). tokio-rustls reports an unclean EOF with no rustls
    // error attached: TlsFailed, not CertificateRejected.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            drop(tcp);
        }
    });
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::Https, vec![addr.ip()]),
        Arc::new(DirectConnector),
        true,
        vec![addr.port()],
    );
    assert_eq!(
        fwd.try_forward(&sample_query(0x0009), UPSTREAM_TIMEOUT).await,
        Err(ForwardFailure::Upstream(UpstreamCause::TlsFailed))
    );
}

/// Accept one connection, signal it, and never write. Returns the address and
/// a receiver that fires once the connection is ESTABLISHED — a real
/// rendezvous, so the timeout tests advance virtual time only after the
/// connect has completed rather than racing it.
async fn silent_tcp_peer() -> (SocketAddr, tokio::sync::oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = accepted_tx.send(());
        std::future::pending::<()>().await;
        drop(tcp);
    });
    (addr, accepted_rx)
}

#[skuld::test]
async fn try_forward_reports_timeout_when_an_established_peer_stays_silent() {
    let (addr, accepted_rx) = silent_tcp_peer().await;
    let fwd = Arc::new(DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainTcp, vec![addr.ip()]),
        Arc::new(DirectConnector),
        true,
        vec![addr.port()],
    ));
    let call = tokio::spawn({
        let fwd = Arc::clone(&fwd);
        async move { fwd.try_forward(&sample_query(0x000A), UPSTREAM_TIMEOUT).await }
    });

    accepted_rx.await.expect("stub accepted the connection");
    tokio::time::pause();

    assert_eq!(
        call.await.unwrap(),
        Err(ForwardFailure::Upstream(UpstreamCause::Timeout))
    );
}

// Forward: TCP ========================================================================================================

#[skuld::test]
async fn plain_tcp_primary_succeeds() {
    let q = sample_query(0x00AA);
    let (addr, _h) = start_tcp_stub(Vec::new()).await;
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainTcp, vec![addr.ip()]),
        Arc::new(DirectConnector),
        true,
        vec![addr.port()],
    );
    let reply = fwd.forward(&q).await;
    assert_eq!(&reply[..2], &[0x00, 0xAA]);
    assert_eq!(reply[2] & 0x80, 0x80);
    assert_ne!(reply[3] & 0x0F, 2);
}

// IPv6 skip ===========================================================================================================

#[skuld::test]
async fn ipv6_upstream_skipped_when_no_v6_bypass() {
    let q = sample_query(0x0003);
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let (v4_addr, _h) = start_udp_stub(None).await;
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainUdp, vec![v6, v4_addr.ip()]),
        Arc::new(DirectConnector),
        false, // no v6 bypass
        vec![0, v4_addr.port()],
    );
    let reply = fwd.forward(&q).await;
    // The v6 server was skipped; v4 answered.
    assert_ne!(reply[3] & 0x0F, 2);
}

// Throttle ============================================================================================================

#[skuld::test]
async fn duplicate_server_in_list_creates_one_throttle_entry() {
    // Two identical dead addresses share one per-IP throttle entry; a
    // single failure burst against the same server doesn't duplicate
    // state across the map.
    let dead_addr = dead_addr(0);
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainTcp, vec![dead_addr.ip(), dead_addr.ip()]),
        RefusingConnector::all(),
        true,
        vec![dead_addr.port(), dead_addr.port()],
    );
    let q = sample_query(0x0001);
    let _ = fwd.forward(&q).await;
    let map = fwd.failure_throttle.lock().unwrap();
    assert_eq!(map.len(), 1, "duplicate server has one throttle entry");
    let state = map.get(&dead_addr.ip()).expect("throttle entry exists");
    // Both attempts were below the full-limit, so both were logged in
    // full — but `suppressed` remains 0 since we never crossed the
    // limit.
    assert_eq!(state.logged, 2, "both attempts counted as logged");
    assert_eq!(state.suppressed, 0, "under limit, nothing suppressed");
}

#[skuld::test]
async fn throttle_logs_first_n_then_suppresses() {
    // Pins the per-server log throttle: the first LOG_FULL_LIMIT=3
    // failures log in full, subsequent ones are counted as suppressed
    // (never silently dedup-forever).
    let dead_addr = dead_addr(0);
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainTcp, vec![dead_addr.ip()]),
        RefusingConnector::all(),
        true,
        vec![dead_addr.port()],
    );
    let q = sample_query(0x0002);
    // 5 attempts against the same server.
    for _ in 0..5 {
        let _ = fwd.forward(&q).await;
    }
    let map = fwd.failure_throttle.lock().unwrap();
    let state = map.get(&dead_addr.ip()).expect("throttle entry exists");
    assert_eq!(state.logged, LOG_FULL_LIMIT, "first LOG_FULL_LIMIT logged in full");
    assert_eq!(state.suppressed, 5 - LOG_FULL_LIMIT, "remainder suppressed");
}

// Error-chain errno extraction ========================================================================================

#[skuld::test]
fn first_os_errno_walks_nested_io_error() {
    // Simulate the tokio-rustls shape: outer io::Error wrapping an
    // inner io::Error that carries a raw_os_error (as rustls would from
    // a real ECONNRESET on the underlying stream).
    let inner = io::Error::from_raw_os_error(10054); // WSAECONNRESET
    let outer = io::Error::other(inner);
    assert_eq!(first_os_errno(&outer), Some(10054));
}

#[skuld::test]
fn first_os_errno_returns_none_for_pure_custom_error() {
    // tokio-rustls's `tls handshake eof` is a Custom error with no
    // inner raw_os_error — represents a graceful FIN, not an RST.
    let e = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
    assert_eq!(first_os_errno(&e), None);
}

// Rustls-error extraction + cause classification ======================================================================

#[skuld::test]
fn first_rustls_error_found_through_tokio_rustls_wrapper() {
    // tokio-rustls's exact wrap shape — see first_rustls_error's doc.
    let inner = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
    let outer = io::Error::new(io::ErrorKind::InvalidData, inner.clone());
    assert_eq!(first_rustls_error(&outer), Some(&inner));
}

#[skuld::test]
fn first_rustls_error_is_none_for_plain_socket_error() {
    let e = io::Error::from_raw_os_error(10054); // WSAECONNRESET
    assert_eq!(first_rustls_error(&e), None);
}

#[skuld::test]
fn cause_of_tls_layer_with_a_trust_chain_rejection_is_certificate_rejected() {
    // Both trust-rejection families, not just the UnknownIssuer one.
    for rustls_err in [
        rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature),
        rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked),
        rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownRevocationStatus),
        rustls::Error::InvalidCertRevocationList(rustls::CertRevocationListError::BadSignature),
    ] {
        let e = UpstreamErr::new(
            UpstreamLayer::Tls,
            io::Error::new(io::ErrorKind::InvalidData, rustls_err.clone()),
        );
        assert_eq!(e.cause(), UpstreamCause::CertificateRejected, "{rustls_err:?}");
    }
}

#[skuld::test]
fn cause_of_a_non_trust_certificate_complaint_is_not_certificate_rejected() {
    // The non-trust CertificateError variants `is_trust_chain_rejection`'s doc
    // explains must not be reported as interception: they come from the user's
    // own config or clock, not the network.
    for rustls_err in [
        // A CRL we merely could not parse is a fault in material we supply, not
        // an interceptor's doing — it must not inherit the interception claim.
        rustls::Error::InvalidCertRevocationList(rustls::CertRevocationListError::ParseError),
        rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName),
        rustls::Error::InvalidCertificate(rustls::CertificateError::Expired),
        rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidYet),
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding),
    ] {
        let e = UpstreamErr::new(
            UpstreamLayer::Tls,
            io::Error::new(io::ErrorKind::InvalidData, rustls_err.clone()),
        );
        assert_eq!(e.cause(), UpstreamCause::TlsFailed, "{rustls_err:?}");
    }
}

#[skuld::test]
fn cause_of_tls_layer_without_cert_error_is_tls_failed() {
    // tokio-rustls's unclean-EOF shape: a Custom error carrying no rustls error.
    let e = UpstreamErr::new(
        UpstreamLayer::Tls,
        io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof"),
    );
    assert_eq!(e.cause(), UpstreamCause::TlsFailed);
}

#[skuld::test]
fn cause_of_tls_layer_with_a_non_certificate_rustls_error_is_tls_failed() {
    // The other half of the catch-all arm: a rustls error IS present, it just
    // isn't about certificate trust. Covered separately from the no-rustls-error
    // case so a future edit cannot change one without the suite noticing.
    let e = UpstreamErr::new(
        UpstreamLayer::Tls,
        io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::PeerIncompatible(rustls::PeerIncompatible::NoCipherSuitesInCommon),
        ),
    );
    assert_eq!(e.cause(), UpstreamCause::TlsFailed);
}

#[skuld::test]
fn cause_of_non_tls_layers_follows_the_layer_tag() {
    let refused = UpstreamErr::new(
        UpstreamLayer::Connect,
        io::Error::from(io::ErrorKind::ConnectionRefused),
    );
    assert_eq!(refused.cause(), UpstreamCause::Unreachable);
    let timed_out = UpstreamErr::new(
        UpstreamLayer::Timeout,
        io::Error::new(io::ErrorKind::TimedOut, "upstream timeout"),
    );
    assert_eq!(timed_out.cause(), UpstreamCause::Timeout);
    let http = UpstreamErr::new(UpstreamLayer::Http, io::Error::other("non-200 DoH response"));
    assert_eq!(http.cause(), UpstreamCause::BadResponse);
    let io_err = UpstreamErr::new(UpstreamLayer::Io, io::Error::from(io::ErrorKind::BrokenPipe));
    assert_eq!(io_err.cause(), UpstreamCause::Io);
}

#[skuld::test]
fn upstream_cause_ranking_is_total_and_ordered() {
    // Pins the total order `rank` promises across every UpstreamCause variant.
    let order = [
        UpstreamCause::Unreachable,
        UpstreamCause::Timeout,
        UpstreamCause::Io,
        UpstreamCause::BadResponse,
        UpstreamCause::TlsFailed,
        UpstreamCause::CertificateRejected,
    ];
    for pair in order.windows(2) {
        assert!(
            pair[1].rank() > pair[0].rank(),
            "{:?} must outrank {:?}",
            pair[1],
            pair[0]
        );
    }
}

// Short-query safety ==================================================================================================

#[skuld::test]
async fn forward_on_short_query_returns_servfail() {
    let short = b"abc"; // below 12-byte DNS header
    let (addr, _h) = start_udp_stub(None).await;
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainUdp, vec![addr.ip()]),
        Arc::new(DirectConnector),
        true,
        vec![addr.port()],
    );
    let reply = fwd.forward(short).await;
    assert!(reply.len() >= 12);
    assert_eq!(reply[3] & 0x0F, 2);
}

// URL split helpers (whitebox) ========================================================================================

#[skuld::test]
fn split_https_url_recovers_host_and_path() {
    let (h, p) = split_https_url("https://cloudflare-dns.com/dns-query").unwrap();
    assert_eq!(h, "cloudflare-dns.com");
    assert_eq!(p, "/dns-query");
}

#[skuld::test]
fn split_https_url_rejects_non_https() {
    assert!(split_https_url("http://foo/bar").is_err());
}

#[skuld::test]
fn https_target_for_known_ip_uses_hostname_sni() {
    let v4: IpAddr = "1.1.1.1".parse().unwrap();
    let (name, (host, path)) = https_target_for(v4).unwrap();
    assert_eq!(host, "cloudflare-dns.com");
    assert_eq!(path, "/dns-query");
    match name {
        ServerName::DnsName(dns) => assert_eq!(dns.as_ref(), "cloudflare-dns.com"),
        other => panic!("expected DnsName SNI, got {other:?}"),
    }
}

#[skuld::test]
fn https_target_for_unknown_ip_uses_literal() {
    let v4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let (name, (host, path)) = https_target_for(v4).unwrap();
    assert_eq!(host, "192.0.2.1");
    assert_eq!(path, "/dns-query");
    match name {
        ServerName::IpAddress(_) => {}
        other => panic!("expected IP SNI, got {other:?}"),
    }
}

#[skuld::test]
fn https_target_for_unknown_ipv6_brackets_host() {
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let (_name, (host, _path)) = https_target_for(v6).unwrap();
    assert_eq!(host, "[2001:db8::1]");
}

#[skuld::test]
fn tls_server_name_known_ip() {
    let v4: IpAddr = "8.8.8.8".parse().unwrap();
    match tls_server_name_for(v4).unwrap() {
        ServerName::DnsName(n) => assert_eq!(n.as_ref(), "dns.google"),
        _ => panic!("expected DnsName"),
    }
}

#[skuld::test]
fn tls_server_name_unknown_ip() {
    let v4: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    match tls_server_name_for(v4).unwrap() {
        ServerName::IpAddress(_) => {}
        _ => panic!("expected IpAddress"),
    }
}

// HTTP response parsing ===============================================================================================

#[skuld::test]
fn parse_http_dns_rejects_non_200() {
    let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    assert!(parse_http_dns_response(resp).is_err());
}

#[skuld::test]
fn parse_http_dns_extracts_body() {
    let body: &[u8] = b"\x12\x34\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00";
    let mut resp = Vec::new();
    resp.extend_from_slice(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    resp.extend_from_slice(body);
    let out = parse_http_dns_response(&resp).unwrap();
    assert_eq!(out, body);
}

#[skuld::test]
fn parse_http_dns_rejects_wrong_content_type() {
    let body: &[u8] = b"hi";
    let mut resp = Vec::new();
    resp.extend_from_slice(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    resp.extend_from_slice(body);
    assert!(parse_http_dns_response(&resp).is_err());
}

#[skuld::test]
fn parse_http_dns_rejects_missing_content_length() {
    let resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\nbody";
    assert!(parse_http_dns_response(resp).is_err());
}

#[skuld::test]
fn parse_http_dns_rejects_oversize_content_length() {
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
        MAX_REPLY_SIZE + 1
    );
    assert!(parse_http_dns_response(resp.as_bytes()).is_err());
}

// Question-section parsing ============================================================================================

#[skuld::test]
fn question_end_normal_name() {
    // 7 example 3 com 0 + qtype(2) + qclass(2) = 17 bytes
    let q = b"\x07example\x03com\x00\x00\x01\x00\x01";
    assert_eq!(question_end(q), Some(q.len()));
}

#[skuld::test]
fn question_end_rejects_truncated() {
    let q = b"\x07example"; // no null terminator
    assert!(question_end(q).is_none());
}

// Typed upstream errors + source-chain logging ========================================================================
//
// These tests assert the `layer=...`, `elapsed_ms=...`, `caused_by=...`
// fields on the "upstream failed" warn log line, so connect-layer,
// TLS-layer, IO-layer, and timeout failures are distinguishable rather
// than all collapsing to a bare `tls handshake eof`.

#[cfg(test)]
mod typed_error_logs {
    use super::*;
    use crate::test_support::log_capture::VecWriter;
    use garter::tracing_test::set_default_in_current_thread;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    /// Closed TCP upstream + PlainTcp protocol → the "upstream failed" log
    /// line must include `layer=connect` and `elapsed_ms=<n>`, so Phase 2
    /// observation can tell connect-level failures from mid-stream ones.
    #[skuld::test]
    async fn closed_tcp_upstream_logs_connect_layer_and_elapsed_ms() {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        let _guard = set_default_in_current_thread(subscriber);

        let dead = dead_addr(0);
        let fwd = DnsForwarder::new_with_ports(
            build_cfg(DnsProtocol::PlainTcp, vec![dead.ip()]),
            RefusingConnector::all(),
            true,
            vec![dead.port()],
        );
        let _ = fwd.forward(&sample_query(0x0001)).await;

        let output = writer.snapshot_string();
        assert!(
            output.contains("upstream failed"),
            "expected 'upstream failed' log; got:\n{output}"
        );
        assert!(
            output.contains("layer=connect"),
            "expected 'layer=connect'; got:\n{output}"
        );
        assert!(output.contains("elapsed_ms"), "expected 'elapsed_ms'; got:\n{output}");
    }

    /// The `caused_by` field must surface `std::error::Error::source()` so
    /// Phase 2 sees the underlying error kind (e.g. `ConnectionRefused`)
    /// not just the outer display message.
    #[skuld::test]
    async fn upstream_failure_log_includes_caused_by_chain() {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        let _guard = set_default_in_current_thread(subscriber);

        let dead = dead_addr(0);
        let fwd = DnsForwarder::new_with_ports(
            build_cfg(DnsProtocol::PlainTcp, vec![dead.ip()]),
            RefusingConnector::all(),
            true,
            vec![dead.port()],
        );
        let _ = fwd.forward(&sample_query(0x0002)).await;

        let output = writer.snapshot_string();
        assert!(
            output.contains("caused_by"),
            "expected 'caused_by' field in log; got:\n{output}"
        );
    }

    /// TCP stub that accepts then closes immediately → forwarder sees EOF
    /// while reading the framed reply. With `PlainTcp`, this is the `Io`
    /// layer (not `Connect` — we got past the connect, we hit an EOF on
    /// read).
    #[skuld::test]
    async fn tcp_accept_then_close_logs_io_layer() {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        let _guard = set_default_in_current_thread(subscriber);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _h = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        let fwd = DnsForwarder::new_with_ports(
            build_cfg(DnsProtocol::PlainTcp, vec![addr.ip()]),
            Arc::new(DirectConnector),
            true,
            vec![addr.port()],
        );
        let _ = fwd.forward(&sample_query(0x0003)).await;

        let output = writer.snapshot_string();
        assert!(
            output.contains("layer=io"),
            "expected 'layer=io' for EOF mid-exchange; got:\n{output}"
        );
    }

    /// `forward`'s short-query guard exists to keep untrusted local traffic
    /// away from `try_forward`'s malformed-query WARN, which sits OUTSIDE the
    /// per-server throttle. `LocalDnsEndpoint` calls `forward` once per
    /// intercepted UDP/53 datagram, so without the guard any local process
    /// could flood `bridge.log` one line per datagram. Deleting the guard keeps
    /// every byte-level assertion passing, so this is the only thing pinning it.
    #[skuld::test]
    async fn forward_does_not_log_for_a_short_query_but_try_forward_does() {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        let _guard = set_default_in_current_thread(subscriber);

        let fwd = DnsForwarder::new_with_ports(
            build_cfg(DnsProtocol::PlainUdp, vec![dead_addr(0).ip()]),
            RefusingConnector::all(),
            true,
            vec![dead_addr(0).port()],
        );

        let reply = fwd.forward(b"abc").await;
        assert_eq!(reply[3] & 0x0F, 2, "still SERVFAIL");
        assert_eq!(
            writer.snapshot_string(),
            "",
            "the in-TUN datagram path must not log per malformed datagram"
        );

        // The same input through `try_forward` DOES warn: a caller that
        // consumes the typed error is our own code, and a caller bug there
        // should be visible.
        let _ = fwd.try_forward(b"abc", UPSTREAM_TIMEOUT).await;
        assert!(
            writer.snapshot_string().contains("shorter than the header"),
            "try_forward must warn; got:\n{}",
            writer.snapshot_string()
        );
    }

    /// A caller-supplied budget must reach `forward_one` AND still produce the
    /// `upstream failed` WARN. `budget_ms` is stamped inside `forward_one` from
    /// the deadline it actually applied, so asserting it discriminates a
    /// honored budget from an ignored one without measuring elapsed time — the
    /// virtual clock's quantisation and the real time spent connecting make any
    /// exact elapsed-span assertion a race, not a measurement.
    #[skuld::test]
    async fn expired_caller_budget_still_logs_the_upstream_failure() {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        let _guard = set_default_in_current_thread(subscriber);

        const CALLER_BUDGET: Duration = Duration::from_millis(1500);
        assert!(CALLER_BUDGET < UPSTREAM_TIMEOUT, "the budget must be the tighter one");

        let (addr, accepted_rx) = super::silent_tcp_peer().await;
        let fwd = Arc::new(DnsForwarder::new_with_ports(
            build_cfg(DnsProtocol::PlainTcp, vec![addr.ip()]),
            Arc::new(DirectConnector),
            true,
            vec![addr.port()],
        ));
        let call = tokio::spawn({
            let fwd = Arc::clone(&fwd);
            async move { fwd.try_forward(&sample_query(0x000C), CALLER_BUDGET).await }
        });
        accepted_rx.await.expect("stub accepted the connection");
        tokio::time::pause();
        let result = call.await.unwrap();

        assert_eq!(result, Err(ForwardFailure::Upstream(UpstreamCause::Timeout)));
        let output = writer.snapshot_string();
        assert!(
            output.contains("upstream failed"),
            "an expired budget must still log; got:\n{output}"
        );
        assert!(
            output.contains("layer=timeout"),
            "expected 'layer=timeout'; got:\n{output}"
        );
        assert!(
            output.contains("cause=timeout"),
            "expected 'cause=timeout'; got:\n{output}"
        );
        assert!(
            output.contains("budget_ms=1500"),
            "the log must report the budget in force, not the default; got:\n{output}"
        );
    }

    /// Install a WARN-capturing subscriber and return its buffer.
    fn warn_capture() -> (VecWriter, tracing::subscriber::DefaultGuard) {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        let guard = set_default_in_current_thread(subscriber);
        (writer, guard)
    }

    /// A budget that fires mid-attempt must still report the bytes the attempt
    /// had already moved — see [`AttemptProbe`].
    #[skuld::test]
    async fn a_timed_out_attempt_reports_the_bytes_it_had_already_moved() {
        let (writer, _guard) = warn_capture();

        let (connector, connected_rx) = SilentConnector::new();
        let fwd = Arc::new(DnsForwarder::new(
            build_cfg(DnsProtocol::PlainTcp, vec!["127.0.0.1".parse().unwrap()]),
            connector,
            true,
        ));
        let call = tokio::spawn({
            let fwd = Arc::clone(&fwd);
            async move { fwd.try_forward(&sample_query(0x000D), UPSTREAM_TIMEOUT).await }
        });
        connected_rx.await.expect("the stub connector completed a connect");
        tokio::time::pause();
        assert_eq!(
            call.await.unwrap(),
            Err(ForwardFailure::Upstream(UpstreamCause::Timeout))
        );

        let output = writer.snapshot_string();
        assert!(
            output.contains("layer=timeout"),
            "expected 'layer=timeout'; got:\n{output}"
        );
        // The query was framed and written before the peer went silent.
        assert!(
            output.contains("tcp_wrote=Some("),
            "a timed-out attempt must report what it wrote; got:\n{output}"
        );
        assert!(
            output.contains("tcp_read=Some(0)"),
            "the peer sent nothing, and that must be a measured 0, not None; got:\n{output}"
        );
        assert!(
            output.contains("socks5_ms=Some("),
            "the connect completed, so its duration is known; got:\n{output}"
        );
    }

    /// A handshake that was in flight when the budget fired reports how long it
    /// had been running — the TLS/DoH half of the same guarantee.
    #[skuld::test]
    async fn a_cancelled_tls_handshake_reports_how_long_it_ran() {
        let (writer, _guard) = warn_capture();

        let (connector, connected_rx) = SilentConnector::new();
        let fwd = Arc::new(DnsForwarder::new(
            build_cfg(DnsProtocol::Tls, vec!["127.0.0.1".parse().unwrap()]),
            connector,
            true,
        ));
        let call = tokio::spawn({
            let fwd = Arc::clone(&fwd);
            async move { fwd.try_forward(&sample_query(0x000F), UPSTREAM_TIMEOUT).await }
        });
        connected_rx.await.expect("the stub connector completed a connect");
        tokio::time::pause();
        assert_eq!(
            call.await.unwrap(),
            Err(ForwardFailure::Upstream(UpstreamCause::Timeout))
        );

        let output = writer.snapshot_string();
        assert!(
            output.contains("layer=timeout"),
            "expected 'layer=timeout'; got:\n{output}"
        );
        assert!(
            output.contains("tls_ms=Some("),
            "a handshake in flight at the deadline must report its duration; got:\n{output}"
        );
        // rustls wrote its ClientHello into the tunnel and got nothing back.
        assert!(output.contains("tcp_read=Some(0)"), "got:\n{output}");
    }

    /// A timed-out DATAGRAM attempt reports its own counts. UDP opens no
    /// stream, so all-`None` here would read as "never sent anything".
    #[skuld::test]
    async fn a_timed_out_udp_attempt_reports_its_datagram_counts() {
        let (writer, _guard) = warn_capture();

        let (connector, connected_rx) = SilentConnector::new();
        let fwd = Arc::new(DnsForwarder::new(
            build_cfg(DnsProtocol::PlainUdp, vec!["127.0.0.1".parse().unwrap()]),
            connector,
            true,
        ));
        let call = tokio::spawn({
            let fwd = Arc::clone(&fwd);
            async move { fwd.try_forward(&sample_query(0x0010), UPSTREAM_TIMEOUT).await }
        });
        connected_rx.await.expect("the stub connector completed a connect");
        tokio::time::pause();
        assert_eq!(
            call.await.unwrap(),
            Err(ForwardFailure::Upstream(UpstreamCause::Timeout))
        );

        let output = writer.snapshot_string();
        assert!(
            output.contains("layer=timeout"),
            "expected 'layer=timeout'; got:\n{output}"
        );
        assert!(
            output.contains("udp_sent=Some("),
            "the datagram left before the deadline; got:\n{output}"
        );
        assert!(
            output.contains("udp_received=Some(0)"),
            "nothing came back, measured; got:\n{output}"
        );
    }
}

// Cumulative upstream byte totals =====================================================================================

#[skuld::test]
async fn upstream_activity_accumulates_across_a_timed_out_walk() {
    let (connector, connected_rx) = SilentConnector::new();
    let fwd = Arc::new(DnsForwarder::new(
        build_cfg(DnsProtocol::PlainTcp, vec!["127.0.0.1".parse().unwrap()]),
        connector,
        true,
    ));
    let before = fwd.upstream_activity();
    assert_eq!(before, UpstreamActivity::default());

    let call = tokio::spawn({
        let fwd = Arc::clone(&fwd);
        async move { fwd.try_forward(&sample_query(0x000E), UPSTREAM_TIMEOUT).await }
    });
    connected_rx.await.expect("the stub connector completed a connect");
    tokio::time::pause();
    assert_eq!(
        call.await.unwrap(),
        Err(ForwardFailure::Upstream(UpstreamCause::Timeout))
    );

    let moved = fwd.upstream_activity().since(before);
    assert!(
        moved.written > 0,
        "the query was written into the tunnel; got {moved:?}"
    );
    assert_eq!(moved.read, 0, "the peer answered nothing; got {moved:?}");
}

/// A connection the upstream accepts and then resets before the first write
/// moves no bytes, but it IS a connection — the reading has to say so, or a
/// caller reads zero bytes as "nothing was ever opened".
#[skuld::test]
async fn a_connection_reset_before_the_first_write_still_counts_as_established() {
    // Accept, then close gracefully. `exchange_tcp_framed`'s write can fail
    // before `CountingStream` counts a byte.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            drop(tcp);
        }
    });
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainTcp, vec![addr.ip()]),
        Arc::new(DirectConnector),
        true,
        vec![addr.port()],
    );
    let before = fwd.upstream_activity();
    let _ = fwd.try_forward(&sample_query(0x0011), UPSTREAM_TIMEOUT).await;
    let moved = fwd.upstream_activity().since(before);
    assert_eq!(moved.connects, 1, "the connect completed; got {moved:?}");
    assert_eq!(moved.read, 0, "the peer sent nothing; got {moved:?}");
}

/// UDP has no stream — pins that `upstream_activity` measures it too, per
/// [`AttemptProbe`].
#[skuld::test]
async fn upstream_activity_counts_udp_datagrams() {
    let q = sample_query(0x00BB);
    let (addr, _h) = start_udp_stub(Some(sample_reply(&q))).await;
    let fwd = DnsForwarder::new_with_ports(
        build_cfg(DnsProtocol::PlainUdp, vec![addr.ip()]),
        Arc::new(DirectConnector),
        true,
        vec![addr.port()],
    );
    let before = fwd.upstream_activity();
    fwd.try_forward(&q, UPSTREAM_TIMEOUT).await.expect("the stub replies");
    let moved = fwd.upstream_activity().since(before);
    assert_eq!(moved.written, q.len() as u64, "got {moved:?}");
    assert!(moved.read > 0, "the stub's reply must be counted; got {moved:?}");
}
