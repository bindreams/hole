use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use hole_common::config::{DnsConfig, DnsProtocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use super::*;
use crate::dns::connector::DirectConnector;

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

/// A closed listener, pre-computed so the connect attempt fails.
async fn unused_tcp_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn build_cfg(protocol: DnsProtocol, servers: Vec<IpAddr>) -> DnsConfig {
    DnsConfig {
        enabled: true,
        servers,
        protocol,
        intercept_udp53: true,
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
    let fwd = DnsForwarder::new(
        build_cfg(DnsProtocol::PlainUdp, vec![addr.ip()]),
        Arc::new(DirectConnector),
        true,
    );
    // Override server list to include the ephemeral port via the connector
    // layer: the forwarder always targets port 53, but our stub listens on
    // ephemeral — so we swap via a test-only helper.
    let reply = fwd.forward_on_port(&q, addr.port()).await;
    assert_eq!(&reply[..2], &[0x00, 0x42], "tx id echoed");
    assert_eq!(reply[2] & 0x80, 0x80, "QR set (real reply, not SERVFAIL)");
    assert_ne!(reply[3] & 0x0F, 2, "RCODE is not SERVFAIL");
}

#[skuld::test]
async fn plain_udp_primary_fails_secondary_succeeds() {
    let q = sample_query(0x0001);
    // Primary: bind then drop to get a closed port.
    let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let (live_addr, _h) = start_udp_stub(None).await;

    let fwd = DnsForwarder::new(
        DnsConfig {
            enabled: true,
            servers: vec![dead_addr.ip(), live_addr.ip()],
            protocol: DnsProtocol::PlainUdp,
            intercept_udp53: true,
        },
        Arc::new(DirectConnector),
        true,
    );
    // Both stubs live on 127.0.0.1 but different ports; the test helper
    // overrides the forwarder's port. Since we can only override one port,
    // use two distinct addresses via the `forward_with_ports` helper.
    let reply = fwd.forward_with_ports(&q, &[dead_addr.port(), live_addr.port()]).await;
    // We expect success from the second server.
    assert_ne!(reply[3] & 0x0F, 2, "secondary succeeded, not SERVFAIL");
}

#[skuld::test]
async fn all_servers_fail_returns_servfail() {
    let q = sample_query(0x5678);
    // Two closed addresses.
    let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let fwd = DnsForwarder::new(
        build_cfg(DnsProtocol::PlainTcp, vec![s1.ip(), s2.ip()]),
        Arc::new(DirectConnector),
        true,
    );
    // Use TCP (closed address → immediate RST or connect failure).
    let reply = fwd.forward_with_ports(&q, &[s1.port(), s2.port()]).await;
    assert_eq!(reply[3] & 0x0F, 2, "RCODE=SERVFAIL");
    assert_eq!(&reply[..2], &[0x56, 0x78]);
}

// Forward: TCP ========================================================================================================

#[skuld::test]
async fn plain_tcp_primary_succeeds() {
    let q = sample_query(0x00AA);
    let (addr, _h) = start_tcp_stub(Vec::new()).await;
    let fwd = DnsForwarder::new(
        build_cfg(DnsProtocol::PlainTcp, vec![addr.ip()]),
        Arc::new(DirectConnector),
        true,
    );
    let reply = fwd.forward_on_port(&q, addr.port()).await;
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
    let fwd = DnsForwarder::new(
        DnsConfig {
            enabled: true,
            servers: vec![v6, v4_addr.ip()],
            protocol: DnsProtocol::PlainUdp,
            intercept_udp53: true,
        },
        Arc::new(DirectConnector),
        false, // no v6 bypass
    );
    let reply = fwd.forward_with_ports(&q, &[0, v4_addr.port()]).await;
    // The v6 server was skipped; v4 answered.
    assert_ne!(reply[3] & 0x0F, 2);
}

// Throttle ============================================================================================================

#[skuld::test]
async fn duplicate_server_in_list_creates_one_throttle_entry() {
    // Two identical dead addresses share one per-IP throttle entry.
    // The throttle counts `logged + suppressed` per server — in #248's
    // Phase-2 shape, a single failure burst against the same server does
    // not duplicate state across the map.
    let dead_addr = unused_tcp_port().await;
    let fwd = DnsForwarder::new(
        build_cfg(DnsProtocol::PlainTcp, vec![dead_addr.ip(), dead_addr.ip()]),
        Arc::new(DirectConnector),
        true,
    );
    let q = sample_query(0x0001);
    let _ = fwd.forward_with_ports(&q, &[dead_addr.port(), dead_addr.port()]).await;
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
    // The #248 bug was fully invisible after the first-per-server log
    // line because of dedup-forever. This test pins the replacement
    // behavior: first LOG_FULL_LIMIT=3 failures log in full, subsequent
    // ones are counted as suppressed.
    let dead_addr = unused_tcp_port().await;
    let fwd = DnsForwarder::new(
        build_cfg(DnsProtocol::PlainTcp, vec![dead_addr.ip()]),
        Arc::new(DirectConnector),
        true,
    );
    let q = sample_query(0x0002);
    // 5 attempts against the same server.
    for _ in 0..5 {
        let _ = fwd.forward_with_ports(&q, &[dead_addr.port()]).await;
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

// Short-query safety ==================================================================================================

#[skuld::test]
async fn forward_on_short_query_returns_servfail() {
    let short = b"abc"; // below 12-byte DNS header
    let (addr, _h) = start_udp_stub(None).await;
    let fwd = DnsForwarder::new(
        build_cfg(DnsProtocol::PlainUdp, vec![addr.ip()]),
        Arc::new(DirectConnector),
        true,
    );
    let reply = fwd.forward_on_port(short, addr.port()).await;
    assert!(reply.len() >= 12);
    assert_eq!(reply[3] & 0x0F, 2);
}

// Test-only helpers allowing ephemeral-port stubs =====================================================================
//
// The forwarder always targets fixed well-known ports (53/853/443). Tests
// need ephemeral ports to run without privilege. These helpers mirror the
// public API but let tests substitute the port.

impl DnsForwarder {
    async fn forward_on_port(&self, query: &[u8], port: u16) -> Vec<u8> {
        self.forward_with_ports(query, &[port]).await
    }

    async fn forward_with_ports(&self, query: &[u8], ports: &[u16]) -> Vec<u8> {
        if query.len() < 12 {
            return synthesize_servfail(query);
        }
        for (i, &server) in self.config.servers.iter().enumerate() {
            if server.is_ipv6() && !self.ipv6_bypass_available {
                self.log_ipv6_skip_once(server);
                continue;
            }
            let port = ports.get(i).copied().unwrap_or(match self.config.protocol {
                DnsProtocol::PlainUdp | DnsProtocol::PlainTcp => 53,
                DnsProtocol::Tls => 853,
                DnsProtocol::Https => 443,
            });
            let target = SocketAddr::new(server, port);
            // Delegate to the production `forward_one` — now `SocketAddr`-shaped,
            // so ephemeral-port stubs work without any in-test protocol inlining.
            match self.forward_one(target, query).await {
                Ok(reply) => return reply,
                Err(e) => self.log_upstream_failure(server, &e),
            }
        }
        synthesize_servfail(query)
    }
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

// Phase 1 #248 — typed error + source-chain logging ===================================================================
//
// These tests drive the introduction of `UpstreamLayer` + `UpstreamErr` in
// `forwarder.rs`, plus the `layer=...`, `elapsed_ms=...`, `caused_by=...`
// fields on the "upstream failed" warn log line. Phase 2 observation uses
// these fields to tell SOCKS5-layer failures from TLS-layer failures from
// mid-tunnel EOFs, all of which surface as bare `tls handshake eof` today.

#[cfg(test)]
mod typed_error_logs {
    use super::*;
    use crate::test_support::log_capture::VecWriter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    use tracing_subscriber::util::SubscriberInitExt;

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
        let _guard = subscriber.set_default();

        let dead = unused_tcp_port().await;
        let fwd = DnsForwarder::new(
            build_cfg(DnsProtocol::PlainTcp, vec![dead.ip()]),
            Arc::new(DirectConnector),
            true,
        );
        let _ = fwd.forward_on_port(&sample_query(0x0001), dead.port()).await;

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
        let _guard = subscriber.set_default();

        let dead = unused_tcp_port().await;
        let fwd = DnsForwarder::new(
            build_cfg(DnsProtocol::PlainTcp, vec![dead.ip()]),
            Arc::new(DirectConnector),
            true,
        );
        let _ = fwd.forward_on_port(&sample_query(0x0002), dead.port()).await;

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
        let _guard = subscriber.set_default();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _h = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        let fwd = DnsForwarder::new(
            build_cfg(DnsProtocol::PlainTcp, vec![addr.ip()]),
            Arc::new(DirectConnector),
            true,
        );
        let _ = fwd.forward_on_port(&sample_query(0x0003), addr.port()).await;

        let output = writer.snapshot_string();
        assert!(
            output.contains("layer=io"),
            "expected 'layer=io' for EOF mid-exchange; got:\n{output}"
        );
    }
}
