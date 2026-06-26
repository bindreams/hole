use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use super::{build_a_query, build_aaaa_query, parse_addrs, BootstrapError};

/// Decode our query bytes with hickory and assert the question shape.
fn decode(bytes: &[u8]) -> Message {
    Message::from_vec(bytes).expect("query is valid wire format")
}

#[skuld::test]
fn build_a_query_has_a_question_for_name() {
    let q = build_a_query("example.com", 0x1234).unwrap();
    let msg = decode(&q);
    assert_eq!(msg.id, 0x1234); // pub field via Deref<Metadata>, not msg.id()
    assert_eq!(msg.op_code, OpCode::Query);
    assert!(msg.recursion_desired);
    let question = &msg.queries[0]; // pub Vec field, not msg.queries()
    assert_eq!(question.query_type(), RecordType::A);
    assert_eq!(question.name().to_utf8(), "example.com.");
}

#[skuld::test]
fn build_aaaa_query_has_aaaa_question() {
    let q = build_aaaa_query("example.com", 0x0001).unwrap();
    let msg = decode(&q);
    assert_eq!(msg.queries[0].query_type(), RecordType::AAAA);
}

#[skuld::test]
fn build_query_rejects_invalid_name() {
    // A label > 63 octets is not a valid DNS name.
    let bad = "a".repeat(64);
    assert!(matches!(build_a_query(&bad, 1), Err(BootstrapError::InvalidName)));
}

#[skuld::test]
fn parse_addrs_extracts_a_and_aaaa_records() {
    // Synthesize a reply with one A and one AAAA answer for example.com.
    let mut msg = Message::new(7, MessageType::Response, OpCode::Query);
    msg.metadata.response_code = ResponseCode::NoError;
    let name = Name::from_ascii("example.com.").unwrap();
    msg.add_query(Query::query(name.clone(), RecordType::A));
    let v4 = Ipv4Addr::new(93, 184, 216, 34);
    let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946);
    msg.add_answer(Record::from_rdata(name.clone(), 60, RData::A(A(v4))));
    msg.add_answer(Record::from_rdata(name, 60, RData::AAAA(AAAA(v6))));
    let bytes = msg.to_vec().unwrap();

    let addrs = parse_addrs(&bytes);
    assert!(addrs.contains(&IpAddr::V4(v4)));
    assert!(addrs.contains(&IpAddr::V6(v6)));
}

#[skuld::test]
fn parse_addrs_ignores_garbage() {
    // < 12 bytes is not a parseable DNS message.
    assert!(parse_addrs(&[0u8; 4]).is_empty());
}

// resolve_via_doh =====================================================================================================

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hole_common::config::{DnsConfig, DnsProtocol};

use super::{resolve_via_doh_with, DohQuerier};

/// In-test querier: answers ONLY for resolver IPs it was given a canned reply
/// for; returns `None` otherwise (models "this resolver unreachable"). Records
/// which resolver IPs it was asked, so a test can assert the CONFIGURED
/// resolver — not the OS resolver — was consulted.
struct StubQuerier {
    answer_for: HashMap<IpAddr, Vec<u8>>,
    asked: Mutex<Vec<IpAddr>>,
}

#[async_trait]
impl DohQuerier for StubQuerier {
    async fn query(&self, _doh_url: &str, server: IpAddr, _wire: &[u8]) -> Option<Vec<u8>> {
        self.asked.lock().unwrap().push(server);
        self.answer_for.get(&server).cloned()
    }
}

fn stub(answers: HashMap<IpAddr, Vec<u8>>) -> Arc<StubQuerier> {
    Arc::new(StubQuerier {
        answer_for: answers,
        asked: Mutex::new(Vec::new()),
    })
}

fn a_reply_for(name: &str, v4: Ipv4Addr) -> Vec<u8> {
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    let n = Name::from_ascii(format!("{name}.")).unwrap();
    msg.add_query(Query::query(n.clone(), RecordType::A));
    msg.add_answer(Record::from_rdata(n, 60, RData::A(A(v4))));
    msg.to_vec().unwrap()
}

fn aaaa_reply_for(name: &str, v6: Ipv6Addr) -> Vec<u8> {
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    let n = Name::from_ascii(format!("{name}.")).unwrap();
    msg.add_query(Query::query(n.clone(), RecordType::AAAA));
    msg.add_answer(Record::from_rdata(n, 60, RData::AAAA(AAAA(v6))));
    msg.to_vec().unwrap()
}

fn cfg(servers: Vec<IpAddr>, allow_insecure: bool) -> DnsConfig {
    DnsConfig {
        enabled: true,
        servers,
        protocol: DnsProtocol::Https,
        allow_insecure_bootstrap: allow_insecure,
    }
}

#[skuld::test]
async fn resolve_uses_configured_resolver_not_system() {
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let expected = Ipv4Addr::new(203, 0, 113, 7);
    let mut answers = HashMap::new();
    answers.insert(resolver, a_reply_for("proxy.example", expected));
    let q = stub(answers);

    let ip = resolve_via_doh_with("proxy.example", &cfg(vec![resolver], false), q.clone())
        .await
        .unwrap();
    assert_eq!(ip, IpAddr::V4(expected));
    assert_eq!(
        *q.asked.lock().unwrap(),
        vec![resolver],
        "asked the configured resolver only"
    );
}

#[skuld::test]
async fn resolve_surfaces_invalid_name_not_no_answer() {
    // A label > 63 octets is not a valid DNS name; the builder returns
    // InvalidName, which must reach the caller rather than being downgraded to
    // NoAnswer. The querier is never consulted because the query never builds.
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let q = stub(HashMap::new());
    let bad = "a".repeat(64);
    let err = resolve_via_doh_with(&bad, &cfg(vec![resolver], false), q.clone())
        .await
        .unwrap_err();
    assert_eq!(err, BootstrapError::InvalidName);
    assert!(q.asked.lock().unwrap().is_empty(), "an invalid name must not query DoH");
}

#[skuld::test]
async fn resolve_fails_closed_when_no_resolver_answers() {
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let q = stub(HashMap::new()); // querier returns None for every server.
    let err = resolve_via_doh_with("proxy.example", &cfg(vec![resolver], false), q)
        .await
        .unwrap_err();
    assert_eq!(err, BootstrapError::NoAnswer);
}

#[skuld::test]
async fn resolve_returns_ipv6_when_only_aaaa_answers() {
    // No A record from any resolver; an AAAA answer must be returned (the v6
    // branch is correct, not dodged). The wiring task verifies the bracket-safe
    // handoff of this exact result.
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946);
    let mut answers = HashMap::new();
    answers.insert(resolver, aaaa_reply_for("proxy.example", v6));
    let q = stub(answers);
    let ip = resolve_via_doh_with("proxy.example", &cfg(vec![resolver], false), q)
        .await
        .unwrap();
    assert_eq!(ip, IpAddr::V6(v6));
}

#[skuld::test]
async fn resolve_prefers_ipv4_when_both_answer() {
    // One resolver answers both A and AAAA; IPv4 wins (bypass-route compat).
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let v4 = Ipv4Addr::new(203, 0, 113, 7);
    let mut answers = HashMap::new();
    answers.insert(resolver, a_reply_for("proxy.example", v4));
    let q = stub(answers);
    let ip = resolve_via_doh_with("proxy.example", &cfg(vec![resolver], false), q)
        .await
        .unwrap();
    assert_eq!(ip, IpAddr::V4(v4));
}

#[skuld::test]
async fn resolve_allow_insecure_falls_back_to_system_for_localhost() {
    // No resolver answers, but allow_insecure_bootstrap → fall back to the OS
    // path. "localhost" is resolvable on every CI host without network.
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let q = stub(HashMap::new());
    let ip = resolve_via_doh_with("localhost", &cfg(vec![resolver], true), q)
        .await
        .unwrap();
    assert!(ip.is_loopback(), "localhost resolved to a loopback address: {ip}");
}

#[skuld::test]
async fn resolve_returns_literal_ip_unchanged_without_querying() {
    let q = stub(HashMap::new());
    let ip = resolve_via_doh_with("198.51.100.9", &cfg(vec!["1.1.1.1".parse().unwrap()], false), q.clone())
        .await
        .unwrap();
    assert_eq!(ip, "198.51.100.9".parse::<IpAddr>().unwrap());
    assert!(q.asked.lock().unwrap().is_empty(), "a literal IP must not query DoH");
}

// handoff_host ========================================================================================================

use std::net::SocketAddr;

use super::handoff_host;

#[skuld::test]
fn handoff_host_v4_is_plain() {
    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    assert_eq!(handoff_host(ip), "203.0.113.7");
    // garter's `format!("{host}:{port}")` must parse.
    assert!(format!("{}:443", handoff_host(ip)).parse::<SocketAddr>().is_ok());
}

#[skuld::test]
fn handoff_host_v6_is_bracketed_and_parses_with_port() {
    let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946);
    let ip = IpAddr::V6(v6);
    assert_eq!(handoff_host(ip), format!("[{v6}]"));
    // The exact string garter builds (chain.rs:227) MUST be a valid SocketAddr;
    // a bare (unbracketed) v6 + ":443" would NOT parse.
    let combined = format!("{}:443", handoff_host(ip));
    let sa: SocketAddr = combined.parse().expect("bracketed v6 host:port parses");
    assert_eq!(sa, SocketAddr::new(ip, 443));
}

// Loopback-TLS e2e ====================================================================================================

use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Stand up a loopback rustls DoH server on 127.0.0.2:<ephemeral> that serves
/// one canned `application/dns-message` reply, returning the server's cert DER
/// (for the client trust root) and the bound port. The cert carries an IP SAN
/// for 127.0.0.2 because `https_target_for` uses IP-SNI for non-table IPs.
async fn spawn_loopback_doh(reply: Vec<u8>) -> (CertificateDer<'static>, u16) {
    use rcgen::{CertificateParams, KeyPair, SanType};
    use std::net::Ipv4Addr;
    use tokio_rustls::TlsAcceptor;

    let san_ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.subject_alt_names = vec![SanType::IpAddress(san_ip)];
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();

    let server_cfg =
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_cfg));

    let listener = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                // Drain the POST request (best-effort) then write the HTTP reply.
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;
                let body = reply;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls.write_all(&body).await;
                // Graceful TLS shutdown sends `close_notify`; without it rustls's
                // `read_to_end` on the client errors on the unclean EOF, as a real
                // DoH server (which closes cleanly) never would.
                let _ = tls.shutdown().await;
            }
        }
    });
    (cert_der, port)
}

#[skuld::test]
async fn resolve_via_doh_e2e_through_real_forwarder() {
    let expected = Ipv4Addr::new(203, 0, 113, 42);
    let reply = a_reply_for("proxy.example", expected);
    let (cert_der, port) = spawn_loopback_doh(reply).await;

    // Production path: ForwarderQuerier-equivalent built with the test root +
    // a port override so the DirectConnector reaches the loopback listener.
    let resolver: IpAddr = "127.0.0.2".parse().unwrap();
    let ip = super::resolve_via_doh_with(
        "proxy.example",
        &cfg(vec![resolver], false),
        super::test_loopback_querier(cert_der, port),
    )
    .await
    .unwrap();
    assert_eq!(ip, IpAddr::V4(expected));
}
