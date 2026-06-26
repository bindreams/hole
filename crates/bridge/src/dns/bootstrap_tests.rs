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
