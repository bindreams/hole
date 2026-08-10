use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use super::{build_a_query, build_aaaa_query, parse_addrs, BootstrapError};
use crate::dns::ech::PinSource;

/// Decode our query bytes with hickory and assert the question shape.
fn decode(bytes: &[u8]) -> Message {
    Message::from_vec(bytes).expect("query is valid wire format")
}

#[skuld::test]
fn build_a_query_has_a_question_for_name() {
    let q = build_a_query("example.com", 0x1234).unwrap();
    let msg = decode(&q);
    assert_eq!(msg.id, 0x1234);
    assert_eq!(msg.op_code, OpCode::Query);
    assert!(msg.recursion_desired);
    let question = &msg.queries[0];
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

    let parsed = parse_addrs(&bytes).unwrap();
    assert!(parsed.addrs.contains(&IpAddr::V4(v4)));
    assert!(parsed.addrs.contains(&IpAddr::V6(v6)));
    assert!(!parsed.name_missing, "NOERROR is not NXDOMAIN");
}

#[skuld::test]
fn parse_addrs_reports_nxdomain_separately_from_an_empty_answer() {
    // NXDOMAIN is a verdict on the NAME; an empty NOERROR speaks only for the
    // record type queried. The resolve loop folds NoAnswer on the former from
    // either leg, but on the latter only when both legs answered.
    let name = Name::from_ascii("proxy.example.").unwrap();
    let mut empty = Message::new(0, MessageType::Response, OpCode::Query);
    empty.metadata.response_code = ResponseCode::NoError;
    empty.add_query(Query::query(name.clone(), RecordType::A));
    let parsed = parse_addrs(&empty.to_vec().unwrap()).unwrap();
    assert!(parsed.addrs.is_empty());
    assert!(!parsed.name_missing);

    let mut nx = Message::new(0, MessageType::Response, OpCode::Query);
    nx.metadata.response_code = ResponseCode::NXDomain;
    nx.add_query(Query::query(name, RecordType::A));
    assert!(parse_addrs(&nx.to_vec().unwrap()).unwrap().name_missing);
}

#[skuld::test]
fn parse_addrs_reports_an_unparseable_reply() {
    // < 12 bytes is not a parseable DNS message. Distinct from a reply that
    // parses and carries no records — a resolver that answered garbage is a
    // different finding from one that answered "I have nothing".
    assert_eq!(parse_addrs(&[0u8; 4]), None);
}

// resolve_via_doh =====================================================================================================

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hole_common::config::{DnsConfig, DnsProtocol};

use tracing_subscriber::layer::{Layer, SubscriberExt};

use super::{resolve_via_doh_with, DohQuerier};
use crate::dns::forwarder::UpstreamCause;

/// In-test querier: answers ONLY for resolver IPs it was given a canned reply
/// for; returns `Err(fail_with)` otherwise (default: `Unreachable`). Records
/// which resolver IPs it was asked, so a test can assert the CONFIGURED
/// resolver — not the OS resolver — was consulted.
struct StubQuerier {
    answer_for: HashMap<IpAddr, Vec<u8>>,
    /// Returned for any server without a canned reply.
    fail_with: UpstreamCause,
    asked: Mutex<Vec<IpAddr>>,
}

#[async_trait]
impl DohQuerier for StubQuerier {
    async fn query(&self, server: IpAddr, _wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
        self.asked.lock().unwrap().push(server);
        self.answer_for.get(&server).cloned().ok_or(self.fail_with)
    }
}

fn stub(answers: HashMap<IpAddr, Vec<u8>>) -> Arc<StubQuerier> {
    stub_failing(answers, UpstreamCause::Unreachable)
}

fn stub_failing(answers: HashMap<IpAddr, Vec<u8>>, fail_with: UpstreamCause) -> Arc<StubQuerier> {
    Arc::new(StubQuerier {
        answer_for: answers,
        fail_with,
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
        .unwrap()
        .server_ip;
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
async fn resolve_reports_unreachable_when_no_resolver_answers() {
    // Fail-closed AND specific: an unreachable resolver is not "no answer".
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let err = resolve_via_doh_with("proxy.example", &cfg(vec![resolver], false), stub(HashMap::new()))
        .await
        .unwrap_err();
    assert_eq!(err, BootstrapError::Unreachable);
}

#[skuld::test]
async fn resolve_maps_every_upstream_cause_to_its_bootstrap_error() {
    // Every variant the seam can carry — the match in `classify` is total, so
    // this list is exhaustive by construction.
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let cases = [
        (UpstreamCause::CertificateRejected, BootstrapError::CertificateRejected),
        (UpstreamCause::Unreachable, BootstrapError::Unreachable),
        (UpstreamCause::Timeout, BootstrapError::Timeout),
        (UpstreamCause::TlsFailed, BootstrapError::Transport),
        (UpstreamCause::BadResponse, BootstrapError::Transport),
        (UpstreamCause::Io, BootstrapError::Transport),
    ];
    for (cause, expected) in cases {
        let q = stub_failing(HashMap::new(), cause);
        let err = resolve_via_doh_with("proxy.example", &cfg(vec![resolver], false), q)
            .await
            .unwrap_err();
        assert_eq!(err, expected, "cause {cause:?}");
    }
}

#[skuld::test]
async fn resolve_reports_no_answer_when_a_resolver_replies_without_records() {
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.metadata.response_code = ResponseCode::ServFail;
    msg.add_query(Query::query(Name::from_ascii("proxy.example.").unwrap(), RecordType::A));
    let mut answers = HashMap::new();
    answers.insert(resolver, msg.to_vec().unwrap());
    let err = resolve_via_doh_with("proxy.example", &cfg(vec![resolver], false), stub(answers))
        .await
        .unwrap_err();
    assert_eq!(err, BootstrapError::NoAnswer);
}

#[skuld::test]
async fn resolve_reports_malformed_reply_when_a_resolver_answers_non_dns() {
    // HTTP 200, `application/dns-message`, body that is not DNS: the resolver
    // is answering, but not with DNS. Distinct from an empty answer.
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let mut answers = HashMap::new();
    answers.insert(resolver, b"not dns at all".to_vec());
    let err = resolve_via_doh_with("proxy.example", &cfg(vec![resolver], false), stub(answers))
        .await
        .unwrap_err();
    assert_eq!(err, BootstrapError::MalformedReply);
}

#[skuld::test]
fn bootstrap_error_ranking_is_total_and_ordered() {
    // The fold reports the highest-ranked failure observed. Pin the whole
    // order: an answered-but-empty resolver must NOT be masked by another
    // resolver's failed connect, or the toast claims a network failure that
    // did not happen. `InvalidName` is included even though it short-circuits
    // before the loop today — if it ever reaches the fold, it must win.
    let order = [
        BootstrapError::Unreachable,
        BootstrapError::Timeout,
        BootstrapError::Transport,
        BootstrapError::NoAnswer,
        BootstrapError::MalformedReply,
        BootstrapError::CertificateRejected,
        BootstrapError::InvalidName,
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

#[skuld::test]
async fn resolve_does_not_mask_an_answering_resolver_with_another_resolvers_failure() {
    // One resolver answered (with nothing); another could not be reached.
    // Reporting "could not reach a secure DNS resolver" would be a false
    // network diagnosis.
    let answered: IpAddr = "1.1.1.1".parse().unwrap();
    let dead: IpAddr = "9.9.9.9".parse().unwrap();
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.metadata.response_code = ResponseCode::NXDomain;
    msg.add_query(Query::query(Name::from_ascii("proxy.example.").unwrap(), RecordType::A));
    let mut answers = HashMap::new();
    answers.insert(answered, msg.to_vec().unwrap());
    for servers in [vec![answered, dead], vec![dead, answered]] {
        let err = resolve_via_doh_with("proxy.example", &cfg(servers.clone(), false), stub(answers.clone()))
            .await
            .unwrap_err();
        assert_eq!(err, BootstrapError::NoAnswer, "servers {servers:?}");
    }
}

#[skuld::test]
async fn an_a_query_without_ipv4_does_not_mask_a_transport_failure() {
    // Ordinary dual-stack shape: the A leg parses with no IPv4 (an AAAA-only
    // host), then the AAAA leg fails at the transport. The A leg concluded
    // nothing about whether the address exists, so the transport finding must
    // survive — reporting "could not resolve … via secure DNS" here would hand
    // the user a hostname diagnosis for a network fault.
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    struct AEmptyThenTimeout;
    #[async_trait]
    impl DohQuerier for AEmptyThenTimeout {
        async fn query(&self, _server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            let q = Message::from_vec(wire).unwrap();
            if q.queries[0].query_type() == RecordType::A {
                // Parses, NOERROR, zero answers.
                let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
                reply.add_query(q.queries[0].clone());
                return Ok(reply.to_vec().unwrap());
            }
            Err(UpstreamCause::Timeout)
        }
    }
    let err = resolve_via_doh_with(
        "proxy.example",
        &cfg(vec![resolver], false),
        Arc::new(AEmptyThenTimeout),
    )
    .await
    .unwrap_err();
    assert_eq!(err, BootstrapError::Timeout);
}

#[skuld::test]
async fn an_aaaa_query_without_ipv6_does_not_mask_a_transport_failure() {
    // The mirror, and the commoner shape: an IPv4-only host makes the AAAA leg
    // answer emptily. With the A leg failed at the transport, that emptiness
    // concludes nothing about the hostname, so the transport finding survives.
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    struct ATimeoutThenAaaaEmpty;
    #[async_trait]
    impl DohQuerier for ATimeoutThenAaaaEmpty {
        async fn query(&self, _server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            let q = Message::from_vec(wire).unwrap();
            if q.queries[0].query_type() == RecordType::A {
                return Err(UpstreamCause::Timeout);
            }
            let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
            reply.add_query(q.queries[0].clone());
            Ok(reply.to_vec().unwrap())
        }
    }
    let err = resolve_via_doh_with(
        "proxy.example",
        &cfg(vec![resolver], false),
        Arc::new(ATimeoutThenAaaaEmpty),
    )
    .await
    .unwrap_err();
    assert_eq!(err, BootstrapError::Timeout);
}

#[skuld::test]
async fn an_nxdomain_from_one_leg_reports_no_answer() {
    // NXDOMAIN is conclusive about the NAME, so it folds even though only one
    // leg answered — the actionable finding (fix the hostname) must not be
    // displaced by the other leg's transient network failure.
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    struct ANxdomainThenTimeout;
    #[async_trait]
    impl DohQuerier for ANxdomainThenTimeout {
        async fn query(&self, _server: IpAddr, wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            let q = Message::from_vec(wire).unwrap();
            if q.queries[0].query_type() == RecordType::A {
                let mut reply = Message::new(0, MessageType::Response, OpCode::Query);
                reply.metadata.response_code = ResponseCode::NXDomain;
                reply.add_query(q.queries[0].clone());
                return Ok(reply.to_vec().unwrap());
            }
            Err(UpstreamCause::Timeout)
        }
    }
    let err = resolve_via_doh_with(
        "proxy.example",
        &cfg(vec![resolver], false),
        Arc::new(ANxdomainThenTimeout),
    )
    .await
    .unwrap_err();
    assert_eq!(err, BootstrapError::NoAnswer);
}

#[skuld::test]
async fn resolve_reports_certificate_rejection_over_a_weaker_failure_from_another_resolver() {
    let intercepted: IpAddr = "1.1.1.1".parse().unwrap();
    let unreachable: IpAddr = "9.9.9.9".parse().unwrap();
    struct PerServer(IpAddr);
    #[async_trait]
    impl DohQuerier for PerServer {
        async fn query(&self, server: IpAddr, _wire: &[u8]) -> Result<Vec<u8>, UpstreamCause> {
            if server == self.0 {
                Err(UpstreamCause::CertificateRejected)
            } else {
                Err(UpstreamCause::Unreachable)
            }
        }
    }
    for servers in [vec![intercepted, unreachable], vec![unreachable, intercepted]] {
        let err = resolve_via_doh_with(
            "proxy.example",
            &cfg(servers.clone(), false),
            Arc::new(PerServer(intercepted)),
        )
        .await
        .unwrap_err();
        assert_eq!(err, BootstrapError::CertificateRejected, "servers {servers:?}");
    }
}

#[skuld::test]
async fn resolve_reports_no_answer_when_no_resolvers_are_configured() {
    // Degenerate config: the loop never runs, so nothing is observed. Must be
    // an error, and specifically the generic one — not a panic, and not a
    // cause the code never actually saw.
    let err = resolve_via_doh_with("proxy.example", &cfg(vec![], false), stub(HashMap::new()))
        .await
        .unwrap_err();
    assert_eq!(err, BootstrapError::NoAnswer);
}

#[skuld::test]
async fn bootstrap_error_display_never_leaks_the_hostname() {
    // The PII contract: `ProxyError::DohBootstrap` renders this verbatim into a
    // toast, so no variant may name the host it was resolving. All seven —
    // including the two reached through a SUCCESSFUL round trip, which are the
    // newest surface and the easiest to enrich with reply detail later.
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let host = "secret-proxy.example";
    let mut empty = Message::new(0, MessageType::Response, OpCode::Query);
    empty.metadata.response_code = ResponseCode::NXDomain;
    empty.add_query(Query::query(
        Name::from_ascii("secret-proxy.example.").unwrap(),
        RecordType::A,
    ));
    let answered = |bytes: Vec<u8>| {
        let mut m = HashMap::new();
        m.insert(resolver, bytes);
        stub(m)
    };

    let queriers: Vec<Arc<StubQuerier>> = vec![
        stub_failing(HashMap::new(), UpstreamCause::CertificateRejected),
        stub_failing(HashMap::new(), UpstreamCause::Unreachable),
        stub_failing(HashMap::new(), UpstreamCause::Timeout),
        stub_failing(HashMap::new(), UpstreamCause::TlsFailed),
        answered(empty.to_vec().unwrap()),    // -> NoAnswer
        answered(b"not dns at all".to_vec()), // -> MalformedReply
    ];
    for q in queriers {
        let err = resolve_via_doh_with(host, &cfg(vec![resolver], false), q)
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(!text.contains(host), "{err:?} Display leaked the host: {text}");
        assert!(!text.contains("1.1.1.1"), "{err:?} Display leaked the resolver: {text}");
    }

    // InvalidName is the seventh variant and the one built directly FROM the
    // untrusted hostname, so it is the likeliest to acquire the offending name
    // in a later edit. It short-circuits before any querier runs, hence the
    // separate drive: a 64-octet label is not a valid DNS name.
    let bad = "a".repeat(64);
    let err = resolve_via_doh_with(&bad, &cfg(vec![resolver], false), stub(HashMap::new()))
        .await
        .unwrap_err();
    assert_eq!(err, BootstrapError::InvalidName);
    assert!(!err.to_string().contains(&bad), "InvalidName Display leaked the host");
}

#[skuld::test]
async fn insecure_fallback_logs_the_certificate_rejection_even_when_it_succeeds() {
    // allow_insecure_bootstrap turns a rejected certificate into a SUCCESSFUL
    // start over plaintext system DNS -- the one channel an interceptor
    // certainly controls. The log line is then the only surviving evidence.
    let writer = crate::test_support::log_capture::VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let q = stub_failing(HashMap::new(), UpstreamCause::CertificateRejected);
    // "localhost" resolves on every CI host without network.
    let ip = resolve_via_doh_with("localhost", &cfg(vec![resolver], true), q)
        .await
        .expect("insecure fallback resolves localhost")
        .server_ip;
    assert!(ip.is_loopback());

    let output = writer.snapshot_string();
    assert!(
        output.contains("PLAINTEXT system DNS"),
        "the WARN must state the consequence, not just flag it; got:\n{output}"
    );
    assert!(
        output.contains("CertificateRejected"),
        "the WARN must name the finding the fallback is proceeding past; got:\n{output}"
    );
}

#[skuld::test]
async fn a_recovering_resolve_logs_no_failure_warning() {
    // An AAAA-only host makes the A query answer with no IPv4 — ordinary
    // dual-stack behavior, not a failure. A WARN here would put a false alarm
    // in bridge.log on a start that worked.
    let writer = crate::test_support::log_capture::VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x35);
    let mut answers = HashMap::new();
    answers.insert(resolver, aaaa_reply_for("proxy.example", v6));
    let ip = resolve_via_doh_with("proxy.example", &cfg(vec![resolver], false), stub(answers))
        .await
        .unwrap()
        .server_ip;
    assert_eq!(ip, IpAddr::V6(v6));
    assert_eq!(writer.snapshot_string(), "", "a successful resolve must log no warning");
}

#[skuld::test]
async fn a_malformed_reply_logs_even_when_a_later_resolver_rescues_the_resolve() {
    // The deliberate asymmetry with the empty-answer case above: a resolver
    // answering non-DNS is evidence of something rewriting the response, so it
    // is recorded the moment it happens — even though this resolve succeeds.
    let writer = crate::test_support::log_capture::VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

    let garbage: IpAddr = "1.1.1.1".parse().unwrap();
    let good: IpAddr = "9.9.9.9".parse().unwrap();
    let expected = Ipv4Addr::new(203, 0, 113, 7);
    let mut answers = HashMap::new();
    answers.insert(garbage, b"not dns at all".to_vec());
    answers.insert(good, a_reply_for("proxy.example", expected));

    let ip = resolve_via_doh_with("proxy.example", &cfg(vec![garbage, good], false), stub(answers))
        .await
        .expect("the second resolver rescues the resolve")
        .server_ip;
    assert_eq!(ip, IpAddr::V4(expected));

    let output = writer.snapshot_string();
    assert!(
        output.contains("not parseable DNS"),
        "a non-DNS reply must be recorded even on a rescued resolve; got:\n{output}"
    );
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
    let got = resolve_via_doh_with("proxy.example", &cfg(vec![resolver], false), q)
        .await
        .unwrap();
    assert_eq!(got.server_ip, IpAddr::V6(v6));
    // The AAAA leg answered, so the resolver that served it is the pin.
    assert_eq!(got.via, PinSource::Answered(resolver));
}

#[skuld::test]
async fn resolve_prefers_ipv4_when_both_answer() {
    // A genuinely dual-stack answer: ONE reply carrying both an A and an AAAA
    // record. Answering only A would prove nothing — the A branch returns
    // before the AAAA query is ever issued, so IPv6 would never be a candidate.
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let v4 = Ipv4Addr::new(203, 0, 113, 7);
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x7);
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    let n = Name::from_ascii("proxy.example.").unwrap();
    msg.add_query(Query::query(n.clone(), RecordType::A));
    msg.add_answer(Record::from_rdata(n.clone(), 60, RData::AAAA(AAAA(v6))));
    msg.add_answer(Record::from_rdata(n, 60, RData::A(A(v4))));
    // AAAA first in the answer section, so a naive "take the first address"
    // would pick IPv6 and this test would catch it.
    let mut answers = HashMap::new();
    answers.insert(resolver, msg.to_vec().unwrap());
    let q = stub(answers);
    let ip = resolve_via_doh_with("proxy.example", &cfg(vec![resolver], false), q)
        .await
        .unwrap()
        .server_ip;
    assert_eq!(ip, IpAddr::V4(v4), "IPv4 wins (bypass-route compat)");
}

#[skuld::test]
async fn resolve_allow_insecure_falls_back_to_system_for_localhost() {
    // No resolver answers, but allow_insecure_bootstrap → fall back to the OS
    // path. "localhost" is resolvable on every CI host without network.
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let q = stub(HashMap::new());
    let got = resolve_via_doh_with("localhost", &cfg(vec![resolver], true), q)
        .await
        .unwrap();
    assert!(
        got.server_ip.is_loopback(),
        "localhost resolved to a loopback address: {}",
        got.server_ip
    );
    // Every configured resolver failed; the OS resolver answered instead, so
    // nothing here is known to serve the ECH lookup.
    assert_eq!(got.via, PinSource::SecureBootstrapFailed);
}

#[skuld::test]
async fn resolve_returns_literal_ip_unchanged_without_querying() {
    let q = stub(HashMap::new());
    let ip = resolve_via_doh_with("198.51.100.9", &cfg(vec!["1.1.1.1".parse().unwrap()], false), q.clone())
        .await
        .unwrap()
        .server_ip;
    assert_eq!(ip, "198.51.100.9".parse::<IpAddr>().unwrap());
    assert!(q.asked.lock().unwrap().is_empty(), "a literal IP must not query DoH");
}

// Which resolver answered =============================================================================================

// `via` is the resolver that answered, which may not be `servers[0]`.
#[skuld::test]
async fn via_names_the_resolver_that_answered_not_the_first() {
    let dead: IpAddr = "2606:4700:4700::1111".parse().unwrap();
    let answering: IpAddr = "1.0.0.1".parse().unwrap();
    let expected = Ipv4Addr::new(203, 0, 113, 7);
    let mut answers = HashMap::new();
    answers.insert(answering, a_reply_for("proxy.example", expected));

    let got = resolve_via_doh_with("proxy.example", &cfg(vec![dead, answering], false), stub(answers))
        .await
        .unwrap();
    assert_eq!(got.server_ip, IpAddr::V4(expected));
    assert_eq!(
        got.via,
        PinSource::Answered(answering),
        "via is the resolver that answered"
    );
}

// A resolver that answered NOERROR-empty is reachable for DoH even though it
// resolved nothing here, so the insecure tail still has a resolver to pin —
// serving an HTTPS record for another name is exactly what it just proved it can do.
#[skuld::test]
async fn an_empty_but_well_formed_reply_still_pins_the_resolver() {
    let resolver: IpAddr = "1.1.1.1".parse().unwrap();
    let mut empty = Message::new(0, MessageType::Response, OpCode::Query);
    empty.metadata.response_code = ResponseCode::NoError;
    empty.add_query(Query::query(Name::from_ascii("localhost.").unwrap(), RecordType::A));
    let mut answers = HashMap::new();
    answers.insert(resolver, empty.to_vec().unwrap());

    let got = resolve_via_doh_with("localhost", &cfg(vec![resolver], true), stub(answers))
        .await
        .expect("the insecure fallback resolves localhost");
    assert!(got.server_ip.is_loopback());
    assert_eq!(got.via, PinSource::Answered(resolver));
}

// A literal server entry short-circuits before any query runs, so no resolver
// was consulted and there is none to report.
#[skuld::test]
async fn literal_server_entry_reports_no_resolver() {
    let q = stub(HashMap::new());
    let got = resolve_via_doh_with("198.51.100.4", &cfg(vec!["1.1.1.1".parse().unwrap()], false), q.clone())
        .await
        .unwrap();
    assert_eq!(got.server_ip, "198.51.100.4".parse::<IpAddr>().unwrap());
    assert_eq!(got.via, PinSource::NoQueryNeeded);
    assert!(q.asked.lock().unwrap().is_empty(), "no resolver consulted");
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
    // The exact string garter builds in chain.rs MUST be a valid SocketAddr;
    // a bare (unbracketed) v6 + ":443" would NOT parse.
    let combined = format!("{}:443", handoff_host(ip));
    let sa: SocketAddr = combined.parse().expect("bracketed v6 host:port parses");
    assert_eq!(sa, SocketAddr::new(ip, 443));
}

// Loopback-TLS e2e ====================================================================================================

use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Stand up a loopback rustls DoH server on 127.0.0.1:<ephemeral> that serves
/// one canned `application/dns-message` reply to EVERY connection (the resolver
/// loop opens a second one for the AAAA fallback), returning the server's cert DER
/// (for the client trust root) and the bound port. The cert carries an IP SAN
/// for 127.0.0.1 because `https_target_for` uses IP-SNI for non-table IPs.
/// (127.0.0.1, not another 127/8 address: macOS makes only 127.0.0.1 loopback
/// by default, so binding e.g. 127.0.0.2 fails with `AddrNotAvailable`.)
async fn spawn_loopback_doh(reply: Vec<u8>) -> (CertificateDer<'static>, u16) {
    use rcgen::{CertificateParams, KeyPair, SanType};
    use std::net::Ipv4Addr;
    use tokio_rustls::TlsAcceptor;

    let san_ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let body = reply.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return; // Handshake refused by the client (untrusted chain).
                };
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                // Drain the POST request (best-effort).
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;
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
            });
        }
    });
    (cert_der, port)
}

#[skuld::test]
async fn resolve_reports_certificate_rejection_through_a_real_tls_handshake() {
    // End-to-end: a real rustls client with the PRODUCTION trust config rejects
    // a real self-signed chain as UnknownIssuer (see test_untrusted_querier).
    let expected = Ipv4Addr::new(203, 0, 113, 42);
    let (_cert_der, port) = spawn_loopback_doh(a_reply_for("proxy.example", expected)).await;

    let resolver: IpAddr = "127.0.0.1".parse().unwrap();
    let err = super::resolve_via_doh_with(
        "proxy.example",
        &cfg(vec![resolver], false),
        super::test_untrusted_querier(port),
    )
    .await
    .unwrap_err();

    assert_eq!(
        err,
        BootstrapError::CertificateRejected,
        "a rejected resolver certificate must not be reported as no answer"
    );
}

// The `Unreachable` branch is deliberately NOT driven through a real closed
// socket here: "connect to a port nothing is listening on" has no portable
// failure shape (macOS black-holes it, GitHub's Windows runners drop SYNs to
// closed ephemeral loopback ports), so it cannot pin an exact cause. It is
// covered deterministically by `resolve_maps_every_upstream_cause_to_its_bootstrap_error`
// and, at the forwarder layer, by `try_forward_reports_unreachable_when_every_server_refuses`.

#[skuld::test]
async fn resolve_reports_no_answer_through_a_real_trusted_resolver_with_no_records() {
    // Trusted chain, real handshake, real HTTP 200 — the reply just carries no
    // address. This is the only branch that may still say "no answer".
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.metadata.response_code = ResponseCode::ServFail;
    msg.add_query(Query::query(Name::from_ascii("proxy.example.").unwrap(), RecordType::A));
    let (cert_der, port) = spawn_loopback_doh(msg.to_vec().unwrap()).await;

    let resolver: IpAddr = "127.0.0.1".parse().unwrap();
    let err = super::resolve_via_doh_with(
        "proxy.example",
        &cfg(vec![resolver], false),
        super::test_loopback_querier(cert_der, port),
    )
    .await
    .unwrap_err();
    assert_eq!(err, BootstrapError::NoAnswer);
}

#[skuld::test]
async fn loopback_doh_stub_serves_the_aaaa_query_after_the_a_query() {
    // Second connection for the AAAA fallback: a single-shot stub would fail
    // that connection at connect and mis-report the cause.
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x35);
    let (cert_der, port) = spawn_loopback_doh(aaaa_reply_for("proxy.example", v6)).await;
    let resolver: IpAddr = "127.0.0.1".parse().unwrap();
    let ip = super::resolve_via_doh_with(
        "proxy.example",
        &cfg(vec![resolver], false),
        super::test_loopback_querier(cert_der, port),
    )
    .await
    .unwrap()
    .server_ip;
    assert_eq!(ip, IpAddr::V6(v6));
}

#[skuld::test]
async fn resolve_via_doh_e2e_through_real_forwarder() {
    let expected = Ipv4Addr::new(203, 0, 113, 42);
    let reply = a_reply_for("proxy.example", expected);
    let (cert_der, port) = spawn_loopback_doh(reply).await;

    // Production path: ForwarderQuerier-equivalent built with the test root +
    // a port override so the DirectConnector reaches the loopback listener.
    let resolver: IpAddr = "127.0.0.1".parse().unwrap();
    let ip = super::resolve_via_doh_with(
        "proxy.example",
        &cfg(vec![resolver], false),
        super::test_loopback_querier(cert_der, port),
    )
    .await
    .unwrap()
    .server_ip;
    assert_eq!(ip, IpAddr::V4(expected));
}
