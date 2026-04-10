use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, RecordType};
use ipnet::{Ipv4Net, Ipv6Net};

use super::*;

// Helpers =============================================================================================================

fn build_query(domain: &str, qtype: RecordType) -> Vec<u8> {
    let name = Name::from_str(domain).unwrap();
    let mut request = Message::new();
    request.set_id(0x1234);
    request.set_message_type(MessageType::Query);
    request.set_op_code(OpCode::Query);
    request.set_recursion_desired(true);
    request.add_query(hickory_proto::op::Query::query(name, qtype));
    request.to_vec().unwrap()
}

fn parse_response(bytes: &[u8]) -> Message {
    Message::from_vec(bytes).unwrap()
}

fn answer_ipv4(msg: &Message) -> Option<Ipv4Addr> {
    msg.answers().iter().find_map(|r| {
        if let RData::A(A(ip)) = r.data() {
            Some(*ip)
        } else {
            None
        }
    })
}

fn answer_ipv6(msg: &Message) -> Option<Ipv6Addr> {
    msg.answers().iter().find_map(|r| {
        if let RData::AAAA(AAAA(ip)) = r.data() {
            Some(*ip)
        } else {
            None
        }
    })
}

fn small_pools() -> (Ipv4Net, Ipv6Net) {
    // 198.18.0.0/30 — 4 addresses, makes pool exhaustion testable.
    let v4 = Ipv4Net::new(Ipv4Addr::new(198, 18, 0, 0), 30).unwrap();
    let v6 = Ipv6Net::new(Ipv6Addr::new(0xfd00, 0, 0, 0xff00, 0, 0, 0, 0), 126).unwrap();
    (v4, v6)
}

// Construction ========================================================================================================

#[skuld::test]
fn with_defaults_succeeds() {
    let _ = FakeDns::with_defaults();
}

#[skuld::test]
fn default_pool_constants_parse() {
    let v4 = DEFAULT_POOL_V4.parse::<Ipv4Net>().unwrap();
    assert_eq!(v4.prefix_len(), 15);
    let v6 = DEFAULT_POOL_V6.parse::<Ipv6Net>().unwrap();
    assert_eq!(v6.prefix_len(), 64);
}

// A queries ===========================================================================================================

#[skuld::test]
fn a_query_returns_fake_ip_in_pool() {
    let dns = FakeDns::with_defaults();
    let request = build_query("example.com.", RecordType::A);
    let response = parse_response(&dns.handle_udp(&request));

    assert_eq!(response.message_type(), MessageType::Response);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.id(), 0x1234);

    let pool: Ipv4Net = DEFAULT_POOL_V4.parse().unwrap();
    let ip = answer_ipv4(&response).expect("expected an A record");
    assert!(pool.contains(&ip), "{ip} not in pool {pool}");
}

#[skuld::test]
fn a_query_for_same_domain_returns_same_ip() {
    let dns = FakeDns::with_defaults();
    let r1 = parse_response(&dns.handle_udp(&build_query("a.example.com.", RecordType::A)));
    let r2 = parse_response(&dns.handle_udp(&build_query("a.example.com.", RecordType::A)));
    assert_eq!(answer_ipv4(&r1), answer_ipv4(&r2));
}

#[skuld::test]
fn a_query_for_different_domains_returns_different_ips() {
    let dns = FakeDns::with_defaults();
    let r1 = parse_response(&dns.handle_udp(&build_query("a.com.", RecordType::A)));
    let r2 = parse_response(&dns.handle_udp(&build_query("b.com.", RecordType::A)));
    assert_ne!(answer_ipv4(&r1), answer_ipv4(&r2));
}

#[skuld::test]
fn a_query_response_ttl_is_fake_dns_ttl() {
    let dns = FakeDns::with_defaults();
    let response = parse_response(&dns.handle_udp(&build_query("example.com.", RecordType::A)));
    let ttl = response.answers()[0].ttl();
    assert_eq!(ttl, FAKE_DNS_TTL);
}

#[skuld::test]
fn a_query_canonicalizes_domain_case() {
    // Querying for `Example.COM.` should produce the same fake IP as
    // `example.com.` because the bimap key is lowercased.
    let dns = FakeDns::with_defaults();
    let r1 = parse_response(&dns.handle_udp(&build_query("Example.COM.", RecordType::A)));
    let r2 = parse_response(&dns.handle_udp(&build_query("example.com.", RecordType::A)));
    assert_eq!(answer_ipv4(&r1), answer_ipv4(&r2));
}

// AAAA queries ========================================================================================================

#[skuld::test]
fn aaaa_query_returns_fake_ipv6_in_pool() {
    let dns = FakeDns::with_defaults();
    let response = parse_response(&dns.handle_udp(&build_query("example.com.", RecordType::AAAA)));
    let pool: Ipv6Net = DEFAULT_POOL_V6.parse().unwrap();
    let ip = answer_ipv6(&response).expect("expected an AAAA record");
    assert!(pool.contains(&ip), "{ip} not in pool {pool}");
}

#[skuld::test]
fn a_and_aaaa_for_same_domain_yield_separate_ips() {
    // Same domain queried for both families gets a fake v4 and a fake
    // v6, both pinned to that domain in the bimap.
    let dns = FakeDns::with_defaults();
    let r4 = parse_response(&dns.handle_udp(&build_query("dual.example.", RecordType::A)));
    let r6 = parse_response(&dns.handle_udp(&build_query("dual.example.", RecordType::AAAA)));
    let v4 = answer_ipv4(&r4).unwrap();
    let v6 = answer_ipv6(&r6).unwrap();

    assert_eq!(dns.forward_lookup_v4("dual.example"), Some(v4));
    assert_eq!(dns.forward_lookup_v6("dual.example"), Some(v6));
    assert_eq!(dns.reverse_lookup(IpAddr::V4(v4)).as_deref(), Some("dual.example"));
    assert_eq!(dns.reverse_lookup(IpAddr::V6(v6)).as_deref(), Some("dual.example"));
}

// Other query types ===================================================================================================

#[skuld::test]
fn mx_query_returns_noerror_empty() {
    let dns = FakeDns::with_defaults();
    let response = parse_response(&dns.handle_udp(&build_query("example.com.", RecordType::MX)));
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.answers().len(), 0);
}

#[skuld::test]
fn txt_query_returns_noerror_empty() {
    let dns = FakeDns::with_defaults();
    let response = parse_response(&dns.handle_udp(&build_query("example.com.", RecordType::TXT)));
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.answers().len(), 0);
}

#[skuld::test]
fn srv_query_returns_noerror_empty() {
    let dns = FakeDns::with_defaults();
    let response = parse_response(&dns.handle_udp(&build_query("_xmpp._tcp.example.com.", RecordType::SRV)));
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.answers().len(), 0);
}

// Reverse lookup ======================================================================================================

#[skuld::test]
fn reverse_lookup_returns_domain() {
    let dns = FakeDns::with_defaults();
    let response = parse_response(&dns.handle_udp(&build_query("foo.test.", RecordType::A)));
    let ip = answer_ipv4(&response).unwrap();
    assert_eq!(dns.reverse_lookup(IpAddr::V4(ip)).as_deref(), Some("foo.test"));
}

#[skuld::test]
fn reverse_lookup_unknown_ip_returns_none() {
    let dns = FakeDns::with_defaults();
    assert!(dns.reverse_lookup(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).is_none());
}

#[skuld::test]
fn reverse_lookup_canonicalizes_v4_mapped_v6() {
    let dns = FakeDns::with_defaults();
    let response = parse_response(&dns.handle_udp(&build_query("mapped.test.", RecordType::A)));
    let ip = answer_ipv4(&response).unwrap();
    let v6_form = IpAddr::V6(Ipv6Addr::new(
        0,
        0,
        0,
        0,
        0,
        0xffff,
        ((u32::from(ip) >> 16) & 0xffff) as u16,
        (u32::from(ip) & 0xffff) as u16,
    ));
    assert_eq!(dns.reverse_lookup(v6_form).as_deref(), Some("mapped.test"));
}

#[skuld::test]
fn forward_lookup_returns_allocated_ip() {
    let dns = FakeDns::with_defaults();
    let response = parse_response(&dns.handle_udp(&build_query("forward.test.", RecordType::A)));
    let ip = answer_ipv4(&response).unwrap();
    assert_eq!(dns.forward_lookup_v4("forward.test"), Some(ip));
    assert_eq!(dns.forward_lookup_v4("nonexistent.test"), None);
}

// Pin / unpin =========================================================================================================

#[skuld::test]
fn pin_prevents_lru_eviction() {
    let (v4, v6) = small_pools();
    let dns = FakeDns::new(v4, v6);

    // Allocate one IP and pin it.
    let r = parse_response(&dns.handle_udp(&build_query("pinned.test.", RecordType::A)));
    let pinned_ip = answer_ipv4(&r).unwrap();
    dns.pin(IpAddr::V4(pinned_ip));

    // Allocate enough other domains to fill and overflow the pool.
    // /30 = 4 addresses (one is pinned, three available). Allocate
    // five more domains; LRU eviction will recycle the unpinned ones,
    // never the pinned one.
    for i in 0..5u32 {
        let _ = dns.handle_udp(&build_query(&format!("burn{i}.test."), RecordType::A));
    }

    // The pinned IP should still resolve to its original domain.
    assert_eq!(
        dns.reverse_lookup(IpAddr::V4(pinned_ip)).as_deref(),
        Some("pinned.test")
    );
}

#[skuld::test]
fn unpin_releases_for_eviction() {
    let (v4, v6) = small_pools();
    let dns = FakeDns::new(v4, v6);

    let _ = dns.handle_udp(&build_query("temp.test.", RecordType::A));
    let original_ip = dns.forward_lookup_v4("temp.test").unwrap();
    dns.pin(IpAddr::V4(original_ip));
    dns.unpin(IpAddr::V4(original_ip));

    // Now eligible for eviction. Burn enough new domains to evict it.
    // /30 has 4 IPs; we need to push 'temp.test' out of the LRU. Use
    // the forward map to detect eviction (the IP slot itself is reused
    // for a different domain).
    for i in 0..10u32 {
        let _ = dns.handle_udp(&build_query(&format!("burn{i}.test."), RecordType::A));
    }
    assert_eq!(
        dns.forward_lookup_v4("temp.test"),
        None,
        "temp.test should have been evicted from the forward map"
    );
    assert_ne!(
        dns.reverse_lookup(IpAddr::V4(original_ip)).as_deref(),
        Some("temp.test"),
        "the original IP slot should no longer map to temp.test"
    );
}

#[skuld::test]
fn pin_is_refcounted() {
    let (v4, v6) = small_pools();
    let dns = FakeDns::new(v4, v6);

    let _ = dns.handle_udp(&build_query("rc.test.", RecordType::A));
    let original_ip = dns.forward_lookup_v4("rc.test").unwrap();
    dns.pin(IpAddr::V4(original_ip));
    dns.pin(IpAddr::V4(original_ip));
    dns.unpin(IpAddr::V4(original_ip));

    // Still pinned (refcount 1). Burn the rest of the pool — should
    // remain unaffected. The forward map and the reverse lookup of
    // the *original* IP both still point to "rc.test".
    for i in 0..10u32 {
        let _ = dns.handle_udp(&build_query(&format!("burn{i}.test."), RecordType::A));
    }
    assert_eq!(dns.forward_lookup_v4("rc.test"), Some(original_ip));
    assert_eq!(dns.reverse_lookup(IpAddr::V4(original_ip)).as_deref(), Some("rc.test"));

    // Final unpin → the entry returns to the LRU and the next round
    // of pressure evicts it.
    dns.unpin(IpAddr::V4(original_ip));
    for i in 10..20u32 {
        let _ = dns.handle_udp(&build_query(&format!("burn{i}.test."), RecordType::A));
    }
    assert_eq!(
        dns.forward_lookup_v4("rc.test"),
        None,
        "rc.test should have been evicted after final unpin"
    );
}

#[skuld::test]
fn unpin_unknown_ip_is_noop() {
    let dns = FakeDns::with_defaults();
    dns.unpin(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))); // does not panic
}

#[skuld::test]
fn pin_unknown_ip_is_noop() {
    let dns = FakeDns::with_defaults();
    dns.pin(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))); // does not panic
}

// Pool exhaustion =====================================================================================================

#[skuld::test]
fn pool_exhausted_when_all_pinned_returns_servfail() {
    // /30 = 4 addresses. Allocate and pin all four.
    let (v4, v6) = small_pools();
    let dns = FakeDns::new(v4, v6);

    for i in 0..4u32 {
        let r = parse_response(&dns.handle_udp(&build_query(&format!("d{i}.test."), RecordType::A)));
        let ip = answer_ipv4(&r).unwrap();
        dns.pin(IpAddr::V4(ip));
    }

    // Fifth allocation: pool exhausted, no eviction possible → SERVFAIL.
    let response = parse_response(&dns.handle_udp(&build_query("overflow.test.", RecordType::A)));
    assert_eq!(response.response_code(), ResponseCode::ServFail);
    assert!(response.answers().is_empty());
}

// Malformed input =====================================================================================================

#[skuld::test]
fn empty_payload_returns_empty_vec() {
    let dns = FakeDns::with_defaults();
    let resp = dns.handle_udp(&[]);
    assert!(resp.is_empty());
}

#[skuld::test]
fn one_byte_payload_returns_empty_vec() {
    let dns = FakeDns::with_defaults();
    let resp = dns.handle_udp(&[0xff]);
    assert!(resp.is_empty());
}

#[skuld::test]
fn malformed_payload_returns_formerr_with_id() {
    let dns = FakeDns::with_defaults();
    // Two-byte ID prefix, then garbage. The fake DNS should respond
    // with FORMERR carrying the original ID.
    let payload = [0xab, 0xcd, 0xff, 0xff, 0xff];
    let resp_bytes = dns.handle_udp(&payload);
    assert!(!resp_bytes.is_empty());
    let resp = parse_response(&resp_bytes);
    assert_eq!(resp.id(), 0xabcd);
    assert_eq!(resp.response_code(), ResponseCode::FormErr);
}

// IPv4-mapped IPv6 in pin/unpin =======================================================================================

#[skuld::test]
fn pin_canonicalizes_v4_mapped_v6() {
    let (v4, v6) = small_pools();
    let dns = FakeDns::new(v4, v6);

    let r = parse_response(&dns.handle_udp(&build_query("mapped.test.", RecordType::A)));
    let ip = answer_ipv4(&r).unwrap();

    // Pin via the v4-mapped v6 form; reverse lookup via plain v4
    // should still find the entry.
    let mapped = IpAddr::V6(Ipv6Addr::new(
        0,
        0,
        0,
        0,
        0,
        0xffff,
        ((u32::from(ip) >> 16) & 0xffff) as u16,
        (u32::from(ip) & 0xffff) as u16,
    ));
    dns.pin(mapped);
    assert_eq!(dns.reverse_lookup(IpAddr::V4(ip)).as_deref(), Some("mapped.test"));
}
