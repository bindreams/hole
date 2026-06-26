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
