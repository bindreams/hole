use std::net::{IpAddr, SocketAddr};

use super::BlockLog;

fn sa(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip.parse::<IpAddr>().unwrap(), port)
}

#[skuld::test]
fn first_block_is_always_logged() {
    let mut log = BlockLog::new();
    assert!(log.should_log(0, sa("10.0.0.1", 443)));
}

#[skuld::test]
fn same_tuple_suppressed_within_one_second() {
    let mut log = BlockLog::new();
    let dst = sa("10.0.0.1", 443);

    assert!(log.should_log(0, dst));
    assert!(!log.should_log(0, dst));
    assert!(!log.should_log(0, dst));
}

#[skuld::test]
fn different_tuple_is_not_suppressed() {
    let mut log = BlockLog::new();

    assert!(log.should_log(0, sa("10.0.0.1", 443)));
    assert!(log.should_log(0, sa("10.0.0.2", 443)));
    assert!(log.should_log(0, sa("10.0.0.1", 80)));
}

#[skuld::test]
fn different_rule_index_not_suppressed() {
    let mut log = BlockLog::new();
    let dst = sa("10.0.0.1", 443);

    assert!(log.should_log(0, dst));
    assert!(log.should_log(1, dst));
}

#[skuld::test]
fn lru_eviction_allows_re_logging() {
    let mut log = BlockLog::with_capacity(2);
    let dst1 = sa("10.0.0.1", 443);
    let dst2 = sa("10.0.0.2", 443);
    let dst3 = sa("10.0.0.3", 443);

    // Fill the cache with two entries.
    assert!(log.should_log(0, dst1));
    assert!(log.should_log(0, dst2));

    // Third entry evicts dst1.
    assert!(log.should_log(0, dst3));

    // dst1 was evicted, so it should be logged again.
    assert!(log.should_log(0, dst1));

    // dst2 and dst3 are still suppressed.
    assert!(!log.should_log(0, dst3));
}
