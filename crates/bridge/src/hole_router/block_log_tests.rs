use std::net::IpAddr;

use super::BlockLog;

#[skuld::test]
fn first_block_is_always_logged() {
    let mut log = BlockLog::new();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(log.should_log(0, ip, 443));
}

#[skuld::test]
fn same_tuple_suppressed_within_one_second() {
    let mut log = BlockLog::new();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    assert!(log.should_log(0, ip, 443));
    assert!(!log.should_log(0, ip, 443));
    assert!(!log.should_log(0, ip, 443));
}

#[skuld::test]
fn different_tuple_is_not_suppressed() {
    let mut log = BlockLog::new();
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    assert!(log.should_log(0, ip1, 443));
    assert!(log.should_log(0, ip2, 443));
    assert!(log.should_log(0, ip1, 80));
}

#[skuld::test]
fn different_rule_index_not_suppressed() {
    let mut log = BlockLog::new();
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    assert!(log.should_log(0, ip, 443));
    assert!(log.should_log(1, ip, 443));
}

#[skuld::test]
fn lru_eviction_allows_re_logging() {
    let mut log = BlockLog::with_capacity(2);
    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();
    let ip3: IpAddr = "10.0.0.3".parse().unwrap();

    // Fill the cache with two entries.
    assert!(log.should_log(0, ip1, 443));
    assert!(log.should_log(0, ip2, 443));

    // Third entry evicts ip1.
    assert!(log.should_log(0, ip3, 443));

    // ip1 was evicted, so it should be logged again.
    assert!(log.should_log(0, ip1, 443));

    // ip2 and ip3 are still suppressed.
    assert!(!log.should_log(0, ip3, 443));
}
