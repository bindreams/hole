use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use super::*;

fn sample_key() -> FlowKey {
    FlowKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 12345,
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        dst_port: 443,
    }
}

fn blocked_entry() -> FlowEntry {
    FlowEntry {
        handle: FlowHandle::Blocked,
        last_activity: Instant::now(),
        domain: None,
        pinned_ip: None,
    }
}

#[skuld::test]
fn insert_and_lookup() {
    let mut table = FlowTable::new();
    let key = sample_key();
    table.insert(key, blocked_entry());
    assert!(table.get_mut(&key).is_some());
}

#[skuld::test]
fn sweep_evicts_idle() {
    let mut table = FlowTable::new();
    let key = sample_key();
    table.insert(
        key,
        FlowEntry {
            handle: FlowHandle::Blocked,
            last_activity: Instant::now() - Duration::from_secs(120),
            domain: Some("example.com".into()),
            pinned_ip: None,
        },
    );
    let evicted = table.sweep(Duration::from_secs(60));
    assert_eq!(evicted.len(), 1);
    assert_eq!(evicted[0].domain.as_deref(), Some("example.com"));
    assert_eq!(table.len(), 0);
}

#[skuld::test]
fn sweep_keeps_active() {
    let mut table = FlowTable::new();
    let key = sample_key();
    table.insert(key, blocked_entry());
    let evicted = table.sweep(Duration::from_secs(60));
    assert!(evicted.is_empty());
    assert_eq!(table.len(), 1);
}

#[skuld::test]
fn clear_empties_table() {
    let mut table = FlowTable::new();
    table.insert(sample_key(), blocked_entry());
    assert_eq!(table.len(), 1);
    table.clear();
    assert_eq!(table.len(), 0);
}
