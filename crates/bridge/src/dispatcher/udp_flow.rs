//! UDP flow table — tracks active UDP flows by 4-tuple.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

/// 4-tuple identifying a UDP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

/// What to do with datagrams in this flow.
pub enum FlowHandle {
    /// Forward via SOCKS5 UDP relay.
    Proxy { tx: mpsc::Sender<Vec<u8>> },
    /// Forward via interface-bound direct socket.
    Bypass { tx: mpsc::Sender<Vec<u8>> },
    /// Silently drop.
    Blocked,
}

/// A flow table entry: handle + last-activity timestamp.
pub struct FlowEntry {
    pub handle: FlowHandle,
    pub last_activity: Instant,
    /// Domain associated with this flow (for fake DNS unpin on eviction).
    pub domain: Option<String>,
    /// The fake IP that was pinned (for unpin on eviction).
    pub pinned_ip: Option<IpAddr>,
}

/// UDP flow table owned by the driver task.
pub struct FlowTable {
    flows: HashMap<FlowKey, FlowEntry>,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowTable {
    pub fn new() -> Self {
        Self { flows: HashMap::new() }
    }

    pub fn get_mut(&mut self, key: &FlowKey) -> Option<&mut FlowEntry> {
        self.flows.get_mut(key)
    }

    pub fn insert(&mut self, key: FlowKey, entry: FlowEntry) {
        self.flows.insert(key, entry);
    }

    /// Evict flows idle longer than `max_idle`. Returns evicted entries
    /// so the caller can clean up resources (e.g., unpin fake DNS).
    pub fn sweep(&mut self, max_idle: Duration) -> Vec<FlowEntry> {
        let mut evicted = Vec::new();
        let mut to_remove = Vec::new();
        for (key, entry) in &self.flows {
            if entry.last_activity.elapsed() >= max_idle {
                to_remove.push(*key);
            }
        }
        for key in to_remove {
            if let Some(entry) = self.flows.remove(&key) {
                evicted.push(entry);
            }
        }
        evicted
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn clear(&mut self) {
        self.flows.clear();
    }
}

#[cfg(test)]
#[path = "udp_flow_tests.rs"]
mod udp_flow_tests;
