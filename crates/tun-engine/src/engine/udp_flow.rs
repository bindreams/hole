//! UDP flow abstraction exposed to the caller's [`Router`](super::Router).
//!
//! For each inbound UDP 5-tuple the engine sees for the first time, it
//! creates a [`UdpFlow`] and hands it to `Router::route_udp`. The Router
//! loops on [`UdpFlow::recv`] for inbound datagrams and calls
//! [`UdpFlow::send`] to inject replies (source/dest auto-swapped).
//!
//! When the engine's idle-sweep evicts the flow (or the engine is
//! cancelled), the internal sender drops, `recv` returns `None`, and the
//! Router task exits — the Router's RAII cleanup runs automatically.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

// Public ==============================================================================================================

/// 5-tuple identifying a UDP flow (src addr + src port + dst addr + dst
/// port + implicit proto = UDP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// A UDP reply destined for the TUN side — the engine's driver wraps it
/// into an IP+UDP packet with source/dest swapped from the Router's flow
/// and writes it back to the TUN.
pub(crate) struct UdpReply {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// The caller-facing handle to a single UDP flow.
///
/// Obtained as an argument to [`Router::route_udp`](super::Router::route_udp).
/// The Router consumes it until either the client side closes (TUN-side
/// packets stop arriving and the engine's idle sweep evicts it) or the
/// Router itself drops the flow (same effect as returning from the task).
pub struct UdpFlow {
    key: FlowKey,
    rx: mpsc::Receiver<Vec<u8>>,
    reply_tx: mpsc::Sender<UdpReply>,
}

impl UdpFlow {
    /// Wait for the next inbound datagram in this flow.
    ///
    /// Returns `None` when the engine closes the flow — typically because
    /// the idle-sweep fired (no TUN-side activity for
    /// `EngineConfig::udp_flow_idle_timeout`), or because the engine was
    /// cancelled. The Router's natural idiom is:
    ///
    /// ```ignore
    /// while let Some(pkt) = flow.recv().await {
    ///     // handle...
    /// }
    /// ```
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// Inject a reply datagram back to the TUN side.
    ///
    /// The source/destination are auto-swapped from the flow's 5-tuple:
    /// the reply's source is the flow's original destination and vice
    /// versa. The engine handles IP + UDP header construction and
    /// checksumming.
    ///
    /// Returns `Err` only if the engine has already shut down.
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        send_reply(&self.reply_tx, self.key, payload).await
    }

    /// Return a cheap clonable send-only handle for this flow.
    ///
    /// Useful when the Router spawns a sub-task that needs to inject
    /// replies asynchronously while the main loop owns `&mut self` for
    /// [`recv`](Self::recv).
    pub fn sender(&self) -> UdpSender {
        UdpSender {
            key: self.key,
            reply_tx: self.reply_tx.clone(),
        }
    }

    /// The flow's 5-tuple. Rarely needed by the Router itself (the metadata
    /// is already passed separately as `UdpMeta`), but exposed for
    /// diagnostic/logging use.
    pub fn key(&self) -> FlowKey {
        self.key
    }
}

/// Clone-able send-only half of a [`UdpFlow`]. Obtained via
/// [`UdpFlow::sender`].
#[derive(Clone)]
pub struct UdpSender {
    key: FlowKey,
    reply_tx: mpsc::Sender<UdpReply>,
}

impl UdpSender {
    /// Inject a reply datagram — same semantics as [`UdpFlow::send`].
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        send_reply(&self.reply_tx, self.key, payload).await
    }
}

async fn send_reply(reply_tx: &mpsc::Sender<UdpReply>, key: FlowKey, payload: &[u8]) -> io::Result<()> {
    reply_tx
        .send(UdpReply {
            src: key.dst,
            dst: key.src,
            payload: payload.to_vec(),
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "engine shut down"))
}

// Internal ============================================================================================================

/// Per-flow state the driver keeps in its flow table.
///
/// Not exposed — the engine owns the lifecycle of flows; consumers interact
/// only through [`UdpFlow`].
pub(crate) struct FlowEntry {
    /// Send inbound datagrams to the `UdpFlow`. Dropping this causes the
    /// Router's `flow.recv()` to return `None`.
    pub(crate) tx: mpsc::Sender<Vec<u8>>,
    pub(crate) last_activity: Instant,
}

/// Flow capacity — how many inbound datagrams can be buffered per flow
/// before the driver backpressures (drops new datagrams for that flow).
const FLOW_CHANNEL_CAPACITY: usize = 128;

/// UDP flow table owned by the driver task.
pub(crate) struct FlowTable {
    flows: HashMap<FlowKey, FlowEntry>,
}

impl FlowTable {
    pub(crate) fn new() -> Self {
        Self { flows: HashMap::new() }
    }

    pub(crate) fn get_mut(&mut self, key: &FlowKey) -> Option<&mut FlowEntry> {
        self.flows.get_mut(key)
    }

    /// Insert a new flow and return both the internal entry handle and the
    /// caller-facing [`UdpFlow`] that should be passed to `Router::route_udp`.
    pub(crate) fn insert_new(&mut self, key: FlowKey, reply_tx: mpsc::Sender<UdpReply>) -> UdpFlow {
        let (tx, rx) = mpsc::channel(FLOW_CHANNEL_CAPACITY);
        self.flows.insert(
            key,
            FlowEntry {
                tx,
                last_activity: Instant::now(),
            },
        );
        UdpFlow { key, rx, reply_tx }
    }

    /// Evict flows idle longer than `max_idle`. Dropped entries' `tx`
    /// channels close, causing each Router's `flow.recv()` to return None.
    pub(crate) fn sweep(&mut self, max_idle: Duration) -> usize {
        let mut to_remove = Vec::new();
        for (key, entry) in &self.flows {
            if entry.last_activity.elapsed() >= max_idle {
                to_remove.push(*key);
            }
        }
        let count = to_remove.len();
        for key in to_remove {
            self.flows.remove(&key);
        }
        count
    }

    pub(crate) fn len(&self) -> usize {
        self.flows.len()
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.flows.clear();
    }
}

#[cfg(test)]
#[path = "udp_flow_tests.rs"]
mod udp_flow_tests;
