//! A [`UdpFlow`] with both channel ends in the caller's hands.

use std::net::SocketAddr;

use tokio::sync::mpsc;

use crate::engine::udp_flow::{FlowKey, FlowTable, UdpFlow, UdpReply};

/// Matches the driver's own reply-channel capacity, so a simulated flow
/// backpressures where the engine would.
const REPLY_CHANNEL_CAPACITY: usize = 1024;

/// A reply the router injected back toward the TUN — the public shape of
/// the crate-private `UdpReply`. `src`/`dst` are already swapped relative
/// to the flow's key, as [`UdpFlow::send`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// Build a [`UdpFlow`] for `key`, plus the engine-side ends of its two
/// channels.
///
/// `UdpFlow`'s fields are private and its only constructor is
/// `FlowTable::insert_new`, which the driver owns; outside this crate a
/// `UdpFlow` cannot exist without a running engine. That is the entire
/// reason this helper exists.
pub fn udp_flow(key: FlowKey) -> (UdpFlow, UdpFlowPeer) {
    let (reply_tx, reply_rx) = mpsc::channel(REPLY_CHANNEL_CAPACITY);
    // Route through the driver's own constructor rather than rebuilding
    // the flow's innards, so the double cannot drift from the real thing.
    let mut table = FlowTable::new();
    let flow = table.insert_new(key, reply_tx);
    let inbound = table
        .get_mut(&key)
        .expect("insert_new just inserted this key")
        .tx
        .clone();
    (flow, UdpFlowPeer { inbound, reply_rx })
}

/// The engine's half of a simulated [`UdpFlow`].
pub struct UdpFlowPeer {
    inbound: mpsc::Sender<Vec<u8>>,
    reply_rx: mpsc::Receiver<UdpReply>,
}

impl UdpFlowPeer {
    /// Deliver an inbound datagram, as the driver does for a packet off
    /// the TUN. The flow's `recv()` yields it.
    pub async fn deliver(&self, payload: Vec<u8>) {
        self.inbound.send(payload).await.expect("the UdpFlow was dropped");
    }

    /// The next reply the router injected, or `None` once the flow and
    /// every [`UdpSender`](crate::UdpSender) derived from it are dropped.
    pub async fn next_reply(&mut self) -> Option<Reply> {
        self.reply_rx.recv().await.map(|reply| Reply {
            src: reply.src,
            dst: reply.dst,
            payload: reply.payload,
        })
    }

    /// Close the flow, as the driver's idle sweep does: the flow's
    /// `recv()` then yields `None`.
    pub fn close(self) {}
}
