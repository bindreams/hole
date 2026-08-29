//! A [`UdpFlow`] whose engine-side channel ends the caller owns.

use tokio::sync::mpsc;

use crate::engine::udp_flow::{FlowKey, FlowTable, UdpFlow, UdpReply};

/// Matches the driver's own reply-channel capacity, so a simulated flow
/// backpressures where the engine would.
const REPLY_CHANNEL_CAPACITY: usize = 1024;

/// Build a [`UdpFlow`] for `key`, plus the peer that holds it open.
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
    (
        flow,
        UdpFlowPeer {
            _inbound: inbound,
            _reply_rx: reply_rx,
        },
    )
}

/// The engine's half of a simulated [`UdpFlow`] — the inbound sender the
/// driver's flow table would hold and the reply receiver its writer task
/// would drain.
///
/// Hold it for at least as long as the flow. Dropping it is the engine
/// going away: `UdpFlow::recv` then yields `None` and `UdpFlow::send`
/// fails.
pub struct UdpFlowPeer {
    // Underscored because they are held, not read: the flow's liveness is
    // all these two ends are here for. Units that move datagrams through
    // them come later.
    _inbound: mpsc::Sender<Vec<u8>>,
    _reply_rx: mpsc::Receiver<UdpReply>,
}

#[cfg(test)]
#[path = "flow_tests.rs"]
mod flow_tests;
