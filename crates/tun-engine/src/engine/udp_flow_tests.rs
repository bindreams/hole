use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::sync::mpsc;

use super::*;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

fn key() -> FlowKey {
    FlowKey {
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
    }
}

// FlowTable ===========================================================================================================

#[skuld::test]
fn insert_new_registers_flow() {
    let mut table = FlowTable::new();
    let (tx, _rx) = mpsc::channel(8);
    assert_eq!(table.len(), 0);
    let _flow = table.insert_new(key(), tx);
    assert_eq!(table.len(), 1);
    assert!(table.get_mut(&key()).is_some());
}

#[skuld::test]
fn sweep_evicts_idle_flows_and_drops_tx() {
    rt().block_on(async {
        let mut table = FlowTable::new();
        let (reply_tx, _reply_rx) = mpsc::channel(8);
        let mut flow = table.insert_new(key(), reply_tx);

        // Backdate last_activity to appear idle.
        {
            let entry = table.get_mut(&key()).unwrap();
            entry.last_activity = std::time::Instant::now() - Duration::from_secs(60);
        }

        let evicted = table.sweep(Duration::from_secs(30));
        assert_eq!(evicted, 1);
        assert_eq!(table.len(), 0);

        // After sweep, the flow's rx should see None (sender dropped).
        assert!(flow.recv().await.is_none());
    });
}

#[skuld::test]
fn sweep_keeps_active_flows() {
    let mut table = FlowTable::new();
    let (tx, _rx) = mpsc::channel(8);
    let _flow = table.insert_new(key(), tx);

    let evicted = table.sweep(Duration::from_secs(30));
    assert_eq!(evicted, 0);
    assert_eq!(table.len(), 1);
}

// UdpFlow =============================================================================================================

#[skuld::test]
fn flow_recv_delivers_inbound() {
    rt().block_on(async {
        let mut table = FlowTable::new();
        let (reply_tx, _reply_rx) = mpsc::channel(8);
        let mut flow = table.insert_new(key(), reply_tx);

        // Push an inbound datagram via the internal entry's tx.
        let entry = table.get_mut(&key()).unwrap();
        entry.tx.send(b"ping".to_vec()).await.unwrap();

        let got = flow.recv().await.unwrap();
        assert_eq!(got, b"ping");
    });
}

#[skuld::test]
fn flow_send_constructs_reply_with_swapped_tuple() {
    rt().block_on(async {
        let mut table = FlowTable::new();
        let (reply_tx, mut reply_rx) = mpsc::channel(8);
        let flow = table.insert_new(key(), reply_tx);

        flow.send(b"pong").await.unwrap();

        let reply = reply_rx.recv().await.unwrap();
        assert_eq!(reply.src, key().dst);
        assert_eq!(reply.dst, key().src);
        assert_eq!(reply.payload, b"pong");
    });
}

#[skuld::test]
fn flow_recv_returns_none_on_engine_drop() {
    rt().block_on(async {
        let mut table = FlowTable::new();
        let (reply_tx, _reply_rx) = mpsc::channel(8);
        let mut flow = table.insert_new(key(), reply_tx);

        // Dropping the table drops all internal entry tx senders.
        drop(table);

        assert!(flow.recv().await.is_none());
    });
}
