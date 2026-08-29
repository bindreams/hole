//! Tests for [`udp_flow`]. Downstream dispatch tests hold the peer it
//! returns for exactly one reason — to keep the flow open — so what the
//! peer's lifetime does to the flow is the contract worth pinning.

use super::*;

use std::io::ErrorKind;
use std::net::SocketAddr;

fn key() -> FlowKey {
    FlowKey {
        src: "10.255.0.2:51000".parse::<SocketAddr>().unwrap(),
        dst: "8.8.8.8:443".parse::<SocketAddr>().unwrap(),
    }
}

#[skuld::test]
async fn a_flow_carries_its_key_and_stays_open_while_the_peer_lives() {
    let key = key();
    let (flow, _peer) = udp_flow(key);

    assert_eq!(flow.key(), key);
    flow.send(b"reply").await.expect("the peer still holds the reply end");
}

#[skuld::test]
async fn dropping_the_peer_is_the_engine_going_away() {
    let (mut flow, peer) = udp_flow(key());

    drop(peer);

    // Both channel ends are gone, so neither call can park: `recv` sees a
    // closed flow and `send` sees no writer.
    assert!(flow.recv().await.is_none(), "recv outlived the engine");
    assert_eq!(flow.send(b"reply").await.unwrap_err().kind(), ErrorKind::BrokenPipe);
}
