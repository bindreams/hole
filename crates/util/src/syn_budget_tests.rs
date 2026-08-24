use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::SynBudget;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// connect =============================================================================================================

#[skuld::test]
async fn connect_reaches_a_live_listener_under_each_budget() {
    for budget in [SynBudget::HostDefault, SynBudget::NoRetransmit] {
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, 0))
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("local_addr");

        let accept = tokio::spawn(async move { listener.accept().await });
        super::connect(addr, budget)
            .await
            .unwrap_or_else(|e| panic!("connect under {budget:?} to a live listener should succeed: {e}"));
        accept
            .await
            .expect("accept task")
            .expect("accept should observe the connection");
    }
}
