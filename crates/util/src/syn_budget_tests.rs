use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::SynBudget;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Bind an ephemeral loopback port and immediately drop the listener, so
/// the returned address is (modulo TOCTOU against a concurrent bind) a
/// closed port with nothing listening.
async fn closed_loopback_port() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, 0))
        .await
        .expect("bind ephemeral loopback port");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    addr
}

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

#[skuld::test]
#[cfg(windows)]
async fn no_retransmit_refuses_a_closed_port_far_faster_than_the_host_default() {
    let addr = closed_loopback_port().await;

    let pinned_start = tokio::time::Instant::now();
    let pinned_err = super::connect(addr, SynBudget::NoRetransmit)
        .await
        .expect_err("a closed port must refuse, not connect");
    let pinned_elapsed = pinned_start.elapsed();
    assert_eq!(pinned_err.kind(), std::io::ErrorKind::ConnectionRefused);

    let default_start = tokio::time::Instant::now();
    let default_err = super::connect(addr, SynBudget::HostDefault)
        .await
        .expect_err("a closed port must refuse, not connect");
    let default_elapsed = default_start.elapsed();
    assert_eq!(default_err.kind(), std::io::ErrorKind::ConnectionRefused);

    // Timing assertions are measurements of the OS's own behaviour, not a
    // synchronisation mechanism between two things this test controls.
    assert!(
        pinned_elapsed < Duration::from_millis(100),
        "NoRetransmit should refuse in ~0.1 ms, took {pinned_elapsed:?}"
    );
    assert!(
        default_elapsed >= pinned_elapsed.saturating_mul(10),
        "HostDefault ({default_elapsed:?}) should take at least 10x NoRetransmit ({pinned_elapsed:?})"
    );
}

// set_no_syn_retransmissions ==========================================================================================

#[skuld::test]
#[cfg(windows)]
async fn set_no_syn_retransmissions_surfaces_an_ioctl_failure() {
    use std::os::windows::io::{FromRawSocket, IntoRawSocket};

    // SIO_TCP_INITIAL_RTO is TCP-specific. Applying it to a UDP socket's
    // handle makes the ioctl fail deterministically, without racing the OS
    // to reuse a handle this process just closed.
    let udp = std::net::UdpSocket::bind(SocketAddr::new(LOCALHOST, 0)).expect("bind UDP socket");
    let raw = udp.into_raw_socket();
    let mismatched = unsafe { tokio::net::TcpSocket::from_raw_socket(raw) };

    super::set_no_syn_retransmissions(&mismatched).expect_err("SIO_TCP_INITIAL_RTO on a UDP socket should fail");
}
