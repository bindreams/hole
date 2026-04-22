use super::{ensure_port_free, free_port, Protocols};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// Protocols ===========================================================================================================

#[skuld::test]
fn protocols_display_single() {
    assert_eq!(format!("{}", Protocols::TCP), "TCP");
    assert_eq!(format!("{}", Protocols::UDP), "UDP");
}

#[skuld::test]
fn protocols_display_combined() {
    assert_eq!(format!("{}", Protocols::TCP | Protocols::UDP), "TCP | UDP");
}

#[skuld::test]
fn protocols_display_empty() {
    assert_eq!(format!("{}", Protocols::empty()), "-");
}

// free_port ===========================================================================================================

#[skuld::test]
async fn free_port_rejects_empty_protocols() {
    let err = free_port(LOCALHOST, Protocols::empty())
        .await
        .expect_err("empty Protocols should be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[skuld::test]
async fn free_port_tcp_only_returns_bindable_port() {
    let port = free_port(LOCALHOST, Protocols::TCP).await.expect("allocate TCP port");
    // The port was free a moment ago; binding TCP on it now should
    // succeed (modulo TOCTOU from concurrent tests, which PORT_ALLOC
    // serialization handles in the broader bridge suite).
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, port))
        .await
        .expect("TCP rebind on returned port");
    drop(listener);
}

#[skuld::test]
async fn free_port_udp_only_returns_bindable_port() {
    let port = free_port(LOCALHOST, Protocols::UDP).await.expect("allocate UDP port");
    let sock = tokio::net::UdpSocket::bind(SocketAddr::new(LOCALHOST, port))
        .await
        .expect("UDP rebind on returned port");
    drop(sock);
}

#[skuld::test]
async fn free_port_tcp_and_udp_returns_port_bindable_on_both() {
    let port = free_port(LOCALHOST, Protocols::TCP | Protocols::UDP)
        .await
        .expect("allocate TCP+UDP port");
    let tcp = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, port))
        .await
        .expect("TCP rebind");
    let udp = tokio::net::UdpSocket::bind(SocketAddr::new(LOCALHOST, port))
        .await
        .expect("UDP rebind on same port");
    drop(tcp);
    drop(udp);
}

// ensure_port_free ====================================================================================================

#[skuld::test]
async fn ensure_port_free_vacuous_empty_protocols() {
    // `ensure_port_free(addr, empty)` is Ok by definition — verifies
    // nothing, so cannot fail. Use port 1 (privileged on Unix) to prove
    // no bind is attempted.
    ensure_port_free(SocketAddr::new(LOCALHOST, 1), Protocols::empty())
        .await
        .expect("vacuous empty protocols should succeed");
}

#[skuld::test]
async fn ensure_port_free_ok_on_free_port() {
    // Pick a fresh port, drop immediately, probe it.
    let port = free_port(LOCALHOST, Protocols::TCP | Protocols::UDP)
        .await
        .expect("allocate port");
    ensure_port_free(SocketAddr::new(LOCALHOST, port), Protocols::TCP | Protocols::UDP)
        .await
        .expect("freshly-allocated port should still be free");
}

#[skuld::test]
async fn ensure_port_free_errors_on_busy_tcp_port() {
    let hostage = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, 0))
        .await
        .expect("bind hostage TCP");
    let busy = hostage.local_addr().expect("local_addr");
    let err = ensure_port_free(busy, Protocols::TCP)
        .await
        .expect_err("TCP probe on held port must fail");
    // `AddrInUse` is the canonical surfacing; `PermissionDenied` /
    // `AddrNotAvailable` are also acceptable on some Windows configs.
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrNotAvailable,
        ),
        "unexpected error kind: {:?} ({err})",
        err.kind()
    );
    drop(hostage);
}

#[skuld::test]
async fn ensure_port_free_errors_on_busy_udp_port() {
    let hostage = tokio::net::UdpSocket::bind(SocketAddr::new(LOCALHOST, 0))
        .await
        .expect("bind hostage UDP");
    let busy = hostage.local_addr().expect("local_addr");
    let err = ensure_port_free(busy, Protocols::UDP)
        .await
        .expect_err("UDP probe on held port must fail");
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrNotAvailable,
        ),
        "unexpected error kind: {:?} ({err})",
        err.kind()
    );
    drop(hostage);
}
