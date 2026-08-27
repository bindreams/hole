use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::try_wait_for_port;

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

#[skuld::test]
async fn wait_for_port_records_a_refusal_not_a_timeout() {
    let addr = closed_loopback_port().await;

    let failure = try_wait_for_port(addr, Duration::from_millis(500))
        .await
        .expect_err("a closed port should never become connectable");

    assert!(
        !failure.error_counts.contains_key(&None),
        "a refusal must not be recorded as a None-code timeout entry: {:?}",
        failure.error_counts
    );

    #[cfg(windows)]
    assert!(
        failure.error_counts.contains_key(&Some(10061)),
        "expected WSAECONNREFUSED (10061) in the histogram, got {:?}",
        failure.error_counts
    );

    #[cfg(not(windows))]
    {
        // POSIX raw_os_error codes for ECONNREFUSED vary by platform (111
        // on Linux, 61 on macOS); confirm the shape independently via the
        // portable `ErrorKind` on a fresh connect to the same address.
        let err = tokio::net::TcpStream::connect(addr)
            .await
            .expect_err("closed port should still refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    }
}
