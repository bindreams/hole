//! UDP echo-server fixture for E2E tests.
//!
//! Two binding shapes:
//!
//! * [`UdpEchoServer::start`] — binds `0.0.0.0:0` and reports the host's
//!   primary non-loopback IPv4. Required for TUN-mode tests because the
//!   bridge's `route add 127.0.0.1 ...` bypass redirects loopback
//!   traffic around the TUN adapter (see
//!   `proxy_manager_e2e_tests.rs` `run_full_tunnel_e2e` caveat).
//! * [`UdpEchoServer::start_loopback`] — binds and reports
//!   `127.0.0.1:0`. For SocksOnly-mode tests, where there is no TUN
//!   and therefore no loopback bypass; loopback delivery is direct.
//!
//! `Drop` aborts the echo task.

use crate::test_support::net_discovery::detect_primary_ipv4;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

pub struct UdpEchoServer {
    /// The address tests should send UDP datagrams to.
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl UdpEchoServer {
    /// Bind `0.0.0.0:0` and report the host's primary non-loopback IPv4.
    pub async fn start() -> std::io::Result<Self> {
        let primary = detect_primary_ipv4().map_err(std::io::Error::other)?;
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let port = sock.local_addr()?.port();
        let reported = SocketAddr::from((primary, port));
        Ok(Self::spawn(sock, reported))
    }

    /// Bind and report `127.0.0.1:0`. For tests that don't go through TUN.
    pub async fn start_loopback() -> std::io::Result<Self> {
        let sock = UdpSocket::bind("127.0.0.1:0").await?;
        let reported = sock.local_addr()?;
        Ok(Self::spawn(sock, reported))
    }

    fn spawn(sock: UdpSocket, reported: SocketAddr) -> Self {
        let sock = Arc::new(sock);
        let server_sock = Arc::clone(&sock);
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                match server_sock.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        // Echo back to the recv_from origin. Ignore send
                        // errors — clients may already be gone.
                        let _ = server_sock.send_to(&buf[..n], src).await;
                    }
                    Err(_) => return,
                }
            }
        });
        Self { addr: reported, task }
    }
}

impl Drop for UdpEchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
