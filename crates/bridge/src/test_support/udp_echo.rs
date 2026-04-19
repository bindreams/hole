//! UDP echo-server fixture for E2E tests. Binds on `0.0.0.0:0` and
//! reports the host's primary non-loopback IPv4 address — TUN-mode
//! bridge tests cannot use `127.0.0.1` because the bridge's
//! `route add 127.0.0.1 ...` bypass redirects loopback traffic through
//! the TUN adapter (see `proxy_manager_e2e_tests.rs` `run_full_tunnel_e2e`
//! caveat). `Drop` aborts the echo task.

use crate::test_support::net_discovery::detect_primary_ipv4;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

pub struct UdpEchoServer {
    /// The address tests should send UDP datagrams to. Uses the host's
    /// primary non-loopback IPv4 so packets flow through the TUN device
    /// and back to the local socket.
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl UdpEchoServer {
    pub async fn start() -> std::io::Result<Self> {
        let primary = detect_primary_ipv4().map_err(std::io::Error::other)?;
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let port = sock.local_addr()?.port();
        let addr = SocketAddr::from((primary, port));
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
        Ok(Self { addr, task })
    }
}

impl Drop for UdpEchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
