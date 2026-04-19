//! UDP echo-server fixture for E2E tests. Binds `127.0.0.1:0` and
//! echoes every datagram back to its sender. Keyed to per-test use —
//! `Drop` aborts the echo task.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

pub struct UdpEchoServer {
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl UdpEchoServer {
    pub async fn start() -> std::io::Result<Self> {
        let sock = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = sock.local_addr()?;
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
