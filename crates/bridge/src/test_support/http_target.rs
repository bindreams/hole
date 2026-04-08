//! HTTP / TCP sentinel helpers for tests that need a controllable "upstream"
//! destination.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Bind a TCP listener on `127.0.0.1:0` that, on the first accept, drains the
/// request (so the client's `write_all` completes cleanly without an RST race),
/// then sends `response` and closes. Returns the bound address and the
/// spawned task handle.
pub(crate) async fn start_fake_sentinel(response: Vec<u8>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut sink = [0u8; 256];
            let _ = sock.read(&mut sink).await;
            let _ = sock.write_all(&response).await;
            let _ = sock.shutdown().await;
        }
    });
    (addr, handle)
}
