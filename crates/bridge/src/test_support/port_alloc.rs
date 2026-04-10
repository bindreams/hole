//! Ephemeral TCP port allocation helpers.
//!
//! Tests need unique ephemeral ports for SOCKS5 local binds, v2ray-plugin
//! public-facing bindings, and similar. The kernel's own ephemeral-port
//! allocator is the source of truth; these helpers wrap the "bind to 0,
//! read port, drop" pattern with a consistent TOCTOU caveat.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

/// Pre-allocate a TCP port number and immediately drop the listener. The
/// port is used to construct a bind address before the real owner binds.
/// There is a tiny TOCTOU window between drop and the real bind; in practice
/// the kernel does not reissue freshly-released ports immediately.
pub(crate) async fn allocate_ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Synchronous version for use from non-async test bodies. Same TOCTOU
/// semantics as [`allocate_ephemeral_port`].
pub(crate) fn allocate_ephemeral_port_sync() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
    // listener drops here — port is released.
}

/// Poll-connect to `addr` until either a TCP connection succeeds or
/// `timeout` elapses. Used by tests that spawn a child process which binds
/// asynchronously after the parent function returns. Panics on timeout,
/// including the last OS-level connect error for diagnostics.
pub(crate) async fn wait_for_port(addr: SocketAddr, timeout: Duration) {
    let start = std::time::Instant::now();
    let mut last_err: Option<std::io::Error> = None;
    while start.elapsed() < timeout {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => return,
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("port {addr} did not become connectable within {timeout:?} (last error: {last_err:?})");
}
