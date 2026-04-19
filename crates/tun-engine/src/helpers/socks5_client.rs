//! SOCKS5 CONNECT client for the proxy dispatch path.

use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

/// Connect to the target through a SOCKS5 upstream.
///
/// - `proxy`: full SOCKS5 server address. Typically a loopback address
///   for an in-process SS listener, but the helper does not constrain
///   it.
/// - `dst`: the connection's destination address. The SOCKS5 server
///   connects to exactly this `(IP, port)` — the caller is responsible
///   for any name resolution upstream of this helper.
pub async fn socks5_connect(proxy: SocketAddr, dst: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = Socks5Stream::connect(proxy, dst)
        .await
        .map_err(|e| std::io::Error::other(format!("SOCKS5 connect failed: {e}")))?;
    Ok(stream.into_inner())
}

#[cfg(test)]
#[path = "socks5_client_tests.rs"]
mod socks5_client_tests;
