//! SOCKS5 CONNECT client for the proxy dispatch path.

use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

/// Connect to the target through a SOCKS5 upstream.
///
/// - `local_port`: SOCKS5 server's listen port on 127.0.0.1.
/// - `dst`: the connection's destination address (IP may be a fake-DNS IP).
/// - `domain`: if available, used as the SOCKS5 target (preferred to
///   prevent DNS leaks).
pub async fn socks5_connect(local_port: u16, dst: SocketAddr, domain: Option<&str>) -> std::io::Result<TcpStream> {
    let proxy_addr = format!("127.0.0.1:{local_port}");
    let stream = match domain {
        Some(d) => {
            let target = format!("{d}:{}", dst.port());
            Socks5Stream::connect(proxy_addr.as_str(), target.as_str())
                .await
                .map_err(|e| std::io::Error::other(format!("SOCKS5 connect (domain) failed: {e}")))?
        }
        None => Socks5Stream::connect(proxy_addr.as_str(), dst)
            .await
            .map_err(|e| std::io::Error::other(format!("SOCKS5 connect (IP) failed: {e}")))?,
    };
    Ok(stream.into_inner())
}

#[cfg(test)]
#[path = "socks5_client_tests.rs"]
mod socks5_client_tests;
