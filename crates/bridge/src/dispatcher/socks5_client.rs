//! SOCKS5 CONNECT client for the proxy dispatch path.

use std::net::IpAddr;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

/// Connect to the target through the SS SOCKS5 local.
///
/// - `local_port`: SS's SOCKS5 listen port on 127.0.0.1.
/// - `dst_ip`: the connection's destination IP (may be a fake-DNS IP).
/// - `dst_port`: the connection's destination port.
/// - `domain`: if available, used as the SOCKS5 target (preferred to
///   prevent DNS leaks).
pub async fn socks5_connect(
    local_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    domain: Option<&str>,
) -> std::io::Result<TcpStream> {
    let proxy_addr = format!("127.0.0.1:{local_port}");
    let stream = match domain {
        Some(d) => {
            let target = format!("{d}:{dst_port}");
            Socks5Stream::connect(proxy_addr.as_str(), target.as_str())
                .await
                .map_err(|e| std::io::Error::other(format!("SOCKS5 connect (domain) failed: {e}")))?
        }
        None => {
            let target = std::net::SocketAddr::new(dst_ip, dst_port);
            Socks5Stream::connect(proxy_addr.as_str(), target)
                .await
                .map_err(|e| std::io::Error::other(format!("SOCKS5 connect (IP) failed: {e}")))?
        }
    };
    Ok(stream.into_inner())
}

#[cfg(test)]
#[path = "socks5_client_tests.rs"]
mod socks5_client_tests;
