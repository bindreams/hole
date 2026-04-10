//! Minimal SOCKS5 CONNECT client for tests.
//!
//! Implements just enough of [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)
//! to open a tunneled TCP connection through the bridge's local SOCKS5
//! listener and read the response. No auth, no UDP ASSOCIATE, no
//! DOMAINNAME — IPv4 / IPv6 literal addresses only.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Connect to `target` through a SOCKS5 proxy at `proxy_addr`, send `request_bytes`,
/// and return everything the target sent back until EOF (or `max_bytes`).
///
/// Used by e2e tests to send a tiny HTTP/1.0 GET through the bridge's
/// SOCKS5 local and verify the upstream HTTP target responds with the
/// expected sentinel.
pub(crate) async fn socks5_request(
    proxy_addr: SocketAddr,
    target: SocketAddr,
    request_bytes: &[u8],
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let mut sock = TcpStream::connect(proxy_addr).await?;

    // 1. Greeting: VER=5, NMETHODS=1, METHODS=[0x00 NoAuth]
    sock.write_all(&[0x05, 0x01, 0x00]).await?;

    // 2. Method selection reply: VER=5, METHOD=0x00
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await?;
    if greet != [0x05, 0x00] {
        return Err(std::io::Error::other(format!("SOCKS5 greeting rejected: {greet:?}")));
    }

    // 3. CONNECT request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP, ADDR, PORT
    let mut req = vec![0x05, 0x01, 0x00];
    match target {
        SocketAddr::V4(v4) => {
            req.push(0x01); // ATYP = IPv4
            req.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            req.push(0x04); // ATYP = IPv6
            req.extend_from_slice(&v6.ip().octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    sock.write_all(&req).await?;

    // 4. CONNECT reply: VER=5, REP, RSV=0, ATYP, BND.ADDR, BND.PORT
    let mut reply_head = [0u8; 4];
    sock.read_exact(&mut reply_head).await?;
    if reply_head[0] != 0x05 {
        return Err(std::io::Error::other(format!(
            "SOCKS5 reply has wrong VER: {}",
            reply_head[0]
        )));
    }
    if reply_head[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "SOCKS5 CONNECT failed with REP={}",
            reply_head[1]
        )));
    }
    // Drain BND.ADDR + BND.PORT according to ATYP
    let bnd_len = match reply_head[3] {
        0x01 => 4 + 2,  // IPv4 + port
        0x04 => 16 + 2, // IPv6 + port
        0x03 => {
            // DOMAINNAME: 1 length byte + N bytes + 2 port
            let mut len_byte = [0u8; 1];
            sock.read_exact(&mut len_byte).await?;
            len_byte[0] as usize + 2
        }
        other => {
            return Err(std::io::Error::other(format!("SOCKS5 reply has unknown ATYP: {other}")));
        }
    };
    let mut bnd = vec![0u8; bnd_len];
    sock.read_exact(&mut bnd).await?;

    // 5. Tunnel is open. Send the request bytes and read until EOF.
    sock.write_all(request_bytes).await?;
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    while response.len() < max_bytes {
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n.min(max_bytes - response.len())]);
    }
    Ok(response)
}

/// Build a minimal HTTP/1.0 GET request for the given path with the right
/// `Host` header. Used by tests that hit the [`super::http_target::HttpTarget`]
/// fixture.
pub(crate) fn http_get_request(host: &SocketAddr, path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        host = host,
    )
    .into_bytes()
}

/// Convenience: extract the body from a raw HTTP/1.0 response by skipping
/// past the `\r\n\r\n` header terminator. Returns `None` if not present.
pub(crate) fn http_response_body(response: &[u8]) -> Option<&[u8]> {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &response[i + 4..])
}
