//! Minimal SOCKS5 CONNECT + UDP ASSOCIATE client for tests.
//!
//! Implements just enough of [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)
//! to open a tunneled TCP connection or relay a single UDP datagram
//! through the bridge's local SOCKS5 listener. No auth, no DOMAINNAME
//! ATYP — IPv4 / IPv6 literal addresses only.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

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

/// Perform a SOCKS5 UDP ASSOCIATE exchange through `proxy_addr`, send one
/// encapsulated datagram addressed at `target`, and return the payload of
/// the first reply (stripped of its 10-byte SOCKS5 UDP header).
///
/// Rolls its own wire encoding (does not depend on
/// `tun_engine::helpers::socks5_udp`) so the test stays independent of
/// the implementation under test. Times out after 2s waiting for a
/// reply.
pub(crate) async fn socks5_udp_associate(
    proxy_addr: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    // TCP control channel for the ASSOCIATE lifecycle.
    let mut control = TcpStream::connect(proxy_addr).await?;

    // Greeting + method selection (NoAuth).
    control.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greet = [0u8; 2];
    control.read_exact(&mut greet).await?;
    if greet != [0x05, 0x00] {
        return Err(io::Error::other(format!("SOCKS5 greeting rejected: {greet:?}")));
    }

    // UDP ASSOCIATE request: VER=5, CMD=3, RSV=0, ATYP, ADDR, PORT.
    // RFC 1928 §6 says the DST.ADDR may be 0 — we use IPv4 0.0.0.0:0
    // because we don't know which local UDP port we'll bind yet.
    let mut req = vec![0x05, 0x03, 0x00, 0x01];
    req.extend_from_slice(&[0, 0, 0, 0]);
    req.extend_from_slice(&[0, 0]);
    control.write_all(&req).await?;

    // Reply: VER=5, REP, RSV=0, ATYP, BND.ADDR, BND.PORT.
    let mut reply_head = [0u8; 4];
    control.read_exact(&mut reply_head).await?;
    if reply_head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 UDP ASSOCIATE failed with REP={}",
            reply_head[1]
        )));
    }
    let relay_addr = match reply_head[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            control.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            control.read_exact(&mut port).await?;
            SocketAddr::from((ip, u16::from_be_bytes(port)))
        }
        0x04 => {
            let mut ip = [0u8; 16];
            control.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            control.read_exact(&mut port).await?;
            SocketAddr::from((ip, u16::from_be_bytes(port)))
        }
        other => {
            return Err(io::Error::other(format!(
                "SOCKS5 UDP ASSOCIATE: unsupported ATYP {other}"
            )));
        }
    };

    let local_udp = UdpSocket::bind("127.0.0.1:0").await?;

    // SOCKS5 UDP datagram per §7: RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT + DATA.
    let mut dgram = vec![0x00, 0x00, 0x00];
    match target {
        SocketAddr::V4(v4) => {
            dgram.push(0x01);
            dgram.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            dgram.push(0x04);
            dgram.extend_from_slice(&v6.ip().octets());
        }
    }
    dgram.extend_from_slice(&target.port().to_be_bytes());
    dgram.extend_from_slice(payload);
    local_udp.send_to(&dgram, relay_addr).await?;

    let mut reply = vec![0u8; 65_536];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), local_udp.recv_from(&mut reply))
        .await
        .map_err(|_| io::Error::other("SOCKS5 UDP reply timeout"))??;

    // Strip header. Minimum header size for IPv4: 3 + 1 + 4 + 2 = 10 bytes.
    if n < 4 {
        return Err(io::Error::other("SOCKS5 UDP reply shorter than header"));
    }
    let header_len = match reply[3] {
        0x01 => 3 + 1 + 4 + 2,
        0x04 => 3 + 1 + 16 + 2,
        other => {
            return Err(io::Error::other(format!("SOCKS5 UDP reply: unsupported ATYP {other}")));
        }
    };
    if n < header_len {
        return Err(io::Error::other(format!(
            "SOCKS5 UDP reply ({n} bytes) shorter than expected header ({header_len})"
        )));
    }

    // Hold the control channel open until we've got the reply — some
    // SOCKS5 servers close the UDP relay when the TCP control dies.
    drop(control);

    Ok(reply[header_len..n].to_vec())
}
