//! SOCKS5 UDP Associate client for the proxy dispatch path.
//!
//! Implements the UDP ASSOCIATE command (RFC 1928 §4, §7) to relay UDP
//! datagrams through the shadowsocks SOCKS5 local.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

// SOCKS5 UDP datagram encoding/decoding ===============================================================================

/// Encode a SOCKS5 UDP datagram (RFC 1928 §7).
///
/// When `domain` is `Some`, the ATYP=Domain form is used (preferred —
/// it lets the proxy resolve the name and avoids DNS leaks). Otherwise
/// ATYP=IPv4/IPv6 is used with `dst_ip`.
pub fn encode_socks5_udp(dst_ip: IpAddr, dst_port: u16, domain: Option<&str>, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // RSV (2 bytes) + FRAG (1 byte)
    buf.extend_from_slice(&[0x00, 0x00, 0x00]);

    if let Some(d) = domain {
        // ATYP = Domain (0x03)
        buf.push(0x03);
        let domain_bytes = d.as_bytes();
        // Length prefix (1 byte) — domain names > 255 bytes are invalid per
        // RFC 1928 but we truncate defensively.
        buf.push(domain_bytes.len().min(255) as u8);
        buf.extend_from_slice(&domain_bytes[..domain_bytes.len().min(255)]);
    } else {
        match dst_ip {
            IpAddr::V4(v4) => {
                buf.push(0x01); // ATYP = IPv4
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(0x04); // ATYP = IPv6
                buf.extend_from_slice(&v6.octets());
            }
        }
    }

    // DST.PORT (2 bytes, big-endian)
    buf.extend_from_slice(&dst_port.to_be_bytes());
    // DATA
    buf.extend_from_slice(payload);
    buf
}

/// Decode a SOCKS5 UDP datagram header (RFC 1928 §7).
///
/// Returns `(src_ip, src_port, header_len)` so the payload starts at
/// `data[header_len..]`. Returns `None` if the datagram is malformed or
/// fragmented (FRAG != 0).
pub fn decode_socks5_udp(data: &[u8]) -> Option<(IpAddr, u16, usize)> {
    // Minimum: RSV(2) + FRAG(1) + ATYP(1) + addr(4 for IPv4) + port(2) = 10
    if data.len() < 10 {
        return None;
    }

    // FRAG != 0 means a fragmented datagram — we don't support reassembly.
    if data[2] != 0x00 {
        return None;
    }

    let atyp = data[3];
    match atyp {
        0x01 => {
            // IPv4: 4 bytes address
            if data.len() < 10 {
                return None;
            }
            let ip = IpAddr::V4(Ipv4Addr::new(data[4], data[5], data[6], data[7]));
            let port = u16::from_be_bytes([data[8], data[9]]);
            Some((ip, port, 10))
        }
        0x03 => {
            // Domain: 1-byte length + domain string (we return 0.0.0.0 as IP
            // since the caller typically doesn't need it for incoming replies).
            let dlen = data[4] as usize;
            let header_len = 4 + 1 + dlen + 2;
            if data.len() < header_len {
                return None;
            }
            let port = u16::from_be_bytes([data[4 + 1 + dlen], data[4 + 1 + dlen + 1]]);
            Some((IpAddr::V4(Ipv4Addr::UNSPECIFIED), port, header_len))
        }
        0x04 => {
            // IPv6: 16 bytes address
            let header_len = 4 + 16 + 2; // 22
            if data.len() < header_len {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = IpAddr::V6(octets.into());
            let port = u16::from_be_bytes([data[20], data[21]]);
            Some((ip, port, header_len))
        }
        _ => None,
    }
}

// SOCKS5 UDP relay session ============================================================================================

/// A live SOCKS5 UDP Associate session.
///
/// The TCP `control` connection MUST stay open for the lifetime of the
/// relay — closing it signals the SOCKS5 server to tear down the UDP
/// association (RFC 1928 §6).
pub struct Socks5UdpRelay {
    #[allow(dead_code)]
    control: TcpStream,
    socket: UdpSocket,
    relay_addr: SocketAddr,
}

impl Socks5UdpRelay {
    /// Perform a SOCKS5 UDP ASSOCIATE handshake against the SS local on
    /// `127.0.0.1:{local_port}` and return the ready-to-use relay.
    pub async fn associate(local_port: u16) -> io::Result<Self> {
        let proxy_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port);

        // Step 1: TCP connect to SOCKS5 server.
        let mut control = TcpStream::connect(proxy_addr).await?;

        // Step 2: Auth negotiation — NO AUTH (method 0x00).
        control.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut auth_reply = [0u8; 2];
        control.read_exact(&mut auth_reply).await?;
        if auth_reply != [0x05, 0x00] {
            return Err(io::Error::other(format!(
                "SOCKS5 auth failed: {:02x} {:02x}",
                auth_reply[0], auth_reply[1]
            )));
        }

        // Step 3: UDP ASSOCIATE request.
        // CMD=0x03 (UDP ASSOCIATE), ATYP=0x01, ADDR=0.0.0.0, PORT=0
        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await?;

        // Step 4: Read reply.
        let mut reply_head = [0u8; 4];
        control.read_exact(&mut reply_head).await?;
        if reply_head[1] != 0x00 {
            return Err(io::Error::other(format!(
                "SOCKS5 UDP ASSOCIATE failed: REP={:#04x}",
                reply_head[1]
            )));
        }

        let relay_addr = match reply_head[3] {
            0x01 => {
                // IPv4
                let mut addr_buf = [0u8; 4];
                control.read_exact(&mut addr_buf).await?;
                let mut port_buf = [0u8; 2];
                control.read_exact(&mut port_buf).await?;
                let ip = Ipv4Addr::from(addr_buf);
                let port = u16::from_be_bytes(port_buf);
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            0x04 => {
                // IPv6
                let mut addr_buf = [0u8; 16];
                control.read_exact(&mut addr_buf).await?;
                let mut port_buf = [0u8; 2];
                control.read_exact(&mut port_buf).await?;
                let ip = std::net::Ipv6Addr::from(addr_buf);
                let port = u16::from_be_bytes(port_buf);
                SocketAddr::new(IpAddr::V6(ip), port)
            }
            atyp => {
                return Err(io::Error::other(format!(
                    "SOCKS5 UDP ASSOCIATE: unsupported BND.ATYP={atyp:#04x}"
                )));
            }
        };

        // Replace 0.0.0.0 with localhost (shadowsocks-rust returns 0.0.0.0
        // when it means "same host as the control connection").
        let relay_addr = if relay_addr.ip().is_unspecified() {
            SocketAddr::new(proxy_addr.ip(), relay_addr.port())
        } else {
            relay_addr
        };

        // Step 5: Bind a local UDP socket and "connect" to the relay address.
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(relay_addr).await?;

        Ok(Self {
            control,
            socket,
            relay_addr,
        })
    }

    /// Send a datagram through the relay.
    pub async fn send_to(&self, dst_ip: IpAddr, dst_port: u16, domain: Option<&str>, payload: &[u8]) -> io::Result<()> {
        let pkt = encode_socks5_udp(dst_ip, dst_port, domain, payload);
        self.socket.send(&pkt).await?;
        Ok(())
    }

    /// Receive a datagram from the relay. Returns `(payload_len, src_ip, src_port)`.
    ///
    /// The caller's `buf` receives the full SOCKS5 UDP datagram; the payload
    /// starts at `buf[header_len..]` where `header_len` is derived from
    /// [`decode_socks5_udp`].
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, IpAddr, u16)> {
        let n = self.socket.recv(buf).await?;
        let (src_ip, src_port, header_len) =
            decode_socks5_udp(&buf[..n]).ok_or_else(|| io::Error::other("malformed SOCKS5 UDP reply"))?;

        // Shift payload to the front of buf for convenience.
        let payload_len = n - header_len;
        buf.copy_within(header_len..n, 0);

        Ok((payload_len, src_ip, src_port))
    }

    /// The relay address returned by the SOCKS5 server.
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }
}

#[cfg(test)]
#[path = "socks5_udp_tests.rs"]
mod socks5_udp_tests;
