//! [`Socks5Connector`] — routes DNS forwarder upstream I/O through the
//! local shadowsocks SOCKS5 listener so user filter rules that `Block`
//! the resolver IP cannot strand the forwarder's own queries.
//!
//! TCP (PlainTcp / DoT / DoH) uses [`tokio_socks::tcp::Socks5Stream`]:
//! SOCKS5 CONNECT, then treat the resulting stream as a bare TCP pipe.
//!
//! UDP (PlainUdp) uses a hand-rolled SOCKS5 UDP ASSOCIATE per RFC 1928 —
//! `tokio-socks` 0.5 ships no UDP helper. The shadowsocks listener can
//! only relay UDP when the configured plugin supports UDP (e.g. galoshes,
//! NOT plain v2ray-plugin). For TCP-only plugins the ASSOCIATE command
//! fails at the SS listener; the forwarder surfaces this as an
//! [`io::Error`] and the dedup'd WARN log in
//! [`super::forwarder::DnsForwarder`] fires exactly once per upstream IP.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_socks::tcp::Socks5Stream;

use crate::dns::connector::{ConnectedStream, CountingStream, UpstreamConnector, UpstreamUdp};

const SOCKS5_VER: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;

/// Routes every outbound connection through the shadowsocks SOCKS5
/// listener.
#[derive(Debug, Clone, Copy)]
pub struct Socks5Connector {
    /// Address of the shadowsocks-service local SOCKS5 listener. Always
    /// loopback in production, injectable for tests.
    pub socks5_listener: SocketAddr,
}

impl Socks5Connector {
    pub fn new(socks5_listener: SocketAddr) -> Self {
        Self { socks5_listener }
    }
}

#[async_trait]
impl UpstreamConnector for Socks5Connector {
    async fn connect_tcp(&self, target: SocketAddr) -> io::Result<ConnectedStream> {
        // Time the SOCKS5 handshake + CONNECT — per #248, this separates
        // "SOCKS5 handshake took 3s" from "handshake instant, but TLS
        // EOF'd immediately after" in the Phase-2 breakdown.
        let started = Instant::now();
        let result = Socks5Stream::connect(self.socks5_listener, target).await;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(stream) => {
                tracing::debug!(%target, elapsed_ms, "Socks5Connector::connect_tcp");
                // `into_inner()` returns the underlying `TcpStream` — after
                // the CONNECT handshake the relay is a pure byte pipe. Wrap
                // in a CountingStream so the forwarder can read post-SOCKS5
                // byte counts on TLS-layer failure (diagnostic for #248).
                let counting = CountingStream::new(stream.into_inner());
                let counters = counting.counters();
                Ok(ConnectedStream {
                    stream: Box::new(counting),
                    counters,
                })
            }
            Err(e) => {
                tracing::debug!(%target, elapsed_ms, error = %e, "Socks5Connector::connect_tcp failed");
                Err(io::Error::other(format!("SOCKS5 CONNECT to {target}: {e}")))
            }
        }
    }

    async fn connect_udp(&self, target: SocketAddr) -> io::Result<Box<dyn UpstreamUdp>> {
        let (control, udp, relay) = udp_associate(self.socks5_listener).await?;
        Ok(Box::new(Socks5Udp {
            _control: Arc::new(Mutex::new(control)),
            udp,
            relay,
            target,
        }))
    }
}

// UDP ASSOCIATE protocol ==============================================================================================

/// Negotiate a SOCKS5 UDP ASSOCIATE session with the proxy. Returns
/// `(control_tcp, local_udp, relay_addr)`:
///
/// - `control_tcp`: the TCP control channel; must stay alive for the
///   duration of the UDP session (its close signals "teardown").
/// - `local_udp`: a freshly bound local UDP socket; the caller sends
///   RFC 1928 §7 UDP request datagrams to `relay_addr`.
/// - `relay_addr`: the UDP relay endpoint reported by the SOCKS5 server.
async fn udp_associate(proxy: SocketAddr) -> io::Result<(TcpStream, UdpSocket, SocketAddr)> {
    let mut tcp = TcpStream::connect(proxy).await?;

    // Greeting: VER | NMETHODS=1 | METHOD=NoAuth
    tcp.write_all(&[SOCKS5_VER, 1, SOCKS5_NO_AUTH]).await?;
    let mut greeting_resp = [0u8; 2];
    tcp.read_exact(&mut greeting_resp).await?;
    if greeting_resp[0] != SOCKS5_VER {
        return Err(io::Error::other(format!(
            "SOCKS5 greeting: bad version {}",
            greeting_resp[0]
        )));
    }
    if greeting_resp[1] != SOCKS5_NO_AUTH {
        return Err(io::Error::other(format!(
            "SOCKS5 greeting: unexpected method {}",
            greeting_resp[1]
        )));
    }

    // Request: VER | CMD=UDP_ASSOCIATE | RSV=0 | ATYP=IPV4 | DST.ADDR=0 | DST.PORT=0
    // `0.0.0.0:0` tells the server "use the IP+port from which I'll be sending".
    let req = [
        SOCKS5_VER,
        SOCKS5_CMD_UDP_ASSOCIATE,
        0,
        SOCKS5_ATYP_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    tcp.write_all(&req).await?;

    // Reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await?;
    if head[0] != SOCKS5_VER {
        return Err(io::Error::other(format!("SOCKS5 reply: bad version {}", head[0])));
    }
    if head[1] != 0 {
        return Err(io::Error::other(format!(
            "SOCKS5 UDP ASSOCIATE rejected (REP={}) — plugin likely TCP-only",
            head[1]
        )));
    }

    let relay_ip: IpAddr = match head[3] {
        SOCKS5_ATYP_IPV4 => {
            let mut a = [0u8; 4];
            tcp.read_exact(&mut a).await?;
            IpAddr::V4(a.into())
        }
        SOCKS5_ATYP_IPV6 => {
            let mut a = [0u8; 16];
            tcp.read_exact(&mut a).await?;
            IpAddr::V6(a.into())
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            tcp.read_exact(&mut name).await?;
            let name = std::str::from_utf8(&name).map_err(|_| io::Error::other("SOCKS5 reply: non-UTF8 BND domain"))?;
            // Most SS implementations return a concrete IP; resolving a
            // domain here would loop through the OS resolver — the very
            // thing the forwarder is meant to replace. Reject.
            return Err(io::Error::other(format!(
                "SOCKS5 UDP ASSOCIATE returned domain BND ('{name}'); expected IP"
            )));
        }
        other => return Err(io::Error::other(format!("SOCKS5 reply: unknown ATYP {other}"))),
    };
    let mut port_bytes = [0u8; 2];
    tcp.read_exact(&mut port_bytes).await?;
    let relay_port = u16::from_be_bytes(port_bytes);
    let relay_reported = SocketAddr::new(relay_ip, relay_port);

    // Some SS implementations return `0.0.0.0` as the BND — meaning
    // "reuse the proxy's IP". Normalize to the proxy IP in that case.
    let relay = if relay_reported.ip().is_unspecified() {
        SocketAddr::new(proxy.ip(), relay_reported.port())
    } else {
        relay_reported
    };

    // Bind a local UDP socket in the family matching the relay.
    let bind_addr: SocketAddr = if relay.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    };
    let udp = UdpSocket::bind(bind_addr).await?;

    Ok((tcp, udp, relay))
}

struct Socks5Udp {
    /// Control TCP connection — held to keep the UDP association alive.
    /// Wrapped in `Arc<Mutex<_>>` only so the struct is `Send + Sync`; we
    /// never need to lock it except at drop time.
    _control: Arc<Mutex<TcpStream>>,
    udp: UdpSocket,
    relay: SocketAddr,
    target: SocketAddr,
}

#[async_trait]
impl UpstreamUdp for Socks5Udp {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let header = socks5_udp_header(self.target);
        let mut framed = Vec::with_capacity(header.len() + buf.len());
        framed.extend_from_slice(&header);
        framed.extend_from_slice(buf);
        self.udp.send_to(&framed, self.relay).await?;
        Ok(buf.len())
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Max SOCKS5 UDP frame header is RSV(2)+FRAG(1)+ATYP(1)+ADDR(16)+PORT(2) = 22
        // bytes. Plus the payload. Read into a big temp buffer, then strip.
        let mut tmp = vec![0u8; buf.len() + 64];
        let (n, _from) = self.udp.recv_from(&mut tmp).await?;
        let (payload_off, _dst) = parse_socks5_udp_header(&tmp[..n])?;
        let payload_len = n - payload_off;
        if payload_len > buf.len() {
            return Err(io::Error::other("SOCKS5 UDP recv: payload overflows caller buffer"));
        }
        buf[..payload_len].copy_from_slice(&tmp[payload_off..n]);
        Ok(payload_len)
    }
}

fn socks5_udp_header(target: SocketAddr) -> Vec<u8> {
    // RSV(2)=0 | FRAG(1)=0 | ATYP | DST.ADDR | DST.PORT
    let mut h = vec![0u8, 0, 0];
    match target.ip() {
        IpAddr::V4(v4) => {
            h.push(SOCKS5_ATYP_IPV4);
            h.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            h.push(SOCKS5_ATYP_IPV6);
            h.extend_from_slice(&v6.octets());
        }
    }
    h.extend_from_slice(&target.port().to_be_bytes());
    h
}

/// Parse a SOCKS5 UDP reply header. Returns the byte offset where the
/// payload starts, and the reported source address.
fn parse_socks5_udp_header(buf: &[u8]) -> io::Result<(usize, SocketAddr)> {
    if buf.len() < 10 {
        return Err(io::Error::other("SOCKS5 UDP reply too short"));
    }
    // RSV(2) | FRAG(1) | ATYP | ...
    if buf[2] != 0 {
        return Err(io::Error::other("SOCKS5 UDP: fragmented replies not supported"));
    }
    let atyp = buf[3];
    let (ip, port_offset) = match atyp {
        SOCKS5_ATYP_IPV4 => {
            let ip = IpAddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]));
            (ip, 8)
        }
        SOCKS5_ATYP_IPV6 => {
            if buf.len() < 4 + 16 + 2 {
                return Err(io::Error::other("SOCKS5 UDP: truncated IPv6 reply"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            (IpAddr::V6(octets.into()), 20)
        }
        SOCKS5_ATYP_DOMAIN => {
            let len = buf[4] as usize;
            if buf.len() < 5 + len + 2 {
                return Err(io::Error::other("SOCKS5 UDP: truncated domain reply"));
            }
            // Don't resolve — treat the source as unknown.
            return Ok((5 + len + 2, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)));
        }
        other => return Err(io::Error::other(format!("SOCKS5 UDP: unknown ATYP {other}"))),
    };
    let port = u16::from_be_bytes([buf[port_offset], buf[port_offset + 1]]);
    Ok((port_offset + 2, SocketAddr::new(ip, port)))
}

#[cfg(test)]
#[path = "socks5_connector_tests.rs"]
mod socks5_connector_tests;
