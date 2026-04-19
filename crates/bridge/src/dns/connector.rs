//! Upstream connectors used by the DNS forwarder.
//!
//! Two impls live behind [`UpstreamConnector`]:
//!
//! - [`DirectConnector`] — plain loopback / direct connection to an
//!   upstream resolver. Used in tests and in the not-yet-wired sub-step
//!   (c) path.
//! - `Socks5Connector` (sub-step d) — routes every outbound connection
//!   through the local shadowsocks SOCKS5 listener so user filter rules
//!   cannot strand the forwarder.
//!
//! The trait deliberately returns type-erased streams so a SOCKS5 impl
//! can substitute `tokio_socks::tcp::Socks5Stream<TcpStream>` at the same
//! interface point as a bare `TcpStream`.

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};

/// Bidirectional byte stream used by every TCP-based DNS transport
/// (`PlainTcp`, `Tls`, `Https`). Requiring `Unpin` keeps the
/// `tokio::io::AsyncReadExt` / `AsyncWriteExt` free functions usable on a
/// boxed trait object.
pub trait AsyncDuplex: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> AsyncDuplex for T {}

/// Boxed TCP stream — direct `TcpStream` or a SOCKS5-wrapped
/// `Socks5Stream<TcpStream>` at runtime.
pub type BoxedStream = Box<dyn AsyncDuplex>;

/// UDP send/recv abstraction. Separate from [`AsyncDuplex`] because the
/// SOCKS5 UDP ASSOCIATE path wraps an inner socket and prepends a header,
/// which is orthogonal to the AsyncRead/AsyncWrite shape.
#[async_trait]
pub trait UpstreamUdp: Send + Sync {
    /// Send one DNS datagram.
    async fn send(&self, buf: &[u8]) -> io::Result<usize>;
    /// Receive one DNS datagram. Returns the number of bytes read.
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
}

#[async_trait]
pub trait UpstreamConnector: Send + Sync {
    /// Open a TCP connection to `target`. SOCKS5 impls route via the
    /// shadowsocks listener; the direct impl just calls `TcpStream::connect`.
    async fn connect_tcp(&self, target: SocketAddr) -> io::Result<BoxedStream>;

    /// Open a UDP socket, bound locally and connected to `target`.
    /// SOCKS5 impls perform UDP ASSOCIATE, which only succeeds when the
    /// plugin carries UDP.
    async fn connect_udp(&self, target: SocketAddr) -> io::Result<Box<dyn UpstreamUdp>>;
}

// Direct ==============================================================================================================

/// Opens connections straight to the target, with no SOCKS5 wrapping.
/// Used by tests and as a fallback when no SOCKS5 listener is available.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectConnector;

#[async_trait]
impl UpstreamConnector for DirectConnector {
    async fn connect_tcp(&self, target: SocketAddr) -> io::Result<BoxedStream> {
        let stream = TcpStream::connect(target).await?;
        Ok(Box::new(stream))
    }

    async fn connect_udp(&self, target: SocketAddr) -> io::Result<Box<dyn UpstreamUdp>> {
        let local: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(target).await?;
        Ok(Box::new(DirectUdp { socket }))
    }
}

struct DirectUdp {
    socket: UdpSocket,
}

#[async_trait]
impl UpstreamUdp for DirectUdp {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf).await
    }
}
