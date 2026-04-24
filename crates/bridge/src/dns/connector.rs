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
//! The trait returns [`ConnectedStream`] — a `BoxedStream` paired with
//! two `AtomicU64` byte counters observed by a [`CountingStream`] wrapper
//! around the underlying socket. The counters are what lets the forwarder
//! log `tcp_wrote` / `tcp_read` on a TLS-layer failure in #248
//! diagnostics: `read=0` means the peer FIN'd before sending a byte;
//! `read=<small>` means mid-handshake close; `read=<KBs>` means full
//! handshake bytes delivered then close.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

/// Bidirectional byte stream used by every TCP-based DNS transport
/// (`PlainTcp`, `Tls`, `Https`). Requiring `Unpin` keeps the
/// `tokio::io::AsyncReadExt` / `AsyncWriteExt` free functions usable on a
/// boxed trait object.
pub trait AsyncDuplex: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> AsyncDuplex for T {}

/// Boxed TCP stream — direct `TcpStream` or a SOCKS5-wrapped
/// `Socks5Stream<TcpStream>` at runtime. Always wrapped in a
/// [`CountingStream`] before boxing, so its byte counts are observable
/// via the paired [`StreamCounters`].
pub type BoxedStream = Box<dyn AsyncDuplex>;

/// Per-stream byte counters handed back by a connector alongside the
/// stream itself. Cheap to clone (two `Arc` bumps).
#[derive(Debug, Default, Clone)]
pub struct StreamCounters {
    read_bytes: Arc<AtomicU64>,
    write_bytes: Arc<AtomicU64>,
}

impl StreamCounters {
    pub fn read(&self) -> u64 {
        self.read_bytes.load(Ordering::Relaxed)
    }

    pub fn written(&self) -> u64 {
        self.write_bytes.load(Ordering::Relaxed)
    }
}

/// A stream paired with its byte counters. Returned by
/// [`UpstreamConnector::connect_tcp`]; callers keep the counters to read
/// on error and hand the stream off to rustls / the plain-TCP exchange.
pub struct ConnectedStream {
    pub stream: BoxedStream,
    pub counters: StreamCounters,
}

impl ConnectedStream {
    /// Split into stream + counters so the stream can be moved into
    /// rustls / framed-exchange while the counters are retained for the
    /// error path.
    pub fn into_parts(self) -> (BoxedStream, StreamCounters) {
        (self.stream, self.counters)
    }
}

/// Wraps an `AsyncRead + AsyncWrite` and increments a pair of
/// `Arc<AtomicU64>` counters on every successful `poll_read` / `poll_write`
/// call. Counts raw bytes on the wrapped stream, *not* decoded-TLS bytes —
/// for SOCKS5-wrapped streams the bytes counted are post-SOCKS5-CONNECT
/// payload bytes, i.e. what a DoH server / plain-TCP peer would see.
pub struct CountingStream<S> {
    inner: S,
    counters: StreamCounters,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            counters: StreamCounters::default(),
        }
    }

    pub fn counters(&self) -> StreamCounters {
        self.counters.clone()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let delta = (buf.filled().len() - before) as u64;
            if delta > 0 {
                self.counters.read_bytes.fetch_add(delta, Ordering::Relaxed);
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            self.counters.write_bytes.fetch_add(*n as u64, Ordering::Relaxed);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

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
    /// Both wrap the resulting socket in a [`CountingStream`] so the
    /// forwarder can log post-SOCKS5 byte counts on error.
    async fn connect_tcp(&self, target: SocketAddr) -> io::Result<ConnectedStream>;

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
    async fn connect_tcp(&self, target: SocketAddr) -> io::Result<ConnectedStream> {
        let stream = TcpStream::connect(target).await?;
        let counting = CountingStream::new(stream);
        let counters = counting.counters();
        Ok(ConnectedStream {
            stream: Box::new(counting),
            counters,
        })
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
