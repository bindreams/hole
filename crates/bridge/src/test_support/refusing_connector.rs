//! `UpstreamConnector` stubs for tests that need a specific upstream failure
//! shape from the DNS forwarder.

use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;

use crate::dns::connector::{
    ConnectedStream, CountingStream, DatagramCounters, DirectConnector, UpstreamConnector, UpstreamUdp,
};

/// Refuses `connect_tcp` / `connect_udp` with `ConnectionRefused`.
///
/// Deliberately used INSTEAD of a real closed socket. "Connect to a port
/// nothing is listening on" has no portable failure shape, so it cannot pin an
/// exact failure layer: macOS black-holes connects to a bound-but-unlistened
/// socket (the attempt runs to the full budget and reports `layer=timeout`
/// rather than `layer=connect`), and GitHub's Windows runners drop SYNs to
/// closed ephemeral loopback ports (see `server_test_tests.rs`). A released
/// ephemeral port is also re-bindable by a concurrent test.
///
/// `UpstreamConnector` is the codebase's seam for exactly this: the OS socket
/// is not what these tests are about — the classification and logging of a
/// connect-layer failure is.
#[derive(Debug)]
pub(crate) struct RefusingConnector {
    /// Addresses to refuse. Empty = refuse everything; otherwise anything not
    /// listed is dialled for real, so a test can pair a refused primary with a
    /// live secondary.
    refuse: Vec<SocketAddr>,
}

impl RefusingConnector {
    /// Refuse every target.
    pub(crate) fn all() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self { refuse: Vec::new() })
    }

    /// Refuse only `refuse`; dial anything else for real.
    pub(crate) fn only(refuse: Vec<SocketAddr>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self { refuse })
    }

    fn refuses(&self, target: SocketAddr) -> bool {
        self.refuse.is_empty() || self.refuse.contains(&target)
    }
}

/// Never completes a connect. Pairs with `tokio::time::pause()` to drive
/// budget-expiry paths on virtual time, without any wall-clock wait.
#[derive(Debug)]
pub(crate) struct HangingConnector;

#[async_trait::async_trait]
impl UpstreamConnector for HangingConnector {
    async fn connect_tcp(&self, _target: SocketAddr) -> io::Result<ConnectedStream> {
        std::future::pending().await
    }

    async fn connect_udp(&self, _target: SocketAddr) -> io::Result<Box<dyn UpstreamUdp>> {
        std::future::pending().await
    }
}

#[async_trait::async_trait]
impl UpstreamConnector for RefusingConnector {
    async fn connect_tcp(&self, target: SocketAddr) -> io::Result<ConnectedStream> {
        if self.refuses(target) {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refusing connector"));
        }
        DirectConnector.connect_tcp(target).await
    }

    async fn connect_udp(&self, target: SocketAddr) -> io::Result<Box<dyn UpstreamUdp>> {
        if self.refuses(target) {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refusing connector"));
        }
        DirectConnector.connect_udp(target).await
    }
}

// Silent ==============================================================================================================

/// Connects, accepts writes, and never delivers a byte back — the shape of a
/// black-holed tunnel. `shadowsocks-service`'s SOCKS5 answers `Succeeded` as
/// soon as it reaches the plugin's local port, so a dead plugin transport looks
/// exactly like this from the forwarder: a connection that swallows the query
/// and answers nothing.
///
/// [`Self::new`] hands back a receiver that fires on the first connect, so a
/// test can pause the clock only once the attempt is genuinely in flight. That
/// signal is client-side and the writes complete synchronously, so unlike a
/// real socket there is no OS readiness left for `tokio::time::pause` to race.
#[derive(Debug)]
pub(crate) struct SilentConnector {
    connected: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl SilentConnector {
    pub(crate) fn new() -> (std::sync::Arc<Self>, tokio::sync::oneshot::Receiver<()>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        (
            std::sync::Arc::new(Self {
                connected: Mutex::new(Some(tx)),
            }),
            rx,
        )
    }

    fn signal_connected(&self) {
        if let Some(tx) = self.connected.lock().expect("poisoned").take() {
            let _ = tx.send(());
        }
    }
}

#[async_trait::async_trait]
impl UpstreamConnector for SilentConnector {
    async fn connect_tcp(&self, _target: SocketAddr) -> io::Result<ConnectedStream> {
        let counting = CountingStream::new(SilentStream);
        let counters = counting.counters();
        self.signal_connected();
        Ok(ConnectedStream {
            stream: Box::new(counting),
            counters,
        })
    }

    async fn connect_udp(&self, _target: SocketAddr) -> io::Result<Box<dyn UpstreamUdp>> {
        self.signal_connected();
        Ok(Box::new(SilentUdp {
            counters: DatagramCounters::default(),
        }))
    }
}

/// Accepts every write; never completes a read.
struct SilentStream;

impl tokio::io::AsyncRead for SilentStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Pending
    }
}

impl tokio::io::AsyncWrite for SilentStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Accepts every datagram; never delivers one back.
struct SilentUdp {
    counters: DatagramCounters,
}

#[async_trait::async_trait]
impl UpstreamUdp for SilentUdp {
    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.counters.add_written(buf.len() as u64);
        Ok(buf.len())
    }
    async fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
        std::future::pending().await
    }
    fn counters(&self) -> DatagramCounters {
        self.counters.clone()
    }
}
