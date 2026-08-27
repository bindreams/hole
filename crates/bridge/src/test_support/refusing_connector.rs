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
/// rather than `layer=connect`). Windows instead *refuses* that same shape —
/// it is not a black hole there — but only after paying its own
/// SYN-retransmission budget (`util::syn_budget`), so whether a real closed
/// socket reports a connect-layer or a timeout-layer cause on Windows depends
/// on whether the test's own budget happens to exceed the host's. A released
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

/// Hangs `connect_tcp` for the listed targets and answers one length-prefixed
/// DNS reply from memory for every other target — the shape a failover test
/// needs: a primary that consumes its whole budget, then a secondary that
/// answers.
///
/// Socket-free on BOTH sides on purpose. `tokio::time::pause()` auto-advances
/// the clock whenever the runtime has nothing to run, so a stub backed by a
/// real loopback socket would race its own I/O against virtual time and could
/// see the secondary's budget fire before its reply arrived. Answering
/// in-process removes the race rather than narrowing it.
#[derive(Debug)]
pub(crate) struct HangThenAnswer {
    hang: Vec<SocketAddr>,
    /// `[len:2][reply]`, ready to hand to a fresh [`CannedReplyStream`].
    framed: Vec<u8>,
}

impl HangThenAnswer {
    /// `reply` is the wire-format DNS reply the non-hanging targets answer.
    pub(crate) fn new(hang: Vec<SocketAddr>, reply: &[u8]) -> std::sync::Arc<Self> {
        let mut framed = Vec::with_capacity(2 + reply.len());
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(reply);
        std::sync::Arc::new(Self { hang, framed })
    }
}

#[async_trait::async_trait]
impl UpstreamConnector for HangThenAnswer {
    async fn connect_tcp(&self, target: SocketAddr) -> io::Result<ConnectedStream> {
        if self.hang.contains(&target) {
            std::future::pending::<()>().await;
        }
        let counting = CountingStream::new(CannedReplyStream {
            remaining: self.framed.clone(),
        });
        let counters = counting.counters();
        Ok(ConnectedStream {
            stream: Box::new(counting),
            counters,
        })
    }

    async fn connect_udp(&self, _target: SocketAddr) -> io::Result<Box<dyn UpstreamUdp>> {
        std::future::pending().await
    }
}

/// Accepts every write; serves `remaining` to successive reads, then stays
/// pending. `exchange_tcp_framed` reads the 2-byte length and then the body, so
/// draining one buffer across two reads is exactly what it expects.
struct CannedReplyStream {
    remaining: Vec<u8>,
}

impl tokio::io::AsyncRead for CannedReplyStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.remaining.is_empty() {
            return std::task::Poll::Pending;
        }
        let n = self.remaining.len().min(buf.remaining());
        let chunk: Vec<u8> = self.remaining.drain(..n).collect();
        buf.put_slice(&chunk);
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for CannedReplyStream {
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

// Gated ===============================================================================================================

/// Publishes a signal the instant `connect_tcp` is entered, blocks until
/// released, then answers one length-prefixed DNS reply from memory and stays
/// pending — the shape a "slow but alive" gate test needs: rendezvous on the
/// connect having started, advance virtual time under that rendezvous (not a
/// timer), then release and observe the reply arrive.
///
/// Socket-free, like [`HangThenAnswer`] / [`SilentConnector`] — see their docs
/// for why: a real loopback socket would race its own I/O readiness against
/// `tokio::time::pause()`'s auto-advance.
#[derive(Debug)]
pub(crate) struct GatedConnector {
    connect_requested: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    reply: Vec<u8>,
}

impl GatedConnector {
    /// `(connector, connect_requested, release)` — publishes on
    /// `connect_requested` the moment `connect_tcp` is entered, blocks until
    /// `release` is sent, then answers one length-prefixed DNS query with
    /// `reply`, entirely in memory.
    pub(crate) fn new(
        reply: Vec<u8>,
    ) -> (
        std::sync::Arc<Self>,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (requested_tx, requested_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        (
            std::sync::Arc::new(Self {
                connect_requested: Mutex::new(Some(requested_tx)),
                release: Mutex::new(Some(release_rx)),
                reply,
            }),
            requested_rx,
            release_tx,
        )
    }
}

#[async_trait::async_trait]
impl UpstreamConnector for GatedConnector {
    async fn connect_tcp(&self, _target: SocketAddr) -> io::Result<ConnectedStream> {
        if let Some(tx) = self.connect_requested.lock().expect("poisoned").take() {
            let _ = tx.send(());
        }
        let release = self
            .release
            .lock()
            .expect("poisoned")
            .take()
            .expect("GatedConnector::connect_tcp called more than once");
        let _ = release.await;

        let mut framed = Vec::with_capacity(2 + self.reply.len());
        framed.extend_from_slice(&(self.reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&self.reply);

        let counting = CountingStream::new(CannedReplyStream { remaining: framed });
        let counters = counting.counters();
        Ok(ConnectedStream {
            stream: Box::new(counting),
            counters,
        })
    }

    async fn connect_udp(&self, _target: SocketAddr) -> io::Result<Box<dyn UpstreamUdp>> {
        std::future::pending().await
    }
}

// Silent ==============================================================================================================

/// Connects, accepts writes, and never delivers a byte back — the shape of a
/// black-holed tunnel, and (per [`crate::proxy::ProxyError::TunnelSilent`])
/// exactly what a dead plugin transport looks like from the forwarder.
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
