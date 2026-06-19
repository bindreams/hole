use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::AsyncReadExt as _;
use futures::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

/// Maximum buffered outbound datagrams per UDP association before new ones are
/// dropped. Bounded (not unbounded) so a stalled association — e.g. yamux
/// backpressure while the app floods UDP — can't grow without limit; dropping
/// on a full buffer is the correct lossy-UDP semantic. This is a buffer size,
/// not a retry/timeout budget.
const UDP_ASSOC_CHANNEL_CAPACITY: usize = 64;

/// Default UDP NAT idle-eviction timeout when `udp_timeout` is not configured
/// in `SS_PLUGIN_OPTIONS`. Matches shadowsocks-rust's `udp_timeout` default.
pub const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(300);

// Protocol framing ====================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamTag {
    Tcp = 0x01,
    Udp = 0x02,
}

impl StreamTag {
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Tcp),
            0x02 => Some(Self::Udp),
            _ => None,
        }
    }
}

/// Frame a UDP datagram with a 2-byte big-endian length prefix.
pub fn frame_udp_datagram(payload: &[u8]) -> Vec<u8> {
    debug_assert!(
        payload.len() <= u16::MAX as usize,
        "UDP datagram too large for 2-byte length prefix"
    );
    let len = payload.len() as u16;
    let mut buf = Vec::with_capacity(2 + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Deframe a UDP datagram: returns `(payload, rest)` or `None` if incomplete.
pub fn deframe_udp_datagram(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return None;
    }
    Some((&buf[2..2 + len], &buf[2 + len..]))
}

/// Reassembles length-prefixed UDP datagrams from a yamux substream.
///
/// yamux substreams are reliable **byte** streams, not message-preserving:
/// one `read` may return a partial frame or several coalesced frames. A single
/// `deframe` per `read` would corrupt frames split across reads and drop frames
/// coalesced into one read; the accumulator drains every complete frame and
/// retains the trailing partial for the next `push`.
///
/// Buffer growth is bounded: the 2-byte length prefix is a `u16`, so a
/// pending frame never exceeds `2 + u16::MAX` bytes.
#[derive(Debug, Default)]
pub(crate) struct FrameAccumulator {
    buf: Vec<u8>,
}

impl FrameAccumulator {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Append freshly-read bytes.
    pub(crate) fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pop the next complete datagram payload, or `None` if the buffer does
    /// not yet hold a full frame.
    pub(crate) fn next_frame(&mut self) -> Option<Vec<u8>> {
        let (payload, consumed) = {
            let (payload, rest) = deframe_udp_datagram(&self.buf)?;
            (payload.to_vec(), self.buf.len() - rest.len())
        };
        self.buf.drain(..consumed);
        Some(payload)
    }
}

// Driver ==============================================================================================================

type OpenStreamReply = tokio::sync::oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>;

/// Central driver loop that owns the yamux `Connection`.
///
/// All interaction with the connection goes through channels because `Connection`
/// requires `&mut self` for every poll method.
async fn drive_connection<T: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static>(
    mut conn: yamux::Connection<T>,
    mut open_rx: mpsc::Receiver<OpenStreamReply>,
    inbound_tx: mpsc::Sender<yamux::Stream>,
) {
    let mut pending_opens: Vec<Option<OpenStreamReply>> = Vec::new();

    std::future::poll_fn(|cx| {
        // 1. Service pending outbound stream requests.
        for slot in pending_opens.iter_mut() {
            if slot.is_none() {
                continue;
            }
            match conn.poll_new_outbound(cx) {
                std::task::Poll::Ready(Ok(stream)) => {
                    if let Some(reply) = slot.take() {
                        let _ = reply.send(Ok(stream));
                    }
                }
                std::task::Poll::Ready(Err(e)) => {
                    if let Some(reply) = slot.take() {
                        let _ = reply.send(Err(e));
                    }
                }
                std::task::Poll::Pending => {}
            }
        }
        pending_opens.retain(|slot| slot.is_some());

        // 2. Accept inbound streams.
        loop {
            match conn.poll_next_inbound(cx) {
                std::task::Poll::Ready(Some(Ok(stream))) => {
                    if inbound_tx.try_send(stream).is_err() {
                        tracing::warn!("inbound stream dropped: receiver full or closed");
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    tracing::error!(error = %e, "yamux inbound stream error");
                    return std::task::Poll::Ready(());
                }
                std::task::Poll::Ready(None) => {
                    tracing::debug!("yamux connection closed (no more inbound)");
                    return std::task::Poll::Ready(());
                }
                std::task::Poll::Pending => break,
            }
        }

        // 3. Drain new open requests from the channel.
        loop {
            match open_rx.poll_recv(cx) {
                std::task::Poll::Ready(Some(reply)) => {
                    // Try to open immediately.
                    match conn.poll_new_outbound(cx) {
                        std::task::Poll::Ready(Ok(stream)) => {
                            let _ = reply.send(Ok(stream));
                        }
                        std::task::Poll::Ready(Err(e)) => {
                            let _ = reply.send(Err(e));
                        }
                        std::task::Poll::Pending => {
                            pending_opens.push(Some(reply));
                        }
                    }
                }
                std::task::Poll::Ready(None) => {
                    // All senders dropped — no more open requests possible.
                    // Continue driving until the connection itself closes.
                    break;
                }
                std::task::Poll::Pending => break,
            }
        }

        std::task::Poll::Pending
    })
    .await;
}

/// Request a new outbound stream from the driver.
async fn open_stream(open_tx: &mpsc::Sender<OpenStreamReply>) -> Result<yamux::Stream, yamux::ConnectionError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    open_tx.send(tx).await.map_err(|_| yamux::ConnectionError::Closed)?;
    rx.await.map_err(|_| yamux::ConnectionError::Closed)?
}

// TCP/UDP relay helpers ===============================================================================================

/// An unspecified-address `SocketAddr` of the same family as `target`, port 0.
///
/// A UDP socket must be bound in the same address family as the peer it will
/// `connect()`/`send_to()`; binding IPv4 (`0.0.0.0`) then connecting an IPv6
/// peer fails with an address-family error.
fn unspecified_for(target: SocketAddr) -> SocketAddr {
    if target.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    }
}

/// Bind a non-blocking tokio [`UdpSocket`], with `SIO_UDP_CONNRESET` disabled on
/// Windows.
///
/// Both UDP relay sockets here send *and* receive on the same handle. On Windows
/// a UDP `send_to` to a loopback peer with no live listener makes the kernel
/// surface the resulting ICMP port-unreachable as a phantom `WSAECONNRESET`
/// (10054) on the socket's *next* `recv` — which, on the client's shared socket,
/// would tear the whole tunnel down (every flow reconnects). The peers here are
/// loopback (SS_LOCAL on the client; the ss server's plugin loopback on the
/// server) and routinely come and go, so this is reachable under ordinary UDP
/// churn (e.g. finished DNS queries). Disabling `SIO_UDP_CONNRESET` is the
/// standard fix (also applied by quinn / hickory-dns); tokio/mio leave the
/// Windows default (enabled). See the documented hazard in
/// `crates/bridge/src/dns/forwarder.rs`.
pub(crate) fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    // Bind via std so the raw handle is available for the Windows ioctl before
    // the socket is registered with tokio's reactor.
    let sock = std::net::UdpSocket::bind(addr)?;
    sock.set_nonblocking(true)?;
    #[cfg(windows)]
    disable_udp_connreset(&sock)?;
    UdpSocket::from_std(sock)
}

#[cfg(windows)]
fn disable_udp_connreset(sock: &std::net::UdpSocket) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket as _;

    use windows::Win32::Networking::WinSock::{WSAIoctl, SOCKET};

    // SIO_UDP_CONNRESET = _WSAIOW(IOC_VENDOR, 12) == 0x9800000C. Passing FALSE
    // disables the phantom-reset behavior described on `bind_udp`.
    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

    let disable: u32 = 0; // BOOL FALSE
    let mut bytes_returned: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            SOCKET(sock.as_raw_socket() as usize),
            SIO_UDP_CONNRESET,
            Some(std::ptr::addr_of!(disable).cast()),
            std::mem::size_of::<u32>() as u32,
            None,
            0,
            &mut bytes_returned,
            None,
            None,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Write a stream's leading tag byte and flush it. Every yamux substream
/// begins with one [`StreamTag`] so the server can dispatch TCP vs UDP.
async fn write_tag(stream: &mut yamux::Stream, tag: StreamTag) -> std::io::Result<()> {
    stream.write_all(&[tag.to_byte()]).await?;
    stream.flush().await
}

/// Relay between a tokio TCP stream and a yamux stream (bidirectional),
/// with correct half-close.
///
/// When one direction reaches EOF, `copy_bidirectional` shuts down the peer's
/// write half (propagating the FIN) and keeps copying the other direction until
/// it too reaches EOF. A `tokio::select!` over two one-directional
/// `tokio::io::copy`s would instead drop the surviving copy the instant either
/// finished, discarding an in-flight response — a truncation when a client
/// half-closes its write side mid-request. The compat shim maps
/// `copy_bidirectional`'s `poll_shutdown` onto `yamux::Stream::poll_close`, so
/// the yamux FIN is sent without a separate `close()`. Mirrors the bridge's own
/// endpoints (`endpoint/socks5.rs`, `endpoint/interface.rs`).
async fn relay_tcp(mut yamux_stream: yamux::Stream, mut tcp_stream: TcpStream) -> Result<()> {
    let mut compat = (&mut yamux_stream).compat();
    tokio::io::copy_bidirectional(&mut compat, &mut tcp_stream).await?;
    Ok(())
}

/// Relay UDP datagrams on the server side: yamux stream <-> remote UDP socket.
async fn relay_udp_server(mut yamux_stream: yamux::Stream, remote: SocketAddr) -> Result<()> {
    // Bind in the remote's address family, else an IPv6 `remote` (ss server
    // configured with `server: "::"` hands the plugin an `[::1]` loopback)
    // fails the connect with an address-family mismatch.
    let udp = bind_udp(unspecified_for(remote)).context("bind udp")?;
    udp.connect(remote).await.context("connect udp")?;

    let mut read_buf = [0u8; 65536 + 2];
    let mut udp_buf = [0u8; 65536];
    let mut acc = FrameAccumulator::new();

    loop {
        tokio::select! {
            // yamux -> UDP
            result = yamux_stream.read(&mut read_buf) => {
                let n = result.context("yamux read")?;
                if n == 0 {
                    break;
                }
                acc.push(&read_buf[..n]);
                while let Some(payload) = acc.next_frame() {
                    udp.send(&payload).await.context("udp send")?;
                }
            }
            // UDP -> yamux
            result = udp.recv(&mut udp_buf) => {
                let n = result.context("udp recv")?;
                let framed = frame_udp_datagram(&udp_buf[..n]);
                yamux_stream.write_all(&framed).await.context("yamux write")?;
                yamux_stream.flush().await.context("yamux flush")?;
            }
        }
    }

    Ok(())
}

// Client mode =========================================================================================================

async fn connect_with_backoff(addr: SocketAddr, shutdown: &CancellationToken) -> Option<TcpStream> {
    let mut delay = Duration::from_millis(100);
    let max_delay = Duration::from_secs(30);

    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Some(stream),
            Err(e) => {
                tracing::warn!(error = %e, delay_ms = delay.as_millis(), "connection failed, retrying");
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = shutdown.cancelled() => return None,
                }
                delay = (delay * 2).min(max_delay);
            }
        }
    }
}

/// One client-side UDP NAT association.
///
/// Relays datagrams for a single originating local peer over a dedicated yamux
/// stream, bidirectionally (mirroring [`relay_udp_server`]), until the
/// association is idle-evicted or the stream/connection closes. Outbound
/// datagrams arrive on `outbound_rx` from the [`run_client`] loop; inbound
/// replies are delivered straight to `peer` via the shared `udp_socket`.
///
/// On exit it closes the stream (FINs the substream so the server's
/// `relay_udp_server` read returns 0 and its UDP socket is reclaimed) and
/// notifies the loop via `cleanup_tx` so the stale table entry is dropped.
#[allow(clippy::too_many_arguments)]
async fn run_udp_association(
    open_tx: mpsc::Sender<OpenStreamReply>,
    udp_socket: Arc<UdpSocket>,
    peer: SocketAddr,
    generation: u64,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    cleanup_tx: mpsc::Sender<(SocketAddr, u64)>,
    udp_timeout: Duration,
) {
    let mut stream = match open_stream(&open_tx).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(peer = %peer, error = %e, "failed to open yamux stream for UDP");
            let _ = cleanup_tx.send((peer, generation)).await;
            return;
        }
    };
    if let Err(e) = write_tag(&mut stream, StreamTag::Udp).await {
        tracing::error!(peer = %peer, error = %e, "failed to write UDP tag");
        let _ = cleanup_tx.send((peer, generation)).await;
        return;
    }

    let mut read_buf = [0u8; 65536 + 2];
    let mut acc = FrameAccumulator::new();

    // NAT idle-eviction timer. The delay IS the behavior under management
    // (conntrack-style idle expiry of a UDP association), not synchronization
    // between our own code paths — sanctioned per the synchronization
    // invariant's "the delay IS the behavior" exception.
    let idle = tokio::time::sleep(udp_timeout);
    tokio::pin!(idle);

    let reason = loop {
        // `biased`: traffic in either direction always wins over the idle
        // timer, so an association is never evicted while a datagram is already
        // buffered or a reply is pending. The timer fires only when both
        // directions are genuinely idle.
        tokio::select! {
            biased;
            // local app -> server
            maybe = outbound_rx.recv() => {
                let Some(payload) = maybe else { break "channel closed" };
                idle.as_mut().reset(Instant::now() + udp_timeout);
                let framed = frame_udp_datagram(&payload);
                if stream.write_all(&framed).await.is_err() {
                    break "stream write error";
                }
                if stream.flush().await.is_err() {
                    break "stream flush error";
                }
            }
            // server -> local app
            result = stream.read(&mut read_buf) => {
                let n = match result {
                    Ok(0) => break "stream closed",
                    Ok(n) => n,
                    Err(_) => break "stream read error",
                };
                idle.as_mut().reset(Instant::now() + udp_timeout);
                acc.push(&read_buf[..n]);
                while let Some(payload) = acc.next_frame() {
                    if let Err(e) = udp_socket.send_to(&payload, peer).await {
                        tracing::debug!(peer = %peer, error = %e, "failed to send UDP reply to local peer");
                    }
                }
            }
            // NAT idle eviction.
            _ = &mut idle => break "evicted",
        }
    };

    // Close the outbound channel so that, from here on, a datagram the
    // `run_client` loop tries to forward hits `Closed` and re-creates the
    // association instead of vanishing into a receiver that will never read it.
    // This does not recover datagrams already buffered (or `try_send`-accepted
    // in the brief, multi-thread-only window between the loop `break` and this
    // call): those are dropped when `outbound_rx` is dropped at return. That is
    // correct NAT-teardown lossy-UDP behavior — an `evicted` flow was idle for
    // `udp_timeout`, so a datagram arriving exactly at eviction is the first of
    // a resumed flow that the app will retransmit (DNS/QUIC do); on an error
    // teardown the stream is already dead and those datagrams could not have
    // been delivered anyway. Conntrack/shadowsocks-rust drop the same boundary
    // packet.
    outbound_rx.close();

    tracing::debug!(peer = %peer, reason, "udp association closed");
    let _ = stream.close().await;
    let _ = cleanup_tx.send((peer, generation)).await;
}

/// The client's bound local listener addresses, reported via the `run_client`
/// test seam. The TCP listener and UDP socket are bound separately, so on a
/// `:0` (ephemeral) `local` they land on different ports — tests need both.
/// Production passes `None` and never observes this.
// The fields are read only from `#[cfg(test)]` code (the relay tests), so the
// non-test lib build sees them as write-only; allow that, keep the lint in tests.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ClientBoundAddrs {
    pub tcp: SocketAddr,
    pub udp: SocketAddr,
}

pub(crate) async fn run_client(
    config: yamux::Config,
    local: SocketAddr,
    remote: SocketAddr,
    udp_timeout: Duration,
    shutdown: CancellationToken,
    bound_addr_tx: Option<oneshot::Sender<ClientBoundAddrs>>,
) -> Result<()> {
    // Bind the local TCP + UDP listeners once for the client's lifetime. They
    // belong to `local` (the SS_LOCAL address), not to any single upstream
    // connection, so they persist across reconnects — only the yamux connection
    // churns. Binding per-reconnect would race the previous connection's
    // detached association tasks (which hold `Arc<UdpSocket>` clones) for the
    // port and could fail the rebind, terminating the client.
    let tcp_listener = TcpListener::bind(local).await.context("bind local TCP")?;
    let udp_socket = Arc::new(bind_udp(local).context("bind local UDP")?);

    // Report the actual bound listener addresses (test seam). Production passes `None`.
    if let Some(tx) = bound_addr_tx {
        let _ = tx.send(ClientBoundAddrs {
            tcp: tcp_listener.local_addr().context("local tcp addr")?,
            udp: udp_socket.local_addr().context("local udp addr")?,
        });
    }

    loop {
        // Connect to the remote yamux server.
        let tcp = match connect_with_backoff(remote, &shutdown).await {
            Some(s) => s,
            None => return Ok(()), // shutdown requested
        };

        tracing::info!(remote = %remote, "connected to yamux server");

        let compat_tcp = tcp.compat();
        let conn = yamux::Connection::new(compat_tcp, config.clone(), yamux::Mode::Client);

        let (open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(32);
        let (_inbound_tx, _inbound_rx) = mpsc::channel::<yamux::Stream>(32);

        let driver = tokio::spawn(drive_connection(conn, open_rx, _inbound_tx));

        let result: Result<()> = async {
            // NAT association table: local peer -> (generation, outbound sender).
            // Owned solely by this loop (no shared mutex) and scoped to this
            // connection — on reconnect it drops, every association task sees
            // its `outbound_rx` close and exits, and the next iteration starts
            // empty. `generation` closes the re-create-during-teardown race:
            // a stale cleanup only removes an entry whose generation matches.
            let mut associations: HashMap<SocketAddr, (u64, mpsc::Sender<Vec<u8>>)> = HashMap::new();
            let (cleanup_tx, mut cleanup_rx) = mpsc::channel::<(SocketAddr, u64)>(64);
            let mut next_gen: u64 = 0;
            let mut udp_buf = [0u8; 65536];

            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    // Accept local TCP connections.
                    accept = tcp_listener.accept() => {
                        let (tcp_stream, _peer) = accept.context("tcp accept")?;
                        let open_tx = open_tx.clone();
                        tokio::spawn(async move {
                            match open_stream(&open_tx).await {
                                Ok(mut yamux_stream) => {
                                    if let Err(e) = write_tag(&mut yamux_stream, StreamTag::Tcp).await {
                                        tracing::error!(error = %e, "failed to write TCP tag");
                                        return;
                                    }
                                    if let Err(e) = relay_tcp(yamux_stream, tcp_stream).await {
                                        tracing::debug!(error = %e, "tcp relay ended");
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "failed to open yamux stream for TCP");
                                }
                            }
                        });
                    }
                    // Receive local UDP datagrams; route each to its peer's association.
                    recv = udp_socket.recv_from(&mut udp_buf) => {
                        let (n, peer) = recv.context("udp recv")?;
                        let payload = udp_buf[..n].to_vec();

                        // Forward to an existing association if one is live.
                        // `Closed` returns the payload so we can re-create
                        // without cloning on the hot path; `Full` drops it
                        // (correct lossy-UDP semantics).
                        let payload = match associations.get(&peer) {
                            Some((_, tx)) => match tx.try_send(payload) {
                                Ok(()) => continue,
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    tracing::debug!(peer = %peer, "udp association buffer full, dropping datagram");
                                    continue;
                                }
                                Err(mpsc::error::TrySendError::Closed(payload)) => {
                                    associations.remove(&peer);
                                    payload
                                }
                            },
                            None => payload,
                        };

                        // Create a new association.
                        let generation = next_gen;
                        next_gen += 1;
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(UDP_ASSOC_CHANNEL_CAPACITY);
                        // First datagram always fits the fresh buffer.
                        let _ = tx.try_send(payload);
                        associations.insert(peer, (generation, tx));
                        tokio::spawn(run_udp_association(
                            open_tx.clone(),
                            Arc::clone(&udp_socket),
                            peer,
                            generation,
                            rx,
                            cleanup_tx.clone(),
                            udp_timeout,
                        ));
                    }
                    // An association task exited; drop its entry iff still current.
                    Some((peer, generation)) = cleanup_rx.recv() => {
                        if let Some((current, _)) = associations.get(&peer) {
                            if *current == generation {
                                associations.remove(&peer);
                            }
                        }
                    }
                }
            }

            Ok(())
        }
        .await;

        // Drop the open channel to let the driver finish.
        drop(open_tx);
        let _ = driver.await;

        match result {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::warn!(error = %e, "client session ended, reconnecting");
                // Loop back to reconnect.
            }
        }
    }
}

// Server mode =========================================================================================================

pub(crate) async fn run_server(
    config: yamux::Config,
    local: SocketAddr,
    remote: SocketAddr,
    shutdown: CancellationToken,
    bound_addr_tx: Option<oneshot::Sender<SocketAddr>>,
) -> Result<()> {
    let listener = TcpListener::bind(local)
        .await
        .with_context(|| format!("bind yamux server on {local}"))?;
    tracing::info!(local = %local, "yamux server listening");

    // Signal the actual bound listen address (test seam). Production passes `None`.
    if let Some(tx) = bound_addr_tx {
        let addr = listener.local_addr().context("local tcp addr")?;
        let _ = tx.send(addr);
    }

    loop {
        // Accept one underlying TCP connection.
        let tcp = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            accept = listener.accept() => {
                let (stream, peer) = accept.context("accept")?;
                tracing::info!(peer = %peer, "accepted underlying connection");
                stream
            }
        };

        let compat_tcp = tcp.compat();
        let conn = yamux::Connection::new(compat_tcp, config.clone(), yamux::Mode::Server);

        let (_open_tx, open_rx) = mpsc::channel::<OpenStreamReply>(32);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<yamux::Stream>(64);

        let driver = tokio::spawn(drive_connection(conn, open_rx, inbound_tx));

        let server_shutdown = shutdown.clone();
        let remote_addr = remote;

        // Handle inbound streams until the connection closes.
        loop {
            let stream = tokio::select! {
                _ = server_shutdown.cancelled() => break,
                stream = inbound_rx.recv() => {
                    match stream {
                        Some(s) => s,
                        None => break, // driver closed
                    }
                }
            };

            let remote = remote_addr;
            tokio::spawn(async move {
                if let Err(e) = handle_inbound_stream(stream, remote).await {
                    tracing::debug!(error = %e, "inbound stream handler ended");
                }
            });
        }

        let _ = driver.await;
        tracing::info!("underlying connection closed, waiting for next");
    }
}

/// Handle a single inbound yamux stream: read the tag byte, then relay.
async fn handle_inbound_stream(mut stream: yamux::Stream, remote: SocketAddr) -> Result<()> {
    // Read the tag byte.
    let mut tag_buf = [0u8; 1];
    stream.read_exact(&mut tag_buf).await.context("read stream tag")?;

    let tag = StreamTag::from_byte(tag_buf[0]).context("invalid stream tag")?;

    match tag {
        StreamTag::Tcp => {
            let tcp = TcpStream::connect(remote).await.context("connect to remote TCP")?;
            relay_tcp(stream, tcp).await?;
        }
        StreamTag::Udp => {
            relay_udp_server(stream, remote).await?;
        }
    }

    Ok(())
}

// Plugin ==============================================================================================================

/// Parse the optional client-side `udp_timeout` (whole seconds) from an
/// `SS_PLUGIN_OPTIONS` string.
///
/// Returns [`DEFAULT_UDP_TIMEOUT`] when the key is absent. The last occurrence
/// wins (consistent with ex-ray's duplicate-key semantics). A value that
/// is not a positive integer is a hard error — `0` would evict every
/// association immediately, breaking all UDP. ex-ray ignores this key,
/// so it can share the same options string.
pub fn parse_udp_timeout(plugin_options: Option<&str>) -> Result<Duration> {
    let Some(opts) = plugin_options else {
        return Ok(DEFAULT_UDP_TIMEOUT);
    };
    let mut timeout = DEFAULT_UDP_TIMEOUT;
    for (key, value) in garter::parse_plugin_options(opts) {
        if key == "udp_timeout" {
            let secs: u64 = value
                .parse()
                .with_context(|| format!("invalid udp_timeout (expected a positive integer of seconds): {value:?}"))?;
            if secs == 0 {
                anyhow::bail!("udp_timeout must be greater than 0 seconds");
            }
            timeout = Duration::from_secs(secs);
        }
    }
    Ok(timeout)
}

pub struct YamuxPlugin {
    config: yamux::Config,
    is_server: bool,
    /// Client-side UDP NAT idle-eviction timeout. Ignored in server mode.
    udp_timeout: Duration,
}

impl YamuxPlugin {
    pub fn new(is_server: bool, udp_timeout: Duration) -> Self {
        Self {
            config: yamux::Config::default(),
            is_server,
            udp_timeout,
        }
    }
}

#[async_trait::async_trait]
impl garter::ChainPlugin for YamuxPlugin {
    fn name(&self) -> &str {
        if self.is_server {
            "yamux-server"
        } else {
            "yamux-client"
        }
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        remote: SocketAddr,
        shutdown: CancellationToken,
        ready: tokio::sync::oneshot::Sender<std::result::Result<garter::PluginReady, garter::StartError>>,
    ) -> garter::Result<()> {
        // Self-probe readiness: a YAMUX plugin serves both TCP and UDP at
        // its local listener. Spawn a TCP-connect probe against `local`; on
        // success report TCP|UDP readiness, on shutdown-first drop `ready`
        // unsent (RecvError — the "shutdown before ready" semantics).
        //
        // This is galoshes' INTERNAL hop-readiness signal: it feeds
        // galoshes' OWN `ChainRunner` aggregator, which intersects it with
        // the inner ex-ray hop and fires the chain-level `on_ready`. The
        // PROCESS-level sitrep the bridge reads is emitted separately in
        // `main.rs` off that `on_ready` outcome (see `galoshes::sitrep_out`).
        // This probe knows only its own hop, not the chain, so it cannot
        // own the process-stdout contract.
        //
        // A future refinement could replace the TCP-connect probe with a
        // structured `ready` emitted from inside run_server/run_client at
        // the exact bind point; the probe is the current pragmatic stand-in.
        let probe_local = local;
        let probe_shutdown = shutdown.clone();
        tokio::spawn(async move {
            if probe_tcp_ready(probe_local, &probe_shutdown).await {
                let _ = ready.send(Ok(garter::PluginReady {
                    listen: probe_local,
                    transports: garter::Transports::TCP | garter::Transports::UDP,
                }));
            }
        });

        let result = if self.is_server {
            run_server(self.config, local, remote, shutdown, None).await
        } else {
            run_client(self.config, local, remote, self.udp_timeout, shutdown, None).await
        };

        result.map_err(|e| garter::Error::Chain(e.to_string()))
    }
}

/// TCP-connect probe with exponential backoff. Returns `true` once `addr`
/// accepts a connection, `false` if shutdown fires first. Mirrors garter's
/// internal `poll_ready` (not exported), used to detect the YAMUX local
/// listener coming up.
async fn probe_tcp_ready(addr: SocketAddr, shutdown: &CancellationToken) -> bool {
    let mut delay = Duration::from_millis(10);
    let max_delay = Duration::from_secs(1);
    // Per-attempt connect bound. A readiness self-probe must never wedge on a
    // single hung `connect`: on Windows, a loopback connect can stall for tens
    // of seconds while the network stack is mid-reconfiguration (e.g. a sibling
    // TUN adapter's async NDIS detach churning the stack — bindreams/hole#541).
    // Without a per-attempt bound the probe sticks on that one connect and never
    // retries, so readiness never fires. Bounding each attempt lets the probe
    // retry and self-heal the instant the stack settles. The retry is unbounded
    // (no budget); shutdown is the only exit besides success.
    let attempt_timeout = Duration::from_secs(3);
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        tokio::select! {
            result = tokio::time::timeout(attempt_timeout, TcpStream::connect(addr)) => {
                match result {
                    Ok(Ok(_)) => return true,
                    Ok(Err(e)) => tracing::debug!(%addr, attempt, error = %e, "probe_tcp_ready: connect failed, retrying"),
                    Err(_) => tracing::debug!(%addr, attempt, timeout_s = attempt_timeout.as_secs(),
                        "probe_tcp_ready: connect attempt timed out, retrying"),
                }
            }
            () = shutdown.cancelled() => return false,
        }
        tokio::select! {
            () = tokio::time::sleep(delay) => {
                delay = (delay * 2).min(max_delay);
            }
            () = shutdown.cancelled() => return false,
        }
    }
}
