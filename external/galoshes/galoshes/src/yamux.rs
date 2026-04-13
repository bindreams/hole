use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::AsyncReadExt as _;
use futures::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

// Protocol framing =====

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

// Driver =====

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

// TCP/UDP relay helpers =====

/// Relay between a tokio TCP stream and a yamux stream (bidirectional).
async fn relay_tcp(mut yamux_stream: yamux::Stream, mut tcp_stream: TcpStream) -> Result<()> {
    // Convert yamux stream (futures AsyncRead/Write) to tokio-compatible.
    let mut compat = (&mut yamux_stream).compat();
    let (mut yr, mut yw) = tokio::io::split(&mut compat);
    let (mut tr, mut tw) = tcp_stream.split();

    let _result = tokio::select! {
        r = tokio::io::copy(&mut yr, &mut tw) => r,
        r = tokio::io::copy(&mut tr, &mut yw) => r,
    };

    // Best-effort shutdown.
    let _ = yamux_stream.close().await;
    Ok(())
}

/// Relay UDP datagrams on the server side: yamux stream <-> remote UDP socket.
async fn relay_udp_server(mut yamux_stream: yamux::Stream, remote: SocketAddr) -> Result<()> {
    let udp = UdpSocket::bind("127.0.0.1:0").await.context("bind udp")?;
    udp.connect(remote).await.context("connect udp")?;

    let mut recv_buf = [0u8; 65536 + 2];
    let mut udp_buf = [0u8; 65536];

    loop {
        tokio::select! {
            // yamux -> UDP
            result = yamux_stream.read(&mut recv_buf) => {
                let n = result.context("yamux read")?;
                if n == 0 {
                    break;
                }
                if let Some((payload, _)) = deframe_udp_datagram(&recv_buf[..n]) {
                    udp.send(payload).await.context("udp send")?;
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

// Client mode =====

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

async fn run_client(
    config: yamux::Config,
    local: SocketAddr,
    remote: SocketAddr,
    shutdown: CancellationToken,
) -> Result<()> {
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

        // Bind local TCP + UDP listeners.
        let tcp_listener = TcpListener::bind(local).await.context("bind local TCP")?;
        let udp_socket = UdpSocket::bind(local).await.context("bind local UDP")?;

        let result: Result<()> = async {
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
                                    // Write tag byte.
                                    if let Err(e) = yamux_stream.write_all(&[StreamTag::Tcp.to_byte()]).await {
                                        tracing::error!(error = %e, "failed to write TCP tag");
                                        return;
                                    }
                                    if let Err(e) = yamux_stream.flush().await {
                                        tracing::error!(error = %e, "failed to flush TCP tag");
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
                    // Receive local UDP datagrams.
                    recv = udp_socket.recv_from(&mut udp_buf) => {
                        let (n, _peer) = recv.context("udp recv")?;
                        let open_tx = open_tx.clone();
                        let payload = udp_buf[..n].to_vec();
                        tokio::spawn(async move {
                            match open_stream(&open_tx).await {
                                Ok(mut yamux_stream) => {
                                    // Write tag byte.
                                    if let Err(e) = yamux_stream.write_all(&[StreamTag::Udp.to_byte()]).await {
                                        tracing::error!(error = %e, "failed to write UDP tag");
                                        return;
                                    }
                                    if let Err(e) = yamux_stream.flush().await {
                                        tracing::error!(error = %e, "failed to flush UDP tag");
                                        return;
                                    }
                                    // Send the initial datagram.
                                    let framed = frame_udp_datagram(&payload);
                                    if let Err(e) = yamux_stream.write_all(&framed).await {
                                        tracing::error!(error = %e, "failed to write initial UDP datagram");
                                        return;
                                    }
                                    if let Err(e) = yamux_stream.flush().await {
                                        tracing::error!(error = %e, "failed to flush UDP datagram");
                                        return;
                                    }
                                    // One datagram per stream; bidirectional UDP relay
                                    // would keep the stream open longer.
                                    let _ = yamux_stream.close().await;
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "failed to open yamux stream for UDP");
                                }
                            }
                        });
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

// Server mode =====

async fn run_server(
    config: yamux::Config,
    local: SocketAddr,
    remote: SocketAddr,
    shutdown: CancellationToken,
) -> Result<()> {
    let listener = TcpListener::bind(local)
        .await
        .with_context(|| format!("bind yamux server on {local}"))?;
    tracing::info!(local = %local, "yamux server listening");

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

// Plugin =====

pub struct YamuxPlugin {
    config: yamux::Config,
    is_server: bool,
}

impl YamuxPlugin {
    pub fn new(is_server: bool) -> Self {
        Self {
            config: yamux::Config::default(),
            is_server,
        }
    }

    pub fn from_plugin_options(options: Option<&str>) -> Self {
        let is_server = options.map(|opts| opts.contains("server")).unwrap_or(false);
        Self::new(is_server)
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
    ) -> garter::Result<()> {
        let result = if self.is_server {
            run_server(self.config, local, remote, shutdown).await
        } else {
            run_client(self.config, local, remote, shutdown).await
        };

        result.map_err(|e| garter::Error::Chain(e.to_string()))
    }
}
