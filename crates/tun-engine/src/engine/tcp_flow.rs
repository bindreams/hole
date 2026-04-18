//! `TcpFlow` — per-TCP-connection byte stream handed to the caller's `Router`.
//!
//! The engine relays data between smoltcp TCP sockets and per-connection
//! `Router::route_tcp` tasks through a pair of channels. This adapter
//! presents standard `AsyncRead` / `AsyncWrite` to the Router, plus a
//! [`TcpFlow::peek`] helper for SNI / HTTP-Host style sniffing before the
//! caller decides how to dispatch.
//!
//! Write side uses [`tokio_util::sync::PollSender`] to implement
//! `AsyncWrite::poll_write` without requiring an async context.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::PollSender;

/// Channel capacity for the driver ↔ handler data path. Sized to roughly
/// match a TCP window (~64 KiB at 1400 MTU ≈ 46 segments).
const CHANNEL_CAPACITY: usize = 64;

/// Async read/write adapter backed by mpsc channels. The engine's driver
/// holds the other ends of the channels and relays data between this flow
/// and the smoltcp TCP socket. Consumers get a standard byte stream plus
/// an opt-in `peek(n, timeout)` helper for protocol sniffing.
pub struct TcpFlow {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: PollSender<Vec<u8>>,
    read_buf: BytesMut,
    /// Engine-owned semaphore limiting total concurrent peeks across all
    /// flows. Acquired for the duration of each `peek` call so a
    /// pathological caller can't tie up unbounded memory in buffered
    /// peeks. Not used by `AsyncRead::poll_read`.
    sniffer_sem: Arc<Semaphore>,
}

impl TcpFlow {
    /// Create a new flow and return the channel ends for the driver.
    ///
    /// Returns `(flow, driver_tx, driver_rx)` where:
    /// - `driver_tx` sends data TO the Router (the Router reads it).
    /// - `driver_rx` receives data FROM the Router (the Router wrote it).
    pub fn new(sniffer_sem: Arc<Semaphore>) -> (Self, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (to_handler_tx, to_handler_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (from_handler_tx, from_handler_rx) = mpsc::channel(CHANNEL_CAPACITY);

        let stream = Self {
            rx: to_handler_rx,
            tx: PollSender::new(from_handler_tx),
            read_buf: BytesMut::new(),
            sniffer_sem,
        };

        (stream, to_handler_tx, from_handler_rx)
    }

    /// Peek at up to `n` bytes of the first payload, waiting up to
    /// `timeout`. A timeout is **not** an error — the returned slice is
    /// whatever arrived in the window (possibly empty).
    ///
    /// The data is buffered internally, so subsequent `read` calls see
    /// these bytes first, then continue with any later data. Calling
    /// `peek` twice returns the same buffer (extended if more data
    /// arrived since the previous call).
    ///
    /// Acquires an engine-level permit for the duration of the call; a
    /// bounded number of concurrent peeks are allowed across all flows
    /// (`EngineConfig::max_sniffers`). Blocks waiting for a permit if the
    /// budget is exhausted.
    pub async fn peek(&mut self, n: usize, timeout: Duration) -> io::Result<&[u8]> {
        let _permit = self
            .sniffer_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("sniffer semaphore closed"))?;

        let deadline = Instant::now() + timeout;
        while self.read_buf.len() < n {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, self.rx.recv()).await {
                Ok(Some(data)) => self.read_buf.extend_from_slice(&data),
                Ok(None) => break, // upstream EOF — return what we have
                Err(_) => break,   // timeout — return what we have
            }
        }
        let up_to = n.min(self.read_buf.len());
        Ok(&self.read_buf[..up_to])
    }
}

impl AsyncRead for TcpFlow {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // Drain the internal buffer first.
        if !self.read_buf.is_empty() {
            let n = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }

        // Try to receive new data from the driver.
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed = EOF.
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpFlow {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Reserve capacity in the PollSender.
        match self.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let data = buf.to_vec();
                let len = data.len();
                self.tx
                    .send_item(data)
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Channels don't need flushing.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[path = "tcp_flow_tests.rs"]
mod tcp_flow_tests;
