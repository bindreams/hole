//! `SmoltcpStream` — `AsyncRead + AsyncWrite` adapter over mpsc channels.
//!
//! The TUN driver relays data between smoltcp TCP sockets and per-connection
//! handler tasks through a pair of channels. This adapter lets the handler
//! code use standard tokio I/O traits (`copy_bidirectional`, etc.) without
//! knowing about the underlying channel mechanics.
//!
//! Write side uses [`tokio_util::sync::PollSender`] to implement
//! `AsyncWrite::poll_write` without requiring an async context.

use bytes::BytesMut;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

/// Channel capacity for the driver ↔ handler data path. Sized to
/// roughly match a TCP window (~64 KiB at 1400 MTU ≈ 46 segments).
const CHANNEL_CAPACITY: usize = 64;

/// Async read/write adapter backed by mpsc channels. The TUN driver
/// holds the other ends of the channels and relays data between this
/// stream and the smoltcp TCP socket.
pub struct SmoltcpStream {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: PollSender<Vec<u8>>,
    read_buf: BytesMut,
}

impl SmoltcpStream {
    /// Create a new stream and return the channel ends for the driver.
    ///
    /// Returns `(stream, driver_tx, driver_rx)` where:
    /// - `driver_tx` sends data TO the handler (the handler reads it)
    /// - `driver_rx` receives data FROM the handler (the handler wrote it)
    pub fn new() -> (Self, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (to_handler_tx, to_handler_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (from_handler_tx, from_handler_rx) = mpsc::channel(CHANNEL_CAPACITY);

        let stream = Self {
            rx: to_handler_rx,
            tx: PollSender::new(from_handler_tx),
            read_buf: BytesMut::new(),
        };

        (stream, to_handler_tx, from_handler_rx)
    }
}

impl AsyncRead for SmoltcpStream {
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

impl AsyncWrite for SmoltcpStream {
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
#[path = "smoltcp_stream_tests.rs"]
mod smoltcp_stream_tests;
