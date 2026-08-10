//! Byte-counting wrapper for bidirectional async streams.
//!
//! `CountingStream<S>` wraps any `AsyncRead + AsyncWrite` and increments
//! a pair of `Arc<AtomicU64>` counters on every successful poll. The
//! counters live in a separately-cloneable [`StreamCounters`] handle so
//! callers can read them after the stream itself has been moved into
//! e.g. `tokio::io::copy_bidirectional`.
//!
//! In addition to byte counts, the counters track the `Instant` of the
//! first non-zero `poll_read` (via a `OnceLock`). This lets a tap log a
//! "time to first upstream byte" signal — the diagnostic field that
//! distinguishes "upstream sent nothing for the whole connection" from
//! "upstream sent some bytes then closed."
//!
//! Lives in `garter` (Apache-2.0) so both the bridge's DNS path and the
//! `TapPlugin` decorator can share it without an Apache → GPL → Apache
//! dependency cycle.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A cheap-to-clone (two `Arc` bumps) read/write byte-counter pair, with a
/// manual `add_read`/`add_written` update API — for transports that don't go
/// through a poll-based `AsyncRead`/`AsyncWrite` wrapper (e.g. a datagram
/// socket's explicit `send`/`recv`) and so can't use [`CountingStream`].
/// [`StreamCounters`] is built on this same primitive for the stream case.
#[derive(Debug, Default, Clone)]
pub struct ByteCounters {
    read_bytes: Arc<AtomicU64>,
    write_bytes: Arc<AtomicU64>,
}

impl ByteCounters {
    /// Record `n` more bytes read.
    pub fn add_read(&self, n: u64) {
        self.read_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Record `n` more bytes written.
    pub fn add_written(&self, n: u64) {
        self.write_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Total bytes read so far.
    pub fn read(&self) -> u64 {
        self.read_bytes.load(Ordering::Relaxed)
    }

    /// Total bytes written so far.
    pub fn written(&self) -> u64 {
        self.write_bytes.load(Ordering::Relaxed)
    }
}

/// Per-stream byte counters and first-read timestamp. Cheap to clone.
#[derive(Debug, Default, Clone)]
pub struct StreamCounters {
    bytes: ByteCounters,
    /// Instant of the first non-zero `poll_read`. Set exactly once via
    /// `OnceLock::set`; subsequent reads do not update it. Use with the
    /// connection's `started` instant to compute time-to-first-upstream-byte.
    first_read_at: Arc<OnceLock<Instant>>,
}

impl StreamCounters {
    /// Total bytes successfully read from the wrapped stream so far.
    pub fn read(&self) -> u64 {
        self.bytes.read()
    }

    /// Total bytes successfully written to the wrapped stream so far.
    pub fn written(&self) -> u64 {
        self.bytes.written()
    }

    /// `Instant` of the first non-zero read on the wrapped stream, if any.
    /// `None` means the stream was closed without ever delivering a byte —
    /// the load-bearing diagnostic for tunnel-silent-then-FIN cases.
    pub fn first_read_at(&self) -> Option<Instant> {
        self.first_read_at.get().copied()
    }
}

/// Wraps any `AsyncRead + AsyncWrite` and increments [`StreamCounters`]
/// on every successful `poll_read` / `poll_write`. Counts raw bytes on
/// the wrapped stream (not transformed bytes) — for SOCKS5-wrapped
/// streams, that's post-CONNECT payload bytes; what a peer would see.
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

    /// Cheap clone of the counter handle — outlives the wrapped stream.
    pub fn counters(&self) -> StreamCounters {
        self.counters.clone()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let delta = (buf.filled().len() - before) as u64;
            if delta > 0 {
                self.counters.bytes.add_read(delta);
                // OnceLock::set is no-op on subsequent calls — first wins.
                let _ = self.counters.first_read_at.set(Instant::now());
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            self.counters.bytes.add_written(*n as u64);
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
