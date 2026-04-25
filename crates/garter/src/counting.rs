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
//! Lifted into `garter` (Apache-2.0) from `hole-bridge`'s DNS forwarder
//! (which had its own copy at `dns/connector.rs`) so both the bridge's
//! DNS path and the new `TapPlugin` decorator can share the type
//! without cycling Apache → GPL → Apache. Bridge re-imports from here.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Per-stream byte counters and first-read timestamp. Cheap to clone
/// (three `Arc` bumps).
#[derive(Debug, Default, Clone)]
pub struct StreamCounters {
    read_bytes: Arc<AtomicU64>,
    write_bytes: Arc<AtomicU64>,
    /// Instant of the first non-zero `poll_read`. Set exactly once via
    /// `OnceLock::set`; subsequent reads do not update it. Use with the
    /// connection's `started` instant to compute time-to-first-upstream-byte.
    first_read_at: Arc<OnceLock<Instant>>,
}

impl StreamCounters {
    /// Total bytes successfully read from the wrapped stream so far.
    pub fn read(&self) -> u64 {
        self.read_bytes.load(Ordering::Relaxed)
    }

    /// Total bytes successfully written to the wrapped stream so far.
    pub fn written(&self) -> u64 {
        self.write_bytes.load(Ordering::Relaxed)
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
                self.counters.read_bytes.fetch_add(delta, Ordering::Relaxed);
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
            self.counters.write_bytes.fetch_add(*n as u64, Ordering::Relaxed);
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
