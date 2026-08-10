//! Client-side liveness for one yamux transport connection.
//!
//! A silently black-holed transport — a middlebox dropping packets with no
//! RST/FIN — produces no death signal of its own, so an idle tunnel otherwise
//! waits out ex-ray's inherited 300 s `ConnectionIdle`
//! (`third_party/v2ray-core/features/policy/policy.go`, `SessionDefault`) before
//! anything notices. This module bounds that recovery instead, without relying
//! on any timer further down the stack.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::AsyncReadExt as _;
use futures::AsyncWriteExt as _;
use tokio::sync::mpsc;

use super::{open_stream, OpenStreamReply, StreamTag, KEEPALIVE_NONCE_LEN};

/// How long the transport may stay silent before the client gives it a reason to
/// speak.
pub(crate) const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// How long the transport may stay completely silent after a probe before it is
/// declared dead.
///
/// The probe is a full round trip through the local ex-ray hop, the wire, the
/// remote ex-ray hop and the remote yamux server, so this is sized for a bad day
/// on a long path, not a median RTT: a false positive tears the session down and
/// `driver.abort()` truncates whatever relays were in flight.
pub(crate) const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// The margin that keeps a healthy-but-slow server off the fatal path.
///
/// Detection itself needs no help: a black-holed transport delivers neither an
/// echo nor anything else. But a server whose echo task is merely slow would be
/// silent too, and what covers it is yamux's own RTT ping — due again 10 s after
/// the last pong, and emitted the moment our probe wakes the driver. That holds
/// only while a probe cannot come due sooner than a ping is, so the interval may
/// not drop below yamux's cadence. `PING_INTERVAL` is private to that crate, so
/// the relation is pinned here rather than imported.
const _: () = assert!(KEEPALIVE_INTERVAL.as_nanos() >= Duration::from_secs(10).as_nanos());

/// Worst-case detection is `2 × KEEPALIVE_INTERVAL + KEEPALIVE_TIMEOUT` from the
/// last inbound byte, and there are two ways to reach it. A byte landing just
/// after a cycle boundary makes the next cycle skip, so the probe lands a cycle
/// later. A byte landing just after a probe went out instead costs the rest of
/// that window before the next interval even starts — which stays inside the
/// same bound only while the deadline is no longer than an interval.
const _: () = assert!(KEEPALIVE_TIMEOUT.as_nanos() <= KEEPALIVE_INTERVAL.as_nanos());

/// The keepalive's timings.
///
/// Production always passes [`Cadence::default()`] and nothing configures it; the
/// type exists so a session-level test can drive a real socket on the real clock,
/// which a virtual clock cannot do (tokio's auto-advance polls the I/O driver for
/// 0 ms and then jumps to the next timer, firing a deadline while the answer is
/// still in the kernel).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Cadence {
    interval: Duration,
    timeout: Duration,
}

impl Cadence {
    /// The deadline may not exceed the interval: the `2 × interval + timeout`
    /// detection bound holds only while it does not. The `const` assertion above
    /// pins that for the shipped values; this is the only way to build any other
    /// pair, so none can be built inconsistent.
    pub(crate) fn new(interval: Duration, timeout: Duration) -> Self {
        debug_assert!(timeout <= interval, "a keepalive deadline must fit inside its interval");
        Self { interval, timeout }
    }
}

impl Default for Cadence {
    /// The shipped cadence — the only one production ever uses.
    fn default() -> Self {
        Self::new(KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT)
    }
}

/// Open a keepalive substream and put `tag || nonce` on it.
///
/// The tag and the nonce share one write so there is exactly one failure path
/// between opening and having asked the peer something.
pub(crate) async fn open_probe(open_tx: &mpsc::Sender<OpenStreamReply>, nonce: u64) -> Option<yamux::Stream> {
    let mut stream = match open_stream(open_tx).await {
        Ok(s) => s,
        // A closed connection is expected reconnect-window churn; anything else
        // is a transport-alive failure worth surfacing.
        Err(yamux::ConnectionError::Closed) => {
            tracing::debug!("no keepalive substream: connection closed");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to open the keepalive substream");
            return None;
        }
    };

    let mut request = [0u8; 1 + KEEPALIVE_NONCE_LEN];
    request[0] = StreamTag::Keepalive.to_byte();
    request[1..].copy_from_slice(&nonce.to_be_bytes());
    if let Err(e) = stream.write_all(&request).await {
        tracing::debug!(nonce, error = %e, "keepalive probe could not be written");
        return None;
    }
    if let Err(e) = stream.flush().await {
        tracing::debug!(nonce, error = %e, "keepalive probe could not be flushed");
        return None;
    }
    Some(stream)
}

/// Give an idle transport a reason to speak, then wait for the probe substream to
/// say anything at all. Never resolves when the probe could not be sent — the
/// caller's deadline ends the cycle either way.
///
/// One `read` is the whole client-side protocol. Every outcome — the echo, a peer
/// FIN, a peer reset — required a frame the connection read off the socket, and
/// the tap counted that read; the echo's *value* is never part of the verdict.
/// `read` is also cancel-safe where `read_exact` is not, and the substream is
/// dropped when the cycle ends, so a deadline firing here costs nothing.
async fn elicit(open_tx: &mpsc::Sender<OpenStreamReply>, nonce: u64) {
    let Some(mut stream) = open_probe(open_tx, nonce).await else {
        return std::future::pending().await;
    };
    tracing::debug!(nonce, "keepalive probe sent");

    let mut sink = [0u8; KEEPALIVE_NONCE_LEN];
    match stream.read(&mut sink).await {
        Ok(0) => tracing::debug!(nonce, "keepalive probe substream ended"),
        Ok(_) => {}
        Err(e) => tracing::debug!(nonce, error = %e, "keepalive probe read failed"),
    }
}

/// What one keepalive cycle concluded about the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeepaliveCycle {
    /// The transport spoke during the interval, so nothing was asked of it.
    Skipped,
    /// Something arrived before the deadline was up.
    Answered,
    /// Nothing at all arrived across the whole deadline.
    Silent,
}

/// One cycle against a transport whose tap last read `*last_seen`, re-baselining
/// it whenever the transport speaks.
///
/// A cycle is fatal only when the tap did not move across a whole deadline that
/// began with a probe *attempt*. If the probe could not be sent, the reading is
/// the same: a connection whose substream budget is exhausted while delivering
/// nothing is, at this layer, indistinguishable from a dead one, and reconnecting
/// is the fail-safe choice for a VPN.
pub(crate) async fn keepalive_cycle(
    open_tx: &mpsc::Sender<OpenStreamReply>,
    nonce: u64,
    inbound_reads: &AtomicU64,
    last_seen: &mut u64,
    timeout: Duration,
) -> KeepaliveCycle {
    let seen = inbound_reads.load(Ordering::Relaxed);
    if seen != *last_seen {
        *last_seen = seen;
        return KeepaliveCycle::Skipped;
    }

    // The deadline IS how long silence is tolerated, not synchronization between
    // our own code paths. It covers the substream open too, which parks
    // indefinitely once enough substreams await an ACK — exactly what a black
    // hole produces.
    tokio::select! {
        () = elicit(open_tx, nonce) => {}
        () = tokio::time::sleep(timeout) => {}
    }

    let seen = inbound_reads.load(Ordering::Relaxed);
    if seen != *last_seen {
        *last_seen = seen;
        return KeepaliveCycle::Answered;
    }
    KeepaliveCycle::Silent
}

/// Client-side liveness for one yamux session.
///
/// Every `cadence.interval` in which the transport delivered nothing, it gives the
/// peer a reason to speak and then asks the tap whether *anything* arrived before
/// `cadence.timeout` was up. Resolves only when the answer is no, so the caller
/// can park on it as a plain `select!` arm.
pub(crate) async fn run_keepalive(
    open_tx: mpsc::Sender<OpenStreamReply>,
    inbound_reads: Arc<AtomicU64>,
    cadence: Cadence,
) {
    let mut last_seen = inbound_reads.load(Ordering::Relaxed);
    let mut nonce: u64 = 0;

    loop {
        // The cadence IS the behavior (a keepalive interval), not
        // synchronization between our own code paths.
        tokio::time::sleep(cadence.interval).await;
        nonce = nonce.wrapping_add(1);

        match keepalive_cycle(&open_tx, nonce, &inbound_reads, &mut last_seen, cadence.timeout).await {
            KeepaliveCycle::Skipped => tracing::debug!("transport still active; skipping the keepalive probe"),
            KeepaliveCycle::Answered => tracing::debug!(nonce, "transport answered inside the keepalive deadline"),
            KeepaliveCycle::Silent => {
                tracing::warn!(
                    nonce,
                    "transport silent across the keepalive deadline; declaring it dead"
                );
                return;
            }
        }
    }
}
