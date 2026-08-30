//! TUN write path, extracted from `Driver::flush_to_tun`.
//!
//! `poll_write` on a real TUN device is the loop's only await the OS can
//! hold `Pending` indefinitely: on unix, `tun`'s `AsyncFd`-backed
//! `poll_write` returns `Pending` for as long as the fd is not writable,
//! with no upper bound and no wakeup tied to any cancellation token. `flush`
//! races the driver's token against every write so that wedge cannot
//! outlive cancellation.

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// Outcome of a [`flush`] or [`flush_all`] call.
#[derive(Debug)]
pub(crate) enum Flush {
    Drained,
    Failed(std::io::Error),
    Cancelled,
}

/// Writes each packet in `packets` to `tun`, in order, racing the driver's
/// token against every write. The token is checked once before iterating
/// (so an already-cancelled driver reports `Cancelled` even for an empty
/// queue) and again — via a `biased` select — before each write.
///
/// Never logs; the caller (`flush_all`) names the batch.
pub(crate) async fn flush<W: AsyncWrite + Unpin>(
    tun: &mut W,
    packets: impl IntoIterator<Item = Vec<u8>>,
    cancel: &CancellationToken,
) -> Flush {
    if cancel.is_cancelled() {
        return Flush::Cancelled;
    }

    for pkt in packets {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Flush::Cancelled,
            result = tun.write_all(&pkt) => {
                if let Err(e) = result {
                    return Flush::Failed(e);
                }
            }
        }
    }

    Flush::Drained
}

/// Runs the TX batch, then the reply batch unless the TX batch was
/// cancelled. Logs each `Failed` outcome with the message its batch owns.
///
/// Return precedence is `Cancelled` first, then the first `Failed`, then
/// `Drained` — a `Cancelled` from the reply batch must not be masked by a
/// `Failed` from the TX batch, or the driver misses the cancellation for
/// one extra loop iteration.
pub(crate) async fn flush_all<W: AsyncWrite + Unpin>(
    tun: &mut W,
    tx_queue: Vec<Vec<u8>>,
    replies: Vec<Vec<u8>>,
    cancel: &CancellationToken,
) -> Flush {
    let tx_result = flush(tun, tx_queue, cancel).await;
    if let Flush::Failed(e) = &tx_result {
        warn!("TUN write error: {e}");
    }
    if matches!(tx_result, Flush::Cancelled) {
        return Flush::Cancelled;
    }

    let reply_result = flush(tun, replies, cancel).await;
    if let Flush::Failed(e) = &reply_result {
        warn!("TUN write error (UDP reply): {e}");
    }

    match (tx_result, reply_result) {
        (_, Flush::Cancelled) => Flush::Cancelled,
        (Flush::Failed(e), _) => Flush::Failed(e),
        (_, Flush::Failed(e)) => Flush::Failed(e),
        (Flush::Drained, Flush::Drained) => Flush::Drained,
        (Flush::Cancelled, _) => unreachable!("returned above"),
    }
}

#[cfg(test)]
#[path = "egress_tests.rs"]
mod egress_tests;
