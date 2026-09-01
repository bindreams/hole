#![allow(clippy::disallowed_methods)] // fixtures build their own root CancellationToken; see clippy.toml

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::*;

// Fixtures ============================================================================================================

/// Completes every write immediately and records it.
#[derive(Default, Clone)]
struct RecordingWriter {
    log: Arc<Mutex<Vec<Vec<u8>>>>,
    completed: Arc<AtomicUsize>,
}

impl AsyncWrite for RecordingWriter {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.log.lock().unwrap().push(buf.to_vec());
        self.completed.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Errors on its `error_on_call`-th write (1-indexed); records every write
/// that completes.
struct ErroringWriter {
    log: Arc<Mutex<Vec<Vec<u8>>>>,
    completed: Arc<AtomicUsize>,
    calls: AtomicUsize,
    error_on_call: usize,
}

impl ErroringWriter {
    fn new(error_on_call: usize) -> Self {
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
            completed: Arc::new(AtomicUsize::new(0)),
            calls: AtomicUsize::new(0),
            error_on_call,
        }
    }
}

impl AsyncWrite for ErroringWriter {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let call_no = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call_no == self.error_on_call {
            return Poll::Ready(Err(io::Error::other("simulated write error")));
        }
        self.log.lock().unwrap().push(buf.to_vec());
        self.completed.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Always `Pending`. Signals `polled` the first time it is polled — proof
/// it is really in flight, the same rendezvous shape `dns_tests.rs` uses —
/// and counts every poll in `polls` so a caller can prove a *later* batch
/// was never even attempted.
struct NeverReadyWriter {
    polled: Mutex<Option<oneshot::Sender<()>>>,
    polls: Arc<AtomicUsize>,
}

impl NeverReadyWriter {
    fn new(polled: oneshot::Sender<()>, polls: Arc<AtomicUsize>) -> Self {
        Self {
            polled: Mutex::new(Some(polled)),
            polls,
        }
    }
}

impl AsyncWrite for NeverReadyWriter {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if let Some(tx) = self.polled.lock().unwrap().take() {
            let _ = tx.send(());
        }
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Completes every write immediately, but cancels `cancel` from inside its
/// very first `poll_write` — the deterministic way to prove the token is
/// checked before *each* write, not merely once before the loop: a
/// check-once implementation writes every packet and returns `Drained`,
/// which fails the test cleanly instead of hanging.
struct CancelOnWriteWriter {
    log: Arc<Mutex<Vec<Vec<u8>>>>,
    completed: Arc<AtomicUsize>,
    cancel: CancellationToken,
    fired: AtomicBool,
}

impl CancelOnWriteWriter {
    fn new(cancel: CancellationToken) -> Self {
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
            completed: Arc::new(AtomicUsize::new(0)),
            cancel,
            fired: AtomicBool::new(false),
        }
    }
}

impl AsyncWrite for CancelOnWriteWriter {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if !self.fired.swap(true, Ordering::SeqCst) {
            self.cancel.cancel();
        }
        self.log.lock().unwrap().push(buf.to_vec());
        self.completed.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Errors on its first write, then is `Pending` forever, signalling
/// `polled_second` the first time a write past the error is attempted —
/// the TX-error / reply-wedge combination `flush_all`'s precedence tests
/// need.
struct ErrorThenNeverReadyWriter {
    calls: AtomicUsize,
    polled_second: Mutex<Option<oneshot::Sender<()>>>,
}

impl ErrorThenNeverReadyWriter {
    fn new(polled_second: oneshot::Sender<()>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            polled_second: Mutex::new(Some(polled_second)),
        }
    }
}

impl AsyncWrite for ErrorThenNeverReadyWriter {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        let call_no = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call_no == 1 {
            return Poll::Ready(Err(io::Error::other("simulated write error")));
        }
        if let Some(tx) = self.polled_second.lock().unwrap().take() {
            let _ = tx.send(());
        }
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn packets(bufs: &[&[u8]]) -> Vec<Vec<u8>> {
    bufs.iter().map(|b| b.to_vec()).collect()
}

// flush ===============================================================================================================

#[skuld::test]
async fn flush_writes_every_queued_packet_in_order() {
    let mut writer = RecordingWriter::default();
    let cancel = CancellationToken::new();
    let queue = packets(&[b"a", b"b", b"c"]);

    let result = flush(&mut writer, queue.clone(), &cancel).await;

    assert!(matches!(result, Flush::Drained));
    assert_eq!(*writer.log.lock().unwrap(), queue);
}

#[skuld::test]
async fn flush_of_an_empty_queue_is_drained() {
    let mut writer = RecordingWriter::default();
    let cancel = CancellationToken::new();

    let result = flush(&mut writer, Vec::new(), &cancel).await;

    assert!(matches!(result, Flush::Drained));
}

#[skuld::test]
async fn an_already_cancelled_driver_writes_nothing() {
    let mut writer = RecordingWriter::default();
    let completed = writer.completed.clone();
    let cancel = CancellationToken::new();
    cancel.cancel();

    let result = flush(&mut writer, packets(&[b"a"]), &cancel).await;

    assert!(matches!(result, Flush::Cancelled));
    assert_eq!(completed.load(Ordering::SeqCst), 0);
}

#[skuld::test]
async fn an_empty_queue_on_a_cancelled_driver_is_cancelled_not_drained() {
    let mut writer = RecordingWriter::default();
    let cancel = CancellationToken::new();
    cancel.cancel();

    let result = flush(&mut writer, Vec::new(), &cancel).await;

    assert!(matches!(result, Flush::Cancelled));
}

#[skuld::test]
async fn flush_stops_at_the_first_write_error() {
    let mut writer = ErroringWriter::new(2);
    let completed = writer.completed.clone();
    let cancel = CancellationToken::new();

    let result = flush(&mut writer, packets(&[b"a", b"b", b"c"]), &cancel).await;

    assert!(matches!(result, Flush::Failed(_)));
    assert_eq!(completed.load(Ordering::SeqCst), 1);
}

#[skuld::test]
async fn flush_stops_at_the_packet_after_the_driver_is_cancelled() {
    let cancel = CancellationToken::new();
    let mut writer = CancelOnWriteWriter::new(cancel.clone());
    let completed = writer.completed.clone();

    let result = flush(&mut writer, packets(&[b"a", b"b", b"c"]), &cancel).await;

    assert!(matches!(result, Flush::Cancelled));
    assert_eq!(completed.load(Ordering::SeqCst), 1);
}

#[skuld::test]
async fn a_write_that_never_completes_is_abandoned_when_the_driver_is_cancelled() {
    let (polled_tx, polled_rx) = oneshot::channel();
    let polls = Arc::new(AtomicUsize::new(0));
    let mut writer = NeverReadyWriter::new(polled_tx, polls.clone());
    let cancel = CancellationToken::new();

    let fut = flush(&mut writer, packets(&[b"a"]), &cancel);
    tokio::pin!(fut);

    tokio::select! {
        biased;
        _ = polled_rx => {}
        _ = &mut fut => panic!("flush resolved; the write must hang forever"),
    }

    cancel.cancel();
    let result = fut.await;

    assert!(matches!(result, Flush::Cancelled));
    assert_eq!(polls.load(Ordering::SeqCst), 1);
}

// flush_all ===========================================================================================================

#[skuld::test]
async fn flush_all_writes_the_tx_batch_before_the_reply_batch() {
    let mut writer = RecordingWriter::default();
    let cancel = CancellationToken::new();

    let result = flush_all(&mut writer, packets(&[b"tx1"]), packets(&[b"reply1"]), &cancel).await;

    assert!(matches!(result, Flush::Drained));
    assert_eq!(*writer.log.lock().unwrap(), vec![b"tx1".to_vec(), b"reply1".to_vec()]);
}

#[skuld::test]
async fn flush_all_skips_the_reply_batch_when_the_tx_batch_is_cancelled() {
    let (polled_tx, polled_rx) = oneshot::channel();
    let polls = Arc::new(AtomicUsize::new(0));
    let mut writer = NeverReadyWriter::new(polled_tx, polls.clone());
    let cancel = CancellationToken::new();

    let fut = flush_all(&mut writer, packets(&[b"tx1"]), packets(&[b"reply1"]), &cancel);
    tokio::pin!(fut);

    tokio::select! {
        biased;
        _ = polled_rx => {}
        _ = &mut fut => panic!("flush_all resolved; the TX write must hang forever"),
    }

    cancel.cancel();
    let result = fut.await;

    assert!(matches!(result, Flush::Cancelled));
    // Only the TX packet's write was ever attempted — the reply batch's
    // flush() call never started.
    assert_eq!(polls.load(Ordering::SeqCst), 1);
}

#[skuld::test]
async fn flush_all_still_attempts_the_reply_batch_after_a_tx_write_error() {
    let mut writer = ErroringWriter::new(1);
    let cancel = CancellationToken::new();

    let result = flush_all(&mut writer, packets(&[b"tx1"]), packets(&[b"reply1"]), &cancel).await;

    assert!(matches!(result, Flush::Failed(_)));
    assert_eq!(*writer.log.lock().unwrap(), vec![b"reply1".to_vec()]);
}

#[skuld::test]
async fn flush_all_reports_cancelled_when_the_reply_batch_is_cancelled_after_a_tx_error() {
    let (polled_tx, polled_rx) = oneshot::channel();
    let mut writer = ErrorThenNeverReadyWriter::new(polled_tx);
    let cancel = CancellationToken::new();

    let fut = flush_all(&mut writer, packets(&[b"tx1"]), packets(&[b"reply1"]), &cancel);
    tokio::pin!(fut);

    tokio::select! {
        biased;
        _ = polled_rx => {}
        _ = &mut fut => panic!("flush_all resolved; the reply write must hang forever"),
    }

    cancel.cancel();
    let result = fut.await;

    assert!(matches!(result, Flush::Cancelled));
}
