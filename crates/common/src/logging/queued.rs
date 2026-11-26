//! A queue in front of a destination, so that a write never runs on the thread that logs.
//!
//! Nothing on the path has a time limit: a queue that waits holds its senders until the destination takes bytes,
//! and [`QueuedGuard::finish`] returns once the destination has taken everything. What a destination refused, what a
//! full queue dropped and a panic of the destination are returned by `finish`.

use std::io::{self, Write};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;

use super::{DeliveryThread, PanicReport, DELIVERY_THREAD};

/// How many messages a queue holds. A message is one `write`: a whole event from a `tracing` layer, a line from a
/// relay.
pub(crate) const CAPACITY: usize = 128_000;

/// What a write does when the queue is full.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Overflow {
    /// The write waits for room. Nothing is dropped; a destination that stops taking bytes holds its writers.
    Wait,
    /// The message is dropped and counted.
    Drop,
}

impl Overflow {
    /// Hand `message` to the queue. `Err` when the writer thread has ended.
    fn send(self, sender: &SyncSender<Message>, message: Message, dropped: &AtomicU64) -> Result<(), Ended> {
        match self {
            Overflow::Wait => sender.send(message).map_err(|_| Ended),
            Overflow::Drop => match sender.try_send(message) {
                Ok(()) => Ok(()),
                Err(TrySendError::Full(_)) => {
                    dropped.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
                Err(TrySendError::Disconnected(_)) => Err(Ended),
            },
        }
    }
}

/// The writer thread has ended: it was finished, or its destination panicked.
struct Ended;

impl From<Ended> for io::Error {
    fn from(_: Ended) -> Self {
        io::Error::other("the writer thread of this queue has ended")
    }
}

enum Message {
    Bytes(Vec<u8>),
    /// Everything queued before this is written and flushed, and the writer thread ends.
    Finish,
}

/// Hands each write to a thread that owns the destination. Clone; a `MakeWriter`.
///
/// Contract: Code on a writer thread does not log through `tracing`, and a write to a `Queued` made on a live writer
/// thread breaks this contract (debug assertion). A destination reports its own events into itself. A writer whose
/// destination panicked logs the panic, once its queue has ended, into the sinks still open, and `finish` returns the
/// panic's message and location. A panic raised by logging it is caught and not logged, and `finish` returns that one
/// too; where the writer has two panics to log, such a panic does not stop the logging of the second. A writer thread
/// writes no redirected stream. Its one write elsewhere is `DirRotate`'s notice that the file could not be opened, to
/// the original stderr.
///
/// No destination in Hole catches its own panic. If one did, the panic's record would wait on the writer thread until
/// its queue ends and then go to the sinks still open; for the log file, which `LogGuard` finishes last, that is none.
/// `finish` reports a panic that unwound out of the destination, the first if there were two.
///
/// A writer that waited for a queue or for a redirected stream could be waiting for itself, directly or through the
/// relay thread that reads the stream.
#[derive(Clone)]
pub(crate) struct Queued {
    sender: SyncSender<Message>,
    overflow: Overflow,
    dropped: Arc<AtomicU64>,
}

/// Owns the writer thread. Dropped without [`Self::finish`], the thread keeps writing until every [`Queued`] is gone.
#[must_use]
pub(crate) struct QueuedGuard {
    sender: SyncSender<Message>,
    dropped: Arc<AtomicU64>,
    thread: JoinHandle<Written>,
}

/// What a queue did not deliver.
#[derive(Debug)]
pub(crate) struct QueueError {
    /// The first error the destination returned. The writer went on writing after it.
    pub first: Option<io::Error>,
    /// Writes the destination refused.
    pub refused: u64,
    /// Messages a full queue dropped.
    pub dropped: u64,
    /// The destination panicked, which ended the writer thread; senders failed from then on instead of waiting.
    pub panic: Option<PanicReport>,
    /// The first panic raised while the writer thread, its queue ended, logged its panics: the record being logged
    /// may have reached no sink.
    pub logging_panic: Option<PanicReport>,
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "writes refused: {}, messages dropped: {}",
            self.refused, self.dropped
        )?;
        if let Some(panic) = &self.panic {
            write!(f, ", the writer thread panicked: {panic}")?;
        }
        if let Some(panic) = &self.logging_panic {
            write!(f, ", logging the writer thread's panics panicked: {panic}")?;
        }
        Ok(())
    }
}

impl std::error::Error for QueueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.first.as_ref().map(|first| first as _)
    }
}

/// What the writer thread did with the destination.
#[derive(Default)]
struct Written {
    first: Option<io::Error>,
    refused: u64,
    panic: Option<PanicReport>,
    logging_panic: Option<PanicReport>,
}

impl Written {
    fn write(&mut self, result: io::Result<()>) {
        if let Err(error) = result {
            self.refused += 1;
            self.first.get_or_insert(error);
        }
    }

    fn flush(&mut self, result: io::Result<()>) {
        if let Err(error) = result {
            self.first.get_or_insert(error);
        }
    }
}

/// Start a thread that owns `destination` and writes what the returned [`Queued`] and its clones are handed.
pub(crate) fn queued<W: Write + Send + 'static>(destination: W, overflow: Overflow) -> (Queued, QueuedGuard) {
    let (sender, receiver) = mpsc::sync_channel(CAPACITY);
    let dropped = Arc::new(AtomicU64::new(0));
    let thread = std::thread::Builder::new()
        .name("hole-log-writer".into())
        .spawn(move || {
            DELIVERY_THREAD.set(Some(DeliveryThread::Writer));
            let mut destination = destination;
            let mut written = Written::default();
            let wrote = std::panic::catch_unwind(AssertUnwindSafe(|| {
                write_all_messages(&mut destination, &receiver, &mut written);
            }));
            let wrote = wrote.err().map(|payload| super::writer_panic_report(&*payload));
            // Before the destination is dropped: from here a sender fails instead of waiting for room.
            drop(receiver);
            // Still a writer thread: the destination's drop is the destination's code.
            let dropped = std::panic::catch_unwind(AssertUnwindSafe(move || drop(destination)));
            let dropped = dropped.err().map(|payload| super::writer_panic_report(&*payload));
            // The queue has ended, so the panics logged from here wait for no queue that waits for this thread.
            written.logging_panic = super::leave_writer_thread();
            written.panic = wrote.or(dropped);
            written
        })
        .expect("failed to spawn a log writer thread");
    let queued = Queued {
        sender: sender.clone(),
        overflow,
        dropped: Arc::clone(&dropped),
    };
    (
        queued,
        QueuedGuard {
            sender,
            dropped,
            thread,
        },
    )
}

/// Write each message as it arrives, and flush whenever the queue is empty, until `Finish` or until every sender
/// is gone.
fn write_all_messages(destination: &mut impl Write, receiver: &Receiver<Message>, written: &mut Written) {
    // `recv` waits while the queue is empty.
    while let Ok(first) = receiver.recv() {
        let mut next = Some(first);
        while let Some(message) = next {
            match message {
                Message::Bytes(bytes) => written.write(destination.write_all(&bytes)),
                Message::Finish => {
                    written.flush(destination.flush());
                    return;
                }
            }
            next = receiver.try_recv().ok();
        }
        written.flush(destination.flush());
    }
}

impl Write for Queued {
    /// Hands `buf` over as one message. `Err` once the writer thread has ended.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        debug_assert!(
            DELIVERY_THREAD.get().is_none_or(DeliveryThread::writes_queues),
            "a write to a log queue on a live writer thread, which does not log (see `Queued`)"
        );
        self.overflow
            .send(&self.sender, Message::Bytes(buf.to_vec()), &self.dropped)?;
        Ok(buf.len())
    }

    /// The writer thread flushes the destination whenever its queue is empty.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Queued {
    type Writer = Queued;

    fn make_writer(&'a self) -> Queued {
        self.clone()
    }
}

impl QueuedGuard {
    /// Returns once every message queued before the call is written and flushed. No time limit: a destination that
    /// takes no bytes holds the call. A write made while the call runs may be lost without being counted; a write
    /// made after it returns fails.
    pub(crate) fn finish(self) -> Result<(), QueueError> {
        // Waits for room in a full queue; fails when the writer thread has already ended, which the join reports.
        let _ = self.sender.send(Message::Finish);
        // The thread catches its destination's panics and a panic of logging them: a join error is one outside both.
        let written = self.thread.join().unwrap_or_else(|payload| Written {
            panic: Some(PanicReport::from_payload(&*payload)),
            ..Written::default()
        });
        let error = QueueError {
            first: written.first,
            refused: written.refused,
            dropped: self.dropped.load(Ordering::Relaxed),
            panic: written.panic,
            logging_panic: written.logging_panic,
        };
        if error.first.is_none() && error.dropped == 0 && error.panic.is_none() && error.logging_panic.is_none() {
            Ok(())
        } else {
            Err(error)
        }
    }
}

#[cfg(test)]
#[path = "queued_tests.rs"]
mod queued_tests;
