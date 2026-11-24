//! A queue in front of a destination, so that a write never runs on the thread that logs.
//!
//! Nothing on the path has a time limit: a queue that waits holds its senders until the destination takes bytes,
//! and [`QueuedGuard::finish`] returns once the destination has taken everything. What a destination refused and
//! what a full queue dropped is counted and returned by `finish`.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;

use super::{DeliveryThread, OriginalStderr, DELIVERY_THREAD};

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

/// How a write to a [`Queued`] is handed over, which depends on the thread that makes it.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Handover {
    /// Into the queue; a full queue does what the queue's [`Overflow`] says.
    Queue,
    /// Offered to the queue without waiting; to the original stderr when the queue is full or has ended.
    Offer,
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
/// Contract: on a writer thread a write never waits for a queue. It is offered to the queue, and goes to the original
/// stderr when the queue is full or has ended. Code on a writer thread logs once per event it reports, never once per
/// message it writes. It writes no redirected stream. A writer that waited for a queue or for a redirected stream
/// could be waiting for itself, directly or through the relay thread that reads the stream.
///
/// The panic record of a writer whose own destination panicked is lost with that writer's queue, and so is any record
/// a writer offers to its own queue after `Finish` is queued.
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
    /// The writer thread panicked; senders failed from then on instead of waiting.
    pub panicked: bool,
}

impl std::fmt::Display for QueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "writes refused: {}, messages dropped: {}",
            self.refused, self.dropped
        )?;
        if self.panicked {
            f.write_str(", the writer thread panicked")?;
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
    panicked: bool,
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
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                write_all_messages(&mut destination, &receiver, &mut written);
            }));
            written.panicked = unwound.is_err();
            // Before the destination is dropped: from here a sender fails instead of waiting for room.
            drop(receiver);
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
    /// Hands `buf` over as one message. Off a writer thread, `Err` once the writer thread has ended.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let message = Message::Bytes(buf.to_vec());
        match DELIVERY_THREAD.get().map_or(Handover::Queue, DeliveryThread::handover) {
            Handover::Queue => self.overflow.send(&self.sender, message, &self.dropped)?,
            Handover::Offer => match self.sender.try_send(message) {
                Ok(()) => {}
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => OriginalStderr.write_all(buf)?,
            },
        }
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
    /// Return once every message queued before the call is written and flushed. No time limit: a destination that
    /// takes no bytes holds the call. Later writes to the queue fail.
    pub(crate) fn finish(self) -> Result<(), QueueError> {
        // Waits for room in a full queue; fails when the writer thread has already ended, which the join reports.
        let _ = self.sender.send(Message::Finish);
        // The thread catches its destination's panic, so a join error is a panic outside the destination.
        let written = self.thread.join().unwrap_or_else(|_| Written {
            panicked: true,
            ..Written::default()
        });
        let error = QueueError {
            first: written.first,
            refused: written.refused,
            dropped: self.dropped.load(Ordering::Relaxed),
            panicked: written.panicked,
        };
        if error.first.is_none() && error.dropped == 0 && !error.panicked {
            Ok(())
        } else {
            Err(error)
        }
    }
}

#[cfg(test)]
#[path = "queued_tests.rs"]
mod queued_tests;
