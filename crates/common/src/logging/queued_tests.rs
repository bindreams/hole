// The parties of each test are the thread that writes to the queue, the thread that finishes it and the
// destination. A destination that must be late holds its first write until the test releases it, and every wait is
// on a channel.

use super::{queued, Overflow, CAPACITY};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// What a [`Held`] destination does once its first write is released.
enum Release {
    Write,
    Panic,
}

/// A destination that says when its first write begins and holds it until it is told what to do. Counts the writes
/// it took, and keeps the messages when asked to.
struct Held {
    entered: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<Release>,
    writes: Arc<AtomicUsize>,
    messages: Option<Arc<Mutex<Vec<String>>>>,
    /// Run when the first write is released, before it returns.
    on_release: Observe,
    /// Run when a message with this text is taken.
    on_message: Option<(&'static str, Observe)>,
}

/// Something a test has the destination record, on the writer thread.
type Observe = Box<dyn FnMut() + Send>;

/// The test's ends of a [`Held`] destination.
struct Holder {
    entered: mpsc::Receiver<()>,
    release: mpsc::Sender<Release>,
    writes: Arc<AtomicUsize>,
}

fn held() -> (Held, Holder) {
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let writes = Arc::new(AtomicUsize::new(0));
    let destination = Held {
        entered: Some(entered_tx),
        release: release_rx,
        writes: Arc::clone(&writes),
        messages: None,
        on_release: Box::new(|| {}),
        on_message: None,
    };
    (
        destination,
        Holder {
            entered,
            release,
            writes,
        },
    )
}

impl Write for Held {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(entered) = self.entered.take() {
            entered.send(()).expect("the test waits for the first write");
            let release = self.release.recv().expect("the test releases the first write");
            (self.on_release)();
            if let Release::Panic = release {
                panic!("the destination panics");
            }
        }
        let text = String::from_utf8_lossy(buf).into_owned();
        if let Some((wanted, run)) = &mut self.on_message {
            if text == *wanted {
                run();
            }
        }
        if let Some(messages) = &self.messages {
            messages.lock().unwrap().push(text);
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Fill the queue behind a destination that is inside its first write: exactly `CAPACITY` messages fit.
fn fill(queue: &mut impl Write) {
    for _ in 0..CAPACITY {
        queue.write_all(b"x").expect("the queue has room");
    }
}

/// `finish` returns only after the destination has taken every message queued before it. The destination holds its
/// first write until the finishing thread has said it is about to call `finish`; when it takes the last message it
/// records whether `finish` had returned, which on correct code it cannot have. A write after `finish` fails: nothing
/// is left to write it.
///
/// A `finish` that does not wait is seen only when the finishing thread runs on before the destination reaches the
/// last message. Nothing orders those two without a clock, so that mutant is red on most runs and not on every one.
#[skuld::test]
fn finish_returns_only_after_a_held_destination_has_taken_every_message() {
    let (mut destination, holder) = held();
    let messages = Arc::new(Mutex::new(Vec::new()));
    let finish_returned = Arc::new(AtomicBool::new(false));
    let returned_at_last = Arc::new(Mutex::new(None));
    destination.messages = Some(Arc::clone(&messages));
    destination.on_message = Some((
        "last",
        Box::new({
            let (finish_returned, returned_at_last) = (Arc::clone(&finish_returned), Arc::clone(&returned_at_last));
            move || *returned_at_last.lock().unwrap() = Some(finish_returned.load(Ordering::SeqCst))
        }),
    ));
    let (mut queue, guard) = queued(destination, Overflow::Wait);
    for message in ["first", "middle", "last"] {
        queue.write_all(message.as_bytes()).expect("the queue has room");
    }
    holder.entered.recv().expect("the destination's first write");

    let (about_to_finish, finishing) = mpsc::channel();
    let finisher = std::thread::spawn({
        let finish_returned = Arc::clone(&finish_returned);
        move || {
            about_to_finish.send(()).expect("the test waits for it");
            let result = guard.finish();
            finish_returned.store(true, Ordering::SeqCst);
            result
        }
    });
    finishing.recv().expect("the finishing thread");
    holder.release.send(Release::Write).expect("the destination is waiting");
    let result = finisher.join().expect("the finishing thread");
    let late = queue.write_all(b"late");

    assert!(result.is_ok(), "{result:?}");
    assert!(late.is_err(), "a write to a finished queue returned {late:?}");
    assert_eq!(*messages.lock().unwrap(), ["first", "middle", "last"]);
    assert_eq!(
        *returned_at_last.lock().unwrap(),
        Some(false),
        "whether `finish` had returned when the destination took the last message"
    );
}

/// A full queue that waits holds the thread that writes to it, and drops nothing. When the destination's first write
/// is released the queue is still full, so the write of one message too many cannot have returned; afterwards the
/// destination has taken every message.
///
/// A queue that dropped the message instead is seen only when the writing thread reaches its write before the
/// destination frees a slot; that mutant is red on most runs and not on every one.
#[skuld::test]
fn a_full_queue_that_waits_holds_the_writing_thread_and_drops_nothing() {
    let (mut destination, holder) = held();
    let write_returned = Arc::new(AtomicBool::new(false));
    let returned_at_release = Arc::new(Mutex::new(None));
    destination.on_release = Box::new({
        let (write_returned, returned_at_release) = (Arc::clone(&write_returned), Arc::clone(&returned_at_release));
        move || *returned_at_release.lock().unwrap() = Some(write_returned.load(Ordering::SeqCst))
    });
    let (mut queue, guard) = queued(destination, Overflow::Wait);
    queue.write_all(b"held").expect("the queue has room");
    holder.entered.recv().expect("the destination's first write");
    fill(&mut queue);

    let (about_to_write, writing) = mpsc::channel();
    let writer = std::thread::spawn({
        let write_returned = Arc::clone(&write_returned);
        move || {
            about_to_write.send(()).expect("the test waits for it");
            let result = queue.write_all(b"one too many");
            write_returned.store(true, Ordering::SeqCst);
            result
        }
    });
    writing.recv().expect("the writing thread");
    holder.release.send(Release::Write).expect("the destination is waiting");
    writer
        .join()
        .expect("the writing thread")
        .expect("the write is taken once there is room");
    let result = guard.finish();

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(holder.writes.load(Ordering::SeqCst), CAPACITY + 2);
    assert_eq!(
        *returned_at_release.lock().unwrap(),
        Some(false),
        "whether the write to the full queue had returned while the destination still held its first write"
    );
}

/// A full queue that drops returns from each write at once, takes no more than it holds and counts what it dropped.
///
/// A queue that waited instead would hold this test's own thread for ever: that mutant is a hang, not a failed
/// assertion.
#[skuld::test]
fn a_full_queue_that_drops_counts_what_it_dropped() {
    let (destination, holder) = held();
    let (mut queue, guard) = queued(destination, Overflow::Drop);
    queue.write_all(b"held").expect("the queue has room");
    holder.entered.recv().expect("the destination's first write");
    fill(&mut queue);

    for _ in 0..3 {
        queue.write_all(b"one too many").expect("a dropped write succeeds");
    }
    holder.release.send(Release::Write).expect("the destination is waiting");
    let error = guard.finish().expect_err("three messages were dropped");

    assert_eq!(
        (
            error.dropped,
            error.refused,
            error.first.is_some(),
            error.panic.is_some()
        ),
        (3, 0, false, false),
        "{error:?}"
    );
    assert_eq!(holder.writes.load(Ordering::SeqCst), CAPACITY + 1);
}

/// A destination that refuses a write is given the later ones all the same, and `finish` returns the first error and
/// how many writes were refused.
#[skuld::test]
fn a_refused_write_does_not_stop_the_writer_and_is_counted() {
    struct Refusing(Arc<Mutex<Vec<String>>>);
    impl Write for Refusing {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let text = String::from_utf8_lossy(buf).into_owned();
            match text.as_str() {
                "second" => Err(io::Error::new(io::ErrorKind::StorageFull, "refused the second")),
                "fourth" => Err(io::Error::new(io::ErrorKind::PermissionDenied, "refused the fourth")),
                _ => {
                    self.0.lock().unwrap().push(text);
                    Ok(buf.len())
                }
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let taken = Arc::new(Mutex::new(Vec::new()));
    let (mut queue, guard) = queued(Refusing(Arc::clone(&taken)), Overflow::Wait);
    for message in ["first", "second", "third", "fourth", "fifth"] {
        queue.write_all(message.as_bytes()).expect("the queue has room");
    }
    let error = guard.finish().expect_err("two writes were refused");

    assert_eq!(*taken.lock().unwrap(), ["first", "third", "fifth"]);
    assert_eq!(
        (error.refused, error.dropped, error.panic.is_some()),
        (2, 0, false),
        "{error:?}"
    );
    assert_eq!(
        error.first.as_ref().map(ToString::to_string).as_deref(),
        Some("refused the second")
    );
}

/// A destination that panics ends its writer thread. A thread that was waiting for room in the full queue fails at
/// once, `finish` reports the panic, and later writes fail. The waiting thread can never succeed here: no slot is
/// freed after the panic.
#[skuld::test(serial)]
fn a_destination_that_panics_fails_a_waiting_writer_and_finish_reports_it() {
    // The panic is this test's subject, not a failure of it.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let (destination, holder) = held();
    let (mut queue, guard) = queued(destination, Overflow::Wait);
    queue.write_all(b"held").expect("the queue has room");
    holder.entered.recv().expect("the destination's first write");
    fill(&mut queue);

    let (about_to_write, writing) = mpsc::channel();
    let writer = std::thread::spawn({
        let mut queue = queue.clone();
        move || {
            about_to_write.send(()).expect("the test waits for it");
            queue.write_all(b"one too many")
        }
    });
    writing.recv().expect("the writing thread");
    holder.release.send(Release::Panic).expect("the destination is waiting");
    let waited = writer.join().expect("the writing thread");
    let error = guard.finish().expect_err("the writer thread panicked");
    let late = queue.write_all(b"late");

    std::panic::set_hook(previous_hook);
    assert!(waited.is_err(), "the write that waited for room returned {waited:?}");
    // The hook here is not Hole's, so only the payload is known.
    assert_eq!(
        error.panic,
        Some(crate::logging::PanicReport {
            message: "the destination panics".to_string(),
            location: None
        }),
        "{error:?}"
    );
    assert!(late.is_err(), "a write after the writer thread ended returned {late:?}");
}
