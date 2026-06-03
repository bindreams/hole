//! Test utilities.
//!
//! Public-but-test-only helpers exposed for crates that need to assert
//! on tracing-event content without polling. Lives under a `pub` module
//! rather than `#[cfg(test)]` so integration tests (`tests/*.rs`) can
//! use it — they only see the crate's public API.
//!
//! Production code MUST NOT import from this module — it offers no
//! production value and increases compile time.

use std::collections::HashMap;
use std::io;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

/// A `MakeWriter`-compatible `Vec<u8>` accumulator that also fires
/// `mpsc` acks the first time any registered substring is observed in
/// a written line. Lets tests park on `recv()` until a specific log
/// event has been emitted — no polling, no sleep.
#[derive(Clone, Default)]
pub struct WaitableWriter {
    inner: Arc<Mutex<Vec<u8>>>,
    patterns: Arc<Mutex<HashMap<String, SyncSender<()>>>>,
}

impl WaitableWriter {
    /// Create an empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a one-shot wait — fires the returned receiver the first
    /// time the accumulated buffer contains `substring`. If the buffer
    /// already contains it at the time of this call, the receiver fires
    /// immediately so the caller does not race against past writes.
    /// Subsequent matches are no-ops (the pattern is removed after
    /// firing).
    pub fn wait_for(&self, substring: &str) -> std::sync::mpsc::Receiver<()> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<()>(1);
        // Hold both locks while we check-and-register to avoid losing a
        // write that lands between the check and the insert.
        let inner = self.inner.lock().unwrap();
        let mut patterns = self.patterns.lock().unwrap();
        let text = String::from_utf8_lossy(&inner);
        if text.contains(substring) {
            let _ = tx.send(());
        } else {
            patterns.insert(substring.to_string(), tx);
        }
        rx
    }

    /// Snapshot the captured bytes so far as a `String` (lossy UTF-8).
    pub fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.inner.lock().unwrap().clone()).into_owned()
    }
}

impl io::Write for WaitableWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        inner.extend_from_slice(buf);
        let mut patterns = self.patterns.lock().unwrap();
        if patterns.is_empty() {
            return Ok(buf.len());
        }
        // Scan the ENTIRE accumulated buffer (not just this write's
        // `buf`) so a pattern that spans two `write()` calls — e.g.,
        // tracing-subscriber buffering the header in one call and the
        // body in the next — still matches. Patterns are removed after
        // firing, so the work is bounded by the number of *active*
        // patterns × buffer size.
        let all_text = String::from_utf8_lossy(&inner);
        patterns.retain(|pattern, tx| {
            if all_text.contains(pattern.as_str()) {
                let _ = tx.send(());
                false
            } else {
                true
            }
        });
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for WaitableWriter {
    type Writer = WaitableWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
