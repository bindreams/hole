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
/// event has been emitted — no polling, no sleep. See
/// bindreams/hole#383.
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
    /// time a future write contains `substring`. Subsequent matches are
    /// no-ops (the pattern is removed after firing).
    pub fn wait_for(&self, substring: &str) -> std::sync::mpsc::Receiver<()> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<()>(1);
        self.patterns.lock().unwrap().insert(substring.to_string(), tx);
        rx
    }

    /// Snapshot the captured bytes so far as a `String` (lossy UTF-8).
    pub fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.inner.lock().unwrap().clone()).into_owned()
    }
}

impl io::Write for WaitableWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.lock().unwrap().extend_from_slice(buf);
        let text = String::from_utf8_lossy(buf);
        let mut patterns = self.patterns.lock().unwrap();
        patterns.retain(|pattern, tx| {
            if text.contains(pattern.as_str()) {
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
