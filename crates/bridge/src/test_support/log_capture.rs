//! In-process `tracing` log capture for tests.
//!
//! Mirrors the `VecWriter` pattern used by `crates/common/src/logging/
//! logging_test_helpers.rs` but kept local to the bridge crate so callers
//! don't have to depend on internals of `hole-common`'s test helpers.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

/// A `Write`-able sink that stores everything written to it in memory.
/// Cloneable — both clones share the same backing `Vec<u8>`, so a
/// `tracing_subscriber::fmt::layer().with_writer(writer.clone())` spun up
/// for a test can be inspected from the test body via the original handle.
#[derive(Clone, Default)]
pub(crate) struct VecWriter {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl VecWriter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Snapshot the bytes written so far.
    pub(crate) fn snapshot(&self) -> Vec<u8> {
        self.inner.lock().unwrap().clone()
    }

    /// Snapshot as a UTF-8 string (lossy on non-UTF-8).
    pub(crate) fn snapshot_string(&self) -> String {
        String::from_utf8_lossy(&self.snapshot()).into_owned()
    }
}

impl Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
