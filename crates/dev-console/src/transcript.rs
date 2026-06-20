//! Secondary capture sink for the dev-run transcript (`dev-console.log`).
//!
//! The dev console keeps writing to the terminal exactly as before; a
//! [`Transcript`] additionally mirrors the dev console's OWN output — status
//! lines and the multiplexed child stream — into `dev-console.log`, ANSI
//! stripped. Preflight cargo/npm children keep inherited stdio and are NOT
//! captured (runtime-only policy). Best-effort: a failed file open disables
//! the sink rather than failing the run.

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone)]
pub struct Transcript(Option<Arc<Mutex<Box<dyn Write + Send>>>>);

impl Transcript {
    pub fn disabled() -> Self {
        Self(None)
    }

    pub fn from_writer(w: Box<dyn Write + Send>) -> Self {
        Self(Some(Arc::new(Mutex::new(w))))
    }

    /// Open `path` for the transcript. On failure, warn once to stderr and
    /// return a disabled sink — the transcript is a convenience, never fatal.
    pub fn create(path: &Path) -> Self {
        match std::fs::File::create(path) {
            Ok(f) => Self::from_writer(Box::new(f)),
            Err(e) => {
                eprintln!("dev-console: could not open transcript {}: {e}", path.display());
                Self::disabled()
            }
        }
    }

    /// Append `s` (ANSI stripped) followed by a newline.
    pub fn write_line(&self, s: &str) {
        self.write_stripped(s);
        self.write_raw(b"\n");
    }

    /// Append `s` verbatim (ANSI stripped). `s` already carries its newlines.
    pub fn write_block(&self, s: &str) {
        self.write_stripped(s);
    }

    fn write_stripped(&self, s: &str) {
        let stripped = anstream::adapter::strip_str(s).to_string();
        self.write_raw(stripped.as_bytes());
    }

    fn write_raw(&self, bytes: &[u8]) {
        if let Some(sink) = &self.0 {
            if let Ok(mut w) = sink.lock() {
                let _ = w.write_all(bytes);
                let _ = w.flush();
            }
        }
    }
}

static GLOBAL: OnceLock<Transcript> = OnceLock::new();

/// The process-wide transcript. Disabled until [`set_global`] runs.
pub fn global() -> Transcript {
    GLOBAL.get().cloned().unwrap_or_else(Transcript::disabled)
}

/// Install the process-wide transcript. Idempotent (first wins).
pub fn set_global(t: Transcript) {
    let _ = GLOBAL.set(t);
}

/// `println!` to the terminal AND mirror the line into the transcript.
/// Intra-crate macro (no `#[macro_export]`) — reached by bare name via the
/// `#[macro_use]` on the module in `lib.rs`, like the existing `cli_log!`.
macro_rules! note {
    ($($arg:tt)*) => {{
        let __s = format!($($arg)*);
        println!("{__s}");
        $crate::transcript::global().write_line(&__s);
    }};
}

/// `eprintln!` to the terminal AND mirror the line into the transcript.
macro_rules! enote {
    ($($arg:tt)*) => {{
        let __s = format!($($arg)*);
        eprintln!("{__s}");
        $crate::transcript::global().write_line(&__s);
    }};
}

#[cfg(test)]
#[path = "transcript_tests.rs"]
mod transcript_tests;
