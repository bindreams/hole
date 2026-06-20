//! Multiplexed child-log printing with atomic multi-line entries.
//!
//! Port of dev.py's `prefix_stream` (#393/#394): streams that emit
//! ISO-timestamped tracing entries (bridge, GUI) are framed so a multi-line
//! entry (panic backtrace, YAML body) is written as ONE block and can never
//! be interleaved with another stream's lines; Vite (no timestamp anchor)
//! prints per-line. Atomicity is structural: every stream pumps into one
//! mpsc consumed by a single printer task — one writer, no lock.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;

/// One print job: `lines` are written contiguously, each prefixed.
pub struct Entry {
    pub prefix: String,
    pub lines: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamMode {
    /// ISO-timestamp entry framing (bridge, GUI).
    EntryBuffered,
    /// Immediate per-line emission (Vite — no anchor; buffering would never
    /// flush).
    PerLine,
}

/// `^\d{4}-\d{2}-\d{2}T` without a regex dep.
pub fn is_entry_start(line: &str) -> bool {
    let b = line.as_bytes();
    b.len() > 10
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5].is_ascii_digit()
        && b[6].is_ascii_digit()
        && b[7] == b'-'
        && b[8].is_ascii_digit()
        && b[9].is_ascii_digit()
        && b[10] == b'T'
}

pub enum FramerOutput {
    None,
    /// The PREVIOUS entry, flushed because a new anchor arrived.
    Entry(Vec<String>),
    /// An anchor-less line with no open buffer — emit now (the stdlib
    /// panic-hook line printed after its tracing entry already flushed).
    Immediate(String),
}

#[derive(Default)]
pub struct EntryFramer {
    buffer: Vec<String>,
}

impl EntryFramer {
    pub fn feed(&mut self, line: String) -> FramerOutput {
        if is_entry_start(&line) {
            let prev = std::mem::take(&mut self.buffer);
            self.buffer.push(line);
            if prev.is_empty() {
                FramerOutput::None
            } else {
                FramerOutput::Entry(prev)
            }
        } else if !self.buffer.is_empty() {
            // Continuation — including anchor-less panic-hook lines arriving
            // mid-entry. PINNED TRADE-OFF (see mux_tests): appended, not
            // emitted out-of-band.
            self.buffer.push(line);
            FramerOutput::None
        } else {
            FramerOutput::Immediate(line)
        }
    }

    /// EOF: flush whatever is buffered (the panic-then-exit case).
    pub fn finish(&mut self) -> Option<Vec<String>> {
        let prev = std::mem::take(&mut self.buffer);
        (!prev.is_empty()).then_some(prev)
    }
}

/// Python-`text=True` line splitting: `\n`, `\r\n`, and lone `\r` all end a
/// line (children emitting `\r` progress would otherwise buffer forever). A
/// trailing `\r` at a chunk boundary stays pending until the next chunk
/// disambiguates `\r` vs `\r\n`.
pub fn split_lines_universal(chunk: &[u8], pending: &mut Vec<u8>, out: &mut Vec<String>) {
    for &byte in chunk {
        match byte {
            b'\n' => {
                if pending.last() == Some(&b'\r') {
                    pending.pop();
                }
                out.push(String::from_utf8_lossy(pending).into_owned());
                pending.clear();
            }
            _ => {
                if pending.last() == Some(&b'\r') {
                    pending.pop();
                    out.push(String::from_utf8_lossy(pending).into_owned());
                    pending.clear();
                }
                pending.push(byte);
            }
        }
    }
    // A pending buffer ending in \r waits for the next chunk (or EOF).
}

/// Read `stream` to EOF, framing per `mode`, sending [`Entry`]s to `tx`.
pub async fn pump(mut stream: impl AsyncRead + Unpin, mode: StreamMode, prefix: String, tx: mpsc::Sender<Entry>) {
    let mut framer = EntryFramer::default();
    let mut pending = Vec::new();
    let mut lines = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break, // EOF / stream closed
            Ok(n) => n,
        };
        split_lines_universal(&chunk[..n], &mut pending, &mut lines);
        for line in lines.drain(..) {
            let out = match mode {
                StreamMode::PerLine => FramerOutput::Immediate(line),
                StreamMode::EntryBuffered => framer.feed(line),
            };
            let entry = match out {
                FramerOutput::None => continue,
                FramerOutput::Entry(lines) => Entry {
                    prefix: prefix.clone(),
                    lines,
                },
                FramerOutput::Immediate(l) => Entry {
                    prefix: prefix.clone(),
                    lines: vec![l],
                },
            };
            if tx.send(entry).await.is_err() {
                return; // printer gone — shutdown
            }
        }
    }
    // EOF: flush the trailing partial line, then the buffered entry. A
    // pending `\r` was waiting for a possible `\n`; EOF makes it final, so it
    // terminates a line — emitted even when empty (Python text-mode parity:
    // `b"x\n\r"` is ['x', '']).
    let terminated_by_cr = pending.last() == Some(&b'\r');
    if terminated_by_cr {
        pending.pop();
    }
    if !pending.is_empty() || terminated_by_cr {
        let line = String::from_utf8_lossy(&pending).into_owned();
        let out = match mode {
            StreamMode::PerLine => FramerOutput::Immediate(line),
            StreamMode::EntryBuffered => framer.feed(line),
        };
        match out {
            FramerOutput::Entry(lines) => {
                let _ = tx
                    .send(Entry {
                        prefix: prefix.clone(),
                        lines,
                    })
                    .await;
            }
            FramerOutput::Immediate(l) => {
                let _ = tx
                    .send(Entry {
                        prefix: prefix.clone(),
                        lines: vec![l],
                    })
                    .await;
            }
            FramerOutput::None => {}
        }
    }
    if let Some(lines) = framer.finish() {
        let _ = tx.send(Entry { prefix, lines }).await;
    }
}

/// The single writer: receives entries from every pump, writes each as one
/// contiguous block to `out` (terminal, ANSI kept), and mirrors it into
/// `transcript` (ANSI stripped) for `dev-console.log`.
pub async fn printer(
    mut rx: mpsc::Receiver<Entry>,
    mut out: impl AsyncWrite + Unpin,
    transcript: crate::transcript::Transcript,
) -> std::io::Result<()> {
    while let Some(entry) = rx.recv().await {
        let mut block = String::new();
        for line in &entry.lines {
            block.push_str(&entry.prefix);
            block.push_str(line);
            block.push('\n');
        }
        out.write_all(block.as_bytes()).await?;
        out.flush().await?;
        transcript.write_block(&block);
    }
    Ok(())
}

#[cfg(test)]
#[path = "mux_tests.rs"]
mod mux_tests;
