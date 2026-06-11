use crate::mux::{is_entry_start, pump, split_lines_universal, Entry, EntryFramer, FramerOutput, StreamMode};

// Framing core (pure) =================================================================================================

#[skuld::test]
fn anchor_detection_matches_iso_timestamps_only() {
    assert!(is_entry_start("2026-06-10T12:00:00.000Z INFO ready"));
    assert!(!is_entry_start("  at core::panicking"));
    assert!(!is_entry_start("thread 'main' panicked at src/x.rs:1:1"));
    assert!(!is_entry_start("2026-06-1X bogus"));
    assert!(!is_entry_start(""));
}

#[skuld::test]
fn single_line_entries_pass_through_on_next_anchor() {
    let mut f = EntryFramer::default();
    assert!(matches!(f.feed("2026-01-01T00:00:00Z one".into()), FramerOutput::None));
    let FramerOutput::Entry(prev) = f.feed("2026-01-01T00:00:01Z two".into()) else {
        panic!("second anchor must flush the first entry");
    };
    assert_eq!(prev, vec!["2026-01-01T00:00:00Z one".to_string()]);
}

/// The actual #393 panic-entry shape: a multi-line tracing entry stays one
/// atomic block, flushed by the NEXT anchor.
#[skuld::test]
fn multi_line_entry_buffers_until_next_anchor() {
    let mut f = EntryFramer::default();
    f.feed("2026-01-01T00:00:00Z ERROR panicked".into());
    assert!(matches!(f.feed("  0: core::panicking".into()), FramerOutput::None));
    assert!(matches!(f.feed("  1: hole_bridge::oops".into()), FramerOutput::None));
    let FramerOutput::Entry(entry) = f.feed("2026-01-01T00:00:01Z INFO next".into()) else {
        panic!("anchor must flush");
    };
    assert_eq!(entry.len(), 3);
}

/// EOF flushes the final buffered entry — the panic-then-exit case.
#[skuld::test]
fn eof_flushes_final_entry() {
    let mut f = EntryFramer::default();
    f.feed("2026-01-01T00:00:00Z ERROR last words".into());
    f.feed("  backtrace line".into());
    assert_eq!(f.finish().expect("EOF must flush").len(), 2);
}

/// Standalone anchor-less line with NO buffer in progress (the stdlib panic
/// hook's `thread '...' panicked` printed after its entry already flushed)
/// emits immediately.
#[skuld::test]
fn bare_line_without_open_buffer_emits_immediately() {
    let mut f = EntryFramer::default();
    let FramerOutput::Immediate(line) = f.feed("thread 'main' panicked at x".into()) else {
        panic!("must emit immediately");
    };
    assert_eq!(line, "thread 'main' panicked at x");
}

/// PINNED TRADE-OFF (dev_tests.py:258-285): an anchor-less line arriving
/// while a buffer IS open is appended to that entry — pinned explicitly so a
/// future behavior change is noticed.
#[skuld::test]
fn bare_line_with_open_buffer_appends_to_entry() {
    let mut f = EntryFramer::default();
    f.feed("2026-01-01T00:00:00Z ERROR entry".into());
    assert!(matches!(
        f.feed("thread 'main' panicked at x".into()),
        FramerOutput::None
    ));
    assert_eq!(f.finish().unwrap().len(), 2);
}

// Universal newlines (Python `text=True` parity: \n, \r\n, lone \r) ===================================================

#[skuld::test]
fn splits_lf_crlf_and_lone_cr() {
    let mut pending = Vec::new();
    let mut out = Vec::new();
    split_lines_universal(b"a\nb\r\nc\rd", &mut pending, &mut out);
    assert_eq!(out, vec!["a".to_string(), "b".into(), "c".into()]);
    assert_eq!(pending, b"d");
    // A \r at the chunk boundary must wait to see if \n follows.
    out.clear();
    split_lines_universal(b"\r", &mut pending, &mut out);
    assert!(out.is_empty()); // "d\r" still pending (could be \r\n)
    assert_eq!(pending, b"d\r");
    // The \n arrives: \r\n collapses to ONE break ("d", not "d" + ""); the
    // later lone \r splits as soon as the next byte disambiguates it.
    split_lines_universal(b"\ne\rf", &mut pending, &mut out);
    assert_eq!(out, vec!["d".to_string(), "e".into()]);
    assert_eq!(pending, b"f");
}

// Cross-stream atomicity (ports dev_tests.py:288-354) =================================================================

/// Two entry-buffered streams pumped concurrently into one printer must
/// never interleave a multi-line entry. 10 iterations to surface scheduling
/// races — test-of-timing exception: the property under test is the ABSENCE
/// of interleaving, an intrinsic concurrency property.
#[skuld::test]
async fn concurrent_streams_never_split_entries() {
    for _ in 0..10 {
        let (a_w, a_r) = tokio::io::duplex(4096);
        let (b_w, b_r) = tokio::io::duplex(4096);
        let (tx, rx) = tokio::sync::mpsc::channel::<Entry>(64);
        let mut sink: Vec<u8> = Vec::new();

        let pump_a = tokio::spawn(pump(a_r, StreamMode::EntryBuffered, "[bridge] ".into(), tx.clone()));
        let pump_b = tokio::spawn(pump(b_r, StreamMode::EntryBuffered, "[client] ".into(), tx.clone()));
        drop(tx);

        let feed = |mut w: tokio::io::DuplexStream, tag: &'static str| async move {
            use tokio::io::AsyncWriteExt as _;
            for i in 0..20 {
                let entry =
                    format!("2026-01-01T00:00:{i:02}Z ERROR {tag} entry\n  {tag} frame one\n  {tag} frame two\n");
                w.write_all(entry.as_bytes()).await.unwrap();
            }
            // Close => EOF flush on the pump side.
        };
        let (f1, f2, _, _, printed) = tokio::join!(
            feed(a_w, "alpha"),
            feed(b_w, "beta"),
            pump_a,
            pump_b,
            // tokio 1.52 implements AsyncWrite for Vec<u8> (and the &mut
            // blanket lifts it) — verified against the vendored tokio source.
            crate::mux::printer(rx, &mut sink),
        );
        let (_, _) = (f1, f2);
        printed.unwrap();

        // Reconstruct: every printed line carries its stream prefix; within
        // any one entry (anchor line + 2 frames) the prefixes must be uniform
        // and the frames adjacent to their anchor.
        let text = String::from_utf8(sink).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            let prefix = &line[..line.find("] ").map(|p| p + 2).expect("prefixed")];
            if line[prefix.len()..].starts_with("2026-") {
                assert!(
                    lines[i + 1].starts_with(prefix),
                    "frame 1 split from its entry:\n{text}"
                );
                assert!(
                    lines[i + 2].starts_with(prefix),
                    "frame 2 split from its entry:\n{text}"
                );
                i += 3;
            } else {
                panic!("unexpected non-anchor line at top level: {line}");
            }
        }
    }
}

/// Python text-mode parity at EOF: a trailing lone `\r` terminates a line
/// (possibly empty) — `b"x\n\r"` is ['x', ''] in Python, and dev.py printed
/// the empty prefixed line. A trailing chunk WITHOUT a terminator still
/// emits its partial content; a clean terminator-final stream emits nothing
/// extra.
#[skuld::test]
async fn eof_emits_cr_terminated_empty_line() {
    let (mut w, r) = tokio::io::duplex(64);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Entry>(8);
    let pump_task = tokio::spawn(pump(r, StreamMode::PerLine, "[  vite] ".into(), tx));
    use tokio::io::AsyncWriteExt as _;
    w.write_all(b"x\n\r").await.unwrap();
    drop(w); // EOF with pending == b"\r"
    assert_eq!(rx.recv().await.unwrap().lines, vec!["x".to_string()]);
    assert_eq!(
        rx.recv().await.unwrap().lines,
        vec![String::new()],
        "the \\r-terminated empty line must be emitted"
    );
    assert!(rx.recv().await.is_none());
    pump_task.await.unwrap();
}

/// Per-line mode emits without buffering (Vite has no anchors; buffering
/// would starve forever — dev.py:182-189).
#[skuld::test]
async fn per_line_mode_emits_unanchored_lines() {
    let (mut w, r) = tokio::io::duplex(4096);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Entry>(8);
    let pump_task = tokio::spawn(pump(r, StreamMode::PerLine, "[  vite] ".into(), tx));
    use tokio::io::AsyncWriteExt as _;
    w.write_all(b"VITE v6 ready in 100 ms\n").await.unwrap();
    let entry = rx.recv().await.expect("line emitted before EOF");
    assert_eq!(entry.lines, vec!["VITE v6 ready in 100 ms".to_string()]);
    drop(w);
    pump_task.await.unwrap();
}
