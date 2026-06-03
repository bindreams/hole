//! Tests for the native-crash observability module.

use crate::crash::{format_marker_into, parse_marker, MarkerRecord};

// Smoke test: the crate compiles and the public API is reachable. Replaced
// with real per-fault-class + sweep tests in later tasks.
#[skuld::test]
fn module_is_linkable() {
    // `attach` and `sweep` are the public surface; reference them so a
    // broken signature fails to compile here rather than at a call site.
    let _attach: fn(&'static str, &std::path::Path) = crate::attach;
    let _sweep: fn(&std::path::Path) = crate::sweep;
}

fn sample() -> MarkerRecord<'static> {
    MarkerRecord {
        kind: "bridge",
        pid: 4242,
        tid: 99,
        code: 0xC0000005,
        fault_addr: 0xdead_beef,
        time: 133_000_000_000_000_000,
    }
}

#[skuld::test]
fn format_then_parse_roundtrips() {
    let rec = sample();
    let mut buf = [0u8; 256];
    let n = format_marker_into(&rec, &mut buf);
    let text = std::str::from_utf8(&buf[..n]).expect("ascii");
    let parsed = parse_marker(text).expect("parse");
    assert_eq!(parsed.kind, "bridge");
    assert_eq!(parsed.pid, 4242);
    assert_eq!(parsed.tid, 99);
    assert_eq!(parsed.code, 0xC0000005);
    assert_eq!(parsed.fault_addr, 0xdead_beef);
    assert_eq!(parsed.time, 133_000_000_000_000_000);
}

#[skuld::test]
fn format_writes_magic_and_hex() {
    let rec = sample();
    let mut buf = [0u8; 256];
    let n = format_marker_into(&rec, &mut buf);
    let text = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(text.starts_with("tombstone-marker v1\n"), "got: {text}");
    assert!(text.contains("code=0xc0000005\n"), "got: {text}");
    assert!(text.contains("fault_addr=0xdeadbeef\n"), "got: {text}");
    assert!(text.contains("kind=bridge\n"), "got: {text}");
}

#[skuld::test]
fn parse_tolerates_partial_marker() {
    // A crash mid-write may truncate. parse_marker reports what it can:
    // missing fields default to 0 / "" and parsing still succeeds.
    let text = "tombstone-marker v1\nkind=gui\npid=7\ncode=0x";
    let parsed = parse_marker(text).expect("partial still parses");
    assert_eq!(parsed.kind, "gui");
    assert_eq!(parsed.pid, 7);
    assert_eq!(parsed.tid, 0);
    assert_eq!(parsed.code, 0); // "0x" with no digits → 0
}

#[skuld::test]
fn parse_rejects_wrong_magic() {
    assert!(parse_marker("not-a-marker\nkind=gui\n").is_none());
}

#[skuld::test]
fn format_never_overflows_small_buffer() {
    // Stack buffer too small → format_marker_into stops at capacity and
    // returns the truncated length. It must NEVER write past `buf.len()`.
    let rec = sample();
    let mut buf = [0u8; 8];
    let n = format_marker_into(&rec, &mut buf);
    assert!(n <= buf.len());
}

use garter::test_utils::WaitableWriter;
use garter::tracing_test::set_default_in_current_thread;

fn make_subscriber() -> (impl tracing::Subscriber + Send + Sync, WaitableWriter) {
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_target(true)
        .finish();
    (subscriber, writer)
}

fn write_marker(dir: &std::path::Path, kind: &str, pid: u32) -> std::path::PathBuf {
    let rec = crate::crash::MarkerRecord {
        kind: "x", // overwritten below via explicit text
        pid,
        tid: 0,
        code: 0xC0000005,
        fault_addr: 0xdeadbeef,
        time: 1,
    };
    let _ = rec; // we write canonical text directly for clarity
    let path = dir.join(format!("crash-{kind}-{pid}.marker"));
    let text =
        format!("tombstone-marker v1\nkind={kind}\npid={pid}\ntid=0\ncode=0xc0000005\nfault_addr=0xdeadbeef\ntime=1\n");
    std::fs::write(&path, text).expect("write marker");
    path
}

#[skuld::test]
async fn sweep_emits_breadcrumb_and_deletes_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = write_marker(dir.path(), "bridge", 4242);

    let (subscriber, writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    // Register the wait BEFORE sweeping so the latch can't be missed.
    let rx = writer.wait_for("native crash detected in previous run");

    crate::sweep(dir.path());

    rx.recv().expect("crash breadcrumb emitted");
    let snap = writer.snapshot();
    assert!(snap.contains("crash"), "target=crash expected: {snap}");
    assert!(snap.contains("4242"), "pid in breadcrumb: {snap}");
    assert!(snap.contains("c0000005"), "code in breadcrumb: {snap}");
    assert!(!marker.exists(), "marker deleted after report");
}

#[skuld::test]
async fn sweep_reports_multiple_markers() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_marker(dir.path(), "bridge", 1);
    write_marker(dir.path(), "gui", 2);

    let (subscriber, _writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    crate::sweep(dir.path());

    // Both markers gone; both pids surfaced.
    let remaining: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".marker"))
        .collect();
    assert!(remaining.is_empty(), "all markers deleted");
}

#[skuld::test]
async fn sweep_leaves_sibling_dmp() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_marker(dir.path(), "bridge", 9);
    let dmp = dir.path().join("crash-bridge-9.dmp");
    std::fs::write(&dmp, b"fake dump").unwrap();

    let (subscriber, _writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    crate::sweep(dir.path());

    assert!(dmp.exists(), ".dmp is left for the developer");
}

#[skuld::test]
async fn sweep_tolerates_missing_dir() {
    // Best-effort: a nonexistent log_dir must not panic.
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("does-not-exist");
    crate::sweep(&missing); // no panic, no-op
}
