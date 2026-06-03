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
