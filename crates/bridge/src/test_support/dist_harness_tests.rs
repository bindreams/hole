//! Unit tests for [`crate::test_support::dist_harness`]. Currently
//! covers the panic-hook log-dump path; the rest of the harness is
//! exercised implicitly through the e2e tests that use it.

use super::{dump_harness_log, ChildInfo};
use std::path::PathBuf;

/// Build a log body larger than the old 4 KiB tail cap. If the dump
/// code regresses to a tail cap below this size, the `SENTINEL_START`
/// at the front gets cut off while `SENTINEL_END` at the back remains,
/// and the test will fail.
fn large_log_body() -> String {
    let mut s = String::with_capacity(8200);
    s.push_str("SENTINEL_START\n");
    // ~8 KiB of line-oriented filler so the start sentinel sits well
    // outside the old 4 KiB tail window.
    for i in 0..200 {
        s.push_str(&format!("filler line {i:03} xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"));
    }
    s.push_str("SENTINEL_END\n");
    s
}

#[skuld::test]
fn dump_harness_log_emits_full_log_not_just_tail() {
    let log_dir = tempfile::tempdir().expect("tempdir");
    let log_path = log_dir.path().join("bridge.log");
    let body = large_log_body();
    std::fs::write(&log_path, &body).expect("write bridge.log");
    assert!(
        body.len() > 4096,
        "test fixture must exceed the old 4 KiB tail cap; got {} bytes",
        body.len()
    );

    let info = ChildInfo {
        pid: 12345,
        socket: PathBuf::from("fake-socket"),
        log_dir: log_dir.path().to_path_buf(),
    };

    let mut buf: Vec<u8> = Vec::new();
    dump_harness_log(&mut buf, &info);
    let out = String::from_utf8(buf).expect("utf8");

    assert!(
        out.contains("SENTINEL_START"),
        "dump must include the start of the log (i.e. not truncated to a 4 KB tail); \
         dump len={} preview={:?}",
        out.len(),
        &out[..out.len().min(200)]
    );
    assert!(
        out.contains("SENTINEL_END"),
        "dump must include the end of the log; dump len={}",
        out.len()
    );
    assert!(
        out.contains("---- full"),
        "dump must include the new 'full' framing (not the old 'tail' framing)"
    );
    assert!(out.contains("---- end ----"), "dump must include the end marker");
    assert!(
        out.contains("pid=12345"),
        "dump must include the ChildInfo pid; preview: {}",
        &out[..out.len().min(200)]
    );
}

#[skuld::test]
fn dump_harness_log_handles_missing_file() {
    let log_dir = tempfile::tempdir().expect("tempdir");
    let info = ChildInfo {
        pid: 42,
        socket: PathBuf::from("fake-socket"),
        log_dir: log_dir.path().to_path_buf(),
    };

    let mut buf: Vec<u8> = Vec::new();
    dump_harness_log(&mut buf, &info);
    let out = String::from_utf8(buf).expect("utf8");

    assert!(
        out.contains("could not read"),
        "missing log should produce a diagnostic line, got: {out}"
    );
    assert!(
        out.contains("pid=42"),
        "missing-log diagnostic must still carry the pid"
    );
}
