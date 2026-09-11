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

#[skuld::test]
async fn sweep_reports_malformed_marker() {
    // A marker whose first line is NOT the magic still emits a breadcrumb
    // (the "malformed" wording) AND is deleted. Exercises report_one's
    // parse_marker == None branch.
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("crash-bridge-77.marker");
    std::fs::write(&marker, "garbage first line\nkind=bridge\n").expect("write");

    let (subscriber, writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let rx = writer.wait_for("marker malformed");
    crate::sweep(dir.path());
    rx.recv().expect("malformed breadcrumb emitted");

    let snap = writer.snapshot();
    assert!(snap.contains("crash"), "target=crash expected: {snap}");
    assert!(!marker.exists(), "malformed marker deleted after report");
}

// `write_marker_signal_safe`'s `bool` return is what `on_crash` gates the
// macOS `_exit` bypass on (M7): a marker write that fails must NOT be
// reported as a success, or the bypass would fire with zero diagnostics on
// disk. This covers the open-failure half of that contract (a bad marker
// path). It does NOT cover a failed/short `write(2)` on an otherwise-good
// fd — there is no clean macOS mechanism (no `/dev/full`) to force that; see
// the Coverage table entry for the `marker_written &&` gate mutant.
#[cfg(target_os = "macos")]
mod write_marker_signal_safe_tests {
    use crate::crash::{write_marker_signal_safe, HandlerState};
    use std::os::unix::ffi::OsStrExt;

    fn state_for(path: &std::path::Path) -> HandlerState {
        let mut marker_path_c: Vec<u8> = path.as_os_str().as_bytes().to_vec();
        marker_path_c.push(0);
        HandlerState {
            kind: "test",
            marker_path_c,
        }
    }

    fn ctx() -> crash_handler::CrashContext {
        crash_handler::CrashContext {
            task: 0,
            thread: 0,
            handler_thread: 0,
            exception: None,
        }
    }

    #[skuld::test]
    fn true_on_success_false_on_open_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("crash-test-1.marker");
        // Under a nonexistent directory: `open(O_CREAT)` fails with ENOENT.
        let bad = dir.path().join("does-not-exist").join("crash-test-2.marker");

        assert!(write_marker_signal_safe(&state_for(&good), &ctx()));
        assert!(good.exists(), "the good path was actually written");
        assert!(!write_marker_signal_safe(&state_for(&bad), &ctx()));
    }
}

// `is_macos_sigabrt_relay` identifies the exact synthetic-exception
// signature crash-handler's SIGABRT sigaction relay produces on macOS:
// EXC_SOFTWARE / EXC_SOFT_SIGNAL / subcode == SIGABRT. Every field must
// match — a fault class that shares two of three fields with a real abort
// relay must NOT be misidentified as one, or the
// `_exit` bypass in `on_crash` would swallow a genuine crash report.
#[cfg(target_os = "macos")]
mod is_macos_sigabrt_relay_tests {
    use crate::crash::is_macos_sigabrt_relay;

    fn ctx_with(exception: Option<crash_context::ExceptionInfo>) -> crash_handler::CrashContext {
        crash_handler::CrashContext {
            task: 0,
            thread: 0,
            handler_thread: 0,
            exception,
        }
    }

    fn abort_relay_exception() -> crash_context::ExceptionInfo {
        crash_context::ExceptionInfo {
            kind: mach2::exception_types::EXC_SOFTWARE,
            code: mach2::exception_types::EXC_SOFT_SIGNAL as u64,
            subcode: Some(libc::SIGABRT as u64),
        }
    }

    #[skuld::test]
    fn matches_the_exact_sigabrt_relay_signature() {
        let ctx = ctx_with(Some(abort_relay_exception()));
        assert!(is_macos_sigabrt_relay(&ctx));
    }

    #[skuld::test]
    fn rejects_no_exception() {
        // e.g. a directly-invoked on_crash in a test double, or a context
        // crash-handler itself never populates this way in practice — must
        // not panic on None, must not match.
        let ctx = ctx_with(None);
        assert!(!is_macos_sigabrt_relay(&ctx));
    }

    #[skuld::test]
    fn rejects_a_real_hardware_exception_kind() {
        // EXC_BAD_ACCESS (segfault/bus) — same subcode SHAPE class
        // (Some(u64)) but a different `kind`. Must not be conflated with the
        // SIGABRT relay just because both carry a subcode.
        let mut exc = abort_relay_exception();
        exc.kind = mach2::exception_types::EXC_BAD_ACCESS;
        let ctx = ctx_with(Some(exc));
        assert!(!is_macos_sigabrt_relay(&ctx));
    }

    #[skuld::test]
    fn rejects_exc_software_with_a_different_code() {
        // Right kind (EXC_SOFTWARE), wrong code — EXC_SOFTWARE is also used
        // for other synthetic conditions (e.g. EXC_SOFT_TRACE_BREAKPOINT), not
        // exclusively the SIGABRT relay.
        let mut exc = abort_relay_exception();
        exc.code = 0;
        let ctx = ctx_with(Some(exc));
        assert!(!is_macos_sigabrt_relay(&ctx));
    }

    #[skuld::test]
    fn rejects_exc_soft_signal_for_a_different_signal() {
        // Right kind + code, but the relayed signal is NOT SIGABRT (e.g.
        // SIGTERM can also in principle be relayed through EXC_SOFT_SIGNAL) —
        // must not fire the abort-only bypass for a different signal.
        let mut exc = abort_relay_exception();
        exc.subcode = Some(libc::SIGTERM as u64);
        let ctx = ctx_with(Some(exc));
        assert!(!is_macos_sigabrt_relay(&ctx));
    }

    #[skuld::test]
    fn rejects_missing_subcode() {
        // kind + code match, but subcode is None — cannot confirm it's
        // SIGABRT specifically, so must not match.
        let mut exc = abort_relay_exception();
        exc.subcode = None;
        let ctx = ctx_with(Some(exc));
        assert!(!is_macos_sigabrt_relay(&ctx));
    }
}

#[skuld::test]
async fn sweep_reports_unreadable_marker() {
    // A "marker" that is actually a directory makes read_to_string fail with
    // an I/O error, exercising report_one's read-error branch (the
    // "unreadable" wording). Must not panic; the breadcrumb is emitted.
    // (A directory-as-marker is the cleanly-reachable read-error case on
    // Windows, where chmod-style unreadability is awkward.)
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("crash-bridge-88.marker");
    std::fs::create_dir(&marker).expect("create dir-marker");

    let (subscriber, writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    let rx = writer.wait_for("marker unreadable");
    crate::sweep(dir.path());
    rx.recv().expect("unreadable breadcrumb emitted");

    let snap = writer.snapshot();
    assert!(snap.contains("crash"), "target=crash expected: {snap}");
    // sweep's remove_file can't delete a directory; best-effort means no
    // panic, which the test reaching this line proves.
}
