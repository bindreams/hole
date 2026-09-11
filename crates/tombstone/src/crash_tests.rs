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

// `write_marker_signal_safe` is best-effort and infallible: it writes what
// it can and returns. What must hold is that a GOOD path really gets the
// marker, and that an unopenable one is survived rather than propagated —
// the `fd < 0` branch, which on a crash path has no signal-safe way to
// report anything anyway.
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
    fn writes_a_good_path_and_survives_an_unopenable_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("crash-test-1.marker");
        // Under a nonexistent directory: `open(O_CREAT)` fails with ENOENT.
        let bad = dir.path().join("does-not-exist").join("crash-test-2.marker");

        write_marker_signal_safe(&state_for(&good), &ctx());
        let text = std::fs::read_to_string(&good).expect("the good path was actually written");
        assert!(text.starts_with("tombstone-marker v1\n"), "got: {text}");

        // The open-failure branch: returns normally, leaves nothing behind.
        write_marker_signal_safe(&state_for(&bad), &ctx());
        assert!(!bad.exists());
    }
}

// macOS `on_crash` structural guards ==================================================================================

/// The macOS `CrashEvent` impl's source text, comment lines removed.
///
/// Comments go first because this module's prose names, by name, every
/// symbol the guards below look for — a guard that fires on documentation
/// alone is one that gets deleted rather than obeyed. Crude on purpose, same
/// as `bridge::reconciler_tests::code_lines`: it must never hide real code.
#[cfg(target_os = "macos")]
fn macos_on_crash_impl() -> String {
    let src = include_str!("crash.rs");
    let start = src
        .find("#[cfg(target_os = \"macos\")]\nunsafe impl crash_handler::CrashEvent for MarkerCrashEvent {")
        .expect("macOS CrashEvent impl present (did the attribute or impl header change?)");
    let body = &src[start..];
    let end = body.find("\n}\n").expect("impl is brace-terminated") + 3;
    body[..end]
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("/*")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Remove attribute spans (`#[…]`, bracket-nesting aware) so `#[cfg(…)]`
/// does not read as a call to `cfg`. WHICH attributes may be there at all is
/// the guard above's question, not this one's.
#[cfg(target_os = "macos")]
fn strip_attributes(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let (mut kept_from, mut i) = (0usize, 0usize);
    while i < b.len() {
        if !(b[i] == b'#' && b.get(i + 1) == Some(&b'[')) {
            i += 1;
            continue;
        }
        out.push_str(&src[kept_from..i]);
        i += 1; // now at the opening '['
        let mut depth = 0usize;
        while i < b.len() {
            match b[i] {
                b'[' => depth += 1,
                b']' => depth -= 1,
                _ => {}
            }
            i += 1;
            if depth == 0 {
                break;
            }
        }
        kept_from = i;
    }
    out.push_str(&src[kept_from..]);
    out
}

/// Every call-shaped name in `src`: an identifier — optionally a macro,
/// `ident!` — immediately followed by `(`, `[` or `{`. A free function, a
/// method (`.to_vec()`), an associated fn (`PathBuf::from(…)`), a
/// constructor and a macro all reduce to their last path segment, which is
/// the level the allowlist is written at.
#[cfg(target_os = "macos")]
fn call_names(src: &str) -> Vec<String> {
    fn is_ident(c: u8) -> bool {
        c.is_ascii_alphanumeric() || c == b'_'
    }
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if !is_ident(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_ident(b[i]) {
            i += 1;
        }
        let mut name = src[start..i].to_string();
        let mut j = i;
        if b.get(j) == Some(&b'!') {
            name.push('!');
            j += 1;
        }
        if matches!(b.get(j), Some(b'(') | Some(b'[') | Some(b'{')) {
            out.push(name);
        }
    }
    out
}

// The macOS `on_crash` must terminate the process for EVERY crash, in EVERY
// binary that links tombstone. `tests/crash_child.rs` pins "every fault
// class" and "every attach kind" by crashing real children, but it cannot
// pin "every BUILD": those tests only exist under `crash-child`, so a
// termination re-gated on a cargo feature would still look green there
// while shipped `hole` / `hole bridge` / `galoshes` kept the hang. A
// safety net that only arms in test builds is not a safety net.
//
// Two things already guard this structurally — the impl's sole tail
// expression is a `-> !` call, so making the termination conditional means
// visibly inventing a `CrashEventResult`; and there is no `kind` or feature
// left in that impl to branch on. This asserts the second directly, because
// it is the one a future edit could quietly undo.
#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_on_crash_terminates_unconditionally() {
    let body = macos_on_crash_impl();
    let body = body.as_str();

    // One `cfg` only: the `target_os = "macos"` attribute this match started
    // at. Anything else is a build-dependent termination.
    assert_eq!(
        body.matches("#[cfg(").count(),
        1,
        "macOS on_crash must not be gated on anything but the platform: {body}"
    );
    assert!(
        !body.contains("feature ="),
        "macOS on_crash must not be gated on a cargo feature — shipped builds need it too: {body}"
    );
    assert!(
        !body.contains("kind"),
        "macOS on_crash must not discriminate on the attach kind — it never identified a \
         process (hole-common's log-bridge helpers attach as \"test\" too): {body}"
    );
    assert!(
        body.contains("terminate_without_returning()"),
        "macOS on_crash must end by terminating: {body}"
    );
}

// The macOS `on_crash` must not ALLOCATE — the cause of the #842 hang, and
// the one property this PR's `_exit` does NOT by itself provide. A thread
// Mach-suspended inside `malloc` never releases the allocator lock, so an
// allocation on the handler thread can block forever: measured 8 hangs in 10
// (module doc, "Why the callback cannot allocate").
//
// No behavioural test can stand in for this. The hang needs CI-like
// allocation pressure; the allocating branch ran 15/15 green on an idle
// darwin/arm64 and passes every `crash_marker_*` test in
// `tests/crash_child.rs`, so a straight revert of the `cfg(windows)` gate on
// `write_minidump_best_effort` would land silently. Hence a structural
// guard: the body may CALL nothing but the two functions whose
// allocation-freedom is itself established — `write_marker_signal_safe`
// (pre-encoded path, stack buffer, raw open/write/close) and
// `terminate_without_returning` (a bare `_exit` syscall).
//
// Deliberately strict: a new call of ANY shape fails, because every
// allocation this crate ever put on the handler path arrived as one
// (`write_minidump_best_effort`'s `PathBuf`, `File::create`'s `CString`,
// `MinidumpWriter`'s buffers). Widening the allowlist is how a deliberate
// change gets recorded.
#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_on_crash_calls_nothing_that_can_allocate() {
    const ALLOWED: [&str; 3] = [
        // The impl's own fn header, not a call.
        "on_crash",
        "write_marker_signal_safe",
        "terminate_without_returning",
    ];

    let body = macos_on_crash_impl();
    let names = call_names(&strip_attributes(&body));

    // Anti-vacuity: a broken extraction yields an empty scan, which would
    // pass the real assertion below while checking nothing.
    for expected in ["write_marker_signal_safe", "terminate_without_returning"] {
        assert!(
            names.iter().any(|n| n == expected),
            "extraction is broken — the guard must SEE the calls it permits, \
             else it passes vacuously. Missing {expected:?} in {names:?}\n{body}"
        );
    }

    let offenders: Vec<&String> = names.iter().filter(|n| !ALLOWED.contains(&n.as_str())).collect();
    assert!(
        offenders.is_empty(),
        "macOS on_crash must call nothing but {ALLOWED:?}: allocating on the handler thread \
         deadlocks against a Mach-suspended thread holding the malloc lock (crash.rs module \
         doc). Offending calls: {offenders:?}\n{body}"
    );
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
