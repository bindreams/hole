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
// it can and returns. What must hold is that a GOOD name really gets the
// marker, and that an unopenable one is survived rather than propagated —
// the `fd < 0` branch, which on a crash path has no signal-safe way to
// report anything anyway.
#[cfg(target_os = "macos")]
mod write_marker_signal_safe_tests {
    use crate::crash::{write_marker_signal_safe, HandlerState};
    use std::ffi::OsStr;
    use util::dir::Dir;

    fn state_in(dir: &std::path::Path, name: &str) -> HandlerState {
        HandlerState::new(
            "test",
            Some(Dir::open(dir, false, None).expect("open")),
            OsStr::new(name),
        )
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
    fn writes_a_good_name_and_survives_an_unopenable_one() {
        let dir = tempfile::tempdir().expect("tempdir");

        write_marker_signal_safe(&state_in(dir.path(), "crash-test-1.marker"), &ctx());
        let text = std::fs::read_to_string(dir.path().join("crash-test-1.marker"))
            .expect("the good name was actually written");
        assert!(text.starts_with("tombstone-marker v1\n"), "got: {text}");

        // The open-failure branch: a name that is not a plain file name in the directory (`openat` fails with
        // ENOENT), and a state with no directory at all (`EBADF`). Both return normally and leave nothing behind.
        write_marker_signal_safe(&state_in(dir.path(), "does-not-exist/crash-test-2.marker"), &ctx());
        write_marker_signal_safe(
            &HandlerState::new("test", None, OsStr::new("crash-test-3.marker")),
            &ctx(),
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

// The marker is created by name inside the log directory the handler holds, exclusively. What the user can do to
// that directory or to the name is pinned here without a crash: `write_record_signal_safe` is the whole of the
// handler's I/O, and `tests/crash_child.rs` runs it for real behind a native fault.
mod write_record_signal_safe_tests {
    use crate::crash::{free_marker_name, write_record_signal_safe, HandlerState, MarkerRecord};
    use std::ffi::OsStr;
    use std::path::Path;
    use util::dir::Dir;

    const NAME: &str = "crash-test-1.marker";

    fn rec() -> MarkerRecord<'static> {
        MarkerRecord {
            kind: "test",
            pid: 1,
            tid: 2,
            code: 3,
            fault_addr: 4,
            time: 5,
        }
    }

    fn state_in(dir: &Path) -> HandlerState {
        HandlerState::new(
            "test",
            Some(Dir::open(dir, false, None).expect("open")),
            OsStr::new(NAME),
        )
    }

    #[skuld::test]
    fn writes_the_record_to_a_free_name() {
        let dir = tempfile::tempdir().expect("tempdir");

        write_record_signal_safe(&state_in(dir.path()), &rec());

        let text = std::fs::read_to_string(dir.path().join(NAME)).expect("the marker was written");
        assert!(
            text.starts_with("tombstone-marker v1\nkind=test\npid=1\n"),
            "got: {text}"
        );
    }

    #[skuld::test]
    fn leaves_a_file_already_at_the_name_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(NAME), "keep, and longer than a marker's first line").unwrap();

        write_record_signal_safe(&state_in(dir.path()), &rec());

        assert_eq!(
            std::fs::read_to_string(dir.path().join(NAME)).unwrap(),
            "keep, and longer than a marker's first line"
        );
    }

    #[skuld::test]
    fn does_not_write_through_a_symlink_at_the_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        super::plant_file_symlink(&victim, &dir.path().join(NAME));

        write_record_signal_safe(&state_in(dir.path()), &rec());

        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert!(std::fs::symlink_metadata(dir.path().join(NAME)).unwrap().is_symlink());
    }

    // A create that opened the FIFO would wait for a reader that never comes; `O_EXCL` fails first.
    #[cfg(unix)]
    #[skuld::test]
    fn returns_on_a_fifo_at_the_name() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = std::ffi::CString::new(dir.path().join(NAME).as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        write_record_signal_safe(&state_in(dir.path()), &rec());

        use std::os::unix::fs::FileTypeExt;
        assert!(std::fs::symlink_metadata(dir.path().join(NAME))
            .unwrap()
            .file_type()
            .is_fifo());
    }

    #[skuld::test]
    fn writes_into_the_directory_it_holds_when_the_path_is_swapped() {
        let root = tempfile::tempdir().expect("tempdir");
        let logs = root.path().join("logs");
        let victim = root.path().join("victim");
        std::fs::create_dir(&logs).unwrap();
        std::fs::create_dir(&victim).unwrap();
        let state = state_in(&logs);

        std::fs::rename(&logs, root.path().join("logs.moved")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim, &logs).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&victim, &logs).unwrap();
        write_record_signal_safe(&state, &rec());

        assert_eq!(
            std::fs::read_dir(&victim).unwrap().count(),
            0,
            "wrote into the swapped-in directory"
        );
        assert!(root.path().join("logs.moved").join(NAME).exists());
    }

    #[skuld::test]
    fn writes_nothing_and_returns_without_a_directory() {
        let dir = tempfile::tempdir().expect("tempdir");

        write_record_signal_safe(&HandlerState::new("test", None, OsStr::new(NAME)), &rec());

        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    // `free_marker_name`: an unswept marker or dump of an earlier process with the same pid is that crash's record,
    // so this process takes the next name rather than the taken one.
    #[skuld::test]
    fn the_marker_name_is_the_pid_s_when_free_and_the_next_free_one_otherwise() {
        let dir = tempfile::tempdir().expect("tempdir");
        let held = Dir::open(dir.path(), false, None).expect("open");
        let name = || free_marker_name(&held, "bridge", 42).unwrap();

        assert_eq!(name(), "crash-bridge-42.marker");
        std::fs::write(dir.path().join("crash-bridge-42.marker"), "").unwrap();
        assert_eq!(name(), "crash-bridge-42-1.marker");
        std::fs::write(dir.path().join("crash-bridge-42-1.dmp"), "").unwrap();
        assert_eq!(name(), "crash-bridge-42-2.marker");
    }
}

// `write_all_signal_safe` is the marker write's inner loop. `write(2)` is
// allowed to transfer fewer bytes than asked (a filesystem filling mid-write)
// and to fail with EINTR before transferring any, and on macOS the marker is
// the ONLY crash artifact — a short write there costs a misleading,
// silently-truncated record rather than none. The loop is driven here through
// its `write` seam, which is the only way to produce a short count or an
// EINTR deterministically (a real `write(2)` to a regular file does neither
// on demand).
#[cfg(unix)]
mod write_all_signal_safe_tests {
    use crate::crash::write_all_signal_safe;
    use std::cell::{Cell, RefCell};

    /// Set `errno` on THIS thread, so the scripted `write` below can fail the
    /// way the real syscall does. Same accessor the production reader uses.
    fn set_errno(v: i32) {
        unsafe {
            #[cfg(target_os = "linux")]
            let p = libc::__errno_location();
            #[cfg(not(target_os = "linux"))]
            let p = libc::__error();
            *p = v;
        }
    }

    /// Drive `write_all_signal_safe` over `buf` with a scripted `write(2)`:
    /// a positive entry is that many bytes transferred, `0` is a zero-byte
    /// return, and a negative entry is `-1` with `errno = -entry`. Returns
    /// one `(offset, len)` per call, which is what says whether the loop
    /// resumed at the right place.
    ///
    /// Indexing the script is the termination check: a loop that calls
    /// `write` more times than scripted panics on the out-of-range index
    /// instead of spinning forever, so a broken exit condition fails rather
    /// than hangs.
    fn run(buf: &[u8], script: &[isize]) -> Vec<(usize, usize)> {
        let base = buf.as_ptr() as usize;
        let calls = RefCell::new(Vec::new());
        let next = Cell::new(0usize);
        write_all_signal_safe(buf, |p, len| {
            calls.borrow_mut().push((p as usize - base, len));
            let i = next.get();
            next.set(i + 1);
            let entry = script[i];
            if entry < 0 {
                set_errno(-entry as i32);
                return -1;
            }
            entry
        });
        calls.into_inner()
    }

    #[skuld::test]
    fn resumes_after_a_short_write() {
        let buf = [b'x'; 10];
        // 3 bytes, then 5, then the last 2.
        let calls = run(&buf, &[3, 5, 2]);
        assert_eq!(
            calls,
            vec![(0, 10), (3, 7), (8, 2)],
            "each call must resume where the last stopped"
        );
    }

    #[skuld::test]
    fn retries_an_eintr_from_the_same_offset() {
        let buf = [b'x'; 10];
        let calls = run(&buf, &[-libc::EINTR as isize, 10]);
        assert_eq!(
            calls,
            vec![(0, 10), (0, 10)],
            "EINTR transferred nothing, so the retry repeats the whole write"
        );
    }

    #[skuld::test]
    fn gives_up_on_an_error_that_is_not_eintr() {
        let buf = [b'x'; 10];
        // ENOSPC is not retryable: retrying would spin forever on a full
        // disk. One call, then the loop ends.
        let calls = run(&buf, &[-libc::ENOSPC as isize]);
        assert_eq!(calls, vec![(0, 10)]);
    }

    #[skuld::test]
    fn gives_up_when_write_transfers_nothing_without_failing() {
        let buf = [b'x'; 10];
        // A 0 return moves no bytes and reports no error, so there is
        // nothing to resume from — retrying is the infinite loop.
        let calls = run(&buf, &[0]);
        assert_eq!(calls, vec![(0, 10)]);
    }

    #[skuld::test]
    fn one_full_write_is_one_call() {
        let buf = [b'x'; 10];
        assert_eq!(run(&buf, &[10]), vec![(0, 10)]);
    }
}

// macOS `on_crash` structural guards ==================================================================================

/// Anchor for the macOS `CrashEvent` impl — the entry point of the handler
/// frontier below.
#[cfg(target_os = "macos")]
const MACOS_ON_CRASH_HEADER: &str =
    "#[cfg(target_os = \"macos\")]\nunsafe impl crash_handler::CrashEvent for MarkerCrashEvent {";

/// Source text of the crash.rs item introduced by `header`, comment lines
/// removed. The item ends at the first column-0 `}`.
///
/// Comments go first because this module's prose names, by name, every
/// symbol the guards below look for — a guard that fires on documentation
/// alone is one that gets deleted rather than obeyed. Crude on purpose, same
/// as `bridge::reconciler_tests::code_lines`: it must never hide real code.
#[cfg(target_os = "macos")]
fn item_source(header: &str) -> String {
    let src = include_str!("crash.rs");
    assert_eq!(
        src.matches(header).count(),
        1,
        "the anchor {header:?} must name exactly one item (did an attribute or signature change?)"
    );
    let start = src.find(header).expect("anchor present");
    let body = &src[start..];
    let end = body.find("\n}\n").expect("item is brace-terminated") + 3;
    body[..end]
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("/*")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(target_os = "macos")]
fn macos_on_crash_impl() -> String {
    item_source(MACOS_ON_CRASH_HEADER)
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
/// `ident!` — immediately followed by `(` or `{`, or, for a macro only, `[`.
/// A free function, a method (`.to_vec()`), an associated fn
/// (`PathBuf::from(…)`), a constructor and a macro all reduce to their last
/// path segment, which is the level the allowlist is written at.
///
/// A bare `ident[` is an INDEX, not a call: `Index::index` hands back a
/// reference into data that already exists, so it allocates nothing. Only a
/// macro can be invoked in that position (`vec![…]`), and that one still
/// counts.
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
        let is_macro = b.get(j) == Some(&b'!');
        if is_macro {
            name.push('!');
            j += 1;
        }
        let called = match b.get(j) {
            Some(b'(') | Some(b'{') => true,
            Some(b'[') => is_macro,
            _ => false,
        };
        if called {
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

/// One item on the macOS handler path: what it is called, the anchor that
/// finds it in crash.rs, and the names its body may call.
///
/// `allowed` may name only another frontier member (which is then scanned in
/// turn) or a `SIGNAL_SAFE_PRIMITIVE` — `frontier_allowlists_are_closed`
/// enforces that, and it is what makes the scan transitive rather than a
/// promise about the first call frame.
#[cfg(target_os = "macos")]
struct Frontier {
    name: &'static str,
    header: &'static str,
    allowed: &'static [&'static str],
}

/// Everything `on_crash` can reach on macOS. Each entry's `allowed` lists the
/// next level down, so the closure of this table IS the handler path: a new
/// callee anywhere in it has to be added here (and scanned) before the guard
/// will pass.
#[cfg(target_os = "macos")]
const HANDLER_FRONTIER: &[Frontier] = &[
    Frontier {
        name: "on_crash",
        header: MACOS_ON_CRASH_HEADER,
        allowed: &["write_marker_signal_safe", "terminate_without_returning"],
    },
    Frontier {
        name: "terminate_without_returning",
        header: "#[cfg(target_os = \"macos\")]\nfn terminate_without_returning(",
        allowed: &["_exit"],
    },
    Frontier {
        name: "write_marker_signal_safe",
        header: "#[cfg(unix)]\nfn write_marker_signal_safe(",
        allowed: &["extract_fault_fields", "unix_time", "write_record_signal_safe"],
    },
    Frontier {
        name: "write_record_signal_safe",
        header: "#[cfg(unix)]
fn write_record_signal_safe(",
        allowed: &[
            "format_marker_into",
            "write_all_signal_safe",
            "openat",
            "write",
            "close",
            "as_ptr",
        ],
    },
    Frontier {
        name: "extract_fault_fields",
        header: "#[cfg(target_os = \"macos\")]\nfn extract_fault_fields(",
        allowed: &["Some", "unwrap_or", "getpid"],
    },
    Frontier {
        name: "unix_time",
        header: "#[cfg(unix)]\nfn unix_time(",
        allowed: &["zeroed", "clock_gettime"],
    },
    Frontier {
        name: "format_marker_into",
        // Anchored past `pub(crate)`, which is a visibility modifier and not
        // the call to `pub` it otherwise reads as.
        header: "fn format_marker_into(",
        allowed: &["push_bytes", "push_dec", "push_hex", "as_bytes"],
    },
    Frontier {
        name: "push_bytes",
        header: "fn push_bytes(",
        allowed: &["len"],
    },
    Frontier {
        name: "push_dec",
        header: "fn push_dec(",
        allowed: &["push_bytes"],
    },
    Frontier {
        name: "push_hex",
        header: "fn push_hex(",
        allowed: &["push_bytes"],
    },
    Frontier {
        name: "write_all_signal_safe",
        header: "#[cfg(unix)]\nfn write_all_signal_safe(",
        allowed: &["write", "errno", "len", "as_ptr", "add"],
    },
    Frontier {
        name: "errno",
        header: "#[cfg(unix)]\nfn errno(",
        allowed: &["__errno_location", "__error"],
    },
];

/// Call-SHAPED text that is not a call: `FnMut(…)` is the type of
/// `write_all_signal_safe`'s `write(2)` seam, written in its signature. A
/// trait bound allocates nothing.
#[cfg(target_os = "macos")]
const NOT_A_CALL: &[&str] = &["FnMut"];

/// The only non-frontier names the frontier may call. Each is either a raw
/// syscall (async-signal-safe by POSIX.1-2017 §2.4.3), a thread-local errno
/// accessor, or an operation with nowhere to put an allocation:
///
/// * `_exit`, `openat`, `write`, `close`, `getpid`, `clock_gettime` — syscalls.
///   `write` is also the name of `write_all_signal_safe`'s syscall seam.
/// * `__error` / `__errno_location` — pure thread-local accessors.
/// * `zeroed` — `core::mem::zeroed`, a compiler intrinsic.
/// * `as_ptr`, `add`, `len` — pointer/slice arithmetic on borrowed data.
/// * `as_bytes` — `&str` → `&[u8]`, a view of the same bytes.
/// * `unwrap_or` — `Option<u64>`, `Copy`, by value.
/// * `Some` — an enum constructor.
///
/// This is the escape hatch, so it is kept honest by
/// `frontier_allowlists_are_closed`: nothing defined in crash.rs may appear
/// here. A new helper goes on the frontier and gets scanned.
#[cfg(target_os = "macos")]
const SIGNAL_SAFE_PRIMITIVES: &[&str] = &[
    "_exit",
    "openat",
    "write",
    "close",
    "getpid",
    "clock_gettime",
    "__error",
    "__errno_location",
    "zeroed",
    "as_ptr",
    "add",
    "len",
    "as_bytes",
    "unwrap_or",
    "Some",
];

// The macOS handler path must not ALLOCATE — the cause of the #842 hang, and
// the one property this PR's `_exit` does NOT by itself provide. A thread
// Mach-suspended inside `malloc` never releases the allocator lock, so an
// allocation on the handler thread can block forever: measured 8 hangs in 10
// (module doc, "Why the callback cannot allocate").
//
// No behavioural test can stand in for this. The hang needs CI-like
// allocation pressure; the allocating branch ran 15/15 green on an idle
// darwin/arm64 and passes every `crash_marker_*` test in
// `tests/crash_child.rs`, so a straight revert of the `cfg(windows)` gate on
// `write_minidump_best_effort` would land silently. The structural scan is
// the only line of defence, so it covers the WHOLE path and not just
// `on_crash`'s own frame: a `format!` inside `push_hex` reinstates the
// deadlock exactly as one inside `on_crash` does.
//
// Deliberately strict: a new call of ANY shape fails, because every
// allocation this crate ever put on the handler path arrived as one
// (`write_minidump_best_effort`'s `PathBuf`, `File::create`'s `CString`,
// `MinidumpWriter`'s buffers). Widening an allowlist is how a deliberate
// change gets recorded.
#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_on_crash_calls_nothing_that_can_allocate() {
    for item in HANDLER_FRONTIER {
        let body = item_source(item.header);
        let names: Vec<String> = call_names(&strip_attributes(&body))
            .into_iter()
            .filter(|n| !NOT_A_CALL.contains(&n.as_str()))
            .collect();

        // Anti-vacuity: a broken extraction yields an empty or truncated
        // scan, which would pass the real assertion below while checking
        // nothing. Every frontier callee this item claims must actually be
        // visible in it.
        assert!(
            names.iter().any(|n| n == item.name),
            "extraction is broken — {:?}'s own definition is not in {names:?}\n{body}",
            item.name
        );
        for expected in item.allowed.iter().filter(|a| is_frontier(a)) {
            assert!(
                names.iter().any(|n| n == expected),
                "extraction is broken — {:?} must SEE the call to {expected:?} it permits, \
                 else the allowlist entry is vacuous. Got {names:?}\n{body}",
                item.name
            );
        }

        let offenders: Vec<&String> = names
            .iter()
            .filter(|n| n.as_str() != item.name && !item.allowed.contains(&n.as_str()))
            .collect();
        assert!(
            offenders.is_empty(),
            "{}, on the macOS crash-handler path, must call nothing but {:?}: allocating there \
             deadlocks against a Mach-suspended thread holding the malloc lock (crash.rs module \
             doc). Offending calls: {offenders:?}\n{body}",
            item.name,
            item.allowed
        );
    }
}

#[cfg(target_os = "macos")]
fn is_frontier(name: &str) -> bool {
    HANDLER_FRONTIER.iter().any(|f| f.name == name)
}

// The frontier is only transitive if no allowlist can name something the
// frontier does not scan. Without this, MF3's defect comes straight back:
// `on_crash` allowlisted two functions nobody scanned, and an allocation
// inside either of them was invisible.
#[cfg(target_os = "macos")]
#[skuld::test]
fn frontier_allowlists_are_closed() {
    let src = include_str!("crash.rs");
    for item in HANDLER_FRONTIER {
        for allowed in item.allowed {
            assert!(
                is_frontier(allowed) || SIGNAL_SAFE_PRIMITIVES.contains(allowed),
                "{}'s allowlist names {allowed:?}, which is neither scanned (add it to \
                 HANDLER_FRONTIER) nor a signal-safe primitive",
                item.name
            );
        }
    }
    for primitive in SIGNAL_SAFE_PRIMITIVES {
        assert!(
            !src.contains(&format!("fn {primitive}(")),
            "{primitive:?} is defined in crash.rs, so it is code that can grow an allocation — \
             it belongs on HANDLER_FRONTIER, where it gets scanned, not in the primitives list"
        );
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

// The log directory is the interactive user's while the bridge sweeps it as root, so a name in it is whatever the
// user made it: a symlink to a file of root's, a FIFO. The sweep reads each marker by name inside the directory it
// opened, never through a link and never waiting on a FIFO, and removes the name itself.

/// A symlink to the file `target`, of the kind an unprivileged user can plant.
fn plant_file_symlink(target: &std::path::Path, link: &std::path::Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(target, link).unwrap();
}

#[skuld::test]
async fn sweep_does_not_read_through_a_symlink_at_a_marker_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A valid marker of another process under a name the sweep does not take: reading through the link would
    // report its pid.
    let victim = dir.path().join("victim.txt");
    std::fs::write(&victim, "tombstone-marker v1\nkind=victim\npid=31337\n").unwrap();
    let link = dir.path().join("crash-bridge-5.marker");
    plant_file_symlink(&victim, &link);

    let (subscriber, writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    crate::sweep(dir.path());

    // `sweep` logs on this thread before it returns, so the snapshot is complete: waiting for the breadcrumb instead
    // would hang, not fail, on a sweep that reads through the link and says something else.
    let snap = writer.snapshot();
    assert!(snap.contains("marker unreadable"), "{snap}");
    assert!(!snap.contains("31337"), "read through the link: {snap}");
    assert!(victim.exists(), "what the link pointed at was removed");
    assert!(std::fs::symlink_metadata(&link).is_err(), "the link itself is removed");
}

#[cfg(unix)]
#[skuld::test]
async fn sweep_returns_on_a_fifo_at_a_marker_name_and_removes_it() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("crash-bridge-5.marker");
    let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c_path` is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let real = write_marker(dir.path(), "bridge", 6);

    let (subscriber, writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    // Returning at all is the assertion: a read that waits for a writer to the FIFO never does.
    crate::sweep(dir.path());

    assert!(writer.snapshot().contains("marker unreadable"), "{}", writer.snapshot());
    assert!(std::fs::symlink_metadata(&fifo).is_err(), "the FIFO is removed");
    assert!(!real.exists(), "the real marker next to it is still swept");
}

/// The marker `name` in a folder the system owns, with a second name `name.second`: a file the folder's owner cannot
/// vouch for, whoever runs the test (a user's file in the system's folder, or the system's with two names). Both
/// names are removed when this drops.
struct Unvouched {
    root: std::path::PathBuf,
    names: [String; 2],
}

impl Unvouched {
    fn new(scratch: &util::dir::testing::SystemScratch) -> Self {
        let first = format!("crash-bridge-{}.marker", scratch.name().to_string_lossy());
        let second = format!("{first}.second");
        let root = scratch.root().to_path_buf();
        std::fs::write(
            root.join(&first),
            "tombstone-marker v1
kind=victim
pid=31337
tid=0
code=0x1
fault_addr=0x0
time=1
",
        )
        .unwrap();
        std::fs::hard_link(root.join(&first), root.join(&second)).unwrap();
        Unvouched {
            root,
            names: [first, second],
        }
    }
}

impl Drop for Unvouched {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = std::fs::remove_file(self.root.join(name));
        }
    }
}

#[skuld::test]
async fn sweep_does_not_read_a_marker_the_folders_owner_cannot_vouch_for() {
    let scratch = util::dir::testing::SystemScratch::new();
    let planted = Unvouched::new(&scratch);
    let dir = util::dir::Dir::open(scratch.root(), false, None).unwrap();

    let (subscriber, writer) = make_subscriber();
    let _g = set_default_in_current_thread(subscriber);

    // Only the one name: the scratch folder is shared, so the rest of it is not ours to sweep.
    crate::crash::sweep_dir(&dir, [std::ffi::OsString::from(&planted.names[0])]);

    let snap = writer.snapshot();
    assert!(snap.contains("marker unreadable"), "{snap}");
    assert!(!snap.contains("31337"), "the file was read: {snap}");
}
