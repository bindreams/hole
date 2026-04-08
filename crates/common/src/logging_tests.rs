// Tests for stdio FD-redirect, panic hook, and multi-layer subscriber.
//
// FD-redirect tests run in a child process so they don't corrupt sibling tests
// that share FD 1 / FD 2 in the test runner. The child is the same test binary
// re-invoked with `HOLE_LOGGING_TEST_KIND` set; `lib.rs::main` dispatches early
// (before skuld) into `logging::run_redirect_test_child`. Each child writes a
// JSON result file at `HOLE_LOGGING_TEST_OUTPUT` and exits, and the parent
// reads + asserts on it.

use serde::{Deserialize, Serialize};
use skuld::temp_dir;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

// Test result format ==================================================================================================

/// Captured-event record written by the child to its result file.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapturedEvent {
    pub layer: String,  // "file" | "stderr"
    pub target: String, // tracing target
    pub message: String,
    pub level: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ChildResult {
    /// Events captured by the in-memory tracing subscriber installed inside the child.
    pub events: Vec<CapturedEvent>,
    /// If the child read its saved-original-stderr/-stdout via the tee path,
    /// these contain the bytes the tee wrote (so the parent can verify the tee
    /// preserved CLI script visibility).
    pub tee_stderr: String,
    pub tee_stdout: String,
}

// Parent-side helpers =================================================================================================

/// Spawn the test binary as a child with the given test kind, capture its
/// result file, and return the parsed result. Panics on child failure.
fn run_child(kind: &str, dir: &Path) -> ChildResult {
    let exe = std::env::current_exe().expect("current_exe");
    let result_path = dir.join(format!("result-{kind}.json"));
    let status = Command::new(&exe)
        .env("HOLE_LOGGING_TEST_KIND", kind)
        .env("HOLE_LOGGING_TEST_OUTPUT", &result_path)
        .stdin(Stdio::null())
        // Inherit stdout/stderr to a temp file so the child's actual stdio
        // (post-redirect, post-tee) doesn't pollute the test runner output but
        // is still recoverable for diagnostics if the test fails.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn child");
    assert!(status.success(), "child {kind} failed with status {status:?}");
    let bytes = std::fs::read(&result_path).expect("read child result");
    serde_json::from_slice(&bytes).expect("parse child result")
}

// Tests: stdio redirect ===============================================================================================

#[skuld::test]
fn redirect_captures_libc_stderr_writes(#[fixture(temp_dir)] dir: &Path) {
    let result = run_child("redirect_basic_stderr", dir);
    let relay: Vec<&CapturedEvent> = result
        .events
        .iter()
        .filter(|e| e.target == "hole::stderr_relay")
        .collect();
    assert!(
        relay.iter().any(|e| e.message.contains("hello-from-stderr")),
        "expected stderr_relay event with 'hello-from-stderr', got: {:?}",
        result.events
    );
}

#[skuld::test]
fn redirect_captures_libc_stdout_writes(#[fixture(temp_dir)] dir: &Path) {
    let result = run_child("redirect_basic_stdout", dir);
    let relay: Vec<&CapturedEvent> = result
        .events
        .iter()
        .filter(|e| e.target == "hole::stdout_relay")
        .collect();
    assert!(
        relay.iter().any(|e| e.message.contains("hello-from-stdout")),
        "expected stdout_relay event with 'hello-from-stdout', got: {:?}",
        result.events
    );
}

#[skuld::test]
fn redirect_captures_subprocess_stderr_via_inheritance(#[fixture(temp_dir)] dir: &Path) {
    let result = run_child("redirect_grandchild_stderr", dir);
    let messages: Vec<&str> = result
        .events
        .iter()
        .filter(|e| e.target == "hole::stderr_relay")
        .map(|e| e.message.as_str())
        .collect();
    assert!(
        messages.iter().any(|m| m.contains("from-rust-grandchild")),
        "expected from-rust-grandchild via Rust child, got: {messages:?}"
    );
    let foreign_marker = if cfg!(windows) {
        "from-cmd-grandchild"
    } else {
        "from-sh-grandchild"
    };
    assert!(
        messages.iter().any(|m| m.contains(foreign_marker)),
        "expected {foreign_marker} via foreign-runtime child (cmd/sh), got: {messages:?}"
    );
}

#[skuld::test]
fn redirect_captures_subprocess_stdout_via_inheritance(#[fixture(temp_dir)] dir: &Path) {
    let result = run_child("redirect_grandchild_stdout", dir);
    let messages: Vec<&str> = result
        .events
        .iter()
        .filter(|e| e.target == "hole::stdout_relay")
        .map(|e| e.message.as_str())
        .collect();
    assert!(
        messages.iter().any(|m| m.contains("from-rust-grandchild")),
        "expected from-rust-grandchild stdout, got: {messages:?}"
    );
    let foreign_marker = if cfg!(windows) {
        "from-cmd-grandchild"
    } else {
        "from-sh-grandchild"
    };
    assert!(
        messages.iter().any(|m| m.contains(foreign_marker)),
        "expected {foreign_marker} stdout via foreign runtime, got: {messages:?}"
    );
}

#[skuld::test]
fn redirect_tees_to_saved_original(#[fixture(temp_dir)] dir: &Path) {
    let result = run_child("redirect_tee", dir);
    // Captured events should contain the messages.
    let stderr_in_events = result
        .events
        .iter()
        .any(|e| e.target == "hole::stderr_relay" && e.message.contains("tee-stderr-line"));
    let stdout_in_events = result
        .events
        .iter()
        .any(|e| e.target == "hole::stdout_relay" && e.message.contains("tee-stdout-line"));
    assert!(stderr_in_events, "stderr event missing: {:?}", result.events);
    assert!(stdout_in_events, "stdout event missing: {:?}", result.events);
    // Saved-original tee should also have received the bytes.
    assert!(
        result.tee_stderr.contains("tee-stderr-line"),
        "tee-stderr did not receive bytes: {:?}",
        result.tee_stderr
    );
    assert!(
        result.tee_stdout.contains("tee-stdout-line"),
        "tee-stdout did not receive bytes: {:?}",
        result.tee_stdout
    );
}

#[skuld::test]
fn redirect_handles_multiline(#[fixture(temp_dir)] dir: &Path) {
    let result = run_child("redirect_multiline", dir);
    let relay_msgs: Vec<&str> = result
        .events
        .iter()
        .filter(|e| e.target == "hole::stderr_relay")
        .map(|e| e.message.as_str())
        .collect();
    let count_a = relay_msgs.iter().filter(|m| m.contains("multiline-a")).count();
    let count_b = relay_msgs.iter().filter(|m| m.contains("multiline-b")).count();
    let count_c = relay_msgs.iter().filter(|m| m.contains("multiline-c")).count();
    assert_eq!(count_a, 1, "expected 1 'multiline-a', got {count_a} in {relay_msgs:?}");
    assert_eq!(count_b, 1, "expected 1 'multiline-b', got {count_b} in {relay_msgs:?}");
    assert_eq!(count_c, 1, "expected 1 'multiline-c', got {count_c} in {relay_msgs:?}");
}

#[skuld::test]
fn redirect_does_not_loop(#[fixture(temp_dir)] dir: &Path) {
    let result = run_child("redirect_no_loop", dir);
    // The "normal event" must appear once on the file layer and once on the
    // stderr layer, never with a relay target.
    let on_file: Vec<&CapturedEvent> = result
        .events
        .iter()
        .filter(|e| e.layer == "file" && e.message.contains("normal event"))
        .collect();
    let on_stderr: Vec<&CapturedEvent> = result
        .events
        .iter()
        .filter(|e| e.layer == "stderr" && e.message.contains("normal event"))
        .collect();
    assert_eq!(on_file.len(), 1, "expected 1 file copy, got: {on_file:?}");
    assert_eq!(on_stderr.len(), 1, "expected 1 stderr copy, got: {on_stderr:?}");
    // The stderr layer must NEVER receive a relay-target event (filter check).
    assert!(
        !result
            .events
            .iter()
            .any(|e| e.layer == "stderr" && e.target.starts_with("hole::stderr_relay")),
        "stderr layer should not receive stderr_relay events"
    );
    assert!(
        !result
            .events
            .iter()
            .any(|e| e.layer == "stderr" && e.target.starts_with("hole::stdout_relay")),
        "stderr layer should not receive stdout_relay events"
    );
}

#[skuld::test]
fn lossy_mode_drops_under_backpressure(#[fixture(temp_dir)] dir: &Path) {
    // The child writes 10000 lines to stderr while the file appender is
    // throttled to 100ms per write. Under non-lossy mode, this would block for
    // hundreds of seconds. Under lossy mode, the child completes promptly and
    // MANY events are dropped — the SlowWriter should see far fewer than
    // 10000 writes (proving the lossy channel is actually dropping, not just
    // queuing).
    let start = std::time::Instant::now();
    let result = run_child("lossy_backpressure", dir);
    let elapsed = start.elapsed();
    // Generous deadline: child loop is 10k * a few microseconds per iteration
    // plus a few seconds for process spawn/cleanup. The 100ms-per-write file
    // sink would, without lossy mode, take 10000 * 100ms = 1000 seconds.
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "lossy backpressure test took {elapsed:?} — likely blocking on file writer"
    );
    // `tee_stderr` holds the observed SlowWriter write count (child reused
    // this field — see scenario_lossy_backpressure).
    let writes: usize = result.tee_stderr.parse().expect("observed write count from child");
    assert!(
        writes < 10_000,
        "lossy mode should have dropped events under backpressure, but SlowWriter saw {writes} writes",
    );
}

// Tests: panic hook ===================================================================================================

static CHAINED_HOOK_COUNT: AtomicUsize = AtomicUsize::new(0);

#[skuld::test(serial)]
fn panic_hook_emits_tracing_event() {
    // Install an in-memory subscriber, install the panic hook directly
    // (without going through init() — that would also touch FD redirects),
    // trigger a panic, verify the subscriber recorded a hole::panic event.
    //
    // Replace libtest-mimic's hook with a no-op BEFORE installing ours so
    // our hook chains to the no-op, not to libtest-mimic. Otherwise the
    // worker-thread panic is reported as a test failure.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let writer = TestVecWriter {
        inner: captured.clone(),
    };
    let subscriber = tracing_subscriber::fmt().with_writer(writer).with_ansi(false).finish();
    let _g = tracing::subscriber::set_default(subscriber);

    super::install_panic_hook_for_tests();

    let _ = std::panic::catch_unwind(|| panic!("hook-test-payload"));

    let bytes = captured.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("panic: hook-test-payload"),
        "subscriber did not capture panic event:\n{text}"
    );
    assert!(
        text.contains("hole::panic"),
        "subscriber did not capture panic target:\n{text}"
    );

    let _ours = std::panic::take_hook();
    std::panic::set_hook(prev_hook);
}

/// Tiny `Write` + `MakeWriter` impl for capturing tracing output into an
/// `Arc<Mutex<Vec<u8>>>`. Same shape as the helper in `logging_test_helpers.rs`
/// but kept local here so panic-hook tests don't pull in the full child-process
/// scaffolding.
#[derive(Clone)]
struct TestVecWriter {
    inner: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for TestVecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TestVecWriter {
    type Writer = TestVecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[skuld::test(serial)]
fn panic_hook_chains_previous() {
    // Install a custom counting hook BEFORE installing ours so our hook
    // chains to the counter, not to libtest-mimic.
    let prev_hook = std::panic::take_hook();
    CHAINED_HOOK_COUNT.store(0, Ordering::SeqCst);
    std::panic::set_hook(Box::new(|_info| {
        CHAINED_HOOK_COUNT.fetch_add(1, Ordering::SeqCst);
    }));

    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let writer = TestVecWriter {
        inner: captured.clone(),
    };
    let subscriber = tracing_subscriber::fmt().with_writer(writer).with_ansi(false).finish();
    let _g = tracing::subscriber::set_default(subscriber);

    super::install_panic_hook_for_tests();

    let _ = std::panic::catch_unwind(|| panic!("chain-test-payload"));

    let bytes = captured.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains("panic: chain-test-payload"),
        "subscriber did not capture panic event:\n{text}"
    );
    assert!(
        CHAINED_HOOK_COUNT.load(Ordering::SeqCst) >= 1,
        "previous hook was not called (count = {})",
        CHAINED_HOOK_COUNT.load(Ordering::SeqCst)
    );

    let _ours = std::panic::take_hook();
    std::panic::set_hook(prev_hook);
}

// Tests: size-based rotation ==========================================================================================

#[skuld::test]
fn file_rotate_appender_rotates_and_prunes(#[fixture(temp_dir)] dir: &Path) {
    use file_rotate::{compression::Compression, suffix::AppendCount, ContentLimit, FileRotate};
    use std::io::Write;

    let log_path = dir.join("test.log");
    let mut appender = FileRotate::new(
        &log_path,
        AppendCount::new(1),
        ContentLimit::Bytes(1024),
        Compression::None,
        None,
    );

    // 30 chunks × 100 bytes = 3000 bytes total. With a 1024-byte rotation
    // threshold and max_files=1, this must produce exactly `test.log` and
    // `test.log.1` at the end; older rotations are pruned.
    let payload = vec![b'x'; 100];
    for i in 0..30 {
        appender.write_all(&payload).expect("write payload");
        if i % 10 == 9 {
            appender.flush().expect("flush appender");
        }
    }
    drop(appender); // release the Windows file handle before re-reading the directory

    assert!(log_path.exists(), "active log file is missing");
    assert!(dir.join("test.log.1").exists(), "rotated log file .1 is missing");
    assert!(
        !dir.join("test.log.2").exists(),
        "rotated log file .2 exists — max_files=1 pruning did not run"
    );

    let entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("test.log"))
        .collect();
    assert_eq!(
        entries.len(),
        2,
        "expected exactly 2 test.log* files, found {}: {:?}",
        entries.len(),
        entries.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );
}

// Tests: legacy daily-log cleanup =====================================================================================

#[skuld::test]
fn cleanup_legacy_daily_logs_removes_only_dated_siblings_of_stem(#[fixture(temp_dir)] dir: &Path) {
    std::fs::write(dir.join("bridge.log"), b"").expect("seed bridge.log");
    std::fs::write(dir.join("bridge.log.1"), b"").expect("seed bridge.log.1");
    std::fs::write(dir.join("bridge.other.txt"), b"").expect("seed bridge.other.txt");
    std::fs::write(dir.join("gui.log.2024-01-01"), b"").expect("seed gui.log.2024-01-01");
    std::fs::write(dir.join("bridge.log.2024-01-01"), b"").expect("seed bridge.log.2024-01-01");
    std::fs::write(dir.join("bridge.log.2024-02-15"), b"").expect("seed bridge.log.2024-02-15");

    super::cleanup_legacy_daily_logs(dir, "bridge.log");

    assert!(dir.join("bridge.log").exists(), "bridge.log must survive");
    assert!(dir.join("bridge.log.1").exists(), "bridge.log.1 must survive");
    assert!(dir.join("bridge.other.txt").exists(), "bridge.other.txt must survive");
    assert!(
        dir.join("gui.log.2024-01-01").exists(),
        "gui.log.2024-01-01 must survive (different stem)"
    );
    assert!(
        !dir.join("bridge.log.2024-01-01").exists(),
        "bridge.log.2024-01-01 must be deleted"
    );
    assert!(
        !dir.join("bridge.log.2024-02-15").exists(),
        "bridge.log.2024-02-15 must be deleted"
    );

    // Exercise the co-located streams case: a second call with a different
    // stem must clean up that stem's dated files without disturbing the
    // already-cleaned set.
    super::cleanup_legacy_daily_logs(dir, "gui.log");

    assert!(
        !dir.join("gui.log.2024-01-01").exists(),
        "gui.log.2024-01-01 must now be gone"
    );
    assert!(dir.join("bridge.log").exists(), "bridge.log still present");
    assert!(dir.join("bridge.log.1").exists(), "bridge.log.1 still present");
    assert!(dir.join("bridge.other.txt").exists(), "bridge.other.txt still present");
}

#[skuld::test]
fn is_legacy_daily_suffix_matches_exactly_one_shape() {
    let cases: &[(&str, &str, bool)] = &[
        // Positive
        ("bridge.log.2024-01-01", "bridge.log", true),
        // Negatives
        ("bridge.log", "bridge.log", false),
        ("bridge.log.1", "bridge.log", false),
        ("bridge.log.2024-1-01", "bridge.log", false),
        ("bridge.log.20240101", "bridge.log", false),
        ("bridgeXlog.2024-01-01", "bridge.log", false),
        ("bridge.log.2024-01-01x", "bridge.log", false),
        ("other.log.2024-01-01", "bridge.log", false),
        ("bridge.log.old", "bridge.log", false),
        ("bridge.log.backup", "bridge.log", false),
    ];

    for (candidate, stem, expected) in cases {
        assert_eq!(
            super::is_legacy_daily_suffix(candidate, stem),
            *expected,
            "is_legacy_daily_suffix({candidate:?}, {stem:?}) should be {expected}"
        );
    }
}

#[skuld::test]
fn cleanup_legacy_daily_logs_tolerates_missing_directory(#[fixture(temp_dir)] dir: &Path) {
    let nonexistent = dir.join("does-not-exist");
    // Must not panic.
    super::cleanup_legacy_daily_logs(&nonexistent, "bridge.log");
}

// Tests: log crate bridge =============================================================================================

#[skuld::test(serial)]
fn log_crate_macros_reach_file(#[fixture(temp_dir)] dir: &Path) {
    // Disable the FD redirect inside init() so libtest-mimic's per-test
    // result lines (printed to FD 1) aren't eaten. Clean up the env var on
    // every exit path to avoid leaking the override into other tests.
    struct EnvGuard;
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                std::env::remove_var("HOLE_LOGGING_DISABLE_REDIRECT");
            }
        }
    }
    unsafe {
        std::env::set_var("HOLE_LOGGING_DISABLE_REDIRECT", "1");
    }
    let _env_guard = EnvGuard;
    let log_dir = dir.join("log-bridge-test");
    let _guard = init(&log_dir, "test.log", "info");

    log::info!("from-log-crate-bridge-test");
    std::thread::sleep(std::time::Duration::from_millis(200));

    let entries: Vec<_> = std::fs::read_dir(&log_dir)
        .expect("read log dir")
        .filter_map(|e| e.ok())
        .collect();
    let log_file = entries
        .iter()
        .find(|e| e.file_name().to_string_lossy().starts_with("test.log"))
        .expect("log file");
    let contents = std::fs::read_to_string(log_file.path()).expect("read log file");
    assert!(
        contents.contains("from-log-crate-bridge-test"),
        "log crate event not bridged to tracing file:\n{contents}"
    );
}
