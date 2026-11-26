// Tests for stdio FD-redirect, panic hook, and multi-layer subscriber.
//
// FD-redirect tests run in a child process so they don't corrupt sibling tests
// that share FD 1 / FD 2 in the test runner. The child is the same test binary
// re-invoked with `HOLE_LOGGING_TEST_KIND` set; `lib.rs::main` dispatches early
// (before skuld) into `logging::logging_test_helpers::run_child`. Each child writes a
// JSON result file at `HOLE_LOGGING_TEST_OUTPUT` and exits, and the parent
// reads + asserts on it.

#![allow(clippy::disallowed_methods)] // attended test: bare-name host tools

use serde::{Deserialize, Serialize};
use skuld::temp_dir;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use util::dir::testing::{plant_link, user_dir, SystemScratch};
use util::dir::Dir;

/// Exact type of [`crate::logging::init`]. A regression to a different arity
/// (e.g. dropping `kind` or the trailing `owner`) fails the assertion below.
type InitFn =
    fn(&std::path::Path, crate::logging::ProcessKind, &str, &str, Option<(u32, u32)>) -> crate::logging::LogGuard;

#[skuld::test]
fn init_signature_takes_kind() {
    // Compile-time guard: init's signature includes a process kind
    // between log_dir and log_filename, and a trailing owner. A regression to
    // the old form fails to compile here.
    let _f: InitFn = crate::logging::init;
}

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
    /// What a scenario saw, one fact per line, in the order it saw them.
    pub observed: Vec<String>,
}

// Parent-side helpers =================================================================================================

/// Spawn the test binary as a child with the given test kind, capture its
/// result file, and return the parsed result. Panics on child failure.
fn run_child(kind: &str, dir: &Path) -> ChildResult {
    run_child_reading_stderr(kind, dir).0
}

/// [`run_child`], and what the child wrote to its real stderr (post-redirect: what a tee or a direct write put on
/// the original handle).
fn run_child_reading_stderr(kind: &str, dir: &Path) -> (ChildResult, String) {
    let exe = std::env::current_exe().expect("current_exe");
    let result_path = dir.join(format!("result-{kind}.json"));
    let output = Command::new(&exe)
        .env("HOLE_LOGGING_TEST_KIND", kind)
        .env("HOLE_LOGGING_TEST_OUTPUT", &result_path)
        .stdin(Stdio::null())
        // Discard the child's actual stdout (post-redirect, post-tee) so it
        // doesn't pollute the test runner output; the test's assertions read
        // the JSON result file and, where they ask for it, stderr.
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn child");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "child {kind} failed with status {:?}; its stderr: {stderr}",
        output.status
    );
    let bytes = std::fs::read(&result_path).expect("read child result");
    (serde_json::from_slice(&bytes).expect("parse child result"), stderr)
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

/// What each stream is given reaches its tee target as well as the layers.
/// The relay's `tee.write_all(buf)` goes through a queue to a writer thread,
/// and [`StdioRelayHandles::flush`](crate::logging::StdioRelayHandles)
/// finishes that queue before the scenario reads the target. A `flush` that
/// did not would still pass here whenever the writer thread is quick; the
/// test that fails on it every time is
/// `redirect_reports_the_writes_a_tee_destination_refused`.
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

/// On each stream: a drain that meets a line with no newline yet still delivers the text before the marker, and
/// nothing of the marker. A complete line that looks like a marker is output too and answers no waiting request, since
/// the process cannot know a request's nonce.
#[skuld::test]
fn redirect_delivers_an_open_line_at_a_drain(#[fixture(temp_dir)] dir: &Path) {
    for (scenario, target) in [
        ("redirect_open_line_stderr", "hole::stderr_relay"),
        ("redirect_open_line_stdout", "hole::stdout_relay"),
    ] {
        let result = run_child(scenario, dir);
        let relayed: Vec<&str> = result
            .events
            .iter()
            .filter(|e| e.target == target)
            .map(|e| e.message.as_str())
            .collect();
        assert_eq!(
            relayed,
            [
                "__hole_relay_flush__00000000000000000000000000000000",
                "open-line__hole_relay_flush__abc"
            ],
            "{scenario}: relayed lines: {relayed:?}"
        );
        assert_eq!(
            result.observed,
            ["answered by the line: Err(Empty)"],
            "{scenario}: a waiting drain request must not be answered by a line of the process's own"
        );
    }
}

/// The drain after a relay thread has ended, on each stream, which only a panic in a tracing writer, the redaction
/// writer or a formatter brings about. After the join: a request registered earlier is released, a new request finds
/// the drain ended, `flush` reports once that later output to the stream was lost (though Rust's stdout also holds an
/// unfinished line that can no longer be written), and the other stream's lines all reached their tee. The production
/// panic hook, installed over a recording previous hook, still logs the panic but does not chain to that hook on the
/// relay thread, which would write the panic into the pipe the thread alone reads; on any other thread it chains.
///
/// Not reached: a drain that registers after the thread dropped the pipe's read end and before it called `end`, where a
/// broken pipe becomes the same error and the request is cancelled. That window is a few instructions wide, and no test
/// reaches it without a hook.
#[skuld::test]
fn drain_after_the_relay_thread_ended_releases_and_completes(#[fixture(temp_dir)] dir: &Path) {
    for ended in ["stderr", "stdout"] {
        let result = run_child(&format!("redirect_relay_thread_ended_{ended}"), dir);
        let mut expected = vec![
            "registered request: Err(Disconnected)".to_string(),
            "new request: false".to_string(),
            format!("flush errors: [\"the {ended} relay thread has ended; later output to {ended} was lost\"]"),
            "previous hook ran on: [\"not-a-relay\"]".to_string(),
            "panic records: [\"a tracing writer panics on the relay thread\", \"a panic off the relay thread\"]"
                .to_string(),
        ];
        if ended == "stdout" {
            expected.push("unfinished line flushes: [Some(BrokenPipe), Some(BrokenPipe)]".to_string());
        }
        assert_eq!(result.observed, expected, "{ended} relay ended");
        // `tee_stdout` holds the tee of the stream that kept its relay.
        let other_lines: Vec<String> = (0..5).map(|i| format!("other-line-{i}")).collect();
        assert_eq!(
            result.tee_stdout.lines().collect::<Vec<_>>(),
            other_lines,
            "{ended} relay ended"
        );
    }
}

/// `flush` waits for relays that are behind: every line written to either stream before it has gone through that
/// stream's tee when it returns. Each stream is the slower one in turn, so a drain of one stream that is missing is
/// not hidden by the time the other's takes.
#[skuld::test]
fn redirect_flush_waits_for_a_slow_relay(#[fixture(temp_dir)] dir: &Path) {
    let expected: Vec<String> = (0..15).map(|i| format!("slow-line-{i}")).collect();
    for slow in ["redirect_slow_stderr_relay", "redirect_slow_stdout_relay"] {
        let result = run_child(slow, dir);
        let stdout: Vec<&str> = result.tee_stdout.lines().collect();
        let stderr: Vec<&str> = result.tee_stderr.lines().collect();
        assert_eq!(
            stdout,
            expected,
            "{slow}: the stdout tee holds {} of 15 lines",
            stdout.len()
        );
        assert_eq!(
            stderr,
            expected,
            "{slow}: the stderr tee holds {} of 15 lines",
            stderr.len()
        );
    }
}

/// A tee whose destination refuses some writes goes on writing the rest, and `flush` reports the first error and how
/// many writes were refused: output that did not reach the caller is never lost in silence.
#[skuld::test]
fn redirect_reports_the_writes_a_tee_destination_refused(#[fixture(temp_dir)] dir: &Path) {
    let result = run_child("redirect_tee_refuses", dir);
    assert_eq!(
        result.tee_stderr.lines().collect::<Vec<_>>(),
        ["line-0", "line-2", "line-4"],
        "the lines the destination did not refuse"
    );
    assert_eq!(
        result.observed,
        [format!(
            "flush errors: [\"stderr was not fully written: writes refused: 2, messages dropped: 0: {}\"]",
            std::io::Error::from(std::io::ErrorKind::StorageFull)
        )]
    );
}

/// A tee that drops when its queue is full (the bridge's and the GUI's) says at `flush` how many messages it dropped.
/// The destination holds its first write until the relay has taken every line, so the count is exact: one line in the
/// destination's hands, a full queue, and the rest dropped.
#[skuld::test]
fn redirect_reports_the_messages_a_full_tee_dropped(#[fixture(temp_dir)] dir: &Path) {
    use crate::logging::logging_test_helpers::OVERFLOW_EXCESS;
    use crate::logging::queued::CAPACITY;

    let result = run_child("redirect_tee_overflows", dir);
    assert_eq!(
        result.observed,
        [
            format!("tee writes: {}", CAPACITY + 1),
            format!(
                "flush errors: [\"stderr was not fully written: writes refused: 0, messages dropped: {OVERFLOW_EXCESS}\"]"
            ),
        ]
    );
}

/// A destination that panics on its writer thread: `flush` reports it, and the panic hook logs the panic but does not
/// chain to the previous hook there. The default previous hook prints to stderr, the pipe whose reader may be waiting
/// for this writer's queue. On a thread the delivery does not depend on, the hook chains.
#[skuld::test]
fn a_panic_on_a_writer_thread_is_reported_and_does_not_chain_to_the_previous_hook(#[fixture(temp_dir)] dir: &Path) {
    let result = run_child("redirect_writer_thread_panics", dir);
    assert_eq!(
        result.observed,
        [
            "flush errors: [\"stderr was not fully written: writes refused: 0, messages dropped: 0, the writer thread \
             panicked: a destination panics on its writer thread, at <here>\"]",
            "previous hook ran on: [\"not-a-delivery-thread\"]",
            "panic records: [\"a destination panics on its writer thread\", \"a panic off the delivery threads\"]",
        ]
    );
}

/// A destination that panics on its writer thread: once its queue has ended, the thread logs the panic's message and
/// location into the sinks still open, here a log file whose queue was full when the panic happened, and `finish` of
/// its queue returns them. Nothing goes to the process's stderr.
#[skuld::test]
fn a_writer_logs_its_destinations_panic_into_the_other_sinks_once_its_queue_has_ended(#[fixture(temp_dir)] dir: &Path) {
    let (result, stderr) = run_child_reading_stderr("writer_panic_reaches_the_other_sink", dir);
    assert_eq!(
        result.observed,
        [
            "the panic records the log file took: [\"the other destination panics\"]",
            "each names its location in this file: [true]",
            "finishing the stderr layer's queue names the panic's message: true, and its location: true",
            "finishing the log file's queue returned: ok",
        ]
    );
    assert_eq!(stderr, "", "the child's stderr");
}

/// A destination that panics on its writer thread, while a `tracing` writer panics on every record of a panic: the
/// thread catches the second panic and the hook keeps its record instead of logging it, so the process does not
/// abort. `finish` returns what the writer did (the write it refused, with its error, and the destination's panic) and
/// the panic that stopped the logging. Nothing goes to the process's stderr.
#[skuld::test]
fn a_writer_whose_panic_record_cannot_be_logged_still_reports_what_it_did(#[fixture(temp_dir)] dir: &Path) {
    let (result, stderr) = run_child_reading_stderr("writer_panic_record_cannot_be_logged", dir);
    assert_eq!(
        result.observed,
        [format!(
            "finishing the queue returned: the log on stderr was not fully written: writes refused: 1, messages \
             dropped: 0, the writer thread panicked: the destination panics on its second write, at <here>, logging the \
             writer thread's panics panicked: a tracing writer panics on the record of a panic, at <here>: {}",
            std::io::Error::from(std::io::ErrorKind::StorageFull)
        )]
    );
    assert_eq!(stderr, "", "the child's stderr");
}

/// A layer whose writer refuses an event prints nothing to stderr. A `tracing-subscriber` layer that logs its
/// internal errors prints such a failure, and stderr is the redirected pipe: printed on a relay thread, the line would
/// come back as an event that fails again, without end. `fmt::layer()` does not log them today, though its
/// documentation says it does; `compose_subscriber` sets the flag itself, so a change of that default cannot bring the
/// print back.
#[skuld::test]
fn a_layer_whose_writer_fails_prints_nothing_to_the_redirected_stderr(#[fixture(temp_dir)] dir: &Path) {
    let result = run_child("layer_writers_fail", dir);
    assert_eq!(
        result.observed,
        ["write attempts: 2"],
        "one event, once to each of the two layers"
    );
    assert_eq!(result.tee_stderr, "", "what reached the redirected stderr");
}

/// What a full queue of a terminal sink does, for each kind of process.
#[skuld::test]
fn only_a_command_waits_for_the_reader_of_its_terminal_sinks() {
    use crate::logging::queued::Overflow;
    use crate::logging::ProcessKind;

    assert!(matches!(ProcessKind::Command.terminal(), Overflow::Wait));
    assert!(matches!(ProcessKind::Bridge.terminal(), Overflow::Drop));
    assert!(matches!(ProcessKind::Gui.terminal(), Overflow::Drop));
}

/// What a terminal sink did not deliver is reported unless the caller closed the stream: then every refusal is a
/// broken pipe, nothing was dropped and nothing panicked.
#[skuld::test]
fn a_terminal_sink_reports_a_loss_unless_its_caller_closed_the_stream() {
    use std::io::ErrorKind::{BrokenPipe, StorageFull};
    // (the first error's kind, messages dropped, the writer thread panicked, logging its panics panicked, is a loss)
    let table = [
        (Some(BrokenPipe), 0, false, false, false),
        (Some(StorageFull), 0, false, false, true),
        (Some(BrokenPipe), 1, false, false, true),
        (Some(BrokenPipe), 0, true, false, true),
        (Some(BrokenPipe), 0, false, true, true),
        (None, 1, false, false, true),
        (None, 0, true, false, true),
    ];
    for (first, dropped, panicked, logging_panicked, expected) in table {
        let report = |message: &str| crate::logging::PanicReport {
            message: message.to_string(),
            location: None,
        };
        let error = crate::logging::queued::QueueError {
            first: first.map(std::io::Error::from),
            refused: u64::from(first.is_some()),
            dropped,
            panic: panicked.then(|| report("a destination panics")),
            logging_panic: logging_panicked.then(|| report("a tracing writer panics")),
        };
        assert_eq!(super::terminal_failure_is_loss(&error), expected, "{error:?}");
    }
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
    let _g = garter::tracing_test::set_default_in_current_thread(subscriber);

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
    let _g = garter::tracing_test::set_default_in_current_thread(subscriber);

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

// Tests: legacy daily-log cleanup =====================================================================================

#[skuld::test]
fn cleanup_legacy_daily_logs_removes_only_dated_siblings_of_stem(#[fixture(temp_dir)] dir: &Path) {
    std::fs::write(dir.join("bridge.log"), b"").expect("seed bridge.log");
    std::fs::write(dir.join("bridge.log.1"), b"").expect("seed bridge.log.1");
    std::fs::write(dir.join("bridge.other.txt"), b"").expect("seed bridge.other.txt");
    std::fs::write(dir.join("gui.log.2024-01-01"), b"").expect("seed gui.log.2024-01-01");
    std::fs::write(dir.join("bridge.log.2024-01-01"), b"").expect("seed bridge.log.2024-01-01");
    std::fs::write(dir.join("bridge.log.2024-02-15"), b"").expect("seed bridge.log.2024-02-15");

    super::cleanup_legacy_daily_logs(dir, &Dir::open(dir, false, None).unwrap(), "bridge.log");

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
    super::cleanup_legacy_daily_logs(dir, &Dir::open(dir, false, None).unwrap(), "gui.log");

    assert!(
        !dir.join("gui.log.2024-01-01").exists(),
        "gui.log.2024-01-01 must now be gone"
    );
    assert!(dir.join("bridge.log").exists(), "bridge.log still present");
    assert!(dir.join("bridge.log.1").exists(), "bridge.log.1 still present");
    assert!(dir.join("bridge.other.txt").exists(), "bridge.other.txt still present");
}

#[skuld::test]
fn cleanup_legacy_daily_logs_removes_only_inside_the_opened_directory(#[fixture(temp_dir)] dir: &Path) {
    // The listing path names another directory than the one opened (it was swapped): the names it offers are
    // acted on inside the opened directory only.
    let opened = dir.join("opened");
    let listed = dir.join("listed");
    std::fs::create_dir(&opened).expect("create opened");
    std::fs::create_dir(&listed).expect("create listed");
    std::fs::write(listed.join("bridge.log.2024-01-01"), b"").expect("seed listed");
    std::fs::write(opened.join("bridge.log.2024-02-02"), b"").expect("seed opened");

    super::cleanup_legacy_daily_logs(&listed, &Dir::open(&opened, false, None).unwrap(), "bridge.log");

    assert!(
        listed.join("bridge.log.2024-01-01").exists(),
        "a file of the listed directory was removed"
    );
    assert!(
        opened.join("bridge.log.2024-02-02").exists(),
        "no name from the listing matched it, so it stays"
    );
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
fn cleanup_legacy_daily_logs_tolerates_a_listing_that_is_not_there(#[fixture(temp_dir)] dir: &Path) {
    let nonexistent = dir.join("does-not-exist");
    // Must not panic.
    super::cleanup_legacy_daily_logs(&nonexistent, &Dir::open(dir, false, None).unwrap(), "bridge.log");
}

// Tests: log crate bridge =============================================================================================

#[skuld::test]
fn log_crate_macros_reach_file(#[fixture(temp_dir)] dir: &Path) {
    // Runs as a subprocess: the parent already has the
    // `hole-test-observability` global subscriber installed, so the
    // production `init()`'s `set_global_default` would fail in-process
    // and the file layer would never receive events. The child has a
    // clean global slot (the ctor short-circuits on
    // `HOLE_LOGGING_TEST_KIND`).
    let log_dir = dir.join("log-bridge-test");
    std::fs::create_dir_all(&log_dir).expect("create log dir");
    let exe = std::env::current_exe().expect("current_exe");
    let status = Command::new(&exe)
        .env("HOLE_LOGGING_TEST_KIND", "log_bridge_to_file")
        .env("HOLE_LOGGING_TEST_LOG_DIR", &log_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn child");
    assert!(
        status.success(),
        "log_bridge_to_file child failed with status {status:?}"
    );

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

// Tests: per-sink directive resolution ================================================================================

// split_directives ----------------------------------------------------------------------------------------------------
#[skuld::test]
fn split_directives_trims_and_drops_blanks() {
    assert_eq!(
        super::split_directives("  hole=debug ,, \tshadowsocks_service=trace ,"),
        vec!["hole=debug".to_string(), "shadowsocks_service=trace".to_string()],
    );
}

#[skuld::test]
fn split_directives_empty_is_empty() {
    assert!(super::split_directives("   \t ").is_empty());
}

// resolve_sink_directives_from ----------------------------------------------------------------------------------------
#[skuld::test]
fn resolve_defaults_when_nothing_set() {
    let (file, stderr) = super::resolve_sink_directives_from("hole_bridge=info", None, None, None);
    assert_eq!(file, vec!["hole_bridge=info".to_string()]);
    assert_eq!(stderr, file, "stderr mirrors file when HOLE_LOG_STDERR unset");
}

#[skuld::test]
fn resolve_component_env_overrides_file_and_stderr_mirrors() {
    // HOLE_BRIDGE_LOG=debug → file debug; stderr mirrors (back-compat).
    let (file, stderr) = super::resolve_sink_directives_from("hole_bridge=info", Some("hole_bridge=debug"), None, None);
    assert_eq!(file, vec!["hole_bridge=debug".to_string()]);
    assert_eq!(stderr, file);
}

#[skuld::test]
fn resolve_component_env_takes_precedence_over_hole_log() {
    let (file, _stderr) =
        super::resolve_sink_directives_from("hole_bridge=info", Some("hole_bridge=debug"), Some("hole=trace"), None);
    assert_eq!(
        file,
        vec!["hole_bridge=debug".to_string()],
        "component env wins over HOLE_LOG"
    );
}

#[skuld::test]
fn resolve_hole_log_used_when_no_component_env() {
    let (file, _stderr) = super::resolve_sink_directives_from("hole=info", None, Some("debug,hole=trace"), None);
    assert_eq!(file, vec!["debug".to_string(), "hole=trace".to_string()]);
}

#[skuld::test]
fn resolve_stderr_diverges_when_set() {
    let (file, stderr) =
        super::resolve_sink_directives_from("hole=info", None, Some("debug,hole=trace"), Some("hole=info"));
    assert_eq!(file, vec!["debug".to_string(), "hole=trace".to_string()]);
    assert_eq!(stderr, vec!["hole=info".to_string()]);
}

#[skuld::test]
fn resolve_blank_component_env_falls_back() {
    // A whitespace/comma-only value must not zero out the filter.
    let (file, _stderr) = super::resolve_sink_directives_from("hole=info", Some(" , "), None, None);
    assert_eq!(file, vec!["hole=info".to_string()]);
}

// resolve_log_dir -----------------------------------------------------------------------------------------------------
#[skuld::test]
fn resolve_log_dir_prefers_explicit_override() {
    let got = super::resolve_log_dir_from(
        Some(std::path::PathBuf::from("/explicit")),
        Some(std::path::PathBuf::from("/env")),
        super::default_log_dir,
    );
    assert_eq!(got, std::path::PathBuf::from("/explicit"));
}

#[skuld::test]
fn resolve_log_dir_uses_env_when_no_override() {
    let got = super::resolve_log_dir_from(None, Some(std::path::PathBuf::from("/env")), super::default_log_dir);
    assert_eq!(got, std::path::PathBuf::from("/env"));
}

#[skuld::test]
fn resolve_log_dir_falls_back_to_default() {
    let got = super::resolve_log_dir_from(None, None, super::default_log_dir);
    assert_eq!(got, super::default_log_dir());
}

#[skuld::test]
fn resolve_log_dir_from_uses_supplied_fallback() {
    let got = super::resolve_log_dir_from(None, None, || std::path::PathBuf::from("/service"));
    assert_eq!(got, std::path::PathBuf::from("/service"));
}

#[skuld::test]
fn nonblank_dir_keeps_nonempty() {
    assert_eq!(
        super::nonblank_dir(Some("/x".into())),
        Some(std::path::PathBuf::from("/x"))
    );
}

#[skuld::test]
fn nonblank_dir_drops_blank() {
    // An empty HOLE_LOG_DIR= must fall through, not resolve to a bare path.
    assert_eq!(super::nonblank_dir(Some("".into())), None);
}

#[skuld::test]
fn nonblank_dir_drops_absent() {
    assert_eq!(super::nonblank_dir(None), None);
}

// Per-sink composition ------------------------------------------------------------------------------------------------
#[derive(Clone)]
struct CapBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
impl CapBuf {
    fn new() -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())))
    }
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}
impl std::io::Write for CapBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapBuf {
    type Writer = CapBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[skuld::test]
fn file_sink_gets_trace_stderr_does_not() {
    let file = CapBuf::new();
    let err = CapBuf::new();
    let sub = super::compose_subscriber(
        file.clone(),
        err.clone(),
        &["t1_target=trace".to_string()],
        &["t1_target=info".to_string()],
    );
    // Install as the thread-local default via the workspace helper (raw
    // set_default is clippy-disallowed; hole-common depends on garter, so the
    // helper is available — cf. the existing `panic_hook_emits_tracing_event`
    // test). Target-specific directives in `sub` override any ambient RUST_LOG
    // (caller directives are added after from_env_lossy and win at equal/greater
    // specificity), so this is deterministic regardless of the environment.
    let _g = garter::tracing_test::set_default_in_current_thread(sub);
    tracing::trace!(target: "t1_target", "trace-line");
    tracing::info!(target: "t1_target", "info-line");
    let f = file.contents();
    let e = err.contents();
    assert!(f.contains("trace-line"), "file missing trace:\n{f}");
    assert!(f.contains("info-line"), "file missing info:\n{f}");
    assert!(!e.contains("trace-line"), "stderr leaked trace:\n{e}");
    assert!(e.contains("info-line"), "stderr missing info:\n{e}");
}

#[skuld::test]
fn relay_events_go_to_file_not_stderr() {
    let file = CapBuf::new();
    let err = CapBuf::new();
    let sub = super::compose_subscriber(file.clone(), err.clone(), &["info".to_string()], &["info".to_string()]);
    let _g = garter::tracing_test::set_default_in_current_thread(sub);
    tracing::info!(target: "hole::stderr_relay", "relayed-line");
    drop(_g);
    assert!(file.contents().contains("relayed-line"), "file dropped relay event");
    assert!(
        !err.contents().contains("relayed-line"),
        "stderr must exclude relay events:\n{}",
        err.contents()
    );
}

// Tests: log redaction ================================================================================================

use crate::logging::logging_test_helpers::{REDACT_ADDR, REDACT_TOKEN};

/// The leak test. `init_dual` builds four queued writers and exactly
/// one of them is a log file; this covers that one.
#[skuld::test]
fn init_dual_writes_a_redacted_file(#[fixture(temp_dir)] dir: &Path) {
    let log_dir = dir.join("redact-file-test");
    std::fs::create_dir_all(&log_dir).expect("create log dir");
    let exe = std::env::current_exe().expect("current_exe");
    let status = Command::new(&exe)
        .env("HOLE_LOGGING_TEST_KIND", "redact_file")
        .env("HOLE_LOGGING_TEST_LOG_DIR", &log_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn child");
    assert!(status.success(), "redact_file child failed with status {status:?}");

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
        !contents.contains(REDACT_ADDR),
        "the armed address reached the log file:\n{contents}"
    );
    assert!(
        contents.contains(REDACT_TOKEN),
        "the token is missing, so the line may simply not have been written:\n{contents}"
    );
}

/// Pinned to the console tee target, not the file. The file is a different
/// writer, so a change that wrapped only the file's would still pass an
/// assertion made against the file.
#[skuld::test]
fn the_console_tee_target_is_redacted(#[fixture(temp_dir)] dir: &Path) {
    let result = run_child("redact_tee", dir);
    assert!(
        !result.tee_stderr.contains(REDACT_ADDR),
        "the armed address reached the stderr console tee: {:?}",
        result.tee_stderr
    );
    assert!(
        !result.tee_stdout.contains(REDACT_ADDR),
        "the armed address reached the stdout console tee: {:?}",
        result.tee_stdout
    );
    assert!(
        result.tee_stderr.contains(REDACT_TOKEN),
        "stderr tee received nothing recognizable: {:?}",
        result.tee_stderr
    );
    assert!(
        result.tee_stdout.contains(REDACT_TOKEN),
        "stdout tee received nothing recognizable: {:?}",
        result.tee_stdout
    );
}

// Tests: the log directory is the user's to swap ======================================================================

#[skuld::test]
fn init_dual_through_a_link_to_a_folder_the_system_owns_writes_nothing_there_and_says_so(
    #[fixture(temp_dir)] dir: &Path,
) {
    let scratch = SystemScratch::new();
    let log_dir = dir.join("logs");
    plant_link(scratch.root(), &log_dir);
    let log_file = scratch.root().join("test.log");
    let before = log_file.exists();
    let exe = std::env::current_exe().expect("current_exe");

    let out = Command::new(&exe)
        .env("HOLE_LOGGING_TEST_KIND", "redact_file")
        .env("HOLE_LOGGING_TEST_LOG_DIR", &log_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn child");

    assert!(
        out.status.success(),
        "the bridge keeps running without a log file: {out:?}"
    );
    assert_eq!(
        log_file.exists(),
        before,
        "a log file was written in the system's folder"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("the log file is disabled"),
        "no word that it is: {stderr}"
    );
    assert!(
        !stderr.contains(dir.to_string_lossy().as_ref()),
        "the message carries a path: {stderr}"
    );
}

#[skuld::test]
fn init_dual_through_a_users_link_to_the_users_folder_writes_the_log_there(#[fixture(temp_dir)] dir: &Path) {
    let real = dir.join("real");
    user_dir(&real);
    let log_dir = dir.join("logs");
    plant_link(&real, &log_dir);
    let exe = std::env::current_exe().expect("current_exe");

    let status = Command::new(&exe)
        .env("HOLE_LOGGING_TEST_KIND", "redact_file")
        .env("HOLE_LOGGING_TEST_LOG_DIR", &log_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn child");

    assert!(status.success(), "{status:?}");
    assert!(real.join("test.log").is_file());
}

#[skuld::test]
fn init_dual_creates_the_log_dir_and_the_file(#[fixture(temp_dir)] dir: &Path) {
    let log_dir = dir.join("hole").join("logs");
    let exe = std::env::current_exe().expect("current_exe");

    let status = Command::new(&exe)
        .env("HOLE_LOGGING_TEST_KIND", "redact_file")
        .env("HOLE_LOGGING_TEST_LOG_DIR", &log_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn child");

    assert!(status.success(), "child failed with status {status:?}");
    assert!(log_dir.join("test.log").is_file());
}

#[cfg(unix)]
#[skuld::test]
fn init_dual_hands_the_log_dir_and_file_to_the_owner_when_the_os_allows(#[fixture(temp_dir)] dir: &Path) {
    use std::os::unix::fs::MetadataExt;

    let foreign = dir.metadata().unwrap().uid() + 2;
    let scratch = dir.join("scratch");
    std::fs::write(&scratch, b"").unwrap();
    let allowed = std::os::unix::fs::chown(&scratch, Some(foreign), None).is_ok();
    let log_dir = dir.join("logs");
    let exe = std::env::current_exe().expect("current_exe");

    let status = Command::new(&exe)
        .env("HOLE_LOGGING_TEST_KIND", "redact_file")
        .env("HOLE_LOGGING_TEST_LOG_DIR", &log_dir)
        .env("HOLE_LOGGING_TEST_OWNER", format!("{foreign}:{foreign}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn child");

    assert!(status.success(), "child failed with status {status:?}");
    assert_eq!(log_dir.metadata().unwrap().uid() == foreign, allowed, "the directory");
    assert_eq!(
        log_dir.join("test.log").metadata().unwrap().uid() == foreign,
        allowed,
        "the file"
    );
}

/// A failed flush of Rust's stdout buffer is reported as a loss unless the relay already reports it (redirected) or the
/// caller closed the stream (not redirected).
#[skuld::test]
fn a_stdout_buffer_flush_failure_is_a_loss_unless_it_is_reported_elsewhere() {
    use std::io::ErrorKind::{BrokenPipe, StorageFull};
    // (redirected, the relay's own flush failed, the error's kind, is a loss)
    let table = [
        (true, true, BrokenPipe, false),
        (true, true, StorageFull, true),
        (true, false, BrokenPipe, true),
        (true, false, StorageFull, true),
        (false, false, BrokenPipe, false),
        (false, false, StorageFull, true),
    ];
    for (redirected, relay_failed, kind, expected) in table {
        let error = std::io::Error::from(kind);
        assert_eq!(
            super::buffer_flush_failure_is_loss(&error, redirected, relay_failed),
            expected,
            "redirected {redirected}, relay failed {relay_failed}, {kind:?}"
        );
    }
}
