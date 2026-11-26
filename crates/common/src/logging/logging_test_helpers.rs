// Child-process scenarios for logging FD-redirect tests.
//
// `lib.rs::main` checks `HOLE_LOGGING_TEST_KIND` early, before skuld
// initializes the test runner. If set, it dispatches into `run_child` here
// and exits — keeping the FD-redirect contained to a fresh process so it
// can't interfere with sibling tests.
//
// Each scenario writes a `ChildResult` JSON file to `HOLE_LOGGING_TEST_OUTPUT`
// and the parent reads + asserts on it.

#![allow(clippy::disallowed_methods)] // attended test: bare-name host tools

use crate::logging::logging_tests::{CapturedEvent, ChildResult};
use crate::logging::queued::{queued, Overflow, CAPACITY};
use crate::logging::{redirect_stdio_to_tracing, redirect_stdio_with, ProcessKind, StdioRelayHandles, Stream};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

/// Shared by the redaction scenarios and the parent tests that assert on
/// their output.
pub(crate) const REDACT_ADDR: &str = "203.0.113.7";
pub(crate) const REDACT_TOKEN: &str = "<server:aaaaaaaa>";

// In-memory writer that captures emitted bytes per layer ==============================================================

#[derive(Clone)]
struct VecWriter {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl VecWriter {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }
    fn snapshot(&self) -> Vec<u8> {
        self.inner.lock().unwrap().clone()
    }
}

impl Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// Parsing in-memory layer output into CapturedEvent records ===========================================================

/// The fmt layer writes lines like:
/// ```
/// 2026-04-08T12:34:56.789012Z  INFO hole::stderr_relay: hello-from-stderr
/// ```
/// We parse them into `CapturedEvent` records by collapsing whitespace and
/// splitting positionally: timestamp, level, target+colon, then the remainder
/// is the message.
fn parse_lines(layer: &str, raw: &[u8]) -> Vec<CapturedEvent> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    for line in text.lines() {
        // Tokenize on whitespace, dropping empty tokens.
        let mut iter = line.split_whitespace();
        let _ts = match iter.next() {
            Some(s) => s,
            None => continue,
        };
        let level = match iter.next() {
            Some(s) => s.to_string(),
            None => continue,
        };
        if !["TRACE", "DEBUG", "INFO", "WARN", "ERROR"].contains(&level.as_str()) {
            continue;
        }
        let target_with_colon = match iter.next() {
            Some(s) => s,
            None => continue,
        };
        let target = target_with_colon.trim_end_matches(':').to_string();
        // Recover the message by re-joining the remainder. Use the byte
        // position of the target token's end to slice the original line so
        // multi-word messages survive.
        let target_end = match line.find(target_with_colon) {
            Some(start) => start + target_with_colon.len(),
            None => continue,
        };
        let message = line[target_end..].trim_start().to_string();
        out.push(CapturedEvent {
            layer: layer.to_string(),
            target,
            message,
            level,
        });
    }
    out
}

// Common test subscriber + tee target setup ===========================================================================

/// A in-memory subscriber harness for child scenarios. Two `fmt::layer()`s
/// (file + stderr) backed by `VecWriter`s, with the same filter behavior as
/// production `init()`. Uses `set_global_default` so the later-spawned relay
/// reader thread inherits it (`set_default` is thread-local).
struct ChildHarness {
    file_writer: VecWriter,
    stderr_writer: VecWriter,
    /// Some when the scenario installed the FD redirect; `finish` drains
    /// it before snapshotting. None for non-redirecting scenarios.
    relays: Option<StdioRelayHandles>,
}

fn install_child_subscriber() -> ChildHarness {
    use tracing_subscriber::Layer;

    let file_writer = VecWriter::new();
    let stderr_writer = VecWriter::new();

    let no_relay = tracing_subscriber::filter::filter_fn(|m| {
        !m.target().starts_with("hole::stderr_relay") && !m.target().starts_with("hole::stdout_relay")
    });

    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_writer.clone())
        .with_ansi(false);

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(stderr_writer.clone())
        .with_ansi(false)
        .with_filter(no_relay);

    let subscriber = tracing_subscriber::registry().with(file_layer).with(stderr_layer);
    tracing::subscriber::set_global_default(subscriber).expect("set_global_default in child");

    ChildHarness {
        file_writer,
        stderr_writer,
        relays: None,
    }
}

// Result file output ==================================================================================================

fn output_path() -> PathBuf {
    PathBuf::from(std::env::var("HOLE_LOGGING_TEST_OUTPUT").expect("HOLE_LOGGING_TEST_OUTPUT not set"))
}

fn write_result(result: &ChildResult) {
    let bytes = serde_json::to_vec(result).expect("serialize ChildResult");
    std::fs::write(output_path(), bytes).expect("write result");
}

fn finish(harness: &mut ChildHarness) -> ChildResult {
    // Flush the stdio relay deterministically: write a sentinel through
    // stderr/stdout, block on the reader's ack, then finish the tees'
    // queues. No sleep.
    if let Some(relays) = harness.relays.as_mut() {
        relays.flush(|e| panic!("relay flush: {e}"));
    }
    let mut events = parse_lines("file", &harness.file_writer.snapshot());
    events.extend(parse_lines("stderr", &harness.stderr_writer.snapshot()));
    ChildResult {
        events,
        ..ChildResult::default()
    }
}

// Scenarios ===========================================================================================================

pub(crate) fn run_child(kind: &str) {
    match kind {
        "redirect_basic_stderr" => scenario_basic_stderr(),
        "redirect_basic_stdout" => scenario_basic_stdout(),
        "redirect_grandchild_stderr" => scenario_grandchild_stderr(),
        "redirect_grandchild_stdout" => scenario_grandchild_stdout(),
        "redirect_tee" => scenario_tee(),
        "redirect_multiline" => scenario_multiline(),
        "redirect_open_line_stderr" => scenario_open_line(Stream::Stderr),
        "redirect_open_line_stdout" => scenario_open_line(Stream::Stdout),
        "redirect_relay_thread_ended_stderr" => scenario_relay_thread_ended(Stream::Stderr),
        "redirect_relay_thread_ended_stdout" => scenario_relay_thread_ended(Stream::Stdout),
        "redirect_slow_stderr_relay" => scenario_slow_relay("hole::stderr_relay"),
        "redirect_slow_stdout_relay" => scenario_slow_relay("hole::stdout_relay"),
        "redirect_tee_refuses" => scenario_tee_refuses(),
        "redirect_tee_overflows" => scenario_tee_overflows(),
        "redirect_writer_thread_panics" => scenario_writer_thread_panics(),
        "writer_panic_reaches_the_other_sink" => scenario_writer_panic_reaches_the_other_sink(),
        "layer_writers_fail" => scenario_layer_writers_fail(),
        "redirect_no_loop" => scenario_no_loop(),
        "echo_stderr" => scenario_echo_stderr(),
        "echo_stdout" => scenario_echo_stdout(),
        "log_bridge_to_file" => scenario_log_bridge_to_file(),
        "redact_file" => scenario_redact_file(),
        "redact_tee" => scenario_redact_tee(),
        other => panic!("unknown HOLE_LOGGING_TEST_KIND: {other}"),
    }
}

/// Verifies that `log::info!` (from the `log` crate) is bridged into
/// tracing's file-rotator layer by the production `init` path. The
/// parent test spawns this scenario, then reads the log file the
/// child wrote and asserts the marker is present.
///
/// Runs in a subprocess so that the production `init()`'s
/// `set_global_default` succeeds — the parent test binary already
/// has the `hole-test-observability` global subscriber installed.
fn scenario_log_bridge_to_file() {
    let log_dir_str = std::env::var("HOLE_LOGGING_TEST_LOG_DIR").expect("HOLE_LOGGING_TEST_LOG_DIR var");
    let log_dir = std::path::Path::new(&log_dir_str);
    // The redirect would eat the libtest-mimic per-test result lines; we
    // need its diagnostics if the child fails.
    unsafe { std::env::set_var("HOLE_LOGGING_DISABLE_REDIRECT", "1") };
    let guard = super::init(log_dir, ProcessKind::Command, "test.log", "info", None);
    log::info!("from-log-crate-bridge-test");
    // Drop the guard explicitly: it returns once the file's writer thread
    // has written every event to disk, and the child exits after it.
    drop(guard);
}

/// Helper used by the redirect_grandchild_* scenarios. Writes a marker line
/// to stderr and exits — invoked as a grandchild from the parent test via
/// `Command::new(current_exe).env("HOLE_LOGGING_TEST_KIND", "echo_stderr")`.
fn scenario_echo_stderr() {
    let _ = writeln!(std::io::stderr(), "from-rust-grandchild");
    let _ = std::io::stderr().flush();
}

fn scenario_echo_stdout() {
    let _ = writeln!(std::io::stdout(), "from-rust-grandchild");
    let _ = std::io::stdout().flush();
}

fn scenario_basic_stderr() {
    let mut harness = install_child_subscriber();
    let (relays, _layer_writer) = redirect_stdio_to_tracing(Overflow::Wait).expect("redirect");
    harness.relays = Some(relays);
    let _ = writeln!(std::io::stderr(), "hello-from-stderr");
    let _ = std::io::stderr().flush();
    let result = finish(&mut harness);
    write_result(&result);
}

fn scenario_basic_stdout() {
    let mut harness = install_child_subscriber();
    let (relays, _layer_writer) = redirect_stdio_to_tracing(Overflow::Wait).expect("redirect");
    harness.relays = Some(relays);
    let _ = writeln!(std::io::stdout(), "hello-from-stdout");
    let _ = std::io::stdout().flush();
    let result = finish(&mut harness);
    write_result(&result);
}

fn scenario_grandchild_stderr() {
    let mut harness = install_child_subscriber();
    let (relays, _layer_writer) = redirect_stdio_to_tracing(Overflow::Wait).expect("redirect");
    harness.relays = Some(relays);

    // Pass A: Rust grandchild via current_exe.
    let exe = std::env::current_exe().expect("current_exe");
    let _ = std::process::Command::new(&exe)
        .env_remove("HOLE_LOGGING_TEST_OUTPUT")
        .env("HOLE_LOGGING_TEST_KIND", "echo_stderr")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status();

    // Pass B: foreign-runtime grandchild via cmd.exe / sh.
    if cfg!(windows) {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "echo from-cmd-grandchild 1>&2"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status();
    } else {
        let _ = std::process::Command::new("sh")
            .args(["-c", "echo from-sh-grandchild >&2"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status();
    }

    let result = finish(&mut harness);
    write_result(&result);
}

fn scenario_grandchild_stdout() {
    let mut harness = install_child_subscriber();
    let (relays, _layer_writer) = redirect_stdio_to_tracing(Overflow::Wait).expect("redirect");
    harness.relays = Some(relays);

    let exe = std::env::current_exe().expect("current_exe");
    let _ = std::process::Command::new(&exe)
        .env_remove("HOLE_LOGGING_TEST_OUTPUT")
        .env("HOLE_LOGGING_TEST_KIND", "echo_stdout")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if cfg!(windows) {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "echo from-cmd-grandchild"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    } else {
        let _ = std::process::Command::new("sh")
            .args(["-c", "echo from-sh-grandchild"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    let result = finish(&mut harness);
    write_result(&result);
}

fn scenario_tee() {
    // Use a sink-of-truth temp file as the saved-original writer so the test
    // can verify the tee path. We do this by manually wiring the redirect
    // helper instead of using the convenience wrapper.
    use std::fs::OpenOptions;
    let dir = tempfile::tempdir().expect("tempdir");
    let stderr_path = dir.path().join("tee-stderr.bin");
    let stdout_path = dir.path().join("tee-stdout.bin");

    let stderr_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(&stderr_path)
        .expect("open stderr tee file");
    let stdout_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(&stdout_path)
        .expect("open stdout tee file");

    let mut harness = install_child_subscriber();
    let relays = redirect_stdio_with(
        Box::new(stderr_file.try_clone().unwrap()),
        Box::new(stdout_file.try_clone().unwrap()),
        Overflow::Wait,
    )
    .expect("redirect with custom writers");
    harness.relays = Some(relays);

    let _ = writeln!(std::io::stderr(), "tee-stderr-line");
    let _ = std::io::stderr().flush();
    let _ = writeln!(std::io::stdout(), "tee-stdout-line");
    let _ = std::io::stdout().flush();

    let mut result = finish(&mut harness);
    result.tee_stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    result.tee_stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
    write_result(&result);
}

fn scenario_multiline() {
    let mut harness = install_child_subscriber();
    let (relays, _layer_writer) = redirect_stdio_to_tracing(Overflow::Wait).expect("redirect");
    harness.relays = Some(relays);
    let _ = std::io::stderr().write_all(b"multiline-a\nmultiline-b\nmultiline-c\n");
    let _ = std::io::stderr().flush();
    let result = finish(&mut harness);
    write_result(&result);
}

/// A complete line that looks like a drain marker, and a line still open when the drain marker is written that holds
/// marker-like text of its own, on `stream`. The first is output, and must not answer a drain request that is waiting
/// (the process cannot know the request's nonce); the real marker lands at the end of the second, and the text before
/// it must still be relayed whole.
fn scenario_open_line(stream: Stream) {
    let mut harness = install_child_subscriber();
    let (relays, _layer_writer) = redirect_stdio_to_tracing(Overflow::Wait).expect("redirect");
    let relay = match stream {
        Stream::Stderr => relays.stderr.as_ref(),
        Stream::Stdout => relays.stdout.as_ref(),
    };
    let (_nonce, waiting) = relay
        .expect("the relay")
        .drain
        .request()
        .expect("the relay thread is alive");
    harness.relays = Some(relays);
    let text = b"__hole_relay_flush__00000000000000000000000000000000\nopen-line__hole_relay_flush__abc";
    match stream {
        Stream::Stderr => {
            let _ = std::io::stderr().write_all(text);
            let _ = std::io::stderr().flush();
        }
        Stream::Stdout => {
            let _ = std::io::stdout().write_all(text);
            let _ = std::io::stdout().flush();
        }
    }
    let mut result = finish(&mut harness);
    result.observed = vec![format!("answered by the line: {:?}", waiting.try_recv())];
    write_result(&result);
}

/// The relay thread of `ended` ends, by a panic in a tracing writer, while a drain request is registered, with the
/// production panic hook installed over a previous hook that records the threads it runs on. The result lists what the
/// hook and each drain branch did once the thread has been joined; nothing here blocks, so a branch that is wrong shows
/// as a different line, not as a hang.
fn scenario_relay_thread_ended(ended: Stream) {
    struct PanicWriter;
    impl Write for PanicWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            panic!("a tracing writer panics on the relay thread");
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The events of the relay with `target` go to a writer that panics, the panic hook's records to `records`, the
    /// rest nowhere.
    struct PanicOnRelay {
        target: &'static str,
        records: VecWriter,
    }
    impl<'a> MakeWriter<'a> for PanicOnRelay {
        type Writer = Box<dyn Write>;
        fn make_writer(&'a self) -> Self::Writer {
            Box::new(std::io::sink())
        }
        fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
            match meta.target() {
                target if target == self.target => Box::new(PanicWriter),
                "hole::panic" => Box::new(self.records.clone()),
                _ => Box::new(std::io::sink()),
            }
        }
    }

    // The previous hook of the production hook. The default one writes the panic to stderr, which on the relay thread is
    // the pipe that thread alone reads; with `RUST_BACKTRACE` set the text is longer than the pipe holds, and the thread
    // waits for itself.
    let chained = Arc::new(Mutex::new(Vec::<String>::new()));
    std::panic::set_hook(Box::new({
        let chained = Arc::clone(&chained);
        move |_| {
            let thread = std::thread::current();
            chained
                .lock()
                .unwrap()
                .push(thread.name().unwrap_or("<unnamed>").to_string());
        }
    }));
    crate::logging::install_panic_hook_for_tests();

    let records = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(PanicOnRelay {
                target: match ended {
                    Stream::Stderr => "hole::stderr_relay",
                    Stream::Stdout => "hole::stdout_relay",
                },
                records: records.clone(),
            })
            .with_ansi(false),
    );
    tracing::subscriber::set_global_default(subscriber).expect("set_global_default in child");

    let (stderr_tee, stdout_tee) = (VecWriter::new(), VecWriter::new());
    let mut relays = redirect_stdio_with(
        Box::new(stderr_tee.clone()),
        Box::new(stdout_tee.clone()),
        Overflow::Wait,
    )
    .expect("redirect with custom writers");
    fn relay(relays: &mut StdioRelayHandles, ended: Stream) -> &mut crate::logging::Relay {
        match ended {
            Stream::Stderr => relays.stderr.as_mut().expect("the stderr relay"),
            Stream::Stdout => relays.stdout.as_mut().expect("the stdout relay"),
        }
    }

    // A request registered while the thread is alive: the thread ends before it answers.
    let (_nonce, answered) = relay(&mut relays, ended)
        .drain
        .request()
        .expect("the relay thread is alive");

    // The other stream keeps its relay: its lines must all reach its tee.
    for i in 0..5 {
        match ended {
            Stream::Stderr => writeln!(std::io::stdout(), "other-line-{i}"),
            Stream::Stdout => writeln!(std::io::stderr(), "other-line-{i}"),
        }
        .expect("a line to the other stream");
    }
    match ended {
        Stream::Stderr => writeln!(std::io::stderr(), "boom"),
        Stream::Stdout => writeln!(std::io::stdout(), "boom"),
    }
    .expect("the line that ends the relay thread");

    // The thread has ended once it is joined: after this the drain's state does not change.
    let thread = std::mem::replace(&mut relay(&mut relays, ended)._thread, std::thread::spawn(|| {}));
    thread.join().expect("the relay thread catches the panic");

    // Rust's stdout holds a line that is not complete. A flush writes it into the pipe that nobody reads any more and
    // fails, and the line stays buffered, so the flush in `StdioRelayHandles::flush` below meets the same failure. The
    // result lists what two flushes here do, to show that the buffer still holds the line.
    let unfinished = match ended {
        Stream::Stdout => {
            write!(std::io::stdout(), "a line that is not complete").expect("buffered");
            let flushes = [std::io::stdout().flush(), std::io::stdout().flush()];
            Some(format!(
                "unfinished line flushes: {:?}",
                flushes.map(|r| r.err().map(|e| e.kind()))
            ))
        }
        Stream::Stderr => None,
    };

    // The same hook on a thread that is not a relay: the previous hook must run there, or the check above proves nothing.
    std::thread::Builder::new()
        .name("not-a-relay".into())
        .spawn(|| panic!("a panic off the relay thread"))
        .expect("spawn")
        .join()
        .expect_err("the thread panics");

    let mut observed = Vec::new();
    observed.push(format!("registered request: {:?}", answered.try_recv()));
    observed.push(format!(
        "new request: {}",
        relay(&mut relays, ended).drain.request().is_some()
    ));
    let mut errors = Vec::new();
    relays.flush(|e| errors.push(e.to_string()));
    observed.push(format!("flush errors: {errors:?}"));
    observed.push(format!("previous hook ran on: {:?}", chained.lock().unwrap()));
    let records = String::from_utf8_lossy(&records.snapshot()).into_owned();
    let messages: Vec<&str> = records
        .lines()
        .filter_map(|line| line.split_once("hole::panic: panic: "))
        .map(|(_, rest)| rest.split(" location=").next().unwrap_or(rest))
        .collect();
    observed.push(format!("panic records: {messages:?}"));
    observed.extend(unfinished);
    let other_tee = match ended {
        Stream::Stderr => &stdout_tee,
        Stream::Stdout => &stderr_tee,
    };
    write_result(&ChildResult {
        observed,
        tee_stdout: String::from_utf8_lossy(&other_tee.snapshot()).into_owned(),
        ..ChildResult::default()
    });
}

/// Lines keep arriving on both streams while the relay threads are held up (each tracing event takes a delay, a fault
/// injected to widen the window). The relay of `slow_target` is held up longer than the other, so a
/// `flush` that waits for the other stream alone still returns while this one is behind. `flush` must return only once
/// every line of each stream has gone through its tee.
fn scenario_slow_relay(slow_target: &'static str) {
    use std::fs::OpenOptions;
    const LINES: usize = 15;

    struct SlowWriter(std::time::Duration);
    impl Write for SlowWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.0);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct SlowRelays(&'static str);
    impl<'a> MakeWriter<'a> for SlowRelays {
        type Writer = SlowWriter;
        fn make_writer(&'a self) -> SlowWriter {
            SlowWriter(std::time::Duration::ZERO)
        }
        fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> SlowWriter {
            let millis = if meta.target() == self.0 { 40 } else { 5 };
            SlowWriter(std::time::Duration::from_millis(millis))
        }
    }

    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(SlowRelays(slow_target))
            .with_ansi(false),
    );
    tracing::subscriber::set_global_default(subscriber).expect("set_global_default in child");

    let dir = tempfile::tempdir().expect("tempdir");
    let tee_file = |name: &str| {
        let path = dir.path().join(name);
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .expect("open tee file");
        (path, file)
    };
    let (stderr_path, stderr_file) = tee_file("tee-stderr.bin");
    let (stdout_path, stdout_file) = tee_file("tee-stdout.bin");
    let mut relays = redirect_stdio_with(Box::new(stderr_file), Box::new(stdout_file), Overflow::Wait)
        .expect("redirect with custom writers");

    for i in 0..LINES {
        let _ = writeln!(std::io::stdout(), "slow-line-{i}");
        let _ = writeln!(std::io::stderr(), "slow-line-{i}");
    }
    relays.flush(|e| panic!("relay flush: {e}"));

    let result = ChildResult {
        tee_stderr: std::fs::read_to_string(&stderr_path).unwrap_or_default(),
        tee_stdout: std::fs::read_to_string(&stdout_path).unwrap_or_default(),
        ..ChildResult::default()
    };
    write_result(&result);
}

/// An error and its causes as the exit report prints them.
fn chain_text(error: &std::io::Error) -> String {
    util::error::chain(error)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

/// The stderr tee's destination refuses its second and fourth write. The result holds what the destination took and
/// what `flush` reported.
fn scenario_tee_refuses() {
    struct Refusing {
        taken: VecWriter,
        writes: usize,
    }
    impl Write for Refusing {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            if self.writes.is_multiple_of(2) {
                return Err(std::io::ErrorKind::StorageFull.into());
            }
            self.taken.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let taken = VecWriter::new();
    let mut relays = redirect_stdio_with(
        Box::new(Refusing {
            taken: taken.clone(),
            writes: 0,
        }),
        Box::new(std::io::sink()),
        Overflow::Wait,
    )
    .expect("redirect with custom writers");
    for i in 0..5 {
        writeln!(std::io::stderr(), "line-{i}").expect("a line to stderr");
    }
    let mut errors = Vec::new();
    relays.flush(|e| errors.push(chain_text(&e)));
    write_result(&ChildResult {
        observed: vec![format!("flush errors: {errors:?}")],
        tee_stderr: String::from_utf8_lossy(&taken.snapshot()).into_owned(),
        ..ChildResult::default()
    });
}

/// A destination that says when its first write begins and holds it until the scenario releases it. Counts its writes.
struct Held {
    entered: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<()>,
    writes: Arc<AtomicUsize>,
    took: VecWriter,
}

impl Write for Held {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(entered) = self.entered.take() {
            entered.send(()).expect("the scenario waits for the first write");
            self.release.recv().expect("the scenario releases the first write");
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.took.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// How many lines the overflow scenario writes past what its tee can hold: one in the destination's hands and a full
/// queue.
pub(crate) const OVERFLOW_EXCESS: usize = 7;

/// The stderr tee, one that drops when it is full, has a destination that holds its first write until the relay has
/// taken `OVERFLOW_EXCESS` more lines than the tee can hold. The result holds how many writes the destination took and
/// what `flush` reported.
fn scenario_tee_overflows() {
    let (entered, has_entered) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let writes = Arc::new(AtomicUsize::new(0));
    let mut relays = redirect_stdio_with(
        Box::new(Held {
            entered: Some(entered),
            release: released,
            writes: Arc::clone(&writes),
            took: VecWriter::new(),
        }),
        Box::new(std::io::sink()),
        Overflow::Drop,
    )
    .expect("redirect with custom writers");

    // The destination holds the first line, so the queue behind it is empty and takes exactly its capacity.
    writeln!(std::io::stderr(), "line-0").expect("a line to stderr");
    has_entered.recv().expect("the destination's first write");
    for i in 1..=CAPACITY + OVERFLOW_EXCESS {
        writeln!(std::io::stderr(), "line-{i}").expect("a line to stderr");
    }
    // The relay has handed every line to the tee once it answers a drain; a tee that drops never holds the relay.
    relays
        .stderr
        .as_mut()
        .expect("the stderr relay")
        .drain()
        .expect("the relay takes every line");
    release.send(()).expect("the destination is waiting");

    let mut errors = Vec::new();
    relays.flush(|e| errors.push(chain_text(&e)));
    write_result(&ChildResult {
        observed: vec![
            format!("tee writes: {}", writes.load(Ordering::SeqCst)),
            format!("flush errors: {errors:?}"),
        ],
        ..ChildResult::default()
    });
}

/// `text` with each `file:line:column` location in this file replaced by `<here>`.
fn without_locations_here(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(file!()) {
        out.push_str(&rest[..at]);
        let after = &rest[at + file!().len()..];
        // `:line:column`
        let mut end = 0;
        for _ in 0..2 {
            let digits = after[end..].strip_prefix(':').map_or(0, |s| {
                s.len() - s.trim_start_matches(|c: char| c.is_ascii_digit()).len()
            });
            if digits == 0 {
                break;
            }
            end += 1 + digits;
        }
        out.push_str("<here>");
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// The stderr tee's destination panics on its writer thread, with the production panic hook installed over a previous
/// hook that records the threads it runs on. The result lists where the previous hook ran, the panic records the hook
/// logged, and what `flush` reported.
fn scenario_writer_thread_panics() {
    struct PanicWriter;
    impl Write for PanicWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            panic!("a destination panics on its writer thread");
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The panic hook's records go to `records`, the rest nowhere.
    struct PanicRecords(VecWriter);
    impl<'a> MakeWriter<'a> for PanicRecords {
        type Writer = Box<dyn Write>;
        fn make_writer(&'a self) -> Self::Writer {
            Box::new(std::io::sink())
        }
        fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
            match meta.target() {
                "hole::panic" => Box::new(self.0.clone()),
                _ => Box::new(std::io::sink()),
            }
        }
    }

    let chained = Arc::new(Mutex::new(Vec::<String>::new()));
    std::panic::set_hook(Box::new({
        let chained = Arc::clone(&chained);
        move |_| {
            let thread = std::thread::current();
            chained
                .lock()
                .unwrap()
                .push(thread.name().unwrap_or("<unnamed>").to_string());
        }
    }));
    crate::logging::install_panic_hook_for_tests();

    let records = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(PanicRecords(records.clone()))
            .with_ansi(false),
    );
    tracing::subscriber::set_global_default(subscriber).expect("set_global_default in child");

    let mut relays = redirect_stdio_with(Box::new(PanicWriter), Box::new(std::io::sink()), Overflow::Wait)
        .expect("redirect with custom writers");
    writeln!(std::io::stderr(), "boom").expect("the line that ends the writer thread");

    // `flush` finishes the tee, which joins its writer thread: the hook has run there by the time it returns.
    let mut errors = Vec::new();
    relays.flush(|e| errors.push(without_locations_here(&chain_text(&e))));

    // The same hook on a thread the delivery does not depend on: the previous hook must run there, or the check proves
    // nothing.
    std::thread::Builder::new()
        .name("not-a-delivery-thread".into())
        .spawn(|| panic!("a panic off the delivery threads"))
        .expect("spawn")
        .join()
        .expect_err("the thread panics");

    let records = String::from_utf8_lossy(&records.snapshot()).into_owned();
    let messages: Vec<&str> = records
        .lines()
        .filter_map(|line| line.split_once("hole::panic: panic: "))
        .map(|(_, rest)| rest.split(" location=").next().unwrap_or(rest))
        .collect();
    write_result(&ChildResult {
        observed: vec![
            format!("flush errors: {errors:?}"),
            format!("previous hook ran on: {:?}", chained.lock().unwrap()),
            format!("panic records: {messages:?}"),
        ],
        ..ChildResult::default()
    });
}

/// The production layers over two queues. The stderr layer's destination panics on its first write while the log
/// file's queue, one that waits when it is full, is full behind a destination held inside its first write. The event
/// that sets off the panic is filtered off the file layer. The file's destination is let go once the panicked
/// destination has been dropped, which its writer thread does after its queue has ended. The result holds the panic
/// records the log file took, whether each names its location in this file, and what finishing each queue returned.
fn scenario_writer_panic_reaches_the_other_sink() {
    // Off the writer threads the production hook chains to the default one, so a failing step here still says why.
    crate::logging::install_panic_hook_for_tests();

    let file_took = VecWriter::new();
    let (entered, has_entered) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (mut file, file_guard) = queued(
        Held {
            entered: Some(entered),
            release: released,
            writes: Arc::new(AtomicUsize::new(0)),
            took: file_took.clone(),
        },
        Overflow::Wait,
    );
    // The destination holds the first message, so the queue behind it is empty and takes exactly its capacity.
    file.write_all(b"held\n").expect("the log file's queue has room");
    has_entered.recv().expect("the log file's first write");
    for _ in 0..CAPACITY {
        file.write_all(b"x\n").expect("the log file's queue has room");
    }

    let (gone_tx, gone) = mpsc::channel();
    let (stderr, stderr_guard) = queued(PanicsOnFirstWrite(gone_tx), Overflow::Wait);
    let subscriber =
        crate::logging::compose_subscriber(file, stderr, &["panic_trigger=off".to_string()], &["info".to_string()]);
    tracing::subscriber::set_global_default(subscriber).expect("set_global_default in child");

    tracing::info!(target: "panic_trigger", "an event for the stderr layer only");
    gone.recv().expect("the panicked destination is dropped");
    release.send(()).expect("the log file's destination is waiting");
    let stderr_finished = describe(stderr_guard.finish());
    let file_finished = describe(file_guard.finish());

    let (messages, located_here) = panic_records(&file_took.snapshot());
    write_result(&ChildResult {
        observed: vec![
            format!("the panic records the log file took: {messages:?}"),
            format!("each names its location in this file: {located_here:?}"),
            format!(
                "finishing the stderr layer's queue names the panic's message: {}, and its location: {}",
                stderr_finished.contains("the other destination panics"),
                stderr_finished.contains(&format!("{}:", file!())),
            ),
            format!("finishing the log file's queue returned: {file_finished}"),
        ],
        ..ChildResult::default()
    });
}

/// The message of each panic record in `took`, a layer's output, and whether each names a location in this file.
fn panic_records(took: &[u8]) -> (Vec<String>, Vec<bool>) {
    let took = String::from_utf8_lossy(took);
    let lines: Vec<&str> = took.lines().collect();
    let mut messages = Vec::new();
    let mut located_here = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let Some((_, message)) = line.split_once("hole::panic: panic: ") else {
            continue;
        };
        messages.push(message.trim_end_matches(':').to_string());
        let location = lines[at + 1..]
            .iter()
            .take_while(|field| field.starts_with("  "))
            .find_map(|field| field.strip_prefix("  location: "));
        located_here.push(location.is_some_and(|location| location.contains("logging_test_helpers.rs:")));
    }
    (messages, located_here)
}

/// What `finish` returned, as text.
fn describe(result: Result<(), crate::logging::queued::QueueError>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(error) => error.to_string(),
    }
}

/// A destination that panics on its first write. It says when it is dropped, which is after its queue's receiver:
/// from then on the queue's senders are refused.
struct PanicsOnFirstWrite(mpsc::Sender<()>);

impl Write for PanicsOnFirstWrite {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        panic!("the other destination panics");
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for PanicsOnFirstWrite {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

/// The production subscriber over two writers that refuse every write, with stderr redirected and teed to a buffer.
/// One event is logged. The result holds how many writes the layers attempted and what reached the redirected stderr.
fn scenario_layer_writers_fail() {
    #[derive(Clone)]
    struct Refusing(Arc<AtomicUsize>);
    impl Write for Refusing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(std::io::ErrorKind::StorageFull.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for Refusing {
        type Writer = Refusing;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let attempts = Arc::new(AtomicUsize::new(0));
    let directives = ["info".to_string()];
    let subscriber = crate::logging::compose_subscriber(
        Refusing(Arc::clone(&attempts)),
        Refusing(Arc::clone(&attempts)),
        &directives,
        &directives,
    );
    tracing::subscriber::set_global_default(subscriber).expect("set_global_default in child");

    let tee = VecWriter::new();
    let mut relays = redirect_stdio_with(Box::new(tee.clone()), Box::new(std::io::sink()), Overflow::Wait)
        .expect("redirect with custom writers");
    tracing::info!(target: "some_dependency", "an event both writers refuse");
    // The relay has teed whatever reached the redirected stderr once this returns.
    relays.flush(|e| panic!("relay flush: {e}"));

    write_result(&ChildResult {
        observed: vec![format!("write attempts: {}", attempts.load(Ordering::SeqCst))],
        tee_stderr: String::from_utf8_lossy(&tee.snapshot()).into_owned(),
        ..ChildResult::default()
    });
}

fn scenario_no_loop() {
    let mut harness = install_child_subscriber();
    let (relays, _layer_writer) = redirect_stdio_to_tracing(Overflow::Wait).expect("redirect");
    harness.relays = Some(relays);
    tracing::info!("normal event");
    let result = finish(&mut harness);
    write_result(&result);
}

/// `init` builds the log file's writer; this scenario checks that an armed
/// literal cannot reach it. Addresses come from the RFC 5737 documentation
/// range so they appear in no other fixture.
fn scenario_redact_file() {
    let log_dir_str = std::env::var("HOLE_LOGGING_TEST_LOG_DIR").expect("HOLE_LOGGING_TEST_LOG_DIR var");
    let log_dir = std::path::Path::new(&log_dir_str);
    // The redirect would eat the libtest-mimic per-test result lines; we
    // need its diagnostics if the child fails.
    unsafe { std::env::set_var("HOLE_LOGGING_DISABLE_REDIRECT", "1") };
    // `HOLE_LOGGING_TEST_OWNER=<uid>:<gid>`: the user the files are handed to, as the elevated bridge's `owner`.
    let owner = std::env::var("HOLE_LOGGING_TEST_OWNER").ok().map(|v| {
        let (uid, gid) = v.split_once(':').expect("uid:gid");
        (uid.parse().expect("uid"), gid.parse().expect("gid"))
    });
    let guard = super::init(log_dir, ProcessKind::Command, "test.log", "info", owner);
    util::redact::arm(REDACT_TOKEN, [REDACT_ADDR.to_string()]);
    // A third-party-shaped line: no Hole site authored it, nothing about it
    // is `ServerAddress`-typed, and it still must not reach the file.
    tracing::info!(target: "some_dependency::dialer", "creating connection to {REDACT_ADDR}:8388");
    // Drop the guard explicitly: it returns once the file's writer thread
    // has written every event to disk, and the child exits after it.
    drop(guard);
}

/// The three console writers are wrapped separately from the file writer.
/// This scenario asserts on the **tee target** specifically: the file path
/// is a different writer, so asserting on the file here would pass even if
/// the console wrap were missing.
fn scenario_redact_tee() {
    use std::fs::OpenOptions;
    let dir = tempfile::tempdir().expect("tempdir");
    let stderr_path = dir.path().join("tee-stderr.bin");
    let stdout_path = dir.path().join("tee-stdout.bin");

    let open = |p: &std::path::Path| {
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(p)
            .expect("open tee file")
    };
    let stderr_file = open(&stderr_path);
    let stdout_file = open(&stdout_path);

    let mut harness = install_child_subscriber();
    util::redact::arm(REDACT_TOKEN, [REDACT_ADDR.to_string()]);
    let relays = redirect_stdio_with(
        Box::new(stderr_file.try_clone().unwrap()),
        Box::new(stdout_file.try_clone().unwrap()),
        Overflow::Wait,
    )
    .expect("redirect with custom writers");
    harness.relays = Some(relays);

    let _ = writeln!(std::io::stderr(), "tee-stderr-line {REDACT_ADDR}");
    let _ = std::io::stderr().flush();
    let _ = writeln!(std::io::stdout(), "tee-stdout-line {REDACT_ADDR}");
    let _ = std::io::stdout().flush();

    // `finish` drains the relay through its own rendezvous — no sleep.
    let mut result = finish(&mut harness);
    result.tee_stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    result.tee_stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
    write_result(&result);
}
