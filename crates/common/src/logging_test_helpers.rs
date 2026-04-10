// Child-process scenarios for logging FD-redirect tests.
//
// `lib.rs::main` checks `HOLE_LOGGING_TEST_KIND` early, before skuld
// initializes the test runner. If set, it dispatches into `run_child` here
// and exits — keeping the FD-redirect contained to a fresh process so it
// can't interfere with sibling tests.
//
// Each scenario writes a `ChildResult` JSON file to `HOLE_LOGGING_TEST_OUTPUT`
// and the parent reads + asserts on it.

use crate::logging::logging_tests::{CapturedEvent, ChildResult};
use crate::logging::redirect_stdio_to_tracing_for_tests;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

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
}

fn install_child_subscriber() -> ChildHarness {
    use tracing_subscriber::Layer;

    let file_writer = VecWriter::new();
    let stderr_writer = VecWriter::new();

    let no_relay = tracing_subscriber::filter::filter_fn(|m| {
        !m.target().starts_with("hole::stderr_relay")
            && !m.target().starts_with("hole::stdout_relay")
            && !m.target().starts_with("hole::plugin")
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

fn finish(harness: &ChildHarness) -> ChildResult {
    // Give the in-memory tracing layers a chance to flush.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let mut events = parse_lines("file", &harness.file_writer.snapshot());
    events.extend(parse_lines("stderr", &harness.stderr_writer.snapshot()));
    ChildResult {
        events,
        tee_stderr: String::new(),
        tee_stdout: String::new(),
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
        "redirect_no_loop" => scenario_no_loop(),
        "lossy_backpressure" => scenario_lossy_backpressure(),
        "plugin_log_reformat" => scenario_plugin_log_reformat(),
        "echo_stderr" => scenario_echo_stderr(),
        "echo_stdout" => scenario_echo_stdout(),
        other => panic!("unknown HOLE_LOGGING_TEST_KIND: {other}"),
    }
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
    let harness = install_child_subscriber();
    let (_relays, _layer_writer) = redirect_stdio_to_tracing_for_tests().expect("redirect");
    let _ = writeln!(std::io::stderr(), "hello-from-stderr");
    let _ = std::io::stderr().flush();
    let result = finish(&harness);
    write_result(&result);
}

fn scenario_basic_stdout() {
    let harness = install_child_subscriber();
    let (_relays, _layer_writer) = redirect_stdio_to_tracing_for_tests().expect("redirect");
    let _ = writeln!(std::io::stdout(), "hello-from-stdout");
    let _ = std::io::stdout().flush();
    let result = finish(&harness);
    write_result(&result);
}

fn scenario_grandchild_stderr() {
    let harness = install_child_subscriber();
    let (_relays, _layer_writer) = redirect_stdio_to_tracing_for_tests().expect("redirect");

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

    // Allow relay to drain.
    std::thread::sleep(std::time::Duration::from_millis(150));
    let result = finish(&harness);
    write_result(&result);
}

fn scenario_grandchild_stdout() {
    let harness = install_child_subscriber();
    let (_relays, _layer_writer) = redirect_stdio_to_tracing_for_tests().expect("redirect");

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

    std::thread::sleep(std::time::Duration::from_millis(150));
    let result = finish(&harness);
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

    let harness = install_child_subscriber();
    let _relays = crate::logging::redirect_stdio_to_tracing_with_writers_for_tests(
        Box::new(stderr_file.try_clone().unwrap()),
        Box::new(stdout_file.try_clone().unwrap()),
    )
    .expect("redirect with custom writers");

    let _ = writeln!(std::io::stderr(), "tee-stderr-line");
    let _ = std::io::stderr().flush();
    let _ = writeln!(std::io::stdout(), "tee-stdout-line");
    let _ = std::io::stdout().flush();

    std::thread::sleep(std::time::Duration::from_millis(150));

    let mut result = finish(&harness);
    result.tee_stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    result.tee_stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
    write_result(&result);
}

fn scenario_multiline() {
    let harness = install_child_subscriber();
    let (_relays, _layer_writer) = redirect_stdio_to_tracing_for_tests().expect("redirect");
    let _ = std::io::stderr().write_all(b"multiline-a\nmultiline-b\nmultiline-c\n");
    let _ = std::io::stderr().flush();
    std::thread::sleep(std::time::Duration::from_millis(150));
    let result = finish(&harness);
    write_result(&result);
}

fn scenario_no_loop() {
    let harness = install_child_subscriber();
    let (_relays, _layer_writer) = redirect_stdio_to_tracing_for_tests().expect("redirect");
    tracing::info!("normal event");
    std::thread::sleep(std::time::Duration::from_millis(150));
    let result = finish(&harness);
    write_result(&result);
}

fn scenario_lossy_backpressure() {
    // SlowWriter sleeps 100ms per write and counts the number of successful
    // writes — used in place of the file appender to verify the relay/file
    // pipeline doesn't block AND that some events were actually dropped
    // (not just queued).
    use std::sync::atomic::{AtomicUsize, Ordering};
    static WRITES: AtomicUsize = AtomicUsize::new(0);

    struct SlowWriter;
    impl Write for SlowWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(std::time::Duration::from_millis(100));
            WRITES.fetch_add(1, Ordering::SeqCst);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let (slow_nb, _slow_guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(true)
        .finish(SlowWriter);

    let file_layer = tracing_subscriber::fmt::layer().with_writer(slow_nb).with_ansi(false);

    let subscriber = tracing_subscriber::registry().with(file_layer);
    tracing::subscriber::set_global_default(subscriber).expect("set_global_default for lossy");

    let (_relays, _layer_writer) = redirect_stdio_to_tracing_for_tests().expect("redirect");

    // Write 10000 stderr lines in a tight loop. Without lossy mode this
    // would take ~1000 seconds. With lossy mode it completes in well under
    // a second, and the SlowWriter counter lands well below 10000 (proving
    // events were dropped, not just queued).
    for i in 0..10_000 {
        let _ = writeln!(std::io::stderr(), "lossy-line-{i}");
    }
    let _ = std::io::stderr().flush();

    // Record the observed write count in the result so the parent test can
    // assert on it. Reuse `tee_stderr` as a free-form channel for the value.
    let result = ChildResult {
        tee_stderr: WRITES.load(Ordering::SeqCst).to_string(),
        ..ChildResult::default()
    };
    write_result(&result);
}

fn scenario_plugin_log_reformat() {
    let harness = install_child_subscriber();
    let (_relays, _layer_writer) = redirect_stdio_to_tracing_for_tests().expect("redirect");
    // Go-format line with v2ray-core severity tag on stderr — should be
    // parsed and re-emitted under hole::plugin with WARN level.
    let _ = writeln!(std::io::stderr(), "2026/04/08 17:48:30 [Warning] test-plugin-msg");
    let _ = std::io::stderr().flush();
    // Go-format line on stdout — same parsing should apply.
    let _ = writeln!(std::io::stdout(), "2026/04/08 17:48:30 [Error] test-stdout-plugin-msg");
    let _ = std::io::stdout().flush();
    // Plain line that does NOT match Go log format — should pass through as
    // a generic hole::stderr_relay event.
    let _ = writeln!(std::io::stderr(), "plain-non-go-line");
    let _ = std::io::stderr().flush();
    std::thread::sleep(std::time::Duration::from_millis(150));
    let result = finish(&harness);
    write_result(&result);
}
