// Shared logging initialization.
//
// Three pieces of machinery, all installed by `init()`:
//
// 1. **FD-level stdio safety net.** At startup, FD 1 (stdout) and FD 2 (stderr)
//    are redirected to OS pipes. A reader thread per pipe tees each captured
//    line to (a) a `tracing` event and (b) the *saved-original* handle (which
//    preserves dev-terminal / CLI-script visibility). Lines matching Go's
//    standard log format (`YYYY/MM/DD HH:MM:SS [Severity] msg`) are parsed
//    and re-emitted under target `hole::plugin` with the appropriate tracing
//    level; all other lines fall through to `hole::stdout_relay` /
//    `hole::stderr_relay` at INFO. Catches any third-party output that
//    bypasses tracing — Go runtime stderr from v2ray-plugin, native
//    libraries, the default panic printer, etc.
//
// 2. **Multi-layer tracing subscriber.** A `Registry` with two `fmt::layer()`s:
//    a file layer that records everything (including the relay-target events,
//    that's the whole point) and a stderr layer pointed at the saved-original
//    handle that filters OUT relay-target events to prevent feedback loops.
//
// 3. **Custom panic hook.** Emits an ERROR-level event with backtrace under
//    target `hole::panic`, then chains the previous hook so the default printer
//    still runs in dev mode.
//
// Every non-blocking writer uses `.lossy(true)` so a slow/blocked file
// appender drops events instead of wedging the producing thread (including
// the panic hook itself, which would hang a panicking thread otherwise).

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_subscriber::EnvFilter;

// LogGuard ============================================================================================================

/// Guards for the non-blocking writers and the stdio relay reader threads.
/// Must be held for the process lifetime to ensure logs are flushed.
pub struct LogGuard {
    _file: WorkerGuard,
    _stderr: WorkerGuard,
    _relays: StdioRelayHandles,
}

/// Handles to the relay reader threads and the lossy non-blocking guards for
/// their tee writers. Held inside `LogGuard`. Drop is a no-op — the relay
/// threads run until process exit.
pub(crate) struct StdioRelayHandles {
    _stderr_thread: Option<JoinHandle<()>>,
    _stderr_tee_guard: Option<WorkerGuard>,
    _stdout_thread: Option<JoinHandle<()>>,
    _stdout_tee_guard: Option<WorkerGuard>,
}

/// Default log directory: `<state_dir>/hole/logs`.
///
/// Falls back to `<data_local_dir>/hole/logs` when `state_dir` is not available
/// (macOS and Windows don't define a distinct state dir).
pub fn default_log_dir() -> PathBuf {
    crate::paths::default_user_subdir("logs")
}

// Stdio redirect ======================================================================================================

/// Which standard stream we're redirecting.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Stream {
    Stderr,
    Stdout,
}

impl Stream {
    fn thread_name(self) -> &'static str {
        match self {
            Stream::Stderr => "hole-stderr-relay",
            Stream::Stdout => "hole-stdout-relay",
        }
    }
}

/// Save the original handle for a stream into a `Box<dyn Write + Send>`. On
/// Windows in service mode `STD_*_HANDLE` is null/invalid; on those returns
/// `io::sink()` so the caller can safely write into it. The two return values
/// are independent writers (used as the relay tee target and the stderr layer
/// writer respectively) — for real handles they are `try_clone`'d, for sinks
/// they are two independent sinks.
fn save_original_pair(stream: Stream) -> (Box<dyn Write + Send>, Box<dyn Write + Send>) {
    let dup = match stream {
        Stream::Stderr => os_pipe::dup_stderr(),
        Stream::Stdout => os_pipe::dup_stdout(),
    };
    let Ok(writer) = dup else {
        tracing::debug!(target: "hole::logging", "saved-original {stream:?} dup failed, using sink fallback");
        return (Box::new(io::sink()), Box::new(io::sink()));
    };
    // Windows: `try_clone_to_owned` on a null STD_*_HANDLE (typical for a
    // service with no console) returns `Ok(OwnedHandle::from_raw_handle(null))`.
    // Writing to such a handle silently fails. Detect and substitute sinks.
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let raw = writer.as_raw_handle();
        if raw.is_null() || raw as isize == -1 {
            tracing::debug!(target: "hole::logging", "saved-original {stream:?} handle is null/invalid, using sink fallback");
            return (Box::new(io::sink()), Box::new(io::sink()));
        }
    }
    let Ok(clone) = writer.try_clone() else {
        tracing::debug!(target: "hole::logging", "saved-original {stream:?} try_clone failed, using sink fallback for layer writer");
        return (Box::new(writer), Box::new(io::sink()));
    };
    (Box::new(writer), Box::new(clone))
}

/// Redirect a single stdio stream to a pipe and spawn a reader thread that
/// tees each line to (a) a tracing event and (b) the saved-original handle.
/// Returns the reader-thread handle, the lossy worker guard for the tee, and
/// the second saved-original copy intended for the tracing stderr layer
/// (caller can drop it for stdout where there's no layer).
fn redirect_one(stream: Stream) -> io::Result<(JoinHandle<()>, WorkerGuard, Box<dyn Write + Send>)> {
    // Save the original BEFORE the redirect — once dup2/SetStdHandle runs,
    // io::stdout/stderr point at the pipe.
    let (tee_target, layer_writer) = save_original_pair(stream);

    // Wrap the tee writer in a lossy non-blocking writer so a slow downstream
    // consumer of the saved-original cannot back up the relay reader thread.
    let (tee_nb, tee_guard) = NonBlockingBuilder::default().lossy(true).finish(tee_target);

    let (read_end, write_end) = os_pipe::pipe()?;

    redirect_fd(stream, &write_end)?;
    // After redirect_fd, FD/HANDLE points to the pipe write end. Drop the
    // PipeWriter wrapper carefully: on Unix `dup2` already cloned the FD
    // (the original `write_end` FD can be closed), but on Windows
    // `SetStdHandle` adopts the handle by reference and we must NOT close it
    // here. `redirect_fd` handles the platform-specific lifetime via
    // `mem::forget` where needed.
    drop(write_end);

    let thread = std::thread::Builder::new()
        .name(stream.thread_name().into())
        .spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                relay_loop(read_end, tee_nb, stream);
            }));
        })?;

    Ok((thread, tee_guard, layer_writer))
}

#[cfg(unix)]
fn redirect_fd(stream: Stream, write_end: &os_pipe::PipeWriter) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let target_fd = match stream {
        Stream::Stderr => libc::STDERR_FILENO,
        Stream::Stdout => libc::STDOUT_FILENO,
    };
    let r = unsafe { libc::dup2(write_end.as_raw_fd(), target_fd) };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn redirect_fd(stream: Stream, write_end: &os_pipe::PipeWriter) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
    use windows::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
    use windows::Win32::System::Threading::GetCurrentProcess;

    let std_handle = match stream {
        Stream::Stderr => STD_ERROR_HANDLE,
        Stream::Stdout => STD_OUTPUT_HANDLE,
    };
    let h = HANDLE(write_end.as_raw_handle() as _);

    // Duplicate the write end so SetStdHandle has an independent handle that
    // outlives the PipeWriter wrapper's Drop. Without this, after we drop
    // `write_end`, the kernel handle that STD_*_HANDLE references would be
    // closed, and any subprocess inheriting it would see EBADF.
    let mut dup = HANDLE::default();
    let proc = unsafe { GetCurrentProcess() };
    unsafe {
        DuplicateHandle(proc, h, proc, &mut dup, 0, true, DUPLICATE_SAME_ACCESS)?;
    }

    unsafe { SetStdHandle(std_handle, dup)? };
    // The kernel + child-process layer now reference `dup`. We never close it
    // explicitly; it's reclaimed at process exit.
    Ok(())
}

/// Reader loop: read raw bytes line-by-line from the pipe, tee them to the
/// saved-original handle, and emit a tracing event for each non-empty line.
///
/// Tracing's `event!` macro takes a literal target string, so we dispatch on
/// the `Stream` enum to one of the two known emit_* helpers.
fn relay_loop(reader: os_pipe::PipeReader, mut tee: tracing_appender::non_blocking::NonBlocking, stream: Stream) {
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::with_capacity(4096);
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(_) => {
                // Tee raw bytes to the saved-original first so script-visible
                // output ordering is preserved.
                let _ = tee.write_all(&buf);
                let _ = tee.flush();
                // Emit a tracing event with the trimmed text for the file log.
                let line = String::from_utf8_lossy(&buf);
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if !trimmed.is_empty() {
                    match stream {
                        Stream::Stderr => emit_stderr_relay(trimmed),
                        Stream::Stdout => emit_stdout_relay(trimmed),
                    }
                }
            }
            Err(_) => break,
        }
    }
}

fn emit_stderr_relay(msg: &str) {
    if let Some((level, parsed)) = try_parse_plugin_log_line(msg) {
        emit_plugin_line(level, parsed);
    } else {
        tracing::event!(target: "hole::stderr_relay", tracing::Level::INFO, "{}", msg);
    }
}

fn emit_stdout_relay(msg: &str) {
    if let Some((level, parsed)) = try_parse_plugin_log_line(msg) {
        emit_plugin_line(level, parsed);
    } else {
        tracing::event!(target: "hole::stdout_relay", tracing::Level::INFO, "{}", msg);
    }
}

// Plugin log parsing ==================================================================================================

/// Try to parse a Go-standard-log-format line produced by v2ray-plugin or
/// v2ray-core and return the extracted tracing level + message body.
///
/// Go's `log` package produces `YYYY/MM/DD HH:MM:SS <message>` (always
/// zero-padded, fixed-width). v2ray-core's `GeneralMessage.String()` prepends
/// a bracketed severity tag from its protobuf `Severity` enum — one of
/// `[Error]`, `[Warning]`, `[Info]`, `[Debug]`, or `[Unknown]`. Lines from
/// v2ray-plugin's own `log.Println` calls have no tag.
///
/// Returns `None` for lines that don't match the Go timestamp prefix, or
/// whose message body after timestamp/tag stripping is empty.
pub(crate) fn try_parse_plugin_log_line(line: &str) -> Option<(tracing::Level, &str)> {
    // Go's log format: `YYYY/MM/DD HH:MM:SS ` — exactly 20 bytes.
    let b = line.as_bytes();
    if b.len() < 21 {
        return None;
    }
    if !(b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b[4] == b'/'
        && b[5].is_ascii_digit()
        && b[6].is_ascii_digit()
        && b[7] == b'/'
        && b[8].is_ascii_digit()
        && b[9].is_ascii_digit()
        && b[10] == b' '
        && b[11].is_ascii_digit()
        && b[12].is_ascii_digit()
        && b[13] == b':'
        && b[14].is_ascii_digit()
        && b[15].is_ascii_digit()
        && b[16] == b':'
        && b[17].is_ascii_digit()
        && b[18].is_ascii_digit()
        && b[19] == b' ')
    {
        return None;
    }

    let rest = &line[20..];

    // Try stripping a v2ray-core severity tag.
    let (level, msg) = if let Some(msg) = rest.strip_prefix("[Error] ") {
        (tracing::Level::ERROR, msg)
    } else if let Some(msg) = rest.strip_prefix("[Warning] ") {
        (tracing::Level::WARN, msg)
    } else if let Some(msg) = rest.strip_prefix("[Info] ") {
        (tracing::Level::INFO, msg)
    } else if let Some(msg) = rest.strip_prefix("[Debug] ") {
        (tracing::Level::DEBUG, msg)
    } else if let Some(msg) = rest.strip_prefix("[Unknown] ") {
        (tracing::Level::WARN, msg)
    } else {
        (tracing::Level::INFO, rest)
    };

    let msg = msg.trim();
    if msg.is_empty() {
        return None;
    }
    Some((level, msg))
}

/// Emit a parsed plugin log line under `hole::plugin` with the appropriate
/// tracing level. Matching is required because `tracing::event!` needs a
/// const-level for its compile-time metadata.
fn emit_plugin_line(level: tracing::Level, msg: &str) {
    match level {
        l if l == tracing::Level::ERROR => tracing::error!(target: "hole::plugin", "{}", msg),
        l if l == tracing::Level::WARN => tracing::warn!(target: "hole::plugin", "{}", msg),
        l if l == tracing::Level::DEBUG => tracing::debug!(target: "hole::plugin", "{}", msg),
        _ => tracing::info!(target: "hole::plugin", "{}", msg),
    }
}

/// Set up the FD-level redirect for both stderr and stdout. Returns the relay
/// thread handles + the saved-original-stderr writer for the tracing stderr
/// layer. The saved-original-stdout writer is dropped (no stdout tracing
/// layer) — the relay's tee already preserves CLI script visibility.
fn redirect_stdio_to_tracing() -> io::Result<(StdioRelayHandles, Box<dyn Write + Send>)> {
    let (stderr_thread, stderr_tee_guard, stderr_layer_writer) = redirect_one(Stream::Stderr)?;
    let (stdout_thread, stdout_tee_guard, _stdout_layer_writer) = redirect_one(Stream::Stdout)?;
    let relays = StdioRelayHandles {
        _stderr_thread: Some(stderr_thread),
        _stderr_tee_guard: Some(stderr_tee_guard),
        _stdout_thread: Some(stdout_thread),
        _stdout_tee_guard: Some(stdout_tee_guard),
    };
    Ok((relays, stderr_layer_writer))
}

/// Test-only re-export of `redirect_stdio_to_tracing` so child-side test
/// scenarios can drive the redirect without going through `init()`.
#[cfg(test)]
pub(crate) fn redirect_stdio_to_tracing_for_tests() -> io::Result<(StdioRelayHandles, Box<dyn Write + Send>)> {
    redirect_stdio_to_tracing()
}

/// Test-only variant that lets the caller supply explicit tee target writers
/// for stderr and stdout, instead of using `os_pipe::dup_stderr/stdout`. Used
/// by the `redirect_tee` scenario to verify the tee path receives bytes.
#[cfg(test)]
pub(crate) fn redirect_stdio_to_tracing_with_writers_for_tests(
    stderr_tee: Box<dyn Write + Send>,
    stdout_tee: Box<dyn Write + Send>,
) -> io::Result<StdioRelayHandles> {
    let (stderr_thread, stderr_tee_guard) = redirect_one_with_writer(Stream::Stderr, stderr_tee)?;
    let (stdout_thread, stdout_tee_guard) = redirect_one_with_writer(Stream::Stdout, stdout_tee)?;
    Ok(StdioRelayHandles {
        _stderr_thread: Some(stderr_thread),
        _stderr_tee_guard: Some(stderr_tee_guard),
        _stdout_thread: Some(stdout_thread),
        _stdout_tee_guard: Some(stdout_tee_guard),
    })
}

#[cfg(test)]
fn redirect_one_with_writer(
    stream: Stream,
    tee_target: Box<dyn Write + Send>,
) -> io::Result<(JoinHandle<()>, WorkerGuard)> {
    let (tee_nb, tee_guard) = NonBlockingBuilder::default().lossy(true).finish(tee_target);

    let (read_end, write_end) = os_pipe::pipe()?;
    redirect_fd(stream, &write_end)?;
    drop(write_end);

    let thread = std::thread::Builder::new()
        .name(stream.thread_name().into())
        .spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                relay_loop(read_end, tee_nb, stream);
            }));
        })?;
    Ok((thread, tee_guard))
}

// Test-only escape hatch ==============================================================================================

/// Only in `debug_assertions` builds, honor `HOLE_LOGGING_DISABLE_REDIRECT`.
/// Release builds always perform the FD redirect — the env var is a no-op.
#[cfg(debug_assertions)]
fn disable_redirect_for_tests() -> bool {
    std::env::var_os("HOLE_LOGGING_DISABLE_REDIRECT").is_some()
}

#[cfg(not(debug_assertions))]
fn disable_redirect_for_tests() -> bool {
    false
}

// Panic hook ==========================================================================================================

/// Has `install_panic_hook` already run in this process? Panic hook
/// installation is one-shot: the hook captures `prev = take_hook()` at
/// install time. If `init()` is called twice (as can happen in tests that
/// share a process), the second install would chain our OWN hook, creating
/// an N-level chain whose depth grows with every `init()` call and that
/// leaks across tests. Use this flag to skip subsequent installs.
static PANIC_HOOK_INSTALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// Per-thread re-entry guard for the panic hook. If `tracing::error!` inside
// the hook itself panics (e.g. a writer panics or a format impl misbehaves),
// the global panic dispatcher calls our hook again. Without this guard we'd
// recurse until the thread's stack overflows. When re-entry is detected we
// fall through to the previous hook only, skipping the tracing emit.
std::thread_local! {
    static PANIC_HOOK_ENTERED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only variant that ignores the idempotency guard. Tests that
/// exercise the panic hook want to install it fresh each run so their
/// save/restore pattern works — the production idempotency rule that "only
/// the first init() in a process installs the hook" would cause the second
/// test to see the first test's hook instead of its own chain.
#[cfg(test)]
pub(crate) fn install_panic_hook_for_tests() {
    install_panic_hook_inner();
}

fn install_panic_hook() {
    // Idempotent: only install once per process. See PANIC_HOOK_INSTALLED.
    if PANIC_HOOK_INSTALLED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    install_panic_hook_inner();
}

fn install_panic_hook_inner() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Re-entry guard. If the tracing emit itself panics, skip the emit
        // and fall through to the previous hook directly.
        let reentered = PANIC_HOOK_ENTERED.with(|c| c.replace(true));
        if reentered {
            prev(info);
            return;
        }
        let backtrace = std::backtrace::Backtrace::force_capture();
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".into());
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");
        tracing::error!(
            target: "hole::panic",
            location = %location,
            backtrace = %backtrace,
            "panic: {}",
            payload,
        );
        PANIC_HOOK_ENTERED.with(|c| c.set(false));
        prev(info);
    }));
}

// init ================================================================================================================

/// Size threshold at which the active log file is rotated.
const MAX_LOG_BYTES: usize = 10 * 1024 * 1024;
/// Number of rotated log files to keep alongside the active one.
/// With a value of 1, the on-disk layout is `<name>` (current) + `<name>.1` (previous).
const MAX_ROTATED_LOGS: usize = 1;

/// Initialize logging.
///
/// Creates `log_dir` if it doesn't exist. Returns a guard that must be held
/// for the process lifetime to ensure logs are flushed and the relay reader
/// threads stay alive.
pub fn init(log_dir: &Path, log_filename: &str, default_directive: &str) -> LogGuard {
    let _ = std::fs::create_dir_all(log_dir);
    cleanup_legacy_daily_logs(log_dir, log_filename);

    // Order matters: redirect BEFORE constructing the non-blocking stderr
    // writer so the writer targets the saved-original handle, not the pipe.
    //
    // `HOLE_LOGGING_DISABLE_REDIRECT` is honored only in dev/test builds
    // (`debug_assertions`). Tests that call `init()` but don't want a global
    // FD redirect set it because libtest-mimic prints per-test result lines
    // to FD 1, and the redirect would eat them. In release builds the env
    // var is ignored — the FD safety net is non-negotiable in production.
    let (relays, original_stderr) = if disable_redirect_for_tests() {
        (
            StdioRelayHandles {
                _stderr_thread: None,
                _stderr_tee_guard: None,
                _stdout_thread: None,
                _stdout_tee_guard: None,
            },
            Box::new(io::stderr()) as Box<dyn Write + Send>,
        )
    } else {
        redirect_stdio_to_tracing().expect("stdio redirect failed")
    };

    let file_appender = file_rotate::FileRotate::new(
        log_dir.join(log_filename),
        file_rotate::suffix::AppendCount::new(MAX_ROTATED_LOGS),
        file_rotate::ContentLimit::Bytes(MAX_LOG_BYTES),
        file_rotate::compression::Compression::None,
        None,
    );
    // Lossy mode on every non-blocking writer: when the channel is full
    // (backpressure from a slow disk), drop events instead of blocking the
    // producer. Discarding logs is strictly better than wedging the bridge or
    // the panic hook.
    let (file_nb, file_guard) = NonBlockingBuilder::default().lossy(true).finish(file_appender);
    let (stderr_nb, stderr_guard) = NonBlockingBuilder::default().lossy(true).finish(original_stderr);

    // The EnvFilter default for non-matching targets is ERROR, so we must
    // add explicit directives for the relay and panic targets — otherwise
    // their INFO-level events would be filtered out and the entire FD-level
    // safety net would be a no-op in production.
    let env_filter = EnvFilter::from_default_env()
        .add_directive(default_directive.parse().expect("valid tracing directive"))
        .add_directive("hole::stderr_relay=info".parse().expect("valid directive"))
        .add_directive("hole::stdout_relay=info".parse().expect("valid directive"))
        .add_directive("hole::plugin=info".parse().expect("valid directive"))
        .add_directive("hole::panic=error".parse().expect("valid directive"))
        .add_directive("hole::logging=debug".parse().expect("valid directive"));

    // Exclude relay-originated events from the stderr layer to prevent
    // double output: the relay tee already writes raw bytes to the
    // saved-original handle (terminal / dev.py pipe). Letting the same
    // events through the stderr layer would duplicate them. The file
    // layer has no such filter — capturing relay events is its purpose.
    let no_relay = tracing_subscriber::filter::filter_fn(|m| {
        !m.target().starts_with("hole::stderr_relay")
            && !m.target().starts_with("hole::stdout_relay")
            && !m.target().starts_with("hole::plugin")
    });

    let file_layer = tracing_subscriber::fmt::layer().with_writer(file_nb).with_ansi(false);

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(stderr_nb)
        .with_ansi(true)
        .with_filter(no_relay);

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer;
    if let Err(e) = tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .with(stderr_layer)
        .try_init()
    {
        // Subscriber not yet active; write directly to FD 2. Goes through the
        // redirect → relay → file layer once installed elsewhere.
        let _ = writeln!(io::stderr(), "hole: tracing subscriber init failed: {e}");
    }

    install_panic_hook();

    LogGuard {
        _file: file_guard,
        _stderr: stderr_guard,
        _relays: relays,
    }
}

// Legacy cleanup ======================================================================================================

/// Remove legacy `<log_filename>.YYYY-MM-DD` files left behind by the prior
/// `tracing_appender::rolling::daily` scheme.
///
/// Silent best-effort: never panics, never returns an error, ignores anything
/// it can't delete (missing dir, permission denied, file vanished between
/// `read_dir` and `remove_file`, entry is a directory, etc.). Idempotent —
/// safe to call on every `init()`.
///
/// Runs before the tracing subscriber is installed, so it MUST NOT use any
/// `tracing::*` macros.
///
/// Non-recursive: scans only `log_dir` itself. The old daily scheme wrote
/// dated files flat next to `<log_filename>`, so recursion is unnecessary.
///
/// Scope: one call cleans dated files for a single stem. Callers with
/// multiple streams in the same directory must call this once per stem.
/// In practice each `init()` caller owns exactly one stem.
///
/// Non-UTF-8 filenames are skipped (the old scheme produced pure-ASCII names).
fn cleanup_legacy_daily_logs(log_dir: &Path, log_filename: &str) {
    let Ok(entries) = std::fs::read_dir(log_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if is_legacy_daily_suffix(name_str, log_filename) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// True if `candidate` is exactly `<stem>.YYYY-MM-DD` (ten trailing chars:
/// four digits, dash, two digits, dash, two digits). Deliberately avoids a
/// regex dependency; the shape is fixed so a manual check is clearer.
///
/// Accepted tradeoff: does not validate the calendar (e.g. `9999-99-99`
/// passes). A legitimate file with that exact shape and a matching stem
/// does not exist in practice.
fn is_legacy_daily_suffix(candidate: &str, stem: &str) -> bool {
    let Some(rest) = candidate.strip_prefix(stem) else {
        return false;
    };
    let Some(suffix) = rest.strip_prefix('.') else {
        return false;
    };
    if suffix.len() != 10 {
        return false;
    }
    let b = suffix.as_bytes();
    b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b[4] == b'-'
        && b[5].is_ascii_digit()
        && b[6].is_ascii_digit()
        && b[7] == b'-'
        && b[8].is_ascii_digit()
        && b[9].is_ascii_digit()
}

#[cfg(test)]
#[path = "logging_tests.rs"]
pub(crate) mod logging_tests;

#[cfg(test)]
#[path = "logging_test_helpers.rs"]
pub(crate) mod logging_test_helpers;
