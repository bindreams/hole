// Shared logging initialization.
//
// Three pieces of machinery, all installed by `init()`:
//
// 1. **FD-level stdio safety net.** At startup, FD 1 (stdout) and FD 2 (stderr)
//    are redirected to OS pipes. A reader thread per pipe tees each captured
//    line to (a) a `tracing` event with target `hole::stdout_relay` /
//    `hole::stderr_relay` (which the file layer captures) and (b) the
//    *saved-original* handle (which preserves dev-terminal / CLI-script
//    visibility). Catches any third-party output that bypasses tracing —
//    Go runtime stderr from v2ray-plugin, native libraries, the default panic
//    printer, etc.
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
    fn relay_target(self) -> &'static str {
        match self {
            Stream::Stderr => "hole::stderr_relay",
            Stream::Stdout => "hole::stdout_relay",
        }
    }

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
        return (Box::new(io::sink()), Box::new(io::sink()));
    };
    let Ok(clone) = writer.try_clone() else {
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

    let target = stream.relay_target();
    let thread = std::thread::Builder::new()
        .name(stream.thread_name().into())
        .spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                relay_loop(read_end, tee_nb, target);
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
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};

    let std_handle = match stream {
        Stream::Stderr => STD_ERROR_HANDLE,
        Stream::Stdout => STD_OUTPUT_HANDLE,
    };
    let h = HANDLE(write_end.as_raw_handle() as _);

    // Duplicate the write end so SetStdHandle has an independent handle that
    // outlives the PipeWriter wrapper's Drop. Without this, after we drop
    // `write_end`, the kernel handle that STD_*_HANDLE references would be
    // closed, and any subprocess inheriting it would see EBADF.
    use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE as WHANDLE};
    use windows::Win32::System::Threading::GetCurrentProcess;
    let mut dup: WHANDLE = WHANDLE::default();
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
/// the runtime target value to one of the two known emit_* helpers.
fn relay_loop(reader: os_pipe::PipeReader, mut tee: tracing_appender::non_blocking::NonBlocking, target: &'static str) {
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::with_capacity(4096);
    let emit: fn(&str) = if target == "hole::stderr_relay" {
        emit_stderr_relay
    } else {
        emit_stdout_relay
    };
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
                    emit(trimmed);
                }
            }
            Err(_) => break,
        }
    }
}

fn emit_stderr_relay(msg: &str) {
    tracing::event!(target: "hole::stderr_relay", tracing::Level::INFO, "{}", msg);
}

fn emit_stdout_relay(msg: &str) {
    tracing::event!(target: "hole::stdout_relay", tracing::Level::INFO, "{}", msg);
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

    let target = stream.relay_target();
    let thread = std::thread::Builder::new()
        .name(stream.thread_name().into())
        .spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                relay_loop(read_end, tee_nb, target);
            }));
        })?;
    Ok((thread, tee_guard))
}

// Panic hook ==========================================================================================================

#[cfg(test)]
pub(crate) fn install_panic_hook_for_tests() {
    install_panic_hook();
}

fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
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
        prev(info);
    }));
}

// init ================================================================================================================

/// Initialize logging.
///
/// Creates `log_dir` if it doesn't exist. Returns a guard that must be held
/// for the process lifetime to ensure logs are flushed and the relay reader
/// threads stay alive.
pub fn init(log_dir: &Path, log_filename: &str, default_directive: &str) -> LogGuard {
    let _ = std::fs::create_dir_all(log_dir);

    // Order matters: redirect BEFORE constructing the non-blocking stderr
    // writer so the writer targets the saved-original handle, not the pipe.
    //
    // The `HOLE_LOGGING_DISABLE_REDIRECT` env var is honored for tests that
    // call init() but should not get a global FD redirect — libtest-mimic
    // prints its per-test result lines to FD 1, and those lines would be
    // eaten by the redirect. Tests that specifically exercise the redirect
    // call `redirect_stdio_to_tracing_for_tests` from a child process where
    // the result-line concern doesn't apply.
    let (relays, original_stderr) = if std::env::var_os("HOLE_LOGGING_DISABLE_REDIRECT").is_some() {
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

    let file_appender = tracing_appender::rolling::daily(log_dir, log_filename);
    // Lossy mode on every non-blocking writer: when the channel is full
    // (backpressure from a slow disk), drop events instead of blocking the
    // producer. Discarding logs is strictly better than wedging the bridge or
    // the panic hook.
    let (file_nb, file_guard) = NonBlockingBuilder::default().lossy(true).finish(file_appender);
    let (stderr_nb, stderr_guard) = NonBlockingBuilder::default().lossy(true).finish(original_stderr);

    let env_filter =
        EnvFilter::from_default_env().add_directive(default_directive.parse().expect("valid tracing directive"));

    // Filter that excludes the relay's own events from the stderr layer to
    // prevent any feedback loop in either direction. The file layer has no
    // such filter — the whole point is to capture relay events to the file.
    let no_relay = tracing_subscriber::filter::filter_fn(|m| {
        !m.target().starts_with("hole::stderr_relay") && !m.target().starts_with("hole::stdout_relay")
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

#[cfg(test)]
#[path = "logging_tests.rs"]
pub(crate) mod logging_tests;

#[cfg(test)]
#[path = "logging_test_helpers.rs"]
pub(crate) mod logging_test_helpers;
