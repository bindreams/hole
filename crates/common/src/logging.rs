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
//    Go runtime stderr from the ex-ray plugin, native libraries, the default panic
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
// Non-blocking writers split into two categories:
// - **Stderr + stdio-relay tees** keep `.lossy(true)` — a wedged terminal
//   (Ctrl+S, pipe consumer hung) MUST NOT block the bridge or the panic
//   hook.
// - **File appender** is `.lossy(false)` — the teardown burst MUST land
//   on disk for diagnostics. A wedged disk blocks every thread that logs,
//   with no limit, once the writer's default `buffered_lines_limit` is full;
//   the buffer only delays that.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_subscriber::EnvFilter;
use util::dir::Dir;

// Draining the relays =================================================================================================
//
// A line written to stdout or stderr reaches the caller through a relay thread and a non-blocking tee, and
// `process::exit` ends both without waiting. `LogGuard::drop` therefore drains: it writes a marker line into each
// redirected stream's pipe, through a write end the relay keeps, and waits until the relay thread has read it. The
// thread has then handed every earlier line to its tee and to the tracing layers; dropping the tee guard writes the
// tee's queue out.

/// The text that starts a drain marker line; the line is this and a request number.
const DRAIN_MARKER: &str = "__hole_relay_flush__";

/// What one relay thread shares with whoever waits for it to catch up.
#[derive(Default)]
struct Drain {
    state: std::sync::Mutex<DrainState>,
}

#[derive(Default)]
struct DrainState {
    /// The relay thread has returned: nobody will be answered any more.
    ended: bool,
    next_id: u64,
    /// The requests the thread has not yet answered, by marker number.
    waiting: Vec<(u64, std::sync::mpsc::SyncSender<()>)>,
}

impl Drain {
    fn lock(&self) -> std::sync::MutexGuard<'_, DrainState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register a request. `None` when the relay thread has ended: there is nothing left to wait for. Otherwise
    /// the marker number and a receiver that returns once the thread answers or ends.
    fn request(&self) -> Option<(u64, std::sync::mpsc::Receiver<()>)> {
        let mut state = self.lock();
        if state.ended {
            return None;
        }
        let id = state.next_id;
        state.next_id += 1;
        let (answer, answered) = std::sync::mpsc::sync_channel(1);
        state.waiting.push((id, answer));
        Some((id, answered))
    }

    fn cancel(&self, id: u64) {
        self.lock().waiting.retain(|(waiting, _)| *waiting != id);
    }

    /// Take request `id` out of the waiting list, if it is there.
    fn take(&self, id: u64) -> Option<std::sync::mpsc::SyncSender<()>> {
        let mut state = self.lock();
        let at = state.waiting.iter().position(|(waiting, _)| *waiting == id)?;
        Some(state.waiting.swap_remove(at).1)
    }

    /// The relay thread is over. Every waiting request's sender is dropped, which releases its receiver.
    fn end(&self) {
        let mut state = self.lock();
        state.ended = true;
        state.waiting.clear();
    }
}

/// One redirected stream: its relay thread, the guard of the lossy tee behind it, and the drain they share.
struct Relay {
    _thread: JoinHandle<()>,
    tee_guard: Option<WorkerGuard>,
    drain: std::sync::Arc<Drain>,
    stream: Stream,
    /// A second write end of the stream's pipe, for the markers: they reach the relay whatever the process later does
    /// to its standard handle.
    marker_writer: os_pipe::PipeWriter,
}

impl Relay {
    fn spawn(
        stream: Stream,
        read_end: os_pipe::PipeReader,
        marker_writer: os_pipe::PipeWriter,
        tee: tracing_appender::non_blocking::NonBlocking,
        tee_guard: WorkerGuard,
    ) -> io::Result<Relay> {
        let drain = std::sync::Arc::new(Drain::default());
        let thread = std::thread::Builder::new().name(stream.thread_name().into()).spawn({
            let drain = std::sync::Arc::clone(&drain);
            move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    relay_loop(read_end, tee, stream, &drain);
                }));
                drain.end();
            }
        })?;
        Ok(Relay {
            _thread: thread,
            tee_guard: Some(tee_guard),
            drain,
            stream,
            marker_writer,
        })
    }

    /// Return once the relay thread has consumed everything this process wrote to the stream before the call, then
    /// write out the tee's queue. Later writes to the tee are lost: the tee's worker is gone.
    fn flush(&mut self) -> io::Result<()> {
        let drained = self.drain();
        // The tee's queue is written out whatever became of the marker.
        drop(self.tee_guard.take());
        drained
    }

    fn drain(&mut self) -> io::Result<()> {
        let Some((id, answered)) = self.drain.request() else {
            return Ok(());
        };
        let marker = format!("{DRAIN_MARKER}{id}\n");
        // Under the stream's own lock, so the marker cannot land between the pieces of one `eprintln!`.
        let written = match self.stream {
            Stream::Stderr => {
                let _held = io::stderr().lock();
                self.marker_writer.write_all(marker.as_bytes())
            }
            Stream::Stdout => {
                let _held = io::stdout().lock();
                self.marker_writer.write_all(marker.as_bytes())
            }
        };
        if let Err(e) = written {
            self.drain.cancel(id);
            // No reader is left on the pipe: the relay thread has ended and holds nothing.
            return if e.kind() == io::ErrorKind::BrokenPipe {
                Ok(())
            } else {
                Err(e)
            };
        }
        // An answer, or the end of the relay thread (which drops the sender): either way the thread holds nothing that
        // was written before the marker.
        let _ = answered.recv();
        Ok(())
    }
}

// LogGuard ============================================================================================================

/// Guards for the non-blocking writers and the stdio relay reader threads.
///
/// Held for the process lifetime. Dropping it drains the relays and the writers, so the output and the log lines of
/// a command that ends by dropping it are all delivered; `process::exit` skips the drop, so a command that exits
/// that way drops the guard first.
pub struct LogGuard {
    _file: WorkerGuard,
    _stderr: WorkerGuard,
    _relays: StdioRelayHandles,
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        // The stream is closed or full of an error the caller already has: there is nothing more to deliver.
        let _ = self._relays.flush();
    }
}

/// The relays of the redirected streams, and the guards of their lossy non-blocking tees. A stream that is not
/// redirected (the debug switch) has none. Held inside `LogGuard`.
pub(crate) struct StdioRelayHandles {
    stderr: Option<Relay>,
    stdout: Option<Relay>,
}

impl StdioRelayHandles {
    /// Return once every byte written to stdout and stderr before the call has been consumed by its relay thread,
    /// emitted as a tracing event and written through the tee to the stream's original handle.
    ///
    /// Synchronous (a channel, not a runtime) so it works outside a tokio runtime. No sleep: it waits for the relay
    /// threads' own answers.
    pub fn flush(&mut self) -> io::Result<()> {
        // Rust's stdout holds a line that has no newline yet; it must reach the pipe ahead of the markers.
        let buffered = io::stdout().flush();
        let stderr = self.stderr.as_mut().map_or(Ok(()), |relay| relay.flush());
        let stdout = self.stdout.as_mut().map_or(Ok(()), |relay| relay.flush());
        buffered.and(stderr).and(stdout)
    }
}

/// Default log directory: `<state_dir>/hole/logs`.
///
/// Falls back to `<data_local_dir>/hole/logs` when `state_dir` is not available
/// (macOS and Windows don't define a distinct state dir).
pub fn default_log_dir() -> PathBuf {
    crate::paths::default_user_subdir("logs")
}

/// Read `HOLE_LOG_DIR` as an override directory; a blank value is treated as
/// unset. The one impure seam behind the log-dir resolvers.
pub fn hole_log_dir_env() -> Option<PathBuf> {
    nonblank_dir(std::env::var_os("HOLE_LOG_DIR"))
}

/// Drop a blank value so an empty `HOLE_LOG_DIR=` falls through to the next
/// resolution tier instead of resolving to a bare relative path.
fn nonblank_dir(raw: Option<std::ffi::OsString>) -> Option<PathBuf> {
    raw.filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Resolve the log directory: explicit `override_dir`, else `HOLE_LOG_DIR`,
/// else [`default_log_dir`].
pub fn resolve_log_dir(override_dir: Option<PathBuf>) -> PathBuf {
    resolve_log_dir_from(override_dir, hole_log_dir_env(), default_log_dir)
}

/// Pure resolution core: `override_dir`, else `env_dir`, else `fallback()`.
/// `fallback` is a closure so callers can supply something other than
/// [`default_log_dir`].
pub fn resolve_log_dir_from(
    override_dir: Option<PathBuf>,
    env_dir: Option<PathBuf>,
    fallback: impl FnOnce() -> PathBuf,
) -> PathBuf {
    override_dir.or(env_dir).unwrap_or_else(fallback)
}

// Per-sink directive resolution =======================================================================================

/// Split a comma-separated directive value: trim each piece, drop blanks.
pub fn split_directives(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Resolve `(file_directives, stderr_directives)` from the environment for the
/// native per-sink logging policy. `default` is the component's built-in file
/// directive (`hole=info` / `hole_bridge=info`); `component_file_env` is an
/// optional component-specific override var name (e.g. `HOLE_BRIDGE_LOG`).
///
/// File sink: component env, else `HOLE_LOG`, else `default`. Stderr sink:
/// `HOLE_LOG_STDERR` if set, else mirror the file sink — so with nothing set
/// both sinks match exactly (production parity).
pub fn resolve_sink_directives(default: &str, component_file_env: Option<&str>) -> (Vec<String>, Vec<String>) {
    let component_file = component_file_env.and_then(|name| std::env::var(name).ok());
    let hole_log = std::env::var("HOLE_LOG").ok();
    let hole_log_stderr = std::env::var("HOLE_LOG_STDERR").ok();
    resolve_sink_directives_from(
        default,
        component_file.as_deref(),
        hole_log.as_deref(),
        hole_log_stderr.as_deref(),
    )
}

/// Pure core of [`resolve_sink_directives`] — no env reads, table-testable.
fn resolve_sink_directives_from(
    default: &str,
    component_file: Option<&str>,
    hole_log: Option<&str>,
    hole_log_stderr: Option<&str>,
) -> (Vec<String>, Vec<String>) {
    let nonblank = |s: &str| (!s.trim().is_empty()).then(|| s.to_string());
    let file_raw = component_file
        .and_then(nonblank)
        .or_else(|| hole_log.and_then(nonblank))
        .unwrap_or_else(|| default.to_string());
    let mut file = split_directives(&file_raw);
    if file.is_empty() {
        file = split_directives(default);
    }
    let stderr = match hole_log_stderr.and_then(nonblank) {
        Some(raw) => {
            let s = split_directives(&raw);
            if s.is_empty() {
                file.clone()
            } else {
                s
            }
        }
        None => file.clone(),
    };
    (file, stderr)
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
/// Returns the relay and the second saved-original copy intended for the
/// tracing stderr layer (caller can drop it for stdout where there's no layer).
fn redirect_one(stream: Stream) -> io::Result<(Relay, Box<dyn Write + Send>)> {
    // Save the original BEFORE the redirect — once dup2/SetStdHandle runs,
    // io::stdout/stderr point at the pipe.
    let (tee_target, layer_writer) = save_original_pair(stream);

    // Wrap the tee writer in a lossy non-blocking writer so a slow downstream
    // consumer of the saved-original cannot back up the relay reader thread.
    let (tee_nb, tee_guard) = NonBlockingBuilder::default()
        .lossy(true)
        .finish(util::redact::RedactingWriter::new(tee_target));

    let (read_end, write_end) = os_pipe::pipe()?;

    redirect_fd(stream, &write_end)?;
    // After redirect_fd, the standard stream points at its own copy of the pipe
    // write end (`dup2` on Unix, a duplicated handle on Windows); the relay
    // keeps `write_end` itself for its drain markers.
    Ok((
        Relay::spawn(stream, read_end, write_end, tee_nb, tee_guard)?,
        layer_writer,
    ))
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

    // Duplicate the write end so the standard handle is its own, inheritable
    // handle (a PipeWriter's is not), which a subprocess inherits as its stdio.
    let mut dup = HANDLE::default();
    let proc = unsafe { GetCurrentProcess() };
    unsafe {
        DuplicateHandle(proc, h, proc, &mut dup, 0, true, DUPLICATE_SAME_ACCESS)?;
    }

    unsafe { SetStdHandle(std_handle, dup)? };
    // `dup` is never closed explicitly; it is reclaimed at process exit.
    Ok(())
}

/// Reader loop: read raw bytes line-by-line from the pipe, tee them to the
/// saved-original handle, and emit a tracing event for each non-empty line.
/// A drain marker (see `Relay::flush`) is answered after the text before it is
/// handled, and is not teed or emitted.
///
/// Tracing's `event!` macro takes a literal target string, so we dispatch on
/// the `Stream` enum to one of the two known emit_* helpers.
fn relay_loop(
    reader: os_pipe::PipeReader,
    mut tee: tracing_appender::non_blocking::NonBlocking,
    stream: Stream,
    drain: &Drain,
) {
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::with_capacity(4096);
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(_) => {
                // A line that was still open when the marker was written carries the marker at its end.
                let (output, answer) = match find_drain_marker(&buf, drain) {
                    Some((at, answer)) => (&buf[..at], Some(answer)),
                    None => (&buf[..], None),
                };
                if !output.is_empty() {
                    // Tee raw bytes to the saved-original first so script-visible
                    // output ordering is preserved.
                    let _ = tee.write_all(output);
                    let _ = tee.flush();
                    // Emit a tracing event with the trimmed text for the file log.
                    let line = String::from_utf8_lossy(output);
                    let trimmed = line.trim_end_matches(['\r', '\n']);
                    if !trimmed.is_empty() {
                        match stream {
                            Stream::Stderr => emit_stderr_relay(trimmed),
                            Stream::Stdout => emit_stdout_relay(trimmed),
                        }
                    }
                }
                if let Some(answer) = answer {
                    let _ = answer.send(());
                }
            }
            Err(_) => break,
        }
    }
}

/// Where in `line` a drain marker that `drain` is waiting for starts, and the sender to answer it with. Text that
/// looks like a marker but is not a waiting request's stays ordinary output.
fn find_drain_marker(line: &[u8], drain: &Drain) -> Option<(usize, std::sync::mpsc::SyncSender<()>)> {
    let marker = DRAIN_MARKER.as_bytes();
    // The marker is written last, so it is the last one on the line; an earlier one is the process's own text.
    let at = line.windows(marker.len()).rposition(|window| window == marker)?;
    let id = std::str::from_utf8(&line[at + marker.len()..])
        .ok()?
        .trim_end_matches(['\r', '\n'])
        .parse::<u64>()
        .ok()?;
    Some((at, drain.take(id)?))
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
    let (stderr, stderr_layer_writer) = redirect_one(Stream::Stderr)?;
    let (stdout, _stdout_layer_writer) = redirect_one(Stream::Stdout)?;
    let relays = StdioRelayHandles {
        stderr: Some(stderr),
        stdout: Some(stdout),
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
    Ok(StdioRelayHandles {
        stderr: Some(redirect_one_with_writer(Stream::Stderr, stderr_tee)?),
        stdout: Some(redirect_one_with_writer(Stream::Stdout, stdout_tee)?),
    })
}

#[cfg(test)]
fn redirect_one_with_writer(stream: Stream, tee_target: Box<dyn Write + Send>) -> io::Result<Relay> {
    let (tee_nb, tee_guard) = NonBlockingBuilder::default()
        .lossy(true)
        .finish(util::redact::RedactingWriter::new(tee_target));

    let (read_end, write_end) = os_pipe::pipe()?;
    redirect_fd(stream, &write_end)?;

    Relay::spawn(stream, read_end, write_end, tee_nb, tee_guard)
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

/// Install the tracing-emitting panic hook (chains before stdlib default).
/// Idempotent — subsequent calls in the same process are no-ops.
///
/// Called from production `init_dual` and from
/// `hole-test-observability`'s ctor; safe to invoke from both because
/// the `PANIC_HOOK_INSTALLED` AtomicBool ensures only one hook is
/// chained per process.
pub fn install_panic_hook() {
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

/// Size threshold at which the active log file is rotated. The on-disk layout is `<name>` (current) +
/// `<name>.1` (previous).
const MAX_LOG_BYTES: usize = 10 * 1024 * 1024;

/// Build one `EnvFilter` from a directive slice: global default `info`,
/// `RUST_LOG` via `from_env_lossy`, the slice on top, then the
/// `hole::logging=debug` pin. Built per sink because `EnvFilter` is not Clone.
fn build_filter(directives: &[String]) -> EnvFilter {
    let mut f = EnvFilter::builder()
        .with_default_directive("info".parse().expect("valid directive"))
        .from_env_lossy();
    for d in directives {
        f = f.add_directive(d.parse().expect("valid tracing directive"));
    }
    f.add_directive("hole::logging=debug".parse().expect("valid directive"))
}

/// Compose the two filtered fmt layers over a registry. Generic over the
/// writers so unit tests can supply capturing buffers and the production
/// caller supplies non-blocking writers. The stderr layer additionally drops
/// the relay-target events; the file layer keeps them.
fn compose_subscriber<FW, SW>(
    file_writer: FW,
    stderr_writer: SW,
    file_directives: &[String],
    stderr_directives: &[String],
) -> impl tracing::Subscriber + Send + Sync
where
    FW: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
    SW: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::Layer as _;

    let no_relay = tracing_subscriber::filter::filter_fn(|m| {
        !m.target().starts_with("hole::stderr_relay") && !m.target().starts_with("hole::stdout_relay")
    });

    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_writer)
        .with_ansi(false)
        .event_format(yaml_format::YamlFormat)
        .with_filter(build_filter(file_directives));

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(stderr_writer)
        .with_ansi(true)
        .event_format(yaml_format::YamlFormat)
        .with_filter(no_relay)
        .with_filter(build_filter(stderr_directives));

    tracing_subscriber::registry().with(file_layer).with(stderr_layer)
}

/// Initialize logging with one caller-supplied filter directive (both sinks).
///
/// A wrapper over [`init_multi`] for a caller with one directive. Creates
/// `log_dir` if it doesn't exist; returns a guard that must be held for the
/// process lifetime to ensure logs are flushed and the relay reader threads
/// stay alive.
pub fn init(
    log_dir: &Path,
    kind: &'static str,
    log_filename: &str,
    default_directive: &str,
    owner: Option<(u32, u32)>,
) -> LogGuard {
    init_multi(log_dir, kind, log_filename, [default_directive], owner)
}

/// Initialize logging with one or more caller-supplied filter directives
/// (both sinks).
///
/// Each directive is parsed and added to the env filter via
/// `EnvFilter::add_directive`, in the order given. Later directives override
/// earlier ones at equal specificity per `tracing-subscriber`'s rules.
///
/// Use this rather than [`init`] when the caller wants to honor a
/// comma-separated env var like
/// `HOLE_BRIDGE_LOG=hole_bridge=debug,shadowsocks_service=trace` —
/// `init` accepts only one directive, and silently dropping the rest hides
/// production diagnostics.
pub fn init_multi<I>(
    log_dir: &Path,
    kind: &'static str,
    log_filename: &str,
    directives: I,
    owner: Option<(u32, u32)>,
) -> LogGuard
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let v: Vec<String> = directives.into_iter().map(|d| d.as_ref().to_string()).collect();
    init_dual(log_dir, kind, log_filename, &v, &v, owner)
}

/// Initialize logging with independent file-sink and stderr-sink directives —
/// the native per-sink path. The file sink can run at TRACE while stderr stays
/// at INFO. Creates `log_dir`; returns a guard that must be held for the
/// process lifetime to ensure logs are flushed and the relay reader threads
/// stay alive.
///
/// The global default of `info` is set per sink (third-party crates emit
/// useful startup/warning diagnostics without per-crate directives); `RUST_LOG`
/// is layered next; the sink's directives are layered on top; finally
/// `hole::logging=debug` is pinned so the logging subsystem itself emits
/// lifecycle events.
///
/// `kind` labels the native-crash marker. `owner` is the `(uid, gid)` the log
/// directory and each rotated file are handed to; `None` (the unprivileged GUI)
/// leaves ownership alone.
pub fn init_dual(
    log_dir: &Path,
    kind: &'static str,
    log_filename: &str,
    file_directives: &[String],
    stderr_directives: &[String],
    owner: Option<(u32, u32)>,
) -> LogGuard {
    // The log directory sits in the user's profile when the bridge runs elevated on their behalf, so it is
    // opened once without following a symlink and every step below is by a name inside that handle. The
    // elevated bridge creates it as root; hand it to the real user so they can read `bridge.log` without
    // `sudo`. `owner` is `None` for the unprivileged GUI.
    let dir = match Dir::open(log_dir, true, owner) {
        Ok(dir) => {
            dir.secure(owner, None)
                .expect("securing a directory with no mode has no step that can fail");
            cleanup_legacy_daily_logs(log_dir, &dir, log_filename);
            Some(dir)
        }
        Err(e) => {
            // No subscriber and no redirect yet: the real stderr. The error carries no path.
            let _ = writeln!(
                io::stderr(),
                "hole: the log file is disabled, its directory was not opened: {e}"
            );
            None
        }
    };

    // Order matters: redirect BEFORE constructing the non-blocking stderr
    // writer so the writer targets the saved-original handle, not the pipe.
    // `HOLE_LOGGING_DISABLE_REDIRECT` is honored only in dev/test builds; in
    // release the FD safety net is non-negotiable (the env var is a no-op).
    let (relays, original_stderr) = if disable_redirect_for_tests() {
        (
            StdioRelayHandles {
                stderr: None,
                stdout: None,
            },
            Box::new(io::stderr()) as Box<dyn Write + Send>,
        )
    } else {
        redirect_stdio_to_tracing().expect("stdio redirect failed")
    };

    // Each rotation hands the fresh root-owned active file back to the real user
    // (`owner`; `None` leaves it alone).
    let owned: Box<dyn Write + Send> = match dir {
        Some(dir) => Box::new(DirRotate::new(dir, log_filename.as_ref(), MAX_LOG_BYTES, owner)),
        None => Box::new(io::sink()),
    };
    // The redaction wrap sits under the appender, so every formatted event
    // passes through it whoever authored it — a Hole site, a dependency at
    // the default global `info`, an OS command's argv, or a relayed plugin
    // line. This is the writer that is a log file; wrapping it is what closes
    // the leak, and it is the only redaction between any crate's `info!` and
    // the file.
    //
    // The FILE appender is `lossy(false)`: the proxy-stop teardown burst
    // (SystemRoutes::drop sequence: route commands, state-file clear,
    // Remove-NetAdapter) must never be silently truncated, or `bridge.log`
    // loses the diagnostic for a teardown that broke the user's network.
    // Trade-off: a wedged disk (full filesystem, OneDrive sync stall, AV scan)
    // blocks every thread that logs, with no limit, once the writer's default
    // `buffered_lines_limit` is full.
    let (file_nb, file_guard) = NonBlockingBuilder::default()
        .lossy(false)
        .finish(util::redact::RedactingWriter::new(owned));
    // The STDERR non-blocking writer keeps `lossy(true)`: a wedged terminal
    // (Ctrl+S on a console session) MUST NOT block the bridge.
    let (stderr_nb, stderr_guard) = NonBlockingBuilder::default()
        .lossy(true)
        .finish(util::redact::RedactingWriter::new(original_stderr));

    use tracing_subscriber::util::SubscriberInitExt;
    // Sanctioned by clippy.toml `disallowed_methods`: the ONE
    // production `try_init` workspace-wide. Tests use `register!()`.
    #[allow(clippy::disallowed_methods)]
    if let Err(e) = compose_subscriber(file_nb, stderr_nb, file_directives, stderr_directives).try_init() {
        // Subscriber not yet active; write directly to FD 2. Goes through the
        // redirect → relay → file layer once installed elsewhere.
        let _ = writeln!(io::stderr(), "hole: tracing subscriber init failed: {e}");
    }

    install_panic_hook();

    // Native-crash observability. Installed AFTER the
    // panic hook (disjoint paths: panics unwind into the hook with the heap
    // intact; native faults are caught here). Idempotent + best-effort;
    // never panics. `kind` labels the marker; `log_dir` is user-readable
    // even for the elevated bridge.
    //
    // The crash marker is written by the signal handler at crash time
    // (signal-safe context — no chown). It is transient, lives in the
    // user-owned log dir, and is swept on next start, so it is left
    // root-owned on purpose rather than chowned from an unsafe context.
    tombstone::attach(kind, log_dir);

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
fn cleanup_legacy_daily_logs(log_dir: &Path, dir: &Dir, log_filename: &str) {
    // The listing is by path, but it only supplies names: each removal is by name inside `dir`, so a path
    // swapped for another directory's listing can remove nothing outside `dir`, and only a name of the legacy
    // shape inside it.
    let Ok(entries) = std::fs::read_dir(log_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if is_legacy_daily_suffix(name_str, log_filename) {
            let _ = dir.unlink(&name);
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

pub mod dir_rotate;

/// Arming the redaction registry from a server entry.
pub mod redact_arm;
use dir_rotate::DirRotate;

pub(crate) mod yaml_format;

#[cfg(test)]
pub(crate) mod logging_tests;

#[cfg(test)]
pub(crate) mod logging_test_helpers;
