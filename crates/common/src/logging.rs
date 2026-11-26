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
//    still runs in dev mode. On a writer thread the event waits until the
//    thread's queue has ended.
//
// Every sink is written by a thread of its own, behind a queue (`queued`):
// - **The file** waits when its queue is full: the teardown burst MUST land on disk for diagnostics. A wedged disk
//   holds every thread that logs, with no limit, once the queue is full; the queue only delays that.
// - **The stderr layer and the two stdio tees** do what `ProcessKind::terminal` says for the kind of process: a
//   command waits for its reader; the bridge and the GUI drop and count, so a wedged terminal (Ctrl+S, a pipe
//   consumer that hangs) never holds them.

use queued::{queued, Overflow, QueueError, Queued, QueuedGuard};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use tracing_subscriber::EnvFilter;
use util::dir::Dir;
use uuid::Uuid;

/// The kind of process that initializes logging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessKind {
    /// A one-shot `hole` command.
    Command,
    /// The privileged bridge.
    Bridge,
    /// The unprivileged GUI.
    Gui,
}

impl ProcessKind {
    /// The label of this kind's native-crash marker.
    fn label(self) -> &'static str {
        match self {
            ProcessKind::Command => "gui-cli",
            ProcessKind::Bridge => "bridge",
            ProcessKind::Gui => "gui",
        }
    }

    /// What this kind's terminal sinks (the two tees and the stderr layer) do when their reader falls behind.
    fn terminal(self) -> Overflow {
        match self {
            // The output is the product, and the caller owns the reader.
            ProcessKind::Command => Overflow::Wait,
            // A paused console must not stop the datapath.
            ProcessKind::Bridge => Overflow::Drop,
            // A paused console must not freeze the window.
            ProcessKind::Gui => Overflow::Drop,
        }
    }
}

// Draining the relays =================================================================================================
//
// The protocol is described in docs/contributing/architecture/logging.md.

/// The text that starts a drain marker line; the line is this and the request's nonce.
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
    /// The requests the thread has not yet answered, by nonce.
    waiting: Vec<(Uuid, std::sync::mpsc::SyncSender<()>)>,
}

impl Drain {
    fn lock(&self) -> std::sync::MutexGuard<'_, DrainState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register a request. `None` when the relay thread has ended: there is nothing left to wait for. Otherwise
    /// the marker's nonce, random per request so that no other writer on the stream can guess it, and a receiver
    /// that returns once the thread answers or ends.
    fn request(&self) -> Option<(Uuid, std::sync::mpsc::Receiver<()>)> {
        let mut state = self.lock();
        if state.ended {
            return None;
        }
        let nonce = Uuid::new_v4();
        let (answer, answered) = std::sync::mpsc::sync_channel(1);
        state.waiting.push((nonce, answer));
        Some((nonce, answered))
    }

    fn cancel(&self, nonce: Uuid) {
        self.lock().waiting.retain(|(waiting, _)| *waiting != nonce);
    }

    /// Take the request with `nonce` out of the waiting list, if it is there.
    fn take(&self, nonce: Uuid) -> Option<std::sync::mpsc::SyncSender<()>> {
        let mut state = self.lock();
        let at = state.waiting.iter().position(|(waiting, _)| *waiting == nonce)?;
        Some(state.waiting.swap_remove(at).1)
    }

    /// The relay thread is over. Every waiting request's sender is dropped, which releases its receiver.
    fn end(&self) {
        let mut state = self.lock();
        state.ended = true;
        state.waiting.clear();
    }
}

/// One redirected stream: its relay thread, the guard of the tee behind it, and the drain they share.
struct Relay {
    _thread: JoinHandle<()>,
    tee_guard: Option<QueuedGuard>,
    drain: std::sync::Arc<Drain>,
    stream: Stream,
    /// A second write end of the stream's pipe, for the markers: a marker does not depend on the process's standard
    /// handle. Hole does not replace a standard handle after the redirect.
    marker_writer: os_pipe::PipeWriter,
}

impl Relay {
    fn spawn(
        stream: Stream,
        read_end: os_pipe::PipeReader,
        marker_writer: os_pipe::PipeWriter,
        tee: Queued,
        tee_guard: QueuedGuard,
    ) -> io::Result<Relay> {
        let drain = std::sync::Arc::new(Drain::default());
        let thread = std::thread::Builder::new().name(stream.thread_name().into()).spawn({
            let drain = std::sync::Arc::clone(&drain);
            move || {
                DELIVERY_THREAD.set(Some(DeliveryThread::Relay));
                // A panic in a tracing writer must not skip `end`: a drain would wait for a thread that is gone.
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

    /// Return once the relay thread has consumed everything this process wrote to the stream before the call and the
    /// tee has written it to the stream's original handle, with no time limit. Each failure goes to `failed`. Returns
    /// whether the relay thread took everything. A relay is flushed once: what the stream is given later reaches the
    /// log file only.
    fn flush(&mut self, failed: &mut impl FnMut(io::Error)) -> bool {
        let drained = self.drain().map_err(&mut *failed).is_ok();
        // The tee's queue is written out whatever became of the marker.
        let guard = self.tee_guard.take();
        debug_assert!(guard.is_some(), "a relay is flushed once");
        if let Some(Err(error)) = guard.map(QueuedGuard::finish) {
            if terminal_failure_is_loss(&error) {
                failed(undelivered(self.stream.name(), error));
            }
        }
        drained
    }

    fn drain(&mut self) -> io::Result<()> {
        let Some((nonce, answered)) = self.drain.request() else {
            return Err(self.ended_error());
        };
        let marker = format!("{DRAIN_MARKER}{}\n", nonce.simple());
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
            self.drain.cancel(nonce);
            // The pipe is Hole's own, and its only reader is the relay thread: a broken pipe means that thread is gone,
            // not that the caller closed the stream.
            return Err(if e.kind() == io::ErrorKind::BrokenPipe {
                self.ended_error()
            } else {
                e
            });
        }
        // An answer, or the end of the relay thread (which drops the sender): either way the thread holds nothing that
        // was written before the marker.
        let _ = answered.recv();
        Ok(())
    }

    fn ended_error(&self) -> io::Error {
        let stream = self.stream.name();
        io::Error::other(format!(
            "the {stream} relay thread has ended; later output to {stream} was lost"
        ))
    }
}

// LogGuard ============================================================================================================

/// Guards for the writer threads of the sinks and the stdio relay reader threads.
///
/// Held for the process lifetime. Dropping it returns once everything the process wrote to stdout and stderr, and
/// every event logged before the drop, has been written to the original handles and the log file. There is no time
/// limit: a reader or a disk that takes no bytes holds the exit. What a sink did not deliver is said on the original
/// stderr and, for the terminal sinks, in the file. `process::exit` skips the drop, so a command that exits that way
/// must drop the guard first.
pub struct LogGuard {
    relays: StdioRelayHandles,
    stderr: Option<QueuedGuard>,
    /// The file's queue, for the report of what the terminal sinks did not deliver.
    file: Queued,
    file_guard: Option<QueuedGuard>,
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        let mut failures = Vec::new();
        self.relays.flush(|e| failures.push(e));
        if let Some(Err(error)) = self.stderr.take().map(QueuedGuard::finish) {
            if terminal_failure_is_loss(&error) {
                failures.push(undelivered("the log on stderr", error));
            }
        }
        // The caller has no other way to hear of a loss. This thread writes the report itself: the file's queue is not
        // finished yet, and the original stderr depends on no thread of this process.
        for failure in &failures {
            let line = undelivered_line(failure);
            let _ = self.file.write_all(line.as_bytes());
            let _ = OriginalStderr.write_all(line.as_bytes());
        }
        if let Some(Err(error)) = self.file_guard.take().map(QueuedGuard::finish) {
            let line = undelivered_line(&undelivered("the log file", error));
            let _ = OriginalStderr.write_all(line.as_bytes());
        }
    }
}

/// A sink that did not take everything it was given.
#[derive(Debug, thiserror::Error)]
#[error("{sink} was not fully written")]
struct Undelivered {
    sink: &'static str,
    #[source]
    error: QueueError,
}

/// `error` as the `io::Error` that `StdioRelayHandles::flush` passes on.
fn undelivered(sink: &'static str, error: QueueError) -> io::Error {
    io::Error::other(Undelivered { sink, error })
}

/// The line of the exit report for one failure: the error and its causes.
fn undelivered_line(failure: &io::Error) -> String {
    let causes: Vec<String> = util::error::chain(failure).map(ToString::to_string).collect();
    format!("hole: the output could not be fully delivered: {}\n", causes.join(": "))
}

/// Whether what a terminal sink (a tee or the stderr layer) did not deliver is a loss to report. Its destination is
/// the caller's stream; a caller that closed it has asked for no more, and its refusals are broken pipes.
fn terminal_failure_is_loss(error: &QueueError) -> bool {
    let closed_by_caller = error
        .first
        .as_ref()
        .is_some_and(|first| first.kind() == io::ErrorKind::BrokenPipe);
    error.dropped > 0 || error.panic.is_some() || !closed_by_caller
}

/// The relays of the redirected streams, and the guards of their tees. A stream that is not redirected (the debug
/// switch) has none. Held inside `LogGuard`.
pub(crate) struct StdioRelayHandles {
    stderr: Option<Relay>,
    stdout: Option<Relay>,
}

impl StdioRelayHandles {
    /// Return once every byte written to stdout and stderr before the call has been consumed by its relay thread,
    /// emitted as a tracing event and written by the tee to the stream's original handle. Each failure of a step is
    /// passed to `failed`; a failed step does not skip the next.
    ///
    /// Synchronous (channels and a join, not a runtime) so it works outside a tokio runtime.
    pub fn flush(&mut self, mut failed: impl FnMut(io::Error)) {
        // Rust's stdout holds a line that has no newline yet; it must reach the pipe ahead of the markers.
        let buffered = io::stdout().flush();
        if let Some(relay) = self.stderr.as_mut() {
            relay.flush(&mut failed);
        }
        let stdout_failed = self.stdout.as_mut().is_some_and(|relay| !relay.flush(&mut failed));
        if let Err(e) = buffered {
            if buffer_flush_failure_is_loss(&e, self.stdout.is_some(), stdout_failed) {
                failed(e);
            }
        }
    }
}

/// Whether a failed flush of Rust's stdout buffer is a loss to report. Redirected, the buffer flushes into Hole's own
/// pipe and a broken pipe means the relay thread is gone, which the relay's own failed drain reports (`relay_failed`);
/// any other failure is a loss of its own. Not redirected (the debug switch), the stream is the caller's, and a closed
/// one is not a loss.
fn buffer_flush_failure_is_loss(error: &io::Error, redirected: bool, relay_failed: bool) -> bool {
    if redirected {
        !(relay_failed && error.kind() == io::ErrorKind::BrokenPipe)
    } else {
        error.kind() != io::ErrorKind::BrokenPipe
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
    fn name(self) -> &'static str {
        match self {
            Stream::Stderr => "stderr",
            Stream::Stdout => "stdout",
        }
    }

    fn thread_name(self) -> &'static str {
        match self {
            Stream::Stderr => "hole-stderr-relay",
            Stream::Stdout => "hole-stdout-relay",
        }
    }
}

/// A copy of the process's handle for `stream`, taken before the redirect. `None` when the process has no usable one:
/// on Windows in service mode `STD_*_HANDLE` is null or invalid.
fn dup_original(stream: Stream) -> Option<os_pipe::PipeWriter> {
    let dup = match stream {
        Stream::Stderr => os_pipe::dup_stderr(),
        Stream::Stdout => os_pipe::dup_stdout(),
    };
    let Ok(writer) = dup else {
        tracing::debug!(target: "hole::logging", "saved-original {stream:?} dup failed, using sink fallback");
        return None;
    };
    // Windows: `try_clone_to_owned` on a null STD_*_HANDLE (typical for a
    // service with no console) returns `Ok(OwnedHandle::from_raw_handle(null))`.
    // Writing to such a handle silently fails.
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let raw = writer.as_raw_handle();
        if raw.is_null() || raw as isize == -1 {
            tracing::debug!(target: "hole::logging", "saved-original {stream:?} handle is null/invalid, using sink fallback");
            return None;
        }
    }
    Some(writer)
}

/// Save the original handle for a stream into a `Box<dyn Write + Send>`; a
/// stream the process does not have becomes `io::sink()`, so the caller can
/// safely write into it. The two return values are independent writers (used
/// as the relay tee target and the stderr layer writer respectively) — for
/// real handles they are `try_clone`'d, for sinks they are two independent
/// sinks.
fn save_original_pair(stream: Stream) -> (Box<dyn Write + Send>, Box<dyn Write + Send>) {
    let Some(writer) = dup_original(stream) else {
        return (Box::new(io::sink()), Box::new(io::sink()));
    };
    let Ok(clone) = writer.try_clone() else {
        tracing::debug!(target: "hole::logging", "saved-original {stream:?} try_clone failed, using sink fallback for layer writer");
        return (Box::new(writer), Box::new(io::sink()));
    };
    (Box::new(writer), Box::new(clone))
}

/// Where the redirect put the process's own stderr. Unset while stderr is not redirected.
static ORIGINAL_STDERR: std::sync::OnceLock<SavedStream> = std::sync::OnceLock::new();

enum SavedStream {
    Handle(os_pipe::PipeWriter),
    /// The process has no such stream (a service without a console).
    Absent,
}

/// The process's stderr as its caller gave it: the saved handle once stderr is redirected, `io::stderr()` until then.
/// Redacts what it is given. A write depends on no thread of this process, so the exit report and `DirRotate`'s notice
/// on a writer thread use it where a queue or `io::stderr()` could wait for the thread that is writing.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OriginalStderr;

impl Write for OriginalStderr {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let redacted = util::redact::redact_bytes(buf);
        match ORIGINAL_STDERR.get() {
            Some(SavedStream::Handle(handle)) => (&*handle).write_all(&redacted)?,
            Some(SavedStream::Absent) => {}
            None => io::stderr().write_all(&redacted)?,
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Redirect a single stdio stream to a pipe and spawn a reader thread that tees each line to (a) a tracing event and
/// (b) `tee_target`, through a queue that does `overflow` when it is full.
fn redirect_one_with(stream: Stream, tee_target: Box<dyn Write + Send>, overflow: Overflow) -> io::Result<Relay> {
    // The tee has a writer thread of its own: nothing its destination does (a panic, a notice, a wait for a slow
    // reader) runs on the relay thread.
    let (tee, tee_guard) = queued(util::redact::RedactingWriter::new(tee_target), overflow);

    let (read_end, write_end) = os_pipe::pipe()?;

    redirect_fd(stream, &write_end)?;
    // After redirect_fd, the standard stream points at its own copy of the pipe
    // write end (`dup2` on Unix, a duplicated handle on Windows); the relay
    // keeps `write_end` itself for its drain markers.
    Relay::spawn(stream, read_end, write_end, tee, tee_guard)
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
fn relay_loop(reader: os_pipe::PipeReader, mut tee: Queued, stream: Stream, drain: &Drain) {
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
                    // output ordering is preserved. A write the tee's destination
                    // refuses is counted by the tee's queue and reported at `flush`.
                    // This write fails once the tee's writer thread has ended: after a
                    // panic of the destination, which `flush` reports, or after `flush`
                    // itself, when the line reaches the log file only.
                    let _ = tee.write_all(output);
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
    let nonce = std::str::from_utf8(&line[at + marker.len()..])
        .ok()?
        .trim_end_matches(['\r', '\n']);
    Some((at, drain.take(Uuid::try_parse(nonce).ok()?)?))
}

fn emit_stderr_relay(msg: &str) {
    tracing::event!(target: "hole::stderr_relay", tracing::Level::INFO, "{}", msg);
}

fn emit_stdout_relay(msg: &str) {
    tracing::event!(target: "hole::stdout_relay", tracing::Level::INFO, "{}", msg);
}

/// Set up the FD-level redirect for both stderr and stdout, each teed to its
/// saved-original handle. Returns the relays + the saved-original-stderr writer
/// for the tracing stderr layer. There is no stdout tracing layer — the relay's
/// tee already preserves CLI script visibility.
pub(crate) fn redirect_stdio_to_tracing(terminal: Overflow) -> io::Result<(StdioRelayHandles, Box<dyn Write + Send>)> {
    // Save the originals BEFORE the redirect — once dup2/SetStdHandle runs,
    // io::stdout/stderr point at the pipes.
    let (stderr_tee, stderr_layer_writer) = save_original_pair(Stream::Stderr);
    let (stdout_tee, _) = save_original_pair(Stream::Stdout);
    Ok((
        redirect_stdio_with(stderr_tee, stdout_tee, terminal)?,
        stderr_layer_writer,
    ))
}

/// Redirect stderr and stdout, each teed to the writer given for it through a queue that does `terminal` when it is
/// full. From here [`OriginalStderr`] is the stderr the process had before the call.
pub(crate) fn redirect_stdio_with(
    stderr_tee: Box<dyn Write + Send>,
    stdout_tee: Box<dyn Write + Send>,
    terminal: Overflow,
) -> io::Result<StdioRelayHandles> {
    // The first redirect of the process saves it; there is no second (`init_dual` runs once).
    ORIGINAL_STDERR.get_or_init(|| dup_original(Stream::Stderr).map_or(SavedStream::Absent, SavedStream::Handle));
    Ok(StdioRelayHandles {
        stderr: Some(redirect_one_with(Stream::Stderr, stderr_tee, terminal)?),
        stdout: Some(redirect_one_with(Stream::Stdout, stdout_tee, terminal)?),
    })
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

/// A thread that the delivery of the process's output depends on. Such a thread must not wait for the delivery
/// itself: it would be waiting for itself, directly or through another of these threads.
#[derive(Clone, Copy, Debug)]
pub(crate) enum DeliveryThread {
    /// Reads a redirected stream and hands each line to the stream's tee and to the layers.
    Relay,
    /// Owns the destination of a [`queued::Queued`].
    Writer,
}

impl DeliveryThread {
    /// Whether code on this thread may write a `Queued`.
    fn writes_queues(self) -> bool {
        match self {
            // Handing lines to the queues is this thread's work, and no writer waits for it.
            DeliveryThread::Relay => true,
            // The queue may be this thread's own, which it alone empties: a wait for room could be a wait for itself.
            DeliveryThread::Writer => false,
        }
    }

    /// What the panic hook does with its record on this thread.
    fn take_panic(self, record: PanicRecord) {
        match self {
            // Into the layers' queues, as any other line this thread hands over.
            DeliveryThread::Relay => record.log(),
            // Kept until the thread's queue has ended (`leave_writer_thread`).
            DeliveryThread::Writer => STORED_PANICS.with_borrow_mut(|stored| stored.push(record)),
        }
    }

    /// Whether the panic hook chains to the previous hook on this thread. The default one prints to stderr, a
    /// redirected stream.
    fn chains_panic_hook(self) -> bool {
        match self {
            // Stderr is the pipe this thread alone reads: a text longer than the pipe holds would never be read.
            DeliveryThread::Relay => false,
            // The pipe's reader may be waiting for room in this thread's queue.
            DeliveryThread::Writer => false,
        }
    }
}

// What the current thread is to the delivery, if anything, and the panic records the hook kept on a writer thread. If
// the writer or formatter that ended a relay thread panics on the hook's record too, that is a panic inside the hook,
// and std aborts the process.
std::thread_local! {
    static DELIVERY_THREAD: std::cell::Cell<Option<DeliveryThread>> = const { std::cell::Cell::new(None) };
    static STORED_PANICS: std::cell::RefCell<Vec<PanicRecord>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// What `finish` reports of a panic that unwound out of a writer thread's destination: the hook's record of it, the
/// last one kept on this thread, or the payload's message where the hook did not see it.
pub(crate) fn writer_panic_report(payload: &(dyn std::any::Any + Send)) -> PanicReport {
    STORED_PANICS
        .with_borrow(|stored| stored.last().map(|record| record.report.clone()))
        .unwrap_or_else(|| PanicReport::from_payload(payload))
}

/// The writer thread's queue has ended: the thread is no longer a writer thread, and logs the panics the hook kept on
/// it into the sinks still open.
pub(crate) fn leave_writer_thread() {
    DELIVERY_THREAD.set(None);
    for record in STORED_PANICS.take() {
        record.log();
    }
}

/// What a panic said, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PanicReport {
    pub message: String,
    /// `file:line:column`. `None` where only the payload is known.
    pub location: Option<String>,
}

impl PanicReport {
    fn from_payload(payload: &(dyn std::any::Any + Send)) -> Self {
        PanicReport {
            message: payload_message(payload).to_string(),
            location: None,
        }
    }
}

impl std::fmt::Display for PanicReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)?;
        match &self.location {
            Some(location) => write!(f, ", at {location}"),
            None => Ok(()),
        }
    }
}

/// The text of a panic's payload.
fn payload_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>")
}

/// A panic as the hook logs it.
struct PanicRecord {
    report: PanicReport,
    backtrace: std::backtrace::Backtrace,
}

impl PanicRecord {
    fn new(info: &std::panic::PanicHookInfo<'_>) -> Self {
        PanicRecord {
            report: PanicReport {
                message: payload_message(info.payload()).to_string(),
                location: info
                    .location()
                    .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column())),
            },
            backtrace: std::backtrace::Backtrace::force_capture(),
        }
    }

    /// The one place a panic is logged: by the hook, or by a writer thread once its queue has ended.
    fn log(&self) {
        tracing::error!(
            target: "hole::panic",
            location = %self.report.location.as_deref().unwrap_or("unknown"),
            backtrace = %self.backtrace,
            "panic: {}",
            self.report.message,
        );
    }
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
        let thread = DELIVERY_THREAD.get();
        let record = PanicRecord::new(info);
        match thread {
            Some(thread) => thread.take_panic(record),
            None => record.log(),
        }
        if thread.is_none_or(DeliveryThread::chains_panic_hook) {
            prev(info);
        }
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
/// caller supplies queues. The stderr layer additionally drops
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

    // `log_internal_errors(false)`, the value `fmt::layer()` already has: a layer told to log them prints a failed
    // write to stderr, the redirected stream, on whichever thread logged. On a relay thread the line would come back
    // as an event that fails again. A layer's write fails once its queue's writer thread has ended.
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_writer)
        .with_ansi(false)
        .log_internal_errors(false)
        .event_format(yaml_format::YamlFormat)
        .with_filter(build_filter(file_directives));

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(stderr_writer)
        .with_ansi(true)
        .log_internal_errors(false)
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
    kind: ProcessKind,
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
    kind: ProcessKind,
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
    kind: ProcessKind,
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

    // Order matters: redirect BEFORE constructing the stderr layer's writer
    // so the writer targets the saved-original handle, not the pipe.
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
        redirect_stdio_to_tracing(kind.terminal()).expect("stdio redirect failed")
    };

    // Each rotation hands the fresh root-owned active file back to the real user
    // (`owner`; `None` leaves it alone). The rotator runs on the file's writer
    // thread, so its notice goes to the original stderr.
    let owned: Box<dyn Write + Send> = match dir {
        Some(dir) => Box::new(DirRotate::new(
            dir,
            log_filename.as_ref(),
            MAX_LOG_BYTES,
            owner,
            OriginalStderr,
        )),
        None => Box::new(io::sink()),
    };
    // The redaction wrap sits under the queue, so every formatted event
    // passes through it whoever authored it — a Hole site, a dependency at
    // the default global `info`, an OS command's argv, or a relayed plugin
    // line. This is the writer that is a log file; wrapping it is what closes
    // the leak, and it is the only redaction between any crate's `info!` and
    // the file.
    //
    // The FILE queue waits when it is full: the proxy-stop teardown burst
    // (SystemRoutes::drop sequence: route commands, state-file clear,
    // Remove-NetAdapter) must never be silently truncated, or `bridge.log`
    // loses the diagnostic for a teardown that broke the user's network.
    // Trade-off: a wedged disk (full filesystem, OneDrive sync stall, AV scan)
    // holds every thread that logs, with no limit, once the queue is full.
    let (file, file_guard) = queued(util::redact::RedactingWriter::new(owned), Overflow::Wait);
    let (stderr, stderr_guard) = queued(util::redact::RedactingWriter::new(original_stderr), kind.terminal());

    use tracing_subscriber::util::SubscriberInitExt;
    // Sanctioned by clippy.toml `disallowed_methods`: the ONE
    // production `try_init` workspace-wide. Tests use `register!()`.
    #[allow(clippy::disallowed_methods)]
    if let Err(e) = compose_subscriber(file.clone(), stderr, file_directives, stderr_directives).try_init() {
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
    tombstone::attach(kind.label(), log_dir);

    LogGuard {
        relays,
        stderr: Some(stderr_guard),
        file,
        file_guard: Some(file_guard),
    }
}

// Legacy cleanup ======================================================================================================

/// Remove legacy `<log_filename>.YYYY-MM-DD` files left behind by the old
/// daily-rotation scheme.
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
pub(crate) mod queued;

/// Arming the redaction registry from a server entry.
pub mod redact_arm;
use dir_rotate::DirRotate;

pub(crate) mod yaml_format;

#[cfg(test)]
pub(crate) mod logging_tests;

#[cfg(test)]
pub(crate) mod logging_test_helpers;
