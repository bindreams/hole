use std::path::Path;
use std::sync::OnceLock;

/// Holds the live crash handler for the process lifetime (it detaches on
/// Drop). Second `attach` is a no-op (set returns Err once filled).
static CRASH_HANDLER: OnceLock<crash_handler::CrashHandler> = OnceLock::new();

/// Per-process handler state: the marker path is FULLY PRE-ENCODED at attach
/// time (Windows: NUL-terminated `Vec<u16>` wide; Unix: NUL-terminated
/// `Vec<u8>`) so `on_crash` opens the file with zero allocation — no
/// `encode_wide`, no `as_bytes`, no `to_vec`. We also keep `kind` so
/// on_crash can write it without re-deriving. Stored in a static so the
/// &'static reference the CrashEvent impl needs outlives the handler.
/// See bindreams/hole#438 (review S3 — signal-safe marker path).
static HANDLER_STATE: OnceLock<HandlerState> = OnceLock::new();

struct HandlerState {
    kind: &'static str,
    /// Marker path as a NUL-terminated UTF-16 wide string, pre-encoded at
    /// attach time. Passed straight to `CreateFileW` in on_crash.
    #[cfg(windows)]
    marker_path_wide: Vec<u16>,
    /// Marker path as NUL-terminated bytes, pre-encoded at attach time.
    /// Passed straight to `open` in on_crash. Shared by macOS AND Linux —
    /// the open/write syscall path is identical on every Unix.
    #[cfg(unix)]
    marker_path_c: Vec<u8>,
}

// SAFETY: HandlerState holds only an &'static str and an owned, pre-encoded
// byte/wide vector; it is read-only after attach() and never mutated, so
// sharing across the crash thread is sound.
unsafe impl Send for HandlerState {}
unsafe impl Sync for HandlerState {}

/// Parsed crash-marker record. `kind` borrows from the source text when
/// parsed; for the write path it is `&'static str` from `attach`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MarkerRecord<'a> {
    pub kind: &'a str,
    pub pid: u32,
    pub tid: u32,
    pub code: u64,
    pub fault_addr: u64,
    pub time: u64,
}

const MARKER_MAGIC: &str = "tombstone-marker v1";

/// Append `bytes` into `buf` starting at `*pos`, advancing `*pos`. Never
/// writes past `buf.len()`. Signal-safe: no heap, no panics.
fn push_bytes(buf: &mut [u8], pos: &mut usize, bytes: &[u8]) {
    for &b in bytes {
        if *pos >= buf.len() {
            return;
        }
        buf[*pos] = b;
        *pos += 1;
    }
}

/// Write `v` as decimal ASCII into `buf` at `*pos`. Signal-safe.
fn push_dec(buf: &mut [u8], pos: &mut usize, mut v: u64) {
    // Build digits into a fixed scratch (max 20 digits for u64), reversed.
    let mut tmp = [0u8; 20];
    let mut i = 0usize;
    if v == 0 {
        push_bytes(buf, pos, b"0");
        return;
    }
    while v > 0 {
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        push_bytes(buf, pos, &[tmp[i]]);
    }
}

/// Write `v` as lowercase hex ASCII (no `0x`) into `buf` at `*pos`. Signal-safe.
fn push_hex(buf: &mut [u8], pos: &mut usize, mut v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tmp = [0u8; 16];
    let mut i = 0usize;
    if v == 0 {
        push_bytes(buf, pos, b"0");
        return;
    }
    while v > 0 {
        tmp[i] = HEX[(v & 0xf) as usize];
        v >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        push_bytes(buf, pos, &[tmp[i]]);
    }
}

/// Format a marker record into `buf` using only stack scratch (no heap, no
/// `format!`, no locks). Returns the number of bytes written (<= buf.len()).
/// Safe to call from `on_crash` in a compromised context.
pub(crate) fn format_marker_into(rec: &MarkerRecord, buf: &mut [u8]) -> usize {
    let mut pos = 0usize;
    push_bytes(buf, &mut pos, MARKER_MAGIC.as_bytes());
    push_bytes(buf, &mut pos, b"\nkind=");
    push_bytes(buf, &mut pos, rec.kind.as_bytes());
    push_bytes(buf, &mut pos, b"\npid=");
    push_dec(buf, &mut pos, rec.pid as u64);
    push_bytes(buf, &mut pos, b"\ntid=");
    push_dec(buf, &mut pos, rec.tid as u64);
    push_bytes(buf, &mut pos, b"\ncode=0x");
    push_hex(buf, &mut pos, rec.code);
    push_bytes(buf, &mut pos, b"\nfault_addr=0x");
    push_hex(buf, &mut pos, rec.fault_addr);
    push_bytes(buf, &mut pos, b"\ntime=");
    push_dec(buf, &mut pos, rec.time);
    push_bytes(buf, &mut pos, b"\n");
    pos
}

// === signal-safe marker write (per platform) =========================================================================

/// Best-effort and infallible by design: every failure mode here (disk full,
/// permission, TOCTOU on the pre-encoded path) costs a breadcrumb and
/// nothing else, and there is no signal-safe way to report one from a
/// compromised context anyway.
#[cfg(windows)]
fn write_marker_signal_safe(state: &HandlerState, ctx: &crash_handler::CrashContext) {
    // Extract fields. ctx.exception_code is the top-level code (e.g.
    // 0xC0000005). For an access violation, ExceptionInformation[1] is the
    // faulting data address; otherwise fall back to the instruction ptr.
    let code = ctx.exception_code as u32 as u64;
    let pid = ctx.process_id;
    let tid = ctx.thread_id;
    let fault_addr = unsafe {
        let ep = ctx.exception_pointers;
        if ep.is_null() {
            0
        } else {
            let rec = (*ep).ExceptionRecord;
            if rec.is_null() {
                0
            } else {
                let r = &*rec;
                // ExceptionInformation[1] = accessed address for AV
                // (EXCEPTION_ACCESS_VIOLATION = 0xC0000005).
                // ExceptionCode is NTSTATUS = a plain i32 alias (NO `.0`
                // tuple field). See review M3.
                if r.ExceptionCode as u32 == 0xC0000005u32 && r.NumberParameters >= 2 {
                    r.ExceptionInformation[1] as u64
                } else {
                    r.ExceptionAddress as usize as u64
                }
            }
        }
    };
    let time = win_time();

    let rec = MarkerRecord {
        kind: state.kind,
        pid,
        tid,
        code,
        fault_addr,
        time,
    };
    let mut buf = [0u8; 256];
    let n = format_marker_into(&rec, &mut buf);

    // Open + write via CreateFileW/WriteFile using the marker path PRE-ENCODED
    // at attach time (state.marker_path_wide). NO encode_wide / alloc here —
    // this runs in a compromised context. See review S3.
    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        };
        let h = CreateFileW(
            PCWSTR(state.marker_path_wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            // htemplatefile is Option<HANDLE> in windows 0.62; pass None.
            // See review M6.
            None,
        );
        if let Ok(handle) = h {
            let _ = WriteFile(handle, Some(&buf[..n]), None, None);
            let _ = CloseHandle(handle);
        }
    }
}

#[cfg(windows)]
fn win_time() -> u64 {
    // GetSystemTimeAsFileTime: 100ns intervals since 1601-01-01. Opaque to
    // sweep; surfaced verbatim. Signal-safe (no alloc). In windows 0.62 it
    // takes ZERO args and RETURNS a FILETIME. See review M5.
    unsafe {
        use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
        let ft = GetSystemTimeAsFileTime();
        ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
    }
}

// The Unix (macOS + Linux) marker writer is SHARED: the open/write/close
// syscall path and the clock_gettime time helper are byte-for-byte identical
// on every Unix. Only the CrashContext FIELD EXTRACTION differs per OS
// (macOS reads ctx.exception: Option<ExceptionInfo>; Linux reads
// ctx.siginfo: signalfd_siginfo + ctx.pid/ctx.tid), so that is the one
// per-OS helper; the writer dispatches through it. See the Linux verification
// (crash-context 0.6.3: CrashContext { context, float_state, siginfo, pid,
// tid } — bindreams/hole#438).

/// Best-effort and infallible by design: every failure mode here (disk full,
/// permission, TOCTOU on the pre-encoded path) costs a breadcrumb and
/// nothing else, and there is no signal-safe way to report one from a
/// compromised context anyway.
#[cfg(unix)]
fn write_marker_signal_safe(state: &HandlerState, ctx: &crash_handler::CrashContext) {
    let (code, fault_addr, pid, tid) = extract_fault_fields(ctx);
    let time = unix_time();

    let rec = MarkerRecord {
        kind: state.kind,
        pid,
        tid,
        code,
        fault_addr,
        time,
    };
    let mut buf = [0u8; 256];
    let n = format_marker_into(&rec, &mut buf);

    // open(O_WRONLY|O_CREAT|O_TRUNC) + write + close — all async-signal-safe.
    // Use the marker path PRE-ENCODED at attach time (state.marker_path_c,
    // already NUL-terminated). NO as_bytes / to_vec / alloc here. See review S3.
    unsafe {
        let fd = libc::open(
            state.marker_path_c.as_ptr() as *const libc::c_char,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd >= 0 {
            libc::write(fd, buf.as_ptr() as *const libc::c_void, n);
            libc::close(fd);
        }
    }
}

/// macOS field extraction: CrashContext.exception is
/// `Option<ExceptionInfo { kind, code, subcode }>`; subcode = faulting
/// address for EXC_BAD_ACCESS; thread is ctx.thread. There is no pid field —
/// use getpid(). Returns (code, fault_addr, pid, tid).
#[cfg(target_os = "macos")]
fn extract_fault_fields(ctx: &crash_handler::CrashContext) -> (u64, u64, u32, u32) {
    let (code, fault_addr) = match &ctx.exception {
        Some(exc) => (exc.kind as u64, exc.subcode.unwrap_or(0)),
        None => (0, 0),
    };
    let pid = unsafe { libc::getpid() as u32 };
    // mach `thread_t` is already `u32` on darwin — no cast (clippy::unnecessary_cast).
    let tid = ctx.thread;
    (code, fault_addr, pid, tid)
}

/// Linux field extraction. crash-context 0.6.3's Linux CrashContext is
/// `{ context: ucontext_t, float_state: fpregset_t, siginfo:
/// libc::signalfd_siginfo, pid: libc::pid_t, tid: libc::pid_t }`. The signal
/// number is `siginfo.ssi_signo` (u32) and the faulting data address is
/// `siginfo.ssi_addr` (u64) — both plain integer fields, so reading them is
/// signal-safe (no pointer chase like the Windows ExceptionRecord). `code`
/// in the marker carries the signal number on Linux (e.g. 11=SIGSEGV,
/// 6=SIGABRT, 7=SIGBUS, 4=SIGILL, 8=SIGFPE, 5=SIGTRAP) — sweep surfaces it
/// verbatim. pid/tid come straight off the context. Returns
/// (code, fault_addr, pid, tid). Verified against
/// https://docs.rs/crash-context/0.7.0/src/crash_context/linux.rs.html
/// and https://docs.rs/libc/latest/libc/struct.signalfd_siginfo.html
#[cfg(target_os = "linux")]
fn extract_fault_fields(ctx: &crash_handler::CrashContext) -> (u64, u64, u32, u32) {
    let code = ctx.siginfo.ssi_signo as u64;
    let fault_addr = ctx.siginfo.ssi_addr;
    let pid = ctx.pid as u32;
    let tid = ctx.tid as u32;
    (code, fault_addr, pid, tid)
}

#[cfg(unix)]
fn unix_time() -> u64 {
    // clock_gettime(CLOCK_REALTIME) seconds. Signal-safe. Identical on macOS
    // and Linux.
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) == 0 {
            ts.tv_sec as u64
        } else {
            0
        }
    }
}

// === dev-only minidump (.dmp) — Windows only, NEVER linked in release ================================================

// macOS has NO in-process minidump branch, and Linux never had one.
//
// On macOS `on_crash` runs on crash-handler's message-loop thread with every
// other thread Mach-suspended (`mac/state.rs`'s `ScopedSuspend`), so any
// allocation there can deadlock against a thread suspended mid-`malloc`.
// MEASURED on darwin/arm64, not inferred: with eight threads allocating
// 1 MiB blocks, an allocating `on_crash` hung 8/10 runs, and `sample(1)` of
// a hung child shows the handler thread parked in
// `_xzm_malloc_large_huge` → `_os_unfair_lock_lock_slow` → `__ulock_wait2`
// while a suspended thread sits inside `_xzm_malloc_large_huge` holding
// that lock. `minidump-writer` allocates (and `File::create` builds a
// `CString`, and `dmp_path_from_marker` a `PathBuf`), so there is no
// ordering that keeps it AND keeps the promise that tombstone never hangs
// the process. See `MarkerCrashEvent`'s macOS impl.
//
// Windows is a different shape: `on_crash` runs on the faulting thread via
// a vectored/unhandled exception filter with no threads suspended, so the
// dump branch cannot deadlock the same way.

#[cfg(all(feature = "crash-dumps", windows))]
fn write_minidump_best_effort(state: &HandlerState, ctx: &crash_handler::CrashContext) {
    // Reconstruct the .dmp path from the pre-encoded marker path: same stem,
    // ".dmp" extension. Allocation allowed here (dev-only, best-effort).
    let Some(dmp_path) = dmp_path_from_marker(state) else {
        return;
    };
    let Ok(mut file) = std::fs::File::create(&dmp_path) else {
        return;
    };
    // dump_crash_context is an associated fn; None = default minidump type.
    let _ = minidump_writer::minidump_writer::MinidumpWriter::dump_crash_context(ctx, None, &mut file);
}

#[cfg(all(feature = "crash-dumps", windows))]
fn dmp_path_from_marker(state: &HandlerState) -> Option<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    // Strip the trailing NUL before decoding.
    let wide = &state.marker_path_wide[..state.marker_path_wide.len().saturating_sub(1)];
    let os = std::ffi::OsString::from_wide(wide);
    let mut p = std::path::PathBuf::from(os);
    p.set_extension("dmp");
    Some(p)
}

/// Parse a marker's text (heap-OK; called only by `sweep`). Returns `None`
/// when the magic line is wrong. Tolerates missing/partial fields (a crash
/// mid-write): absent fields default to 0 / "". Hex fields accept an optional
/// `0x` prefix; empty hex → 0.
pub(crate) fn parse_marker(text: &str) -> Option<MarkerRecord<'_>> {
    let mut lines = text.lines();
    if lines.next()? != MARKER_MAGIC {
        return None;
    }
    let mut rec = MarkerRecord {
        kind: "",
        pid: 0,
        tid: 0,
        code: 0,
        fault_addr: 0,
        time: 0,
    };
    for line in lines {
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        match key {
            "kind" => rec.kind = val,
            "pid" => rec.pid = val.parse().unwrap_or(0),
            "tid" => rec.tid = val.parse().unwrap_or(0),
            "code" => rec.code = parse_hex(val),
            "fault_addr" => rec.fault_addr = parse_hex(val),
            "time" => rec.time = val.parse().unwrap_or(0),
            _ => {}
        }
    }
    Some(rec)
}

fn parse_hex(s: &str) -> u64 {
    let digits = s.strip_prefix("0x").unwrap_or(s);
    if digits.is_empty() {
        return 0;
    }
    u64::from_str_radix(digits, 16).unwrap_or(0)
}

/// Install the process-global native-crash handler. Idempotent. Best-effort:
/// on failure logs a `tracing::warn!` and returns — never panics. `kind`
/// labels the marker ("gui", "bridge", "gui-cli", "galoshes", "test").
/// `log_dir` must be user-readable even for the elevated bridge (the marker
/// inherits its perms).
pub fn attach(kind: &'static str, log_dir: &Path) {
    // Idempotent: a second attach (e.g. init_multi called twice in a
    // process) is a no-op once the handler is set.
    if CRASH_HANDLER.get().is_some() {
        return;
    }

    let pid = std::process::id();
    let marker_path = log_dir.join(format!("crash-{kind}-{pid}.marker"));
    // Best-effort: ensure the dir exists so on_crash's open() can succeed.
    let _ = std::fs::create_dir_all(log_dir);

    // Pre-encode the marker path NOW (allocation is fine on the happy path)
    // so on_crash does ZERO allocation. See review S3.
    #[cfg(windows)]
    let state = {
        use std::os::windows::ffi::OsStrExt;
        let marker_path_wide: Vec<u16> = marker_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        HandlerState { kind, marker_path_wide }
    };
    #[cfg(unix)]
    let state = {
        use std::os::unix::ffi::OsStrExt;
        let mut marker_path_c: Vec<u8> = marker_path.as_os_str().as_bytes().to_vec();
        marker_path_c.push(0);
        HandlerState { kind, marker_path_c }
    };
    // Reuse an existing state if attach was previously called (e.g. a prior
    // attach whose CrashHandler::attach failed) so a retry can still install
    // the handler. OnceLock pins the first kind/log_dir, which is correct:
    // attach is always called with the same process's kind + log_dir.
    let state_ref: &'static HandlerState = match HANDLER_STATE.get() {
        Some(existing) => existing,
        None => {
            let _ = HANDLER_STATE.set(state);
            // Another thread could have won the race; either way get() is now Some.
            match HANDLER_STATE.get() {
                Some(s) => s,
                None => unreachable!("HANDLER_STATE must be Some after a successful set()"),
            }
        }
    };

    let event = Box::new(MarkerCrashEvent { state: state_ref });
    // SAFETY: crash-handler requires the closure/handler to be valid; our
    // MarkerCrashEvent borrows only 'static state and does signal-safe work.
    match crash_handler::CrashHandler::attach(event) {
        Ok(handler) => {
            // Store to keep the handler alive (Drop = detach). A concurrent winner is
            // already prevented by the CRASH_HANDLER fast-path + HANDLER_STATE init
            // above; the discard just ignores the benign already-set case.
            let _ = CRASH_HANDLER.set(handler);
        }
        Err(e) => {
            tracing::warn!(error = %e, "tombstone: failed to attach crash handler");
        }
    }
}

struct MarkerCrashEvent {
    state: &'static HandlerState,
}

// `on_crash` runs in a COMPROMISED context: the heap and every lock in the
// process may be held by a thread that will never run again. The marker
// write is therefore allocation-free and lock-free on all three platforms —
// a raw file open/write from a stack buffer plus the marker path pre-encoded
// at attach time — with no `format!`, no locks, and no tracing. That is not
// a nicety; see the macOS impl below for the measured deadlock it avoids.

/// macOS: end the process here, without returning to `crash-handler`.
///
/// `-> !` is the contract, and the compiler enforces it: the macOS
/// `on_crash` below has no other tail expression, so the termination cannot
/// be made conditional without visibly inventing a `CrashEventResult` that
/// arm does not otherwise have.
#[cfg(target_os = "macos")]
fn terminate_without_returning() -> ! {
    // sysexits.h's EX_SOFTWARE, "internal software error" — not in the
    // `libc` crate (BSD-only cruft), so spelled out here.
    const EX_SOFTWARE: i32 = 70;
    // SAFETY: `_exit` is async-signal-safe (POSIX.1-2017 §2.4.3): a bare
    // syscall that runs no atexit handler and touches no libc or heap state.
    unsafe { libc::_exit(EX_SOFTWARE) }
}

// macOS: `on_crash` writes the marker and then never returns.
//
// tombstone is observability only — "turn a silent process death into a
// logged event on the next start". Once the marker is on disk the process
// has nothing left to contribute, while everything that would run after
// this callback returns is unbounded. A hung bridge is far worse than a
// lost crash report: it still holds the TUN device, its routes and its pf
// rules, and never reaches its own cleanup, so the user loses the network.
// Detection of unclean shutdown does not depend on any of this — the
// bridge's `bridge-{routes,plugins,dns}.json` state files are swept on the
// next start and survive SIGKILL and power loss.
//
// What is unbounded, specifically:
//
//  * The SIGABRT relay never detaches. macOS has no exception for `abort()`,
//    so crash-handler hooks SIGABRT with a `sigaction` and relays it as a
//    synthesized `EXC_SOFTWARE`/`EXC_SOFT_SIGNAL` (`mac/signal.rs`). A real
//    fault's branch calls `detach(true)` (`mac/state.rs`,
//    `MessageIds::Exception`); the relay's branch (`MessageIds::SignalCrash`)
//    contains no `detach` at all, so `abort()`'s C-mandated re-raise fires
//    with the task exception port still attached.
//  * Allocation in this callback can deadlock outright. crash-handler
//    Mach-suspends every other thread before calling in (`ScopedSuspend`),
//    so a thread suspended inside `malloc` never releases the allocator
//    lock. MEASURED on darwin/arm64: an allocating `on_crash` hung 8/10 runs
//    under allocator contention, with `sample(1)` showing this thread parked
//    in `_os_unfair_lock_lock_slow` and a suspended thread holding the lock.
//  * The system crash reporter's involvement is not something this process
//    can bound at all.
//
// Calling `detach` from here does not fix the first point — it is what the
// hang looks like. MEASURED, 2/2: `crash_handler::CrashHandler::detach()`
// invoked from inside `on_crash` never returns. `call_user_callback` holds
// `HANDLER.read()` across this callback and `state::detach` takes
// `HANDLER.write()` on that same non-reentrant `parking_lot::RwLock`; the
// `handler_thread.join()` beneath it would deadlock a second time, since
// `on_crash` runs ON the handler thread. Upstream's own `detach(true)` is
// reachable only from its message loop, after this returns.
//
// Restoring the task exception ports by hand instead — `uninstall`'s effect
// without its lock — was measured too, and does not earn its keep: with the
// ports restored the abort class terminates exactly as it does without them
// (SIGABRT, sub-second, 3/3), and a fault raised INSIDE `on_crash` hangs
// either way (2/2 with, 2/2 without). It buys nothing `_exit` does not.
//
// MEASURED, 3 runs each of abort, segfault, stack_overflow, bus,
// illegal_instruction and trap on darwin/arm64: every one exits 70 in under
// 0.02s. `stack_overflow` is covered by the same call and needs no special
// case — it arrives as a genuine `EXC_BAD_ACCESS` guard-page fault, and
// terminating on that first delivery means Rust's own stack-overflow
// handler, which responds by calling `abort()`, never runs at all.
//
// Unconditional by construction: no fault-class predicate, no attach-`kind`
// discriminator (`kind` never identified a process — `hole-common`'s
// log-bridge test helpers attach as `"test"` too), and no cargo feature,
// because a shipped `hole`, `hole bridge` and `galoshes` must not hang
// either. `tests/crash_child.rs` pins each of those three separately.
//
// KNOWN COST, accepted deliberately: no `.ips` crash report and no
// in-process minidump on macOS. The marker still carries kind, pid, tid,
// exception code and fault address, which is what `sweep` reports; what is
// lost is the stack. Reaching the reporter is exactly the unbounded step
// this exists to remove.
#[cfg(target_os = "macos")]
unsafe impl crash_handler::CrashEvent for MarkerCrashEvent {
    fn on_crash(&self, context: &crash_handler::CrashContext) -> crash_handler::CrashEventResult {
        write_marker_signal_safe(self.state, context);
        terminate_without_returning()
    }
}

// Windows and Linux: write the marker, then hand back to the OS default.
//
// Neither has macOS's shape. Windows runs `on_crash` on the faulting thread
// via an exception filter, and Linux on the crashing thread in a signal
// handler; neither suspends other threads or routes the callback through a
// second thread, so returning does not walk into the machinery above.
// Returning `Handled(false)` keeps the OS default path — WER LocalDumps,
// or a re-raise to the default signal disposition and a core dump.
//
// The dev-only minidump branch is Windows-only and MAY allocate; it runs
// after the signal-safe marker is already durable, so a fault inside it
// cannot cost the breadcrumb.
#[cfg(not(target_os = "macos"))]
unsafe impl crash_handler::CrashEvent for MarkerCrashEvent {
    fn on_crash(&self, context: &crash_handler::CrashContext) -> crash_handler::CrashEventResult {
        write_marker_signal_safe(self.state, context);

        #[cfg(all(feature = "crash-dumps", windows))]
        write_minidump_best_effort(self.state, context);

        // Only ever construct Handled(_) — Jump is not used.
        crash_handler::CrashEventResult::Handled(false)
    }
}

/// Scan `log_dir` for `crash-*.marker`, emit one
/// `tracing::error!(target: "crash", …)` breadcrumb per marker, then delete
/// the marker (leaving any sibling `.dmp`). Best-effort; tolerant of
/// malformed/partial markers.
pub fn sweep(log_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(log_dir) else {
        // Missing/unreadable dir — nothing to report. Best-effort.
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_marker = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("crash-") && n.ends_with(".marker"))
            .unwrap_or(false);
        if !is_marker {
            continue;
        }
        report_one(&path);
        // Delete on report (dedup): a marker is reported exactly once by
        // whichever process sweeps first. Leave any sibling .dmp.
        let _ = std::fs::remove_file(&path);
    }
}

fn report_one(path: &Path) {
    let Ok(text) = std::fs::read_to_string(path) else {
        tracing::error!(
            target: "crash",
            marker = %path.display(),
            "native crash detected in previous run (marker unreadable)"
        );
        return;
    };
    let Some(rec) = parse_marker(&text) else {
        tracing::error!(
            target: "crash",
            marker = %path.display(),
            "native crash detected in previous run (marker malformed)"
        );
        return;
    };
    // A sibling .dmp (dev builds only) sits next to the marker.
    let dmp = path.with_extension("dmp");
    let dmp_path = dmp.exists().then(|| dmp.display().to_string());
    tracing::error!(
        target: "crash",
        kind = rec.kind,
        pid = rec.pid,
        tid = rec.tid,
        code = format_args!("0x{:x}", rec.code),
        fault_addr = format_args!("0x{:x}", rec.fault_addr),
        time = rec.time,
        dump = dmp_path.as_deref(),
        "native crash detected in previous run"
    );
}

#[cfg(test)]
#[path = "crash_tests.rs"]
mod crash_tests;
