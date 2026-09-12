//! Native-crash capture: the `on_crash` callback, the signal-safe marker it
//! writes, and the `sweep` that reports one on the next start.
//!
//! # What each platform produces
//!
//! |         | marker | OS-level report  | `.dmp` (dev-only, `crash-dumps`) |
//! |---------|--------|------------------|----------------------------------|
//! | Windows | yes    | WER / LocalDumps | yes                              |
//! | Linux   | yes    | core dump        | never had one                    |
//! | macOS   | yes    | none — no `.ips` | none                             |
//!
//! `crash-dumps` reads like a cross-platform feature and is not one. It gates
//! a Windows-only branch, and `minidump-writer` is declared under
//! `[target.'cfg(windows)'.dependencies]`, so enabling the feature on macOS or
//! Linux links nothing and changes nothing.
//!
//! # macOS: marker only, by decision
//!
//! Owner ruling on bindreams/hole#842, and the whole of the rationale: **no
//! part of Hole should hang the process even sometimes — not a diagnostics
//! crate, not anything else.** The cost was put explicitly and accepted: on
//! macOS a native crash leaves the marker and produces neither an `.ips` nor
//! a minidump. That is a decision, not a gap and not a TODO. Two sites
//! implement it — `MarkerCrashEvent`'s macOS `on_crash`, which `_exit`s
//! instead of returning, so the system reporter never runs; and the
//! `cfg(windows)` on `write_minidump_best_effort`.
//!
//! ## Why the callback cannot allocate
//!
//! `on_crash` runs on crash-handler's message-loop thread with every other
//! thread Mach-suspended — `mac/state.rs`'s `ScopedSuspend`, constructed
//! before `call_user_callback` on both the exception and the SIGABRT-relay
//! branch. A thread suspended inside `malloc` never releases the allocator
//! lock, so anything in the callback that allocates can block forever.
//! `write_minidump_best_effort` allocates three times over: a `PathBuf` for
//! the dump path, a `CString` inside `File::create`, and `MinidumpWriter`'s
//! own buffers. The marker write allocates not at all — path pre-encoded at
//! `attach`, stack scratch buffer, raw `open`/`write`/`close` — and runs
//! first, which is why it is what survives.
//!
//! ## The deadlock is observed, not predicted
//!
//! MEASURED on darwin/arm64: with eight threads allocating 1 MiB blocks, an
//! allocating `on_crash` hung 8 runs in 10, and `sample(1)` of a hung child
//! shows the handler thread parked in `_xzm_malloc_large_huge` →
//! `_os_unfair_lock_lock_slow` → `__ulock_wait2` while a suspended thread
//! sits inside `_xzm_malloc_large_huge` holding that lock.
//!
//! The allocator deadlock is measured, not argued — it is the only causal
//! theory for this hang that survived measurement.
//!
//! ## Three alternatives were built and measured
//!
//! - **Detach inside the callback, then let the OS reporter run.** Hangs,
//!   2/2. `call_user_callback` holds `HANDLER.read()` across `on_crash` and
//!   `state::detach` takes `HANDLER.write()` on that same non-reentrant
//!   `parking_lot::RwLock`; under it, `shutdown` would `handler_thread.join()`
//!   the very thread `on_crash` runs on. `CrashHandler::detach()` hardcodes
//!   `is_handler_thread: false`, so that join is not avoidable from here.
//! - **Restore the task exception ports by hand** — `uninstall`'s effect
//!   without its lock. Measured to earn nothing: with the ports restored the
//!   abort class terminates exactly as it does without them (3/3), and a
//!   fault raised inside `on_crash` hangs either way (2/2 with, 2/2 without).
//! - **Stop allocating but keep returning `Handled(false)`** — the
//!   `cfg(windows)` gate on `write_minidump_best_effort` WITHOUT the `_exit`,
//!   which would keep the `.ips`. 20/20 clean terminations, all under 0.41s,
//!   and nothing has falsified it — but on an idle darwin/arm64, carrying
//!   none of the allocation pressure the deadlock needs, so it says nothing
//!   yet about darwin/amd64 under CI load. `_exit` is preferred for a reason
//!   independent of the allocator: returning hands control back to a process
//!   whose handler is still installed (the `SignalCrash` relay branch never
//!   detaches — `on_crash`'s comment has the detail), and the system
//!   reporter's runtime is not something this process can bound.
//!
//! ## What would reopen this
//!
//! Two candidates. The clean one is a minidump path that is signal-safe and
//! allocation-free end to end — buffers reserved at `attach` time, the dump
//! fd opened there too, a writer touching neither the allocator nor a lock —
//! which removes the reason outright. The cheap one is the third alternative
//! above, the option measurement currently favours; reopening on it means
//! answering the unbounded-return argument, not just re-running the 20.
//! Neither is reopened by a change that merely makes the deadlock rarer: the
//! ruling is about hanging at all.

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
            // `lpNumberOfBytesWritten` may be NULL only when `lpOverlapped`
            // is non-NULL; this handle is synchronous, so the out-param is
            // mandatory — and it is also what tells a full write from a
            // short one. `CREATE_ALWAYS` means the marker file exists the
            // moment the handle opens, so a partial transfer (a disk filling
            // mid-write) would leave a TRUNCATED record that `parse_marker`
            // reports as fact. Resume until the buffer is out; a hard error
            // or a zero-byte transfer has nothing to resume from. Same loop
            // as the Unix writer, same reason.
            let mut total = 0usize;
            while total < n {
                let mut written = 0u32;
                if WriteFile(handle, Some(&buf[total..n]), Some(&mut written), None).is_err() || written == 0 {
                    break;
                }
                total += written as usize;
            }
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
            write_all_signal_safe(&buf[..n], |p, len| libc::write(fd, p as *const libc::c_void, len));
            libc::close(fd);
        }
    }
}

/// Write all of `buf` through `write`, resuming after a short transfer and
/// retrying an EINTR that moved nothing. `O_TRUNC` means a marker file
/// exists the moment `open` succeeds, so a single unchecked `write` leaves a
/// TRUNCATED record on a short count — and `parse_marker` is deliberately
/// tolerant of partial markers, so `sweep` would report the truncation as
/// fact. On macOS this record is the only crash artifact there is.
///
/// Signal-safe: no allocation, no locks, one syscall per iteration. The loop
/// is not a bounded retry — nothing counts attempts — it ends when the buffer
/// is written, when `write` moves nothing (a 0 return has nothing to resume
/// from), or on any error other than EINTR.
///
/// `write` is a seam only so the short-count and EINTR paths are drivable
/// from a test; the production caller passes `write(2)` itself and the
/// closure inlines away.
#[cfg(unix)]
fn write_all_signal_safe(buf: &[u8], mut write: impl FnMut(*const u8, usize) -> isize) {
    let mut written = 0usize;
    while written < buf.len() {
        // SAFETY: `written < buf.len()` on entry, so the offset pointer is
        // inside the allocation.
        let r = write(unsafe { buf.as_ptr().add(written) }, buf.len() - written);
        if r > 0 {
            written += r as usize;
        } else if r < 0 && errno() == libc::EINTR {
            continue;
        } else {
            break;
        }
    }
}

/// `errno` for the calling thread. Async-signal-safe on both Unixes Hole
/// builds: each exposes the thread-local through a pure accessor function
/// (glibc/musl `__errno_location`, Darwin `__error`) that takes no lock and
/// allocates nothing.
#[cfg(unix)]
fn errno() -> i32 {
    unsafe {
        #[cfg(target_os = "linux")]
        let p = libc::__errno_location();
        #[cfg(not(target_os = "linux"))]
        let p = libc::__error();
        *p
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

// The `windows` in the cfg below is load-bearing, not an oversight. This
// branch allocates, and on macOS `on_crash` runs with every other thread
// Mach-suspended, where allocating deadlocked 8 runs in 10 under measurement.
// Deleting the gate reinstates a hang that was directly observed, and macOS
// producing no dump is a decision, not an omission — the module doc's "macOS:
// marker only, by decision" carries the evidence, the alternatives already
// tried, and the one thing that would reopen it. Linux never had an
// in-process dump branch at all.
//
// Windows is a different shape: `on_crash` runs on the faulting thread via a
// vectored/unhandled exception filter with no threads suspended, so this
// branch cannot deadlock that way.

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
// a nicety; module doc has the measured deadlock it avoids.

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
//  * Allocation in this callback can deadlock outright, against a thread
//    Mach-suspended mid-`malloc`. Observed, not predicted — module doc.
//  * The system crash reporter's involvement is not something this process
//    can bound at all.
//
// Three alternatives to `_exit` were built and measured; module doc has them,
// their caveats and their verdicts. Do not re-derive them here.
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
// The cost — no `.ips` and no minidump on macOS — is an owner decision, not
// a limitation; module doc, "macOS: marker only, by decision". The marker
// still carries kind, pid, tid, exception code and fault address, which is
// what `sweep` reports; what is lost is the stack.
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
