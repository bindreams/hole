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

/// Returns whether the marker was actually written (a signal-safe `bool`,
/// no allocation) so `on_crash` can gate the test-only `_exit` bypass on a
/// marker that is really on disk, instead of firing unconditionally and
/// risking zero diagnostics if the write failed (disk full, permission,
/// TOCTOU on the pre-encoded path).
#[cfg(windows)]
fn write_marker_signal_safe(state: &HandlerState, ctx: &crash_handler::CrashContext) -> bool {
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
            let mut written = 0u32;
            let write_ok =
                WriteFile(handle, Some(&buf[..n]), Some(&mut written), None).is_ok() && written as usize == n;
            let _ = CloseHandle(handle);
            write_ok
        } else {
            false
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

/// Returns whether the marker was actually written (a signal-safe `bool`,
/// no allocation) so `on_crash` can gate the test-only `_exit` bypass on a
/// marker that is really on disk, instead of firing unconditionally and
/// risking zero diagnostics if the write failed (disk full, permission,
/// TOCTOU on the pre-encoded path).
#[cfg(unix)]
fn write_marker_signal_safe(state: &HandlerState, ctx: &crash_handler::CrashContext) -> bool {
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
            let written = libc::write(fd, buf.as_ptr() as *const libc::c_void, n);
            let _ = libc::close(fd);
            written == n as isize
        } else {
            false
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

// === dev-only minidump (.dmp) — NEVER linked in release ==============================================================

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

#[cfg(all(feature = "crash-dumps", target_os = "macos"))]
fn write_minidump_best_effort(state: &HandlerState, ctx: &crash_handler::CrashContext) {
    let Some(dmp_path) = dmp_path_from_marker(state) else {
        return;
    };
    let Ok(mut file) = std::fs::File::create(&dmp_path) else {
        return;
    };
    // `with_crash_context` takes CrashContext BY VALUE; on_crash only lends
    // `&CrashContext`. `crash_context::CrashContext` derives only `Debug`
    // (NOT `Clone`), so `ctx.clone()` is NOT available — we MUST rebuild it
    // field-by-field. The macOS CrashContext is cheap (3 Mach-port ints + an
    // Option<ExceptionInfo> of 3 ints). `crash_context::ExceptionInfo` is in
    // scope via the macOS-only `crash-context` direct dep (crash-handler
    // re-exports CrashContext but NOT ExceptionInfo). See review S1.
    let cc = crash_context::CrashContext {
        task: ctx.task,
        thread: ctx.thread,
        handler_thread: ctx.handler_thread,
        exception: ctx.exception.as_ref().map(|e| crash_context::ExceptionInfo {
            kind: e.kind,
            code: e.code,
            subcode: e.subcode,
        }),
    };
    let mut writer = minidump_writer::minidump_writer::MinidumpWriter::with_crash_context(cc);
    let _ = writer.dump(&mut file);
}

// Gated to Win/mac (NOT plain `feature = "crash-dumps"`): on Linux the dump
// call site is cfg'd out, so this fn is never called there — and gating it to
// the same condition means it is never COMPILED on Linux either (otherwise it
// would be a body with no matching inner cfg block → a `() vs Option` type
// error). See the Linux carve-out above.
#[cfg(all(feature = "crash-dumps", any(windows, target_os = "macos")))]
fn dmp_path_from_marker(state: &HandlerState) -> Option<std::path::PathBuf> {
    // Decode the pre-encoded marker path back to a PathBuf, swap extension.
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        // Strip the trailing NUL before decoding.
        let wide = &state.marker_path_wide[..state.marker_path_wide.len().saturating_sub(1)];
        let os = std::ffi::OsString::from_wide(wide);
        let mut p = std::path::PathBuf::from(os);
        p.set_extension("dmp");
        Some(p)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let bytes = &state.marker_path_c[..state.marker_path_c.len().saturating_sub(1)];
        let os = std::ffi::OsStr::from_bytes(bytes);
        let mut p = std::path::PathBuf::from(os);
        p.set_extension("dmp");
        Some(p)
    }
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

// macOS has no hardware exception for `abort()`, so `crash-handler` hooks
// `SIGABRT` with a plain `sigaction` and relays it to this same `on_crash` as
// a SYNTHESIZED `EXC_SOFTWARE`/`EXC_SOFT_SIGNAL` exception (see its own
// `mac/signal.rs`: "Macos doesn't have an exception for process aborts, so we
// hook SIGABRT"). SOURCE-GROUNDED, not inferred, verified in the vendored
// `crash-handler` crate: a REAL fault's message handler
// (`MessageIds::Exception`/`ExceptionStateIdentity`) calls `detach(true)`
// (`mac/state.rs`), which tears down via `uninstall()` →
// `restore_abort_handler` (`mac/state.rs`); the SIGABRT relay's own message
// handler (`MessageIds::SignalCrash`, `mac/state.rs`) contains no `detach`
// call anywhere in its branch, so the task-level exception port is still
// attached once it returns. `abort()`'s
// C-standard-mandated contract (terminate even if a caught signal handler
// returns) means it re-raises `SIGABRT` with the default disposition once
// the relay returns — which, on an unhandled abort, is the textbook
// condition for a second, genuine `EXC_CRASH` exception.
//
// MEASURED, not inferred: that second `on_crash` invocation does not happen.
// With the `_exit` bypass below compiled out via an env-gated no-op (so
// `abort()`'s re-raise is free to run) and a signal-safe per-invocation probe
// added ad hoc for this measurement, 8/8 runs of the SIGABRT-relay path
// produced exactly ONE `on_crash` call, `context.exception.kind ==
// EXC_SOFTWARE` (0x5) every time — never a second call, never `kind ==
// EXC_CRASH` (0xa). The marker's `code` field is consequently
// NON-discriminating between "the `_exit` bypass is present" and "it was
// deleted outright": both were measured to write `code=0x5`, because in
// neither case does a second, `EXC_CRASH`-carrying invocation ever occur to
// overwrite it.
//
// A separate, later measurement confirms the same absence a different way:
// 10/10 runs of the abort class, again with the `_exit` bypass deleted,
// terminated promptly — sub-second, `exit=134` (the default SIGABRT
// disposition) — every time, with the marker still holding `code=0x5`. The
// marker file is opened `O_WRONLY|O_CREAT|O_TRUNC` (`crash.rs:238`), so a
// second, `EXC_CRASH`-bearing invocation would have overwritten `0x5` with
// `0xa` before any of these processes exited; it did not, in 10/10 runs.
//
// Why the second invocation never arrives, and why this class intermittently
// hangs for minutes to hours on CI, is NOT established — unknown, not
// inferred-and-therefore-good-enough. Do not add a guess here without new
// measurement. This PR's justification is narrower and is itself measured:
// the `_exit` bypass removes the process's exposure to the crash reporter
// before `abort()`'s re-raise can produce whatever the second exception is,
// and with it in place `crash_marker_abort` no longer hangs. That is
// sufficient to justify the fix without a correct explanation of the
// failure it fixes.
//
// Every fault class we handle reaches the crash reporter eventually —
// confirmed by per-class `.ips` capture on darwin/arm64:
// abort, segfault, bus, illegal_instruction, trap, and stack_overflow all
// produce one. `termination.byProc` does NOT split cleanly along "port
// attached vs. detached": segfault/bus/illegal_instruction/trap — real
// faults crash-handler detaches and forwards in the same pass — report
// `byProc: exc handler` in every captured instance, and plain `abort`
// reports `byProc: crash_child`, as the dichotomy predicts for both — but
// `stack_overflow` breaks it. It is also a real fault (`EXC_BAD_ACCESS`,
// `KERN_PROTECTION_FAILURE` — a genuine guard-page hit, detached and
// forwarded the same way as the other four) and yet its captured `.ips`
// shows `termination.indicator: Abort trap: 6`, `byProc: crash_child`: the
// forwarded fault reaches Rust's OWN stack-overflow signal handler
// (`std::sys::pal::unix::stack_overflow::imp::signal_handler`, visible in
// the faulting thread's backtrace), which calls `process::abort()` itself.
// So `byProc` does not track which port was attached at fault time; it
// tracks who executed the syscall that actually ended the process — the
// process's own thread (`crash_child`) vs. a registered exception-handling
// agent replying on its behalf (`exc handler`) — and a real, detached fault
// can still end up in the first bucket if something in-process reacts to it
// by calling `abort()`.
//
// Is `stack_overflow` exposed to the same hang, and does this fix
// cover it? MEASURED: no to both, as far as the `_exit` bypass goes.
// `is_macos_sigabrt_relay` requires `kind == EXC_SOFTWARE`; a captured
// `stack_overflow` marker instead carries `code=0x1` (`EXC_BAD_ACCESS`) in
// 5/5 local runs — `on_crash` sees the genuine guard-page fault, not a
// SIGABRT relay, so the `_exit(EX_SOFTWARE)` bypass below never fires for
// it, and this PR does not extend it to. All 5 runs still exited promptly
// (134 = default SIGABRT disposition, the in-process `abort()` above going
// unintercepted post-detach — not a hang, and not this fix's doing). That is
// NOT a guarantee `stack_overflow` can never hang the way `abort`'s SIGABRT
// relay did: 5 local runs is not the intermittent, load-sensitive CI
// condition the hang was observed under. What IS source-grounded, not
// inferred, is that `stack_overflow` cannot take the non-detaching code path
// abort's relay takes: a guard-page hit is delivered through
// `crash-handler`'s `MessageIds::Exception`/`ExceptionStateIdentity` handler
// (`mac/state.rs`), the same branch that calls `detach(true)` for every
// other real fault class above, whereas the SIGABRT relay is delivered
// through the separate `MessageIds::SignalCrash` handler (`mac/state.rs`),
// which never calls `detach` at all. That is a
// verified difference in which code path each class takes through the
// vendored crate — not a claim about what the kernel does with either port
// afterward, which remains unknown. What would settle the open question:
// the same 8-run, probe-instrumented measurement done above for `abort`, run
// instead against `stack_overflow` under sustained CI-like load (parallel
// test-suite pressure), watching for a stalled `wait_bounded`. Absent that,
// `wait_bounded`'s 60s bound — not the `_exit` bypass — is the only thing
// standing between a hypothetical `stack_overflow` hang and consuming the
// whole job's wall, exactly as it was before this PR; the risk is
// unmeasured, not eliminated.
//
// `on_crash` is not wired to see which detour a given call took (the SIGABRT
// relay's "handled" reply is discarded — see the signal handler's ignored
// return value — so returning `Handled(true)` there would not skip the
// reporter hop the way it does for a real exception), so the escape is
// structural: recognize the relay's exact signature and terminate before
// `abort()`'s guaranteed re-raise can run at all.
// `any(test, feature = "crash-child")`, not a bare `target_os = "macos"`:
// this predicate exists only to feed the compile-time-gated `_exit` bypass
// in `on_crash` below (crash-child builds) or the unit tests in
// `crash_tests.rs` (test builds) — a plain macOS release build (neither) has
// no caller for it, and leaving it universally compiled would make it dead
// code there.
#[cfg(all(target_os = "macos", any(test, feature = "crash-child")))]
fn is_macos_sigabrt_relay(ctx: &crash_handler::CrashContext) -> bool {
    matches!(
        ctx.exception,
        Some(crash_context::ExceptionInfo {
            kind: mach2::exception_types::EXC_SOFTWARE,
            code,
            subcode: Some(subcode),
        }) if code == mach2::exception_types::EXC_SOFT_SIGNAL as u64 && subcode == libc::SIGABRT as u64
    )
}

// SAFETY: on_crash runs in a COMPROMISED context (heap + locks unsafe). For
// the always-on marker it does ONLY signal-safe work: a raw file open/write
// from a stack buffer + the pre-encoded marker path, with no heap allocation
// on the success path (the windows-crate wrappers allocate only on their
// discarded failure paths, where the marker is lost anyway — best-effort),
// no `format!`, no locks, and no tracing — this path is total across
// Windows / macOS / Linux.
//
// The macOS-only `_exit` bypass below is likewise signal-safe (a bare
// syscall — no atexit, no libc/heap state) and runs IMMEDIATELY after the
// marker is durable, BEFORE the minidump branch — and only if the marker
// write itself reported success (`write_marker_signal_safe`'s `bool`
// return, also signal-safe): a failed write must fall through to the OS
// reporter instead of exiting with zero diagnostics.
//
// That ordering is deliberate, not cosmetic. HYPOTHESIS, not confirmed:
// vendored `crash-handler`'s Mach message loop (`mac/state.rs`) Mach-
// suspends every other thread (`ScopedSuspend::new()`) before calling into
// the user callback (`on_crash`), and on the SIGABRT-relay path the
// suspended thread is the ABORTING thread itself — unlike a genuine
// hardware fault, which halts at the faulting instruction, outside any
// lock. The relay's own `send_message` does a `mach_msg` SEND (which wakes
// the handler thread into that suspend) and then immediately blocks on a
// condvar; that wait's first park in the process allocates internally
// (`parking_lot_core::create_hashtable` → `Box::into_raw`). This is
// CONSISTENT WITH, and PREDICTS, the observed abort-vs-fault asymmetry and
// the darwin/amd64 load sensitivity: if the suspend lands while the
// aborting thread holds the allocator's lock, any other allocation is
// exactly what would deadlock. It is NOT DIRECTLY OBSERVED — no
// suspended-thread backtrace has confirmed the allocator lock actually held
// at suspend time. What would confirm it: a backtrace of the suspended
// thread captured at the moment `write_minidump_best_effort` hangs, showing
// that lock held. Because the minidump branch itself allocates
// (`dmp_path_from_marker` builds a `PathBuf`, `File::create` builds a
// `CString`, `MinidumpWriter` allocates internally), it must never run
// before the `_exit` escape has had its chance on an allocation-free path.
//
// The minidump branch is DEV-ONLY (never linked in release/shipped
// binaries), Win/mac ONLY (no in-process minidump on Linux — see the Linux
// carve-out at `write_minidump_best_effort`), and MAY allocate / run
// non-signal-safe code — accepted because it runs strictly AFTER the
// signal-safe marker (and the `_exit` escape) have already had their turn,
// so a fault inside the dump branch cannot lose the breadcrumb.
unsafe impl crash_handler::CrashEvent for MarkerCrashEvent {
    fn on_crash(&self, context: &crash_handler::CrashContext) -> crash_handler::CrashEventResult {
        // 1. ALWAYS (Win/mac/Linux): write the signal-safe marker first.
        let marker_written = write_marker_signal_safe(self.state, context);
        // `marker_written` is read below only on macOS `crash-child` builds
        // (it gates the test-only `_exit` bypass); this no-op read keeps it
        // from tripping `unused_variables` under `-D warnings` on every other
        // build, where nothing else consumes it.
        let _ = marker_written;

        // 2. macOS-ONLY: stop the system crash reporter from ever seeing
        // THIS SPECIFIC process kind, instead of relying on it to behave.
        //
        // Gated `feature = "crash-child"` as a COMPILE-TIME fact narrows WHEN
        // this code exists at all — it is off by default, and shipped
        // gui/bridge/galoshes builds never link it in (see Cargo.toml). It
        // does NOT narrow WHICH process it can fire in once the feature IS
        // on: Cargo's feature unification builds one `tombstone` with
        // `crash-child` enabled for the WHOLE dependency graph under a given
        // `cargo`/`nextest` invocation, and CI's nextest run (ci.yaml) covers
        // `package(hole-common)` in the SAME invocation as
        // `package(tombstone)` — so `hole-common`'s own log-bridge test
        // helpers (`logging_test_helpers.rs`, which call
        // `logging::init(..., "test", ...)` → `tombstone::attach("test",
        // log_dir)`) compile this branch in too. The runtime `kind` check
        // below is therefore the ONLY thing that confines the bypass to
        // `crash_child`: that bin attaches under its own dedicated
        // `"crash-child"` kind (see its module doc comment), a string no
        // other caller in the workspace uses, so a SIGABRT in
        // `hole-common`'s test subprocess still reaches the OS reporter
        // instead of being silently rewritten to a clean `_exit(70)`. See
        // `is_macos_sigabrt_relay` for why only the SIGABRT relay needs this
        // at all.
        //
        // Three tests pin this conjunction, each covering the condition the
        // others can't: `crash_marker_abort` (`tests/crash_child.rs`)
        // asserts the child's exit status IS `EX_SOFTWARE` — measured to
        // fail if the whole `if` is disabled, but NOT if only
        // `is_macos_sigabrt_relay(context)` is dropped, since
        // `self.state.kind == "crash-child"` alone still lets abort's relay
        // through. `crash_marker_segfault` closes exactly that gap: a real
        // fault's `CrashContext` never matches `is_macos_sigabrt_relay`, so
        // it asserts the child instead dies by its real signal (`SIGSEGV`)
        // — measured to fail (child wrongly exits 70) if
        // `is_macos_sigabrt_relay(context)` is dropped, because this process
        // also runs under `kind == "crash-child"`. `crash_marker_abort_non_crash_child_kind_still_dies_by_sigabrt`
        // closes the kind-discriminator gap itself: it spawns `crash_child`
        // with `TOMBSTONE_TEST_ATTACH_KIND=test`, i.e. the exact kind
        // `hole-common`'s log-bridge tests use, and asserts the child dies
        // by real `SIGABRT` instead of taking the bypass — measured to fail
        // (child wrongly exits 70) if the `kind` string this `if` compares
        // against is widened back to `"test"`.
        #[cfg(all(target_os = "macos", feature = "crash-child"))]
        if marker_written && self.state.kind == "crash-child" && is_macos_sigabrt_relay(context) {
            // SAFETY: `_exit` is async-signal-safe (POSIX.1-2017 §2.4.3): a
            // bare syscall, no atexit handlers, no libc/heap state touched.
            // Terminating here — before returning from this call, and so
            // before `abort()`'s guaranteed re-raise can run — means the
            // real `EXC_CRASH` this relay would otherwise trigger never
            // happens, and the child never reaches the host-level exception
            // port (ReportCrash). 70 is sysexits.h's `EX_SOFTWARE` (not in
            // the `libc` crate — it's BSD-only cruft), documenting
            // "abnormal, internal" in the exit status that
            // `crash_marker_abort` asserts on.
            const EX_SOFTWARE: i32 = 70;
            unsafe { libc::_exit(EX_SOFTWARE) };
        }

        // 3. dev-only, Win/mac ONLY: best-effort minidump. Linux gets NO
        // in-process minidump — even with crash-dumps enabled, tombstone writes
        // only the marker there. See the Linux carve-out at
        // `write_minidump_best_effort`. Runs AFTER the `_exit` bypass above —
        // see the SAFETY comment on this impl for why the ordering matters.
        #[cfg(all(feature = "crash-dumps", any(windows, target_os = "macos")))]
        write_minidump_best_effort(self.state, context);

        // Forward to the OS default (Windows: WER LocalDumps; macOS: previous
        // Mach exception port → .ips; Linux: re-raises the default signal
        // disposition → core dump if enabled). Only ever construct
        // Handled(_) — Jump is not used.
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
