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
            if !handle.is_invalid() {
                let mut written = 0u32;
                let _ = WriteFile(handle, Some(&buf[..n]), Some(&mut written), None);
                let _ = CloseHandle(handle);
            }
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
            let _ = libc::write(fd, buf.as_ptr() as *const libc::c_void, n);
            let _ = libc::close(fd);
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
    let tid = ctx.thread as u32;
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
    // If HANDLER_STATE is already set (shouldn't happen given the CRASH_HANDLER
    // guard above, but be defensive), bail without attaching.
    if HANDLER_STATE.set(state).is_err() {
        return;
    }
    let state_ref: &'static HandlerState = HANDLER_STATE.get().expect("just set");

    let event = Box::new(MarkerCrashEvent { state: state_ref });
    // SAFETY: crash-handler requires the closure/handler to be valid; our
    // MarkerCrashEvent borrows only 'static state and does signal-safe work.
    match crash_handler::CrashHandler::attach(event) {
        Ok(handler) => {
            // Store to keep it alive (Drop = detach). Ignore the Err arm:
            // if another thread won the race the handler we just attached
            // would detach on drop, which is acceptable (idempotent intent).
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

// SAFETY: on_crash runs in a COMPROMISED context (heap + locks unsafe). For
// the always-on marker it does ONLY signal-safe work: a raw file open/write
// from a stack buffer + the pre-encoded marker path, with no heap allocation,
// no `format!`, no locks, and no tracing — this path is total across
// Windows / macOS / Linux. The minidump branch is DEV-ONLY (never linked in
// release/shipped binaries), Win/mac ONLY (no in-process minidump on Linux —
// see the Linux carve-out at `write_minidump_best_effort`), and MAY allocate /
// run non-signal-safe code — accepted because it runs strictly AFTER the
// signal-safe marker is already durably on disk, so a fault inside the dump
// branch cannot lose the breadcrumb. See review S2/S3.
unsafe impl crash_handler::CrashEvent for MarkerCrashEvent {
    fn on_crash(&self, context: &crash_handler::CrashContext) -> crash_handler::CrashEventResult {
        // 1. ALWAYS (Win/mac/Linux): write the signal-safe marker first.
        write_marker_signal_safe(self.state, context);

        // 2. dev-only, Win/mac ONLY: best-effort minidump. Linux gets NO
        // in-process minidump — even with crash-dumps enabled, tombstone writes
        // only the marker there. See the Linux carve-out at
        // `write_minidump_best_effort`.
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
