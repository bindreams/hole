//! Shared stale-ETW-session sweep used by both
//! [`crate::diagnostics::etw`] and
//! [`crate::diagnostics::netsh_trace`].
//!
//! Both modules need the same Win32 `QueryAllTracesW` +
//! `ControlTraceW(STOP)` dance to clean up orphaned sessions left by a
//! crashed prior bridge run. The only per-caller difference is the
//! session-name prefix and a short log-target string to distinguish
//! output in `bridge.log`. Duplicating 80 lines of unsafe Win32 ETW
//! plumbing once per module would be a DRY violation flagged by the
//! project's CLAUDE.md; this helper centralises the unsafe block.

use tracing::{debug, info, warn};

/// Enumerate live ETW sessions via `QueryAllTracesW` and stop any
/// whose name starts with `prefix`. Best-effort: any failure is logged
/// via the provided `log_target` at `warn!`, never panics.
///
/// `log_target` is a short string (e.g. `"etw"`, `"netsh-trace"`) that
/// prefixes emitted log messages so operators can distinguish which
/// subsystem is sweeping. It's concatenated with a literal message via
/// `format!` because `tracing`'s `target:` attribute must be a `'static`
/// string literal and we want caller-supplied dynamic context.
pub(crate) fn sweep_sessions_with_prefix(prefix: &str, log_target: &str) {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Diagnostics::Etw::{
        ControlTraceW, QueryAllTracesW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_PROPERTIES,
    };

    const MAX_SESSIONS: usize = 128;
    // EVENT_TRACE_PROPERTIES is followed by two inline strings (logger
    // name + log file name). 1 KB per string is generous.
    const STRING_RESERVE: usize = 1024;
    const PROPERTIES_SIZE: usize = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 2 * STRING_RESERVE;

    let mut buffer = vec![0u8; PROPERTIES_SIZE * MAX_SESSIONS];
    let mut pointers: Vec<*mut EVENT_TRACE_PROPERTIES> = Vec::with_capacity(MAX_SESSIONS);
    for i in 0..MAX_SESSIONS {
        // SAFETY: we own `buffer` and lay out one properties-sized slot
        // per index; Windows fills them in via QueryAllTracesW.
        let p = unsafe {
            buffer
                .as_mut_ptr()
                .add(i * PROPERTIES_SIZE)
                .cast::<EVENT_TRACE_PROPERTIES>()
        };
        unsafe {
            (*p).Wnode.BufferSize = PROPERTIES_SIZE as u32;
            (*p).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*p).LogFileNameOffset = (std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + STRING_RESERVE) as u32;
        }
        pointers.push(p);
    }

    let mut session_count: u32 = 0;
    // SAFETY: QueryAllTracesW takes an array of pre-initialised
    // EVENT_TRACE_PROPERTIES pointers, fills them in, and writes the
    // count to the out parameter. Returns WIN32_ERROR (not Result).
    let query_err = unsafe { QueryAllTracesW(&mut pointers, &mut session_count) };
    if query_err != ERROR_SUCCESS {
        warn!(code = query_err.0, "{log_target}: QueryAllTracesW failed during sweep");
        return;
    }

    let count = session_count as usize;
    let mut swept = 0u32;
    for p in pointers.iter().take(count.min(MAX_SESSIONS)).copied() {
        // SAFETY: Windows filled in the null-terminated wide logger name
        // at offset LoggerNameOffset within the allocation we supplied.
        let name_ptr = unsafe {
            (p as *const u8)
                .add(std::mem::size_of::<EVENT_TRACE_PROPERTIES>())
                .cast::<u16>()
        };
        let name = unsafe { crate::diagnostics::etw::read_wide_string(name_ptr) };
        if !name.starts_with(prefix) {
            continue;
        }

        let mut wide: Vec<u16> = name.encode_utf16().collect();
        wide.push(0);

        // SAFETY: `wide` is a null-terminated wide string that outlives
        // this call. `p` is valid for the duration of the sweep. Handle
        // value 0 tells Windows to look up the session by name.
        let stop_err = unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                windows::core::PCWSTR(wide.as_ptr()),
                p,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        if stop_err == ERROR_SUCCESS {
            info!(session = %name, "{log_target}: swept stale session");
            swept += 1;
        } else {
            warn!(
                session = %name,
                code = stop_err.0,
                "{log_target}: failed to stop stale session"
            );
        }
    }
    if swept == 0 {
        debug!("{log_target}: no stale sessions to sweep");
    } else {
        info!(
            swept,
            "{log_target}: swept leftover sessions from prior runs; next start should succeed"
        );
    }
}
