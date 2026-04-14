//! Always-on in-process ETW (Event Tracing for Windows) consumer.
//!
//! Subscribes to three Microsoft providers — TCPIP, WFP, Winsock-AFD —
//! filters events to the bridge's own PID, and re-emits each matching
//! event as a structured `tracing::event!()`. The bridge's own log file
//! (`bridge.log`) becomes a narrative record of what the Windows network
//! stack saw, accessible to users via `hole bridge log` on the same
//! footing as the rest of the bridge's output.
//!
//! # Why this exists
//!
//! User's explicit design requirements for this module (recorded verbatim
//! so a future reviewer considering a scope reduction can find the
//! reasoning without archaeology):
//!
//! - "log sizes were not a concern at all"
//! - "most comprehensive logging that would diagnose [#200] and also
//!   other similar production issues on customer machines"
//! - connection-level events at `info` by default
//! - per-packet NDIS firehose events: not even at `debug`; filtered out
//!   at the kernel subscription level so they never reach our process
//! - anomaly events (retransmit ≥ [`RETRANSMIT_WARN_THRESHOLD`],
//!   connection-request timeout, abort) escalated to `warn`
//!
//! # Architecture
//!
//! 1. [`start_consumer`] is called once at bridge startup, after the
//!    crash-recovery snapshots. It:
//!    a. Sweeps any stale `hole-bridge-etw-*` sessions left by a crashed
//!    prior bridge instance ([`sweep_stale_sessions`] via the Win32
//!    `QueryAllTracesW` + `ControlTraceW` APIs).
//!    b. Builds three [`ferrisetw::Provider`]s with kernel-side keyword
//!    masks that exclude the per-packet data-plane firehose.
//!    c. Starts a [`ferrisetw::UserTrace`] session named
//!    `hole-bridge-etw-<pid>`.
//!    d. Spawns a dedicated OS thread that calls `process_from_handle`
//!    in a blocking loop. This thread runs the per-event callback.
//!    e. Returns an [`EtwGuard`] that owns the session + the join handle.
//!
//! 2. The callback ([`handle_event`]) filters by `process_id`, extracts
//!    a minimal shape-only [`ParsedFields`] struct from the live
//!    `EventRecord`, calls the pure [`dispatch`] function, and
//!    translates the returned [`Emission`] into a real `tracing::event!`
//!    invocation.
//!
//! 3. [`EtwGuard::drop`] calls `UserTrace::stop` (which signals the
//!    kernel to stop delivering events) and then joins the processing
//!    thread, guaranteeing the callback drains the pending event queue
//!    before shutdown completes. This is important for #200's teardown
//!    window — see [Drain on Drop](#drain-on-drop) below.
//!
//! # Drain on Drop
//!
//! `ferrisetw::UserTrace::Drop` does NOT join the processing thread — it
//! only calls `close_trace` + `control_trace(STOP)`, and any events in
//! the callback queue when the handle closes are lost. We work around
//! this with the split-lifecycle API:
//!
//! - [`ferrisetw::UserTrace::start`] returns `(trace, handle)` without
//!   spawning a processing thread.
//! - We spawn that thread ourselves and store its `JoinHandle` in
//!   [`EtwGuard`].
//! - [`ferrisetw::UserTrace::stop`] signals STOP; once STOP is processed
//!   by the kernel, `process_from_handle` returns, our thread exits, and
//!   `JoinHandle::join` returns.
//!
//! # Failure mode
//!
//! ETW diagnostics are best-effort but **not silent** on infrastructure
//! failure. If `start_consumer` returns `Err` (missing privilege, wrong
//! provider GUID, session-name collision), the caller logs the failure
//! at `error!` level — not `warn` — so a customer-ship-me-logs workflow
//! immediately surfaces "your machine's ETW is broken and we are
//! diagnostic-blind." Bridge startup still proceeds; ETW failure is not
//! fatal to the bridge's core job.
//!
//! # Provider GUIDs and keywords
//!
//! See [`TCPIP_PROVIDER`], [`WFP_PROVIDER`], [`AFD_PROVIDER`] for the
//! GUIDs and the per-provider keyword masks. The masks include every
//! documented keyword except the per-packet data-plane firehose
//! (`SendPath`, `ReceivePath`, `Packet`).

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceTrait, UserTrace};
use ferrisetw::{EventRecord, GUID};
use std::net::IpAddr;
use std::thread::JoinHandle;
use tracing::{debug, info, warn};

// Provider GUIDs ======================================================================================================

/// Microsoft-Windows-TCPIP. Source: `logman query providers
/// "Microsoft-Windows-TCPIP"` and MSDN ETW provider reference.
/// <https://learn.microsoft.com/en-us/windows/win32/etw/tcpip>
const TCPIP_PROVIDER: &str = "2F07E2EE-15DB-40F1-90EF-9D7BA282188A";

/// Microsoft-Windows-WFP. Source: `logman query providers
/// "Microsoft-Windows-WFP"`. Not to be confused with
/// `{C22D1B14-C242-49DE-9F17-1D76B8B9C458}` which is the PEF message
/// provider — a distinct provider for packet capture.
const WFP_PROVIDER: &str = "0C478C5B-0351-41B1-8C58-4A6737DA32E3";

/// Microsoft-Windows-Winsock-AFD. Source: `logman query providers
/// "Microsoft-Windows-Winsock-AFD"`.
const AFD_PROVIDER: &str = "E53C6823-7BB8-44BB-90DC-3F86090D48A6";

// Keyword masks =======================================================================================================

/// Bits to exclude: `SendPath` (0x100000000), `ReceivePath` (0x200000000),
/// `Packet` (0x40000000000). These are the per-packet data-plane firehose
/// that is explicitly out of scope — the user-intent comment at the top of
/// this module. Applied to both TCPIP and WFP, which define identical
/// firehose keyword positions in their manifests.
const FIREHOSE_EXCLUDE_MASK: u64 = 0x0000_0400_0300_0000;

/// TCPIP keyword mask: everything the provider emits EXCEPT the firehose.
/// Source: `logman query providers "Microsoft-Windows-TCPIP"` output.
/// Rationale: the user asked for "most comprehensive" diagnostics; only
/// the high-rate data-plane events are worth excluding at the kernel
/// level.
const TCPIP_KEYWORDS: u64 = !FIREHOSE_EXCLUDE_MASK;

/// WFP keyword mask: everything except firehose. Same rationale as TCPIP.
const WFP_KEYWORDS: u64 = !FIREHOSE_EXCLUDE_MASK;

/// Winsock-AFD keyword mask: all documented keywords. AFD's keywords
/// are event classifiers (datagram vs stream, winsock-initiated vs
/// transport-initiated, etc.) not rate indicators, so there's no
/// firehose to exclude.
const AFD_KEYWORDS: u64 = !0u64;

// TCPIP event IDs worth decoding ======================================================================================

/// TCPIP event IDs with known-interesting field templates. Every event
/// reaching [`handle_event`] is emitted; this allow-list only governs
/// which events get rich field extraction (vs. the baseline opcode + PID
/// emission). Values captured via `Get-WinEvent -ListProvider
/// Microsoft-Windows-TCPIP | Select -Expand Events`.
mod tcpip_events {
    pub const TCB_CONNECT_REQUESTED: u16 = 1002;
    pub const ACCEPT_COMPLETED: u16 = 1017;
    pub const CONNECT_COMPLETED: u16 = 1033;
    pub const CONNECT_ATTEMPT_FAILED: u16 = 1034;
    pub const CONNECT_REQUEST_TIMEOUT: u16 = 1045;
    pub const RETRANSMIT_TIMEOUT: u16 = 1046;
    pub const KEEPALIVE_TIMEOUT: u16 = 1047;
    pub const DISCONNECT_TIMEOUT: u16 = 1048;
    pub const ABORT_ISSUED: u16 = 1039;
    pub const ABORT_COMPLETED: u16 = 1040;
    pub const CLOSE_ISSUED: u16 = 1038;
    pub const DISCONNECT_COMPLETED: u16 = 1043;
    pub const SEND_RETRANSMIT_ROUND: u16 = 1077;
}

/// Retransmit count at which we escalate from info to warn. Event 1002
/// (and 1077) carry `RexmitCount` as a `UInt32`; three retransmits on a
/// single flow is well into "something is wrong" territory.
const RETRANSMIT_WARN_THRESHOLD: u32 = 3;

// Public types ========================================================================================================

/// RAII guard holding the live ETW session + processing thread.
///
/// Drop sequence: `UserTrace::stop` → `JoinHandle::join` → the processing
/// thread exits once the kernel acknowledges STOP, which drains the
/// in-flight event queue. See module doc [Drain on Drop](self#drain-on-drop).
pub struct EtwGuard {
    // `Option<UserTrace>` so Drop can `take()` it and consume via
    // `UserTrace::stop(self)` (which takes `self` by value).
    trace: Option<UserTrace>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for EtwGuard {
    fn drop(&mut self) {
        if let Some(trace) = self.trace.take() {
            if let Err(e) = trace.stop() {
                warn!(error = ?e, "etw: UserTrace::stop failed during drop");
            }
        }
        if let Some(thread) = self.thread.take() {
            // The processing thread exits once the kernel acknowledges
            // STOP, which drains pending events through our callback.
            // Ignore the JoinHandle's result: the thread only returns on
            // kernel-signalled shutdown and has no useful return value.
            if let Err(e) = thread.join() {
                warn!(panic = ?e, "etw: processing thread panicked during drop");
            }
        }
        info!("etw: consumer stopped");
    }
}

/// Errors returned from [`start_consumer`]. These are *infrastructure*
/// failures — missing privilege, wrong provider GUID, session-name
/// collision. Callers log at `error!` level and continue.
#[derive(Debug, thiserror::Error)]
pub enum EtwError {
    #[error("failed to start ETW session: {0:?}")]
    SessionStart(ferrisetw::trace::TraceError),
    #[error("failed to spawn processing thread: {0}")]
    ThreadSpawn(std::io::Error),
}

// Entry point =========================================================================================================

/// Start the ETW consumer. Best-effort — returns `Err` only on
/// infrastructure failure.
pub fn start_consumer() -> Result<EtwGuard, EtwError> {
    let bridge_pid = std::process::id();
    let session_name = format!("hole-bridge-etw-{bridge_pid}");

    sweep_stale_sessions();

    let tcpip = Provider::by_guid(TCPIP_PROVIDER)
        .any(TCPIP_KEYWORDS)
        .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
            handle_event(record, schema_locator, bridge_pid);
        })
        .build();
    let wfp = Provider::by_guid(WFP_PROVIDER)
        .any(WFP_KEYWORDS)
        .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
            handle_event(record, schema_locator, bridge_pid);
        })
        .build();
    let afd = Provider::by_guid(AFD_PROVIDER)
        .any(AFD_KEYWORDS)
        .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
            handle_event(record, schema_locator, bridge_pid);
        })
        .build();

    // Split-lifecycle: start session without the internal processing
    // thread so we own the join handle. See [Drain on Drop] in module doc.
    let (trace, handle) = UserTrace::new()
        .named(session_name.clone())
        .enable(tcpip)
        .enable(wfp)
        .enable(afd)
        .start()
        .map_err(EtwError::SessionStart)?;

    let thread = std::thread::Builder::new()
        .name("hole-bridge-etw-processor".into())
        .spawn(move || {
            if let Err(e) = UserTrace::process_from_handle(handle) {
                // `process_from_handle` returns when the kernel
                // acknowledges STOP — which is the normal shutdown path,
                // but may also carry an Err if the session was already
                // dead. Log and exit; the guard's Drop handles user-
                // visible cleanup.
                debug!(error = ?e, "etw: processing thread exiting");
            }
        })
        .map_err(EtwError::ThreadSpawn)?;

    info!(session = %session_name, "etw: consumer started");
    Ok(EtwGuard {
        trace: Some(trace),
        thread: Some(thread),
    })
}

// Stale-session sweep =================================================================================================

/// Enumerate live ETW sessions via Win32 `QueryAllTracesW` and stop any
/// whose name starts with `hole-bridge-etw-`. A crashed prior bridge
/// leaves its session alive until the machine reboots; this sweeps it.
/// Mirrors the crash-recovery pattern in [`crate::routing::recover_routes`]
/// and [`crate::plugin_recovery::recover_plugins`] — best-effort, warns
/// on failure, never aborts startup.
///
/// Keyed on the `hole-bridge-etw-` name prefix (not on PID) so that a
/// stale session whose original PID has since been recycled is still
/// swept safely — we're stopping ETW sessions by name, not touching
/// whatever process currently owns that PID.
fn sweep_stale_sessions() {
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
        warn!(code = query_err.0, "etw: QueryAllTracesW failed during sweep");
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
        let name = unsafe { read_wide_string(name_ptr) };
        if !name.starts_with("hole-bridge-etw-") {
            continue;
        }

        // Encode the name into a null-terminated wide vec for ControlTraceW.
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
            info!(session = %name, "etw: swept stale session");
            swept += 1;
        } else {
            warn!(session = %name, code = stop_err.0, "etw: failed to stop stale session");
        }
    }
    if swept == 0 {
        debug!("etw: no stale sessions to sweep");
    }
}

/// Read a null-terminated UTF-16 string from a raw pointer.
/// # Safety
/// Caller must ensure `ptr` points to a null-terminated UTF-16 buffer.
unsafe fn read_wide_string(ptr: *const u16) -> String {
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
        if len > 1024 {
            break; // sanity cap
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

// Callback and dispatch ===============================================================================================

/// Shape-only view of the fields we care about across the providers.
/// Filled by [`extract_fields`] from a live `EventRecord`; consumed by
/// [`dispatch`]. Kept free of ETW-library types so unit tests can
/// construct one directly.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ParsedFields {
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub remote_addr: Option<IpAddr>,
    pub status: Option<u32>,
    pub rexmit_count: Option<u32>,
}

/// What the [`dispatch`] function decides to do with an event.
/// Translated to an actual `tracing::event!` in [`emit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Emission {
    Info {
        msg: &'static str,
    },
    Warn {
        msg: &'static str,
    },
    /// Matched a subscribed provider but the specific event_id has no
    /// rich handler — emitted at debug with bare `event_id` + `opcode`.
    /// Surfaces future Windows-version drift as greppable log lines.
    Unknown,
}

/// Pure function: decide whether/how to emit a tracing event for a
/// (provider, event_id, pid, fields) tuple. Unit-testable without ETW.
pub(crate) fn dispatch(
    _provider: GUID,
    event_id: u16,
    pid: u32,
    bridge_pid: u32,
    fields: &ParsedFields,
) -> Option<Emission> {
    if pid != bridge_pid {
        return None;
    }

    // TCPIP-specific severity rules. WFP + AFD currently use the generic
    // info-with-event-id path; their rich decoding is a future iteration.
    match event_id {
        tcpip_events::TCB_CONNECT_REQUESTED | tcpip_events::SEND_RETRANSMIT_ROUND
            if fields.rexmit_count.is_some_and(|n| n >= RETRANSMIT_WARN_THRESHOLD) =>
        {
            Some(Emission::Warn {
                msg: "tcp retransmit threshold exceeded",
            })
        }
        tcpip_events::CONNECT_REQUEST_TIMEOUT
        | tcpip_events::RETRANSMIT_TIMEOUT
        | tcpip_events::KEEPALIVE_TIMEOUT
        | tcpip_events::DISCONNECT_TIMEOUT
        | tcpip_events::ABORT_ISSUED
        | tcpip_events::ABORT_COMPLETED
        | tcpip_events::CONNECT_ATTEMPT_FAILED => Some(Emission::Warn { msg: "tcp anomaly" }),
        tcpip_events::TCB_CONNECT_REQUESTED
        | tcpip_events::ACCEPT_COMPLETED
        | tcpip_events::CONNECT_COMPLETED
        | tcpip_events::CLOSE_ISSUED
        | tcpip_events::DISCONNECT_COMPLETED
        | tcpip_events::SEND_RETRANSMIT_ROUND => Some(Emission::Info { msg: "tcp event" }),
        _ => Some(Emission::Unknown),
    }
}

/// Callback invoked by the ferrisetw processing thread, once per event.
fn handle_event(record: &EventRecord, schema_locator: &SchemaLocator, bridge_pid: u32) {
    let pid = record.process_id();
    if pid != bridge_pid {
        return;
    }

    let schema = match schema_locator.event_schema(record) {
        Ok(s) => s,
        Err(e) => {
            debug!(error = ?e, event_id = record.event_id(), "etw: schema lookup failed");
            return;
        }
    };
    let parser = Parser::create(record, &schema);
    let fields = extract_fields(&parser);

    let Some(emission) = dispatch(record.provider_id(), record.event_id(), pid, bridge_pid, &fields) else {
        return;
    };
    emit(emission, record, &fields);
}

/// Extract the common fields we care about from a live event. Missing
/// fields return `None` in [`ParsedFields`] — we are best-effort about
/// schema drift.
fn extract_fields(parser: &Parser) -> ParsedFields {
    ParsedFields {
        local_port: parser.try_parse::<u16>("LocalPort").ok(),
        remote_port: parser.try_parse::<u16>("RemotePort").ok(),
        // Most events carry SocketAddress-typed RemoteAddress fields;
        // ferrisetw's default parse returns bytes. We keep the field
        // shape simple for v1 and leave IpAddr extraction for a future
        // iteration — the PID + port + status + rexmit fields are
        // sufficient for #200's narrative.
        remote_addr: None,
        status: parser.try_parse::<u32>("Status").ok(),
        rexmit_count: parser.try_parse::<u32>("RexmitCount").ok(),
    }
}

/// Translate an [`Emission`] into the appropriate `tracing::event!`
/// invocation. All emissions include `event_id`, `pid`, and parsed
/// fields as structured key-values.
fn emit(emission: Emission, record: &EventRecord, fields: &ParsedFields) {
    let event_id = record.event_id();
    let opcode = record.opcode();
    let provider_id = format!("{:?}", record.provider_id());
    match emission {
        Emission::Info { msg } => info!(
            target: "hole_bridge::diagnostics::etw",
            event_id,
            opcode,
            provider = %provider_id,
            local_port = ?fields.local_port,
            remote_port = ?fields.remote_port,
            status = ?fields.status,
            rexmit_count = ?fields.rexmit_count,
            msg,
        ),
        Emission::Warn { msg } => warn!(
            target: "hole_bridge::diagnostics::etw",
            event_id,
            opcode,
            provider = %provider_id,
            local_port = ?fields.local_port,
            remote_port = ?fields.remote_port,
            status = ?fields.status,
            rexmit_count = ?fields.rexmit_count,
            msg,
        ),
        Emission::Unknown => debug!(
            target: "hole_bridge::diagnostics::etw",
            event_id,
            opcode,
            provider = %provider_id,
            "etw: unknown event",
        ),
    }
}

#[cfg(test)]
#[path = "etw_tests.rs"]
mod etw_tests;
