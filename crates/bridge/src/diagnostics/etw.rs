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
//!    b. Builds three [`ferrisetw::Provider`]s with all keywords
//!    enabled. High-volume firehose events are filtered in userspace
//!    via [`HIGH_VOLUME_TCPIP_EVENTS`] rather than at the kernel
//!    level — see [`TCPIP_KEYWORDS`] for the rationale (events 1004,
//!    1077, and the rest of the SendPath family are critical for the
//!    #200 investigation).
//!    c. Starts a [`ferrisetw::UserTrace`] session named
//!    `hole-bridge-etw-<pid>` with `buffer_size = 256` KB to absorb
//!    the wider event volume without kernel ring-buffer overrun.
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
//! 3. [`EtwGuard::drop`] reads session statistics via
//!    `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)`
//!    ([`query_session_stats`]), then calls `UserTrace::stop` (which
//!    signals the kernel to stop delivering events) and joins the
//!    processing thread, guaranteeing the callback drains the pending
//!    event queue before shutdown completes. The pre-stop query
//!    surfaces `EventsLost` and `BuffersWritten` as a diagnostic
//!    cross-check — nonzero `EventsLost` signals buffer overrun. See
//!    [Drain on Drop](#drain-on-drop) below.
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
//! GUIDs and the per-provider keyword masks. All three providers
//! subscribe to every keyword bit (`!0`); high-volume events are
//! dropped by event-ID in the userspace [`dispatch`] callback via
//! [`HIGH_VOLUME_TCPIP_EVENTS`]. See the rationale comment on
//! [`TCPIP_KEYWORDS`] — earlier versions of this module filtered at
//! the kernel level and silently dropped events 1004 and 1077, both
//! of which are critical to the #200 narrative.

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceProperties, TraceTrait, UserTrace};
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

/// All TCPIP provider keywords enabled.
///
/// Background: the module previously excluded the `SendPath`
/// (`0x100000000`), `ReceivePath` (`0x200000000`), and `Packet`
/// (`0x40000000000`) keywords at the kernel level to dodge the
/// per-packet firehose. That exclusion silently dropped the two events
/// the #200 investigation most needs: event **1004 `TcpTcbSynSend`**
/// and event **1077 `SendRetransmitRound`**, both of which declare
/// `ut:SendPath` in the TCPIP manifest. See
/// <https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-TCPIP.xml>
/// for the keyword declarations.
///
/// The high-volume noise is filtered one level up — at the userspace
/// [`dispatch`] callback, by event-ID drop list
/// ([`HIGH_VOLUME_TCPIP_EVENTS`]). That keeps connect-path /
/// retransmit-path events visible while still silencing the truly
/// noisy per-packet IDs.
const TCPIP_KEYWORDS: u64 = !0u64;

/// All WFP provider keywords enabled. Same rationale as
/// [`TCPIP_KEYWORDS`]: we'd rather filter by event-ID at the
/// userspace seam than drop potentially-relevant events at the kernel.
const WFP_KEYWORDS: u64 = !0u64;

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
    pub const TCB_SYN_SEND: u16 = 1004;
    pub const ACCEPT_COMPLETED: u16 = 1017;
    pub const CONNECT_RESTRICTED_SEND: u16 = 1031;
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

/// TCPIP event IDs observed at high volume in CI logs that are not
/// individually useful for the #200 narrative. Dropped inside
/// [`dispatch`] to keep `HOLE_BRIDGE_LOG=debug` output readable without
/// filtering at the kernel level (kernel filtering also masks events
/// we care about — see [`TCPIP_KEYWORDS`]).
///
/// Each entry is a high-rate data-plane or internal-bookkeeping event.
/// Sourced from the event-ID histogram of PR #207 CI run 9 bridge
/// log. When a new Windows build adds high-volume IDs, extend this
/// list rather than re-introducing a kernel-level keyword mask.
const HIGH_VOLUME_TCPIP_EVENTS: &[u16] = &[
    1300, 1324, 1370, 1371, 1391, 1396, 1397, 1443, 1454, 1551, 1589, 1590, 1626,
];

/// Retransmit count at which we escalate from info to warn. Event 1002
/// (and 1077) carry `RexmitCount` as a `UInt32`; three retransmits on a
/// single flow is well into "something is wrong" territory.
const RETRANSMIT_WARN_THRESHOLD: u32 = 3;

// Public types ========================================================================================================

/// RAII guard holding the live ETW session + processing thread.
///
/// Drop sequence: `query_session_stats` (read EventsLost before the
/// handle is consumed) → `UserTrace::stop` → `JoinHandle::join` → the
/// processing thread exits once the kernel acknowledges STOP, which
/// drains the in-flight event queue. See module doc
/// [Drain on Drop](self#drain-on-drop).
pub struct EtwGuard {
    // `Option<UserTrace>` so Drop can `take()` it and consume via
    // `UserTrace::stop(self)` (which takes `self` by value).
    trace: Option<UserTrace>,
    thread: Option<JoinHandle<()>>,
    /// Session name saved at construction time so
    /// `query_session_stats` can look it up in Drop without holding a
    /// reference into `trace`.
    session_name: String,
}

impl Drop for EtwGuard {
    fn drop(&mut self) {
        // Query first, stop second. `UserTrace::stop` consumes the trace
        // by value, so EventsLost can only be read while the session is
        // still live.
        query_session_stats(&self.session_name);

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
    //
    // Buffer sizing: now that [`TCPIP_KEYWORDS`] = !0, kernel event
    // volume per connect rises substantially (SendPath events are no
    // longer dropped). Default `buffer_size` (32 KB per-processor) risks
    // ring-buffer overflow when the test runner is under IO load. Widen
    // to 256 KB; `max_buffer = 0` tells Windows to choose a reasonable
    // ceiling. EventsLost is queried on [`EtwGuard::drop`] so an overrun
    // shows up as a nonzero count in bridge.log.
    let trace_properties = TraceProperties {
        buffer_size: 256,
        ..Default::default()
    };
    let (trace, handle) = UserTrace::new()
        .named(session_name.clone())
        .set_trace_properties(trace_properties)
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
        session_name,
    })
}

/// Query the live ETW session via Win32 `ControlTraceW(QUERY)` and log
/// `events_lost` / `buffers_written` at info level. Called from
/// [`EtwGuard::drop`] before the session is stopped.
///
/// This is a cross-check for the [`TCPIP_KEYWORDS`] widening: if the
/// widened subscription overruns the kernel ring buffer, the lost
/// events count surfaces in bridge.log as diagnostic signal (and a
/// prompt to raise `buffer_size` further).
///
/// Silently skips on query failure — the guard is in a drop path and
/// double-panicking would hide the original error.
fn query_session_stats(session_name: &str) {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Diagnostics::Etw::{
        ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES, WNODE_FLAG_TRACED_GUID,
    };

    const STRING_RESERVE: usize = 1024;
    const PROPERTIES_SIZE: usize = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 2 * STRING_RESERVE;

    let mut buffer = vec![0u8; PROPERTIES_SIZE];
    let props = buffer.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
    // SAFETY: `buffer` is a zero-initialised block large enough to hold
    // one `EVENT_TRACE_PROPERTIES` plus 2 × 1 KB of inline strings; the
    // field writes below are within that allocation.
    //
    // `Wnode.Flags = WNODE_FLAG_TRACED_GUID` is required by
    // `ControlTraceW` to identify the structure as ETW (vs. WMI); MSDN
    // documents this as a must-set field in EVENT_TRACE_PROPERTIES.
    unsafe {
        (*props).Wnode.BufferSize = PROPERTIES_SIZE as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        (*props).LogFileNameOffset = (std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + STRING_RESERVE) as u32;
    }

    let mut wide: Vec<u16> = session_name.encode_utf16().collect();
    wide.push(0);

    // SAFETY: `wide` outlives the call; `props` points into `buffer`;
    // handle value 0 tells Windows to resolve the session by name.
    let err = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            windows::core::PCWSTR(wide.as_ptr()),
            props,
            EVENT_TRACE_CONTROL_QUERY,
        )
    };

    if err != ERROR_SUCCESS {
        warn!(code = err.0, session = %session_name, "etw: ControlTraceW(QUERY) failed");
        return;
    }

    // SAFETY: `props` is a valid `EVENT_TRACE_PROPERTIES` Windows just
    // filled in with session statistics.
    let (events_lost, buffers_written) = unsafe { ((*props).EventsLost, (*props).BuffersWritten) };
    info!(
        session = %session_name,
        events_lost,
        buffers_written,
        "etw: session stats at stop"
    );
    if events_lost > 0 {
        warn!(
            session = %session_name,
            events_lost,
            "etw: kernel dropped events — consider raising TraceProperties.buffer_size"
        );
    }
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
    crate::diagnostics::etw_sweep::sweep_sessions_with_prefix("hole-bridge-etw-", "etw");
}

/// Read a null-terminated UTF-16 string from a raw pointer.
/// # Safety
/// Caller must ensure `ptr` points to a null-terminated UTF-16 buffer.
pub(crate) unsafe fn read_wide_string(ptr: *const u16) -> String {
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
///
/// Field coverage notes (per
/// <https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-TCPIP.xml>):
///
/// - **1002 `TcbRequestConnect`**: `Tcb`, `LocalAddress`, `LocalPort`,
///   `RemoteAddress`, `RemotePort`, `NewState`, `RexmitCount`.
/// - **1004 `TcbSynSend`**: `Tcb`, `Seq`, no address/port fields.
/// - **1031 `ConnectRestrictedSend`**: `Tcb`, `LocalAddress`,
///   `LocalPort`, `RemoteAddress`, `RemotePort`, `Status`.
/// - **1033 `ConnectTcbComplete`**: `Tcb`, `LocalAddress`, `LocalPort`,
///   `RemoteAddress`, `RemotePort`, `Status`.
/// - **1045 `ConnectTcbTimeout`**: `Tcb`, `Seq`, `TcbState`.
/// - **1046 `DisconnectTcbRtoTimeout`**: `Tcb`, `Seq`.
/// - **1077 `SendRetransmitRound`**: `Tcb`, `SndUna`, `SndNxt`,
///   `SegmentSize`, `RexmitCount`.
///
/// The `tcb` field is a kernel-internal 64-bit TCB pointer / cookie
/// that correlates events belonging to the same TCP connection across
/// the connect-path, send-path, and close-path event IDs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ParsedFields {
    pub local_port: Option<u16>,
    pub local_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub remote_addr: Option<IpAddr>,
    pub status: Option<u32>,
    pub rexmit_count: Option<u32>,
    pub tcb: Option<u64>,
}

// SocketAddress binary decoder ========================================================================================

/// Parse a Windows ETW `win:SocketAddress` binary blob into `(ip, port)`.
///
/// The TCPIP and Winsock-AFD manifests encode addresses as raw
/// `SOCKADDR_IN` / `SOCKADDR_IN6` structures in little-endian wire
/// format for the family / port fields:
///
/// - IPv4 (AF_INET = 2, 16 bytes): family (2B LE), port (2B **BE**),
///   addr (4B BE), 8B padding.
/// - IPv6 (AF_INET6 = 23, 28 bytes): family (2B LE), port (2B **BE**),
///   flowinfo (4B), addr (16B), scope_id (4B).
///
/// Port is network-byte-order (big-endian) per POSIX / Winsock
/// convention. Callers hand us the raw bytes Microsoft's manifest
/// declares as `inType="win:Binary" outType="win:SocketAddress"`.
///
/// Returns `None` if bytes are too short for either family or the
/// family field is neither AF_INET nor AF_INET6.
pub(crate) fn parse_socket_address(bytes: &[u8]) -> Option<(IpAddr, u16)> {
    if bytes.len() < 4 {
        return None;
    }
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    match family {
        // AF_INET
        2 => {
            if bytes.len() < 8 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Some((IpAddr::V4(ip), port))
        }
        // AF_INET6
        23 => {
            if bytes.len() < 24 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            Some((IpAddr::V6(std::net::Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
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
///
/// Drops (returns `None`) for:
/// - events from non-bridge PIDs (primary filter — cross-process ETW is
///   not useful for #200 and adds noise),
/// - events in [`HIGH_VOLUME_TCPIP_EVENTS`] from the TCPIP provider (the
///   userspace replacement for the removed kernel-keyword firehose
///   mask).
///
/// Note: provider discrimination is by [`GUID`] — the high-volume drop
/// list is specific to TCPIP; same event IDs on WFP or AFD stay visible.
pub(crate) fn dispatch(
    provider: GUID,
    event_id: u16,
    pid: u32,
    bridge_pid: u32,
    fields: &ParsedFields,
) -> Option<Emission> {
    if pid != bridge_pid {
        return None;
    }

    if is_tcpip_provider(provider) && HIGH_VOLUME_TCPIP_EVENTS.contains(&event_id) {
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
        | tcpip_events::TCB_SYN_SEND
        | tcpip_events::CONNECT_RESTRICTED_SEND
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
///
/// Address handling: TCPIP and Winsock-AFD encode addresses as
/// `win:Binary` blobs with the `win:SocketAddress` outType. We decode
/// those via [`parse_socket_address`]. A minority of events expose
/// discrete `LocalPort` / `RemotePort` scalars; we try those too and
/// prefer whichever resolves. Empty on both paths → `None`.
fn extract_fields(parser: &Parser) -> ParsedFields {
    let (local_addr, local_port_from_addr) = parser
        .try_parse::<Vec<u8>>("LocalAddress")
        .ok()
        .and_then(|bytes| parse_socket_address(&bytes))
        .map_or((None, None), |(a, p)| (Some(a), Some(p)));
    let (remote_addr, remote_port_from_addr) = parser
        .try_parse::<Vec<u8>>("RemoteAddress")
        .ok()
        .and_then(|bytes| parse_socket_address(&bytes))
        .map_or((None, None), |(a, p)| (Some(a), Some(p)));

    ParsedFields {
        tcb: parser.try_parse::<u64>("Tcb").ok(),
        local_port: parser.try_parse::<u16>("LocalPort").ok().or(local_port_from_addr),
        local_addr,
        remote_port: parser.try_parse::<u16>("RemotePort").ok().or(remote_port_from_addr),
        remote_addr,
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
            tcb = ?fields.tcb,
            local_addr = ?fields.local_addr,
            local_port = ?fields.local_port,
            remote_addr = ?fields.remote_addr,
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
            tcb = ?fields.tcb,
            local_addr = ?fields.local_addr,
            local_port = ?fields.local_port,
            remote_addr = ?fields.remote_addr,
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

// Provider GUID discrimination ========================================================================================

/// Test whether a provider GUID identifies the Microsoft-Windows-TCPIP
/// provider declared by [`TCPIP_PROVIDER`]. Extracted as a standalone
/// predicate so [`dispatch`] can apply TCPIP-specific filters without
/// string-parsing the GUID at every event.
fn is_tcpip_provider(provider: GUID) -> bool {
    // Parse the compile-time constant at the seam rather than duplicating
    // the bytes. `GUID::from_u128` would require a hex literal; using the
    // same parser the `ferrisetw::Provider::by_guid` constructor uses
    // keeps the declarations aligned.
    provider == GUID::from(TCPIP_PROVIDER)
}

#[cfg(test)]
#[path = "etw_tests.rs"]
mod etw_tests;
