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
//! Logging volume is intentionally unbounded here — the goal is the most
//! comprehensive record that can diagnose hard production network issues
//! on customer machines:
//!
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
//!    level — events 1004, 1077, and the rest of the SendPath family
//!    must stay visible — see [`TCPIP_KEYWORDS`].
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
//! 3. A dedicated timer thread ([`run_periodic_stats_inner`]) ticks
//!    [`query_session_stats`] once immediately and then every
//!    [`LIVE_STATS_INTERVAL`] for as long as the session runs — not only at
//!    shutdown — so a `bridge.log` collected from a still-running bridge
//!    (the common case: users collect logs via Help → Collect Logs while
//!    connected) always carries at least one completeness figure for the
//!    session, from as early as the session start. Repeated query failures
//!    (e.g. another bridge instance sweeping this session — see
//!    [`sweep_stale_sessions`]) throttle to `info!` after the first `warn!`
//!    — loud enough to survive log rotation as standing evidence the
//!    session is gone, quiet enough not to re-flood at `warn!` forever.
//!
//! 4. [`EtwGuard::drop`] first stops the timer thread (closing its shutdown
//!    channel wakes it immediately, not after the rest of the current
//!    interval) and joins it, THEN reads session statistics one final time
//!    via `ControlTraceW(EVENT_TRACE_CONTROL_QUERY)` ([`query_session_stats`])
//!    before calling `UserTrace::stop` (which signals the kernel to stop
//!    delivering events) and joining the processing thread, guaranteeing the
//!    callback drains the pending event queue before shutdown completes.
//!    Stopping the timer thread first is load-bearing, not incidental: it
//!    guarantees no periodic tick can still be mid-query when `trace.stop()`
//!    runs, so the two `query_session_stats` callers (periodic, drop-time)
//!    never race the session teardown and no lock needs to serialize them.
//!    Each stats query surfaces `EventsLost`, `BuffersWritten`,
//!    `LogBuffersLost`, and `RealTimeBuffersLost` as a diagnostic
//!    cross-check — nonzero loss in `EventsLost`, `LogBuffersLost`, or
//!    `RealTimeBuffersLost` escalates to `warn!` (`BuffersWritten` is a
//!    throughput count, not a loss counter, and never escalates);
//!    delta-tracked on the periodic path via [`should_escalate`], so an
//!    unchanging cumulative count doesn't re-warn every tick. See
//!    [Drain on Drop](#drain-on-drop) below.
//!
//! # Drop's added wait
//!
//! Joining the timer thread in `Drop` adds a second, small, bounded
//! blocking wait ahead of the pre-existing processing-thread join — bounded
//! by however long one in-flight `ControlTraceW(QUERY)` call takes (a
//! single synchronous Win32 call, not [`LIVE_STATS_INTERVAL`]), because
//! closing the channel wakes a blocked `recv_timeout` immediately rather
//! than waiting out the interval. This is the same shape of synchronous
//! wait `Drop` already performs for the processing thread, not a new
//! category of blocking risk; it is not solved with a timeout (this
//! project does not paper over synchronization with timeouts).
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
//! [`HIGH_VOLUME_TCPIP_EVENTS`]. Kernel-level keyword filtering is
//! avoided because it also masks events 1004 and 1077, which must stay
//! visible — see the rationale comment on [`TCPIP_KEYWORDS`].
//!
//! # AFD/WFP severity
//!
//! Only TCPIP events get rich event-id-aware severity routing.
//! AFD and WFP events are emitted at DEBUG via [`Emission::Unknown`]
//! until either provider grows a rich handler. This matters because the
//! providers recycle small event IDs (AFD `1002`/`1004` collide with
//! TCPIP `TCB_CONNECT_REQUESTED` / `TCB_SYN_SEND`), so an event-id-only
//! match would misclassify AFD background traffic as INFO-level TCPIP
//! events — [`dispatch`] gates on the provider GUID before applying
//! TCPIP severity.

use dump::{dump, DeriveDump};
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceProperties, TraceTrait, UserTrace};
use ferrisetw::{EventRecord, GUID};
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;
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
/// All keywords are on because events **1004 (`TcpTcbSynSend`)** and
/// **1077 (`SendRetransmitRound`)** declare `ut:SendPath` in the TCPIP
/// manifest; a kernel-level `SendPath` exclusion (to dodge the
/// per-packet firehose) would drop them. See
/// <https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-TCPIP.xml>
/// for the keyword declarations.
///
/// The high-volume noise is instead filtered one level up — at the
/// userspace [`dispatch`] callback, by event-ID drop list
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

/// TCPIP event IDs from [`tcpip_events`] mapped to the Microsoft manifest's
/// `symbol` attribute — the human-readable name `Get-WinEvent` and MSDN both
/// use for these events. Sourced from `Microsoft-Windows-TCPIP.xml`'s
/// `<event value=... symbol=...>` elements (both versions of an event share
/// one symbol, so the base non-`_V1` form covers either). This is the single
/// source of truth [`event_name`] reads from; keep it in sync with
/// `dispatch`'s TCPIP match arms below — a unit test in `etw_tests.rs`
/// enumerates the full `u16` ID space through `dispatch` and fails if an ID
/// classified there has no entry here.
const TCPIP_EVENT_NAMES: &[(u16, &str)] = &[
    (tcpip_events::TCB_CONNECT_REQUESTED, "TcpRequestConnect"),
    (tcpip_events::TCB_SYN_SEND, "TcpTcbSynSend"),
    (tcpip_events::ACCEPT_COMPLETED, "TcpAcceptListenerComplete"),
    (tcpip_events::CONNECT_RESTRICTED_SEND, "TcpConnectTcbProceeding"),
    (tcpip_events::CONNECT_COMPLETED, "TcpConnectTcbComplete"),
    (tcpip_events::CONNECT_ATTEMPT_FAILED, "TcpConnectTcbFailure"),
    (tcpip_events::CLOSE_ISSUED, "TcpCloseTcbRequest"),
    (tcpip_events::ABORT_ISSUED, "TcpAbortTcbRequest"),
    (tcpip_events::ABORT_COMPLETED, "TcpAbortTcbComplete"),
    (tcpip_events::DISCONNECT_COMPLETED, "TcpDisconnectTcbComplete"),
    (tcpip_events::CONNECT_REQUEST_TIMEOUT, "TcpConnectTcbTimeout"),
    (tcpip_events::RETRANSMIT_TIMEOUT, "TcpDisconnectTcbRtoTimeout"),
    (tcpip_events::KEEPALIVE_TIMEOUT, "TcpDisconnectTcbKeepaliveTimeout"),
    (tcpip_events::DISCONNECT_TIMEOUT, "TcpDisconnectTcbTimeout"),
    (tcpip_events::SEND_RETRANSMIT_ROUND, "TcpDataTransferRetransmitRound"),
];

/// Look up the symbolic name for an event, gated on provider the same way
/// [`dispatch`] gates TCPIP-specific classification — AFD and WFP recycle
/// small event-id integers that collide with TCPIP's, so a bare `event_id`
/// lookup without the provider check would misname them. Returns `None`
/// (rendered `~` in `bridge.log`) for a non-TCPIP provider or a TCPIP
/// `event_id` outside [`TCPIP_EVENT_NAMES`].
pub(crate) fn event_name(provider: GUID, event_id: u16) -> Option<&'static str> {
    if !is_tcpip_provider(provider) {
        return None;
    }
    TCPIP_EVENT_NAMES
        .iter()
        .find(|(id, _)| *id == event_id)
        .map(|(_, name)| *name)
}

/// TCPIP event IDs observed at high volume that are not individually
/// useful — high-rate data-plane or internal-bookkeeping events.
/// Dropped inside [`dispatch`] to keep `HOLE_BRIDGE_LOG=debug` output
/// readable without filtering at the kernel level (kernel filtering also
/// masks events we care about — see [`TCPIP_KEYWORDS`]).
///
/// When a new Windows build adds high-volume IDs, extend this list
/// rather than re-introducing a kernel-level keyword mask.
const HIGH_VOLUME_TCPIP_EVENTS: &[u16] = &[
    1300, 1324, 1370, 1371, 1391, 1396, 1397, 1443, 1454, 1551, 1589, 1590, 1626,
];

/// Retransmit count (events 1002/1077 `RexmitCount`) at which we
/// escalate from info to warn; three retransmits on a single flow is
/// well into "something is wrong" territory.
const RETRANSMIT_WARN_THRESHOLD: u32 = 3;

// Public types ========================================================================================================

/// RAII guard holding the live ETW session, its processing thread, and the
/// periodic live-stats timer thread. Drop order and rationale: see module
/// doc [Drain on Drop](self#drain-on-drop) and [Drop's added wait](self#drops-added-wait).
pub struct EtwGuard {
    // `Option<UserTrace>` so Drop can `take()` it and consume via
    // `UserTrace::stop(self)` (which takes `self` by value).
    trace: Option<UserTrace>,
    thread: Option<JoinHandle<()>>,
    /// Session name saved at construction time so
    /// `query_session_stats` can look it up in Drop without holding a
    /// reference into `trace`.
    session_name: String,
    /// Dropping this closes the channel, waking the stats timer thread's
    /// blocked `recv_timeout` immediately instead of waiting out the rest
    /// of `LIVE_STATS_INTERVAL`.
    stats_tx: Option<mpsc::Sender<()>>,
    stats_thread: Option<JoinHandle<()>>,
}

impl Drop for EtwGuard {
    fn drop(&mut self) {
        // Stop the periodic timer thread FIRST and join it, so no live-phase
        // query can still be in flight when the stop-phase query and
        // trace.stop() below run — see module doc "Drop's added wait".
        drop(self.stats_tx.take());
        if let Some(stats_thread) = self.stats_thread.take() {
            if let Err(e) = stats_thread.join() {
                warn!(panic = ?e, "etw: live-stats thread panicked during drop");
            }
        }

        // Query first, stop second. `UserTrace::stop` consumes the trace
        // by value, so the loss counters can only be read while the
        // session is still live. One-shot call: unconditional warn on
        // either a query failure or nonzero loss — there is no "previous
        // tick" to throttle repeats against.
        match query_session_stats(&self.session_name, "stop") {
            Ok(stats) => {
                if stats.events_lost > 0 || stats.log_buffers_lost > 0 || stats.real_time_buffers_lost > 0 {
                    warn_loss("stop", &self.session_name, stats);
                }
            }
            Err(code) => {
                warn!(phase = "stop", code, session = %self.session_name, "etw: ControlTraceW(QUERY) failed");
            }
        }

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

    start_consumer_named(session_name, LIVE_STATS_INTERVAL, |_tick_count| {})
}

/// Test-only entry point: builds a full [`EtwGuard`] — real session,
/// processing thread, and stats timer — under a caller-chosen session name
/// and stats interval, with an observer callback for each stats tick (the
/// same test seam [`run_periodic_stats_inner`] exposes, threaded one level
/// up so a privileged test can exercise the real [`EtwGuard::drop`] path
/// rather than [`run_periodic_stats_inner`] in isolation). Does not sweep
/// `hole-bridge-etw-*` — callers use their own private session-name prefix
/// and sweep it themselves, matching `etw_live_privileged_tests`'
/// convention.
#[cfg(test)]
fn start_consumer_for_test(
    session_name: String,
    interval: Duration,
    on_tick: impl FnMut(u32) + Send + 'static,
) -> Result<EtwGuard, EtwError> {
    start_consumer_named(session_name, interval, on_tick)
}

fn start_consumer_named(
    session_name: String,
    interval: Duration,
    on_tick: impl FnMut(u32) + Send + 'static,
) -> Result<EtwGuard, EtwError> {
    let bridge_pid = std::process::id();
    // Captured once and propagated into both spawned threads below via
    // `tracing::dispatcher::with_default`: `tracing::subscriber::set_default`
    // (what `garter::tracing_test::set_default_in_current_thread` — and any
    // caller relying on a non-global default — installs) is strictly
    // thread-local, so without this, events logged from the processing or
    // stats-timer threads would silently miss a caller's non-global
    // subscriber. In production this is the already-active global default,
    // so propagating it is a no-op.
    let dispatch = tracing::dispatcher::get_default(tracing::Dispatch::clone);

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
    // thread so we own the join handle. See the "Drain on Drop" section
    // of the module doc.
    //
    // Buffer sizing: with all TCPIP keywords enabled, per-connect event
    // volume is high (SendPath included). Default `buffer_size` (32 KB
    // per-processor) risks ring-buffer overflow under IO load; widen to
    // 256 KB. `max_buffer = 0` tells Windows to choose a reasonable
    // ceiling. `query_session_stats` reads EventsLost periodically and once
    // more at drop, so an overrun surfaces as a nonzero count in bridge.log
    // well before shutdown.
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

    let processor_dispatch = dispatch.clone();
    let thread = std::thread::Builder::new()
        .name("hole-bridge-etw-processor".into())
        .spawn(move || {
            tracing::dispatcher::with_default(&processor_dispatch, || {
                if let Err(e) = UserTrace::process_from_handle(handle) {
                    // `process_from_handle` returns when the kernel
                    // acknowledges STOP — which is the normal shutdown path,
                    // but may also carry an Err if the session was already
                    // dead. Log and exit; the guard's Drop handles user-
                    // visible cleanup.
                    debug!(error = ?e, "etw: processing thread exiting");
                }
            });
        })
        .map_err(EtwError::ThreadSpawn)?;

    // Best-effort, unlike the session/processing-thread spawns above: by
    // this point the processing thread is already live and consuming real
    // events, so a fallible `?` here would tear the whole consumer down
    // (dropping `trace` without joining `thread` — see the module's
    // "Drain on Drop" contract) over the failure of a purely supplementary
    // 60-second diagnostics timer. Missing live stats is a degraded
    // diagnostic, not a reason to lose ETW event logging entirely.
    let (stats_tx, stats_rx) = mpsc::channel::<()>();
    let stats_session_name = session_name.clone();
    let stats_thread_spawn = std::thread::Builder::new()
        .name("hole-bridge-etw-live-stats".into())
        .spawn(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                run_periodic_stats_inner(stats_session_name, interval, stats_rx, on_tick);
            });
        });
    let (stats_tx, stats_thread) = match stats_thread_spawn {
        Ok(handle) => (Some(stats_tx), Some(handle)),
        Err(e) => {
            warn!(error = ?e, "etw: failed to spawn live-stats timer thread; continuing without periodic stats");
            (None, None)
        }
    };

    info!(session = %session_name, "etw: consumer started");
    Ok(EtwGuard {
        trace: Some(trace),
        thread: Some(thread),
        session_name,
        stats_tx,
        stats_thread,
    })
}

/// Last-observed value of each cumulative loss counter
/// [`EVENT_TRACE_PROPERTIES`] reports, so a caller ticking
/// [`query_session_stats`] repeatedly can escalate only on a genuine
/// change instead of re-warning forever once a counter goes nonzero.
/// `buffers_written` is deliberately excluded — it's a throughput count,
/// not a loss counter, and never escalates.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct LastSeenLoss {
    events_lost: u32,
    log_buffers_lost: u32,
    real_time_buffers_lost: u32,
}

/// Decide whether a fresh stats reading is worth escalating to `warn!`,
/// and advance `last` to the fresh reading either way.
///
/// Compares by inequality (`!=`), not `>`: all three counters are monotonic
/// cumulative counts for the life of the session, so a `current < last`
/// reading can only mean a `u32` wraparound, and `>` would silently treat
/// that as "no increase" — resetting the escalation baseline to a lower
/// value and requiring loss to climb back above the pre-wrap high-water
/// mark before warning again. `!=` still registers a post-wrap value as a
/// change. All three counters get identical treatment; there is no reason
/// for `log_buffers_lost` or `real_time_buffers_lost` to re-warn on every
/// unchanged tick while `events_lost` does not.
fn should_escalate(
    last: &mut LastSeenLoss,
    current_events_lost: u32,
    current_log_buffers_lost: u32,
    current_real_time_buffers_lost: u32,
) -> bool {
    let changed = current_events_lost != last.events_lost
        || current_log_buffers_lost != last.log_buffers_lost
        || current_real_time_buffers_lost != last.real_time_buffers_lost;
    last.events_lost = current_events_lost;
    last.log_buffers_lost = current_log_buffers_lost;
    last.real_time_buffers_lost = current_real_time_buffers_lost;
    changed
}

/// Shared `warn!` for a nonzero-loss reading, called from both the
/// one-shot drop-time query and the throttled periodic tick so the two
/// callers can never drift into differently-shaped log lines for the same
/// event class.
fn warn_loss(phase: &'static str, session_name: &str, stats: SessionStats) {
    warn!(
        phase,
        session = %session_name,
        events_lost = stats.events_lost,
        log_buffers_lost = stats.log_buffers_lost,
        real_time_buffers_lost = stats.real_time_buffers_lost,
        "etw: kernel dropped events — consider raising TraceProperties.buffer_size"
    );
}

/// Cadence for the periodic live-session stats query — see
/// [`run_periodic_stats_inner`]. Matches the existing
/// `dns::forwarder::SUMMARY_INTERVAL` precedent elsewhere in this crate.
const LIVE_STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Session statistics read by [`query_session_stats`]. All four fields are
/// monotonic cumulative counters for the life of the session (never reset
/// except by session recreation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionStats {
    events_lost: u32,
    buffers_written: u32,
    log_buffers_lost: u32,
    real_time_buffers_lost: u32,
}

/// Query the live ETW session via Win32 `ControlTraceW(QUERY)` — works
/// against a running session; MSDN does not gate `EVENT_TRACE_CONTROL_QUERY`
/// on the session stopping. Called both from the periodic timer thread
/// (`phase = "live"`) and once from [`EtwGuard::drop`] (`phase = "stop"`)
/// before the session is actually stopped.
///
/// Logs nothing on failure — that decision belongs to the caller, since the
/// one-shot drop-time caller and the repeating periodic caller need
/// different failure-logging policies (the periodic caller throttles
/// repeats; see [`live_stats_tick`]). Logs exactly one `info!` on success,
/// with a phase-tagged message shared by both callers so a shipped line
/// never claims a phase it isn't in (e.g. a "live" query does not carry an
/// "at stop" message).
fn query_session_stats(session_name: &str, phase: &'static str) -> Result<SessionStats, u32> {
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
        return Err(err.0);
    }

    // SAFETY: `props` is a valid `EVENT_TRACE_PROPERTIES` Windows just
    // filled in with session statistics.
    let stats = unsafe {
        SessionStats {
            events_lost: (*props).EventsLost,
            buffers_written: (*props).BuffersWritten,
            log_buffers_lost: (*props).LogBuffersLost,
            real_time_buffers_lost: (*props).RealTimeBuffersLost,
        }
    };
    info!(
        phase,
        session = %session_name,
        events_lost = stats.events_lost,
        buffers_written = stats.buffers_written,
        log_buffers_lost = stats.log_buffers_lost,
        real_time_buffers_lost = stats.real_time_buffers_lost,
        "etw: session stats"
    );
    Ok(stats)
}

/// One tick of the periodic live-stats loop: query the live session and
/// escalate per [`should_escalate`]. Query failures throttle to `info!`
/// after the first `warn!` (via `last_query_failed`) — necessary because a
/// session another bridge instance swept (see [`sweep_stale_sessions`])
/// turns every subsequent tick into a permanent, expected failure for the
/// rest of this process's life; the repeat stays at `info!` rather than
/// dropping to `debug!` (below the bridge's default file-sink level) so a
/// `bridge.log` rotated hours later still carries a recent, self-describing
/// record that the session is gone — not silence indistinguishable from a
/// healthy bridge that simply logs no ETW.
fn live_stats_tick(session_name: &str, last_loss: &mut LastSeenLoss, last_query_failed: &mut bool) {
    match query_session_stats(session_name, "live") {
        Ok(stats) => {
            *last_query_failed = false;
            if should_escalate(
                last_loss,
                stats.events_lost,
                stats.log_buffers_lost,
                stats.real_time_buffers_lost,
            ) {
                warn_loss("live", session_name, stats);
            }
        }
        Err(code) => {
            if *last_query_failed {
                info!(phase = "live", code, session = %session_name, "etw: ControlTraceW(QUERY) still failing");
            } else {
                warn!(phase = "live", code, session = %session_name, "etw: ControlTraceW(QUERY) failed");
            }
            *last_query_failed = true;
        }
    }
}

/// Drives [`live_stats_tick`] once immediately (so the session's baseline
/// reading — and later deltas measured against it — are in `bridge.log`
/// from the earliest moment a still-running bridge's log can be collected,
/// not only after the first [`LIVE_STATS_INTERVAL`] elapses) and then on a
/// real, cancellable interval: `stop_rx.recv_timeout(interval)` blocks
/// until either `interval` elapses (a `Timeout` — tick) or the sender is
/// dropped (a `Disconnected` — exit immediately, without waiting out the
/// rest of the current interval). `on_tick` is a test seam: production
/// (via [`start_consumer`]) passes a no-op; a test can observe real ticks
/// — including the immediate baseline one, numbered `1` — by blocking on a
/// channel this closure sends into, without sleeping.
fn run_periodic_stats_inner(
    session_name: String,
    interval: Duration,
    stop_rx: mpsc::Receiver<()>,
    mut on_tick: impl FnMut(u32),
) {
    let mut last_loss = LastSeenLoss::default();
    let mut last_query_failed = false;
    let mut tick_count = 0u32;

    live_stats_tick(&session_name, &mut last_loss, &mut last_query_failed);
    tick_count += 1;
    on_tick(tick_count);

    loop {
        match stop_rx.recv_timeout(interval) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                live_stats_tick(&session_name, &mut last_loss, &mut last_query_failed);
                tick_count += 1;
                on_tick(tick_count);
            }
        }
    }
}

// Stale-session sweep =================================================================================================

/// Enumerate live ETW sessions via Win32 `QueryAllTracesW` and stop any
/// whose name starts with `hole-bridge-etw-`. A crashed prior bridge
/// leaves its session alive until the machine reboots; this sweeps it.
/// Best-effort: warns on failure, never aborts startup.
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
/// - **1002 `TcpRequestConnect`**: `Tcb`, `LocalAddress`, `LocalPort`,
///   `RemoteAddress`, `RemotePort`, `NewState`, `RexmitCount`.
/// - **1004 `TcpTcbSynSend`**: `Tcb`, `Seq`, no address/port fields.
/// - **1031 `TcpConnectTcbProceeding`**: `Tcb`, `LocalAddress`,
///   `LocalPort`, `RemoteAddress`, `RemotePort`, `Status`.
/// - **1033 `TcpConnectTcbComplete`**: `Tcb`, `LocalAddress`, `LocalPort`,
///   `RemoteAddress`, `RemotePort`, `Status`.
/// - **1045 `TcpConnectTcbTimeout`**: `Tcb`, `Seq`, `TcbState`.
/// - **1046 `TcpDisconnectTcbRtoTimeout`**: `Tcb`, `Seq`.
/// - **1077 `TcpDataTransferRetransmitRound`**: `Tcb`, `SndUna`, `SndNxt`,
///   `SegmentSize`, `RexmitCount`.
///
/// Every event in the "has address" group above ships its IP and port
/// atomically inside the same `win:SocketAddress` binary blob (SOCKADDR_IN
/// / SOCKADDR_IN6), so `local` / `remote` are `Option<SocketAddr>` — not
/// two independent `Option<IpAddr>` + `Option<u16>` pairs. No subscribed
/// event delivers a port scalar without an address blob; if a future
/// Windows schema adds an event with a port-only shape, both fields will
/// surface as `None` and [`socket_addr_field`] logs a `debug!`
/// breadcrumb to bridge.log.
///
/// The `tcb` field is a kernel-internal 64-bit TCB pointer / cookie
/// that correlates events belonging to the same TCP connection across
/// the connect-path, send-path, and close-path event IDs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ParsedFields {
    pub local: Option<SocketAddr>,
    pub remote: Option<SocketAddr>,
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
pub(crate) fn parse_socket_address(bytes: &[u8]) -> Option<SocketAddr> {
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
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        // AF_INET6
        23 => {
            if bytes.len() < 24 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            Some(SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(octets)), port))
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
///   just noise here),
/// - events in [`HIGH_VOLUME_TCPIP_EVENTS`] from the TCPIP provider
///   (userspace firehose filter — see [`TCPIP_KEYWORDS`]).
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

    // Provider gate. TCPIP, AFD, and WFP all recycle small event-id
    // integers (1002, 1004, 1017, …), so a bare `match event_id` would
    // emit AFD/WFP events as TCPIP `TCB_CONNECT_REQUESTED` /
    // `TCB_SYN_SEND` / etc. at INFO. AFD and WFP have no rich handlers
    // yet, so they surface at DEBUG via `Emission::Unknown` until one
    // exists.
    if !is_tcpip_provider(provider) {
        return Some(Emission::Unknown);
    }

    if HIGH_VOLUME_TCPIP_EVENTS.contains(&event_id) {
        return None;
    }

    // TCPIP-specific severity rules.
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
/// those via [`parse_socket_address`] into a full `SocketAddr`. Every
/// subscribed event in [`ParsedFields`]' coverage table either ships
/// this blob (carrying IP and port together) or ships neither — see
/// the `ParsedFields` doc for the full table. No subscribed event
/// delivers a discrete `LocalPort` / `RemotePort` scalar without a
/// matching address blob.
fn extract_fields(parser: &Parser) -> ParsedFields {
    let local = socket_addr_field(parser, "LocalAddress");
    let remote = socket_addr_field(parser, "RemoteAddress");

    ParsedFields {
        local,
        remote,
        status: parser.try_parse::<u32>("Status").ok(),
        rexmit_count: parser.try_parse::<u32>("RexmitCount").ok(),
        tcb: parser.try_parse::<u64>("Tcb").ok(),
    }
}

/// Decode one SOCKADDR-blob field. Logs a `debug!` breadcrumb when the
/// field is present but unparseable — a signal that ETW schema drift
/// might be eating endpoints before they reach the emitter. Silent
/// `None` is reserved for the expected "field absent" case.
fn socket_addr_field(parser: &Parser, field: &str) -> Option<SocketAddr> {
    let bytes = parser.try_parse::<Vec<u8>>(field).ok()?;
    match parse_socket_address(&bytes) {
        Some(sa) => Some(sa),
        None => {
            debug!(field, len = bytes.len(), "etw: address blob failed to parse");
            None
        }
    }
}

/// YAML-shaped logging view of a decoded ETW event. Fed into
/// [`dump!`] at emission time so the bridge log reads as block YAML
/// (null-safe, no `Some(_)` / `None` Debug noise, kebab-case keys).
///
/// Distinct from [`ParsedFields`]: this is the *logging* shape,
/// `ParsedFields` is the *extraction* shape; they may diverge.
#[derive(DeriveDump)]
#[dump(rename_all = "kebab-case")]
pub(crate) struct EventView<'a> {
    pub event_id: u16,
    /// Symbolic event name (e.g. `TcpConnectTcbComplete`), `~` when the
    /// provider/event_id has no entry in [`TCPIP_EVENT_NAMES`]. See
    /// [`event_name`].
    pub name: Option<&'static str>,
    pub opcode: u8,
    pub provider: &'a str,
    /// Kernel TCB correlator — kept third (right after `provider`) so
    /// readers grepping bridge.log by TCB cookie don't have to scroll past
    /// the endpoint block.
    pub tcb: Option<u64>,
    pub local: Option<SocketAddr>,
    pub remote: Option<SocketAddr>,
    pub status: Option<u32>,
    pub rexmit_count: Option<u32>,
}

/// Translate an [`Emission`] into the appropriate `tracing::event!`
/// invocation, carrying a `dump!`-rendered [`EventView`] in the
/// `event` field. The bridge's `YamlFormat` layer renders multi-line
/// field values as block scalars, so the YAML body lands under the
/// event message in human-readable form.
fn emit(emission: Emission, record: &EventRecord, fields: &ParsedFields) {
    let provider = provider_name(record.provider_id());
    let name = event_name(record.provider_id(), record.event_id());
    let view = EventView {
        event_id: record.event_id(),
        name,
        opcode: record.opcode(),
        provider: &provider,
        tcb: fields.tcb,
        local: fields.local,
        remote: fields.remote,
        status: fields.status,
        rexmit_count: fields.rexmit_count,
    };
    match emission {
        Emission::Info { msg } => info!(
            target: "hole_bridge::diagnostics::etw",
            event = %dump!(&view),
            "{msg}",
        ),
        Emission::Warn { msg } => warn!(
            target: "hole_bridge::diagnostics::etw",
            event = %dump!(&view),
            "{msg}",
        ),
        Emission::Unknown => debug!(
            target: "hole_bridge::diagnostics::etw",
            event = %dump!(&view),
            "etw: unknown event",
        ),
    }
}

// Provider GUID discrimination ========================================================================================

/// Test whether a provider GUID identifies the Microsoft-Windows-TCPIP
/// provider declared by [`TCPIP_PROVIDER`]. Extracted as a standalone
/// predicate so [`dispatch`] can apply TCPIP-specific filters without
/// re-parsing the constant string at every event.
fn is_tcpip_provider(provider: GUID) -> bool {
    // `GUID::from(&str)` parses at call time, not at compile time —
    // `ferrisetw` doesn't expose a `const` constructor for GUIDs. This
    // is fine for the predicate's call volume (one check per raw event,
    // pre-drop-list); keeping the constant as a string keeps the
    // declarations aligned with `ferrisetw::Provider::by_guid`.
    provider == GUID::from(TCPIP_PROVIDER)
}

/// Render a provider GUID as its Microsoft-assigned name, falling back to
/// the Debug form of the raw GUID if we don't recognise it. Called once
/// per emitted event inside [`emit`] — after the high-volume drop list has
/// already filtered the noisy events — so the branch is not on the hot
/// path and is allowed to allocate in the fallback arm.
fn provider_name(provider: GUID) -> Cow<'static, str> {
    if provider == GUID::from(TCPIP_PROVIDER) {
        Cow::Borrowed("Microsoft-Windows-TCPIP")
    } else if provider == GUID::from(WFP_PROVIDER) {
        Cow::Borrowed("Microsoft-Windows-WFP")
    } else if provider == GUID::from(AFD_PROVIDER) {
        Cow::Borrowed("Microsoft-Windows-Winsock-AFD")
    } else {
        Cow::Owned(format!("{provider:?}"))
    }
}

#[cfg(test)]
#[path = "etw_tests.rs"]
mod etw_tests;

#[cfg(test)]
#[path = "etw_live_privileged_tests.rs"]
mod etw_live_privileged_tests;
