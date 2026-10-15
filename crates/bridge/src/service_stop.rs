//! Windows SCM `StopPending` progress, kept platform-neutral so its logic is
//! testable on any OS; `platform::windows` maps a [`StopPhase`] onto a
//! `ServiceStatus`.
//!
//! The checkpoint advances only when [`StopProgress::enter`] is called, which
//! the service does when the previous teardown phase has finished. Nothing
//! reports on a timer: a hung phase stops the checkpoint, and that is the signal
//! the SCM (and anything watching it) reads. Each entry is also logged, so
//! `bridge.log` carries a timestamped trail of the phases reached.
//!
//! The wait hint is the bridge's estimate for the phase and the bridge never
//! acts on it. Per the `SERVICE_STATUS` docs, the SCM or a service control
//! program *may* treat a checkpoint that stays put for longer than the hint as a
//! failed stop, so the hints err long. They are estimates, not measurements.
//!
//! The Stop control (SCM thread) and the main task both enter phases, so
//! [`StopProgress`] serializes them and drops an entry that would not advance the
//! checkpoint.

use std::sync::Mutex;
use std::time::Duration;

/// A teardown phase the service reports to the SCM while stopping. Declaration
/// order is teardown order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StopPhase {
    /// The Stop (or Shutdown) control has arrived; the main task has not yet
    /// left whatever it was awaiting. Reported from the control handler.
    StopRequested,
    /// Stop the proxy: engine, routes, DNS restore, plugin reap.
    StopProxy,
    /// Close the ETW consumer.
    CloseEtw,
    /// Shut down the tokio runtime, which joins outstanding blocking tasks.
    ShutdownRuntime,
}

impl StopPhase {
    pub const ALL: [StopPhase; 4] = [
        StopPhase::StopRequested,
        StopPhase::StopProxy,
        StopPhase::CloseEtw,
        StopPhase::ShutdownRuntime,
    ];

    /// SCM checkpoint while this phase is pending. Starts at 1: checkpoint 0
    /// means "no pending operation".
    pub const fn checkpoint(self) -> u32 {
        match self {
            StopPhase::StopRequested => 1,
            StopPhase::StopProxy => 2,
            StopPhase::CloseEtw => 3,
            StopPhase::ShutdownRuntime => 4,
        }
    }

    /// SCM wait hint: the estimated time before the next checkpoint. Advisory;
    /// see the module doc.
    pub const fn wait_hint(self) -> Duration {
        match self {
            // The main task leaves its current await; a startup recovery step
            // that shells out (`netsh`, `route`) can hold it for seconds.
            StopPhase::StopRequested => Duration::from_secs(10),
            // DNS restore, route deletes through external commands, plugin
            // reap, lockdown/cover handling: the longest phase.
            StopPhase::StopProxy => Duration::from_secs(60),
            // A few synchronous Win32 calls and a thread join.
            StopPhase::CloseEtw => Duration::from_secs(15),
            // Joins outstanding blocking tasks, whose duration is unknown.
            StopPhase::ShutdownRuntime => Duration::from_secs(30),
        }
    }
}

/// Reports teardown phases through `report`. A failed report is logged and
/// otherwise ignored: losing a status update must not abort the teardown it
/// describes. Shareable between the control handler thread and the main task.
pub struct StopProgress<F> {
    report: F,
    last: Mutex<Option<StopPhase>>,
}

impl<F: Fn(StopPhase) -> std::io::Result<()>> StopProgress<F> {
    pub fn new(report: F) -> Self {
        Self {
            report,
            last: Mutex::new(None),
        }
    }

    /// Report `phase` as pending, unless a phase at or after it has already been
    /// reported. The lock is held across the report, so reports reach the SCM in
    /// checkpoint order.
    pub fn enter(&self, phase: StopPhase) {
        let mut last = self.last.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if last.is_some_and(|last| last >= phase) {
            return;
        }
        *last = Some(phase);
        tracing::info!(
            ?phase,
            checkpoint = phase.checkpoint(),
            wait_hint_ms = phase.wait_hint().as_millis() as u64,
            "service stop phase"
        );
        if let Err(e) = (self.report)(phase) {
            tracing::warn!(error = %e, ?phase, "failed to report StopPending to the SCM");
        }
    }
}

/// The Stop/Shutdown control: report [`StopPhase::StopRequested`] first, then
/// `signal` the main task, so the SCM never sees `Running` after a Stop it has
/// delivered.
pub fn request_stop<F: Fn(StopPhase) -> std::io::Result<()>>(progress: &StopProgress<F>, signal: impl FnOnce()) {
    progress.enter(StopPhase::StopRequested);
    signal();
}

/// Teardown after the serve loop exits: report each phase, then do its work.
pub async fn tear_down<F: Fn(StopPhase) -> std::io::Result<()>>(
    progress: &StopProgress<F>,
    stop_proxy: impl std::future::Future<Output = ()>,
    close_etw: impl FnOnce(),
) {
    progress.enter(StopPhase::StopProxy);
    stop_proxy.await;
    progress.enter(StopPhase::CloseEtw);
    close_etw();
}

/// Last teardown step: `Stopped` is reported only once the runtime is gone,
/// because dropping it joins blocking tasks that can still hang.
pub fn finish_stop<F: Fn(StopPhase) -> std::io::Result<()>>(
    progress: &StopProgress<F>,
    drop_runtime: impl FnOnce(),
    report_stopped: impl FnOnce(),
) {
    progress.enter(StopPhase::ShutdownRuntime);
    drop_runtime();
    report_stopped();
}

#[cfg(test)]
#[path = "service_stop_tests.rs"]
mod service_stop_tests;
