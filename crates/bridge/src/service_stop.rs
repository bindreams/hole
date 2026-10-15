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
//! [`StopProgress`] serializes the reports and drops an entry that would not
//! advance the checkpoint. A status report is the only thing done under that
//! lock, and the log line is written after it: a log writer that back-pressures
//! must not delay a `StopPending` report or the shutdown signal.

use std::sync::{Mutex, TryLockError};
use std::time::Duration;

/// A teardown phase the service reports to the SCM while stopping. Declaration
/// order is teardown order. A phase is entered when the previous one has
/// finished and names the work that is about to run, so a stuck checkpoint
/// identifies the step that is stuck. Phases whose work is absent in a given
/// session (no TUN engine in SOCKS-only mode, no plugin chain) are not entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StopPhase {
    /// The Stop (or Shutdown) control has arrived; the main task has not yet
    /// left whatever it was awaiting. Reported from the control handler.
    StopRequested,
    /// Wait for the proxy-manager lock, which an in-flight start or request holds.
    AcquireProxy,
    /// Persist the session event to the target file.
    PersistTarget,
    /// Restore the OS DNS configuration.
    RestoreDns,
    /// Shut down the TUN dispatcher: closes the device, cancels connection handlers.
    StopEngine,
    /// Reap the tracked plugin processes.
    ReapPlugins,
    /// Stop the shadowsocks proxy task.
    StopProxy,
    /// Delete the installed routes.
    TearDownRoutes,
    /// Settle the standing lockdown cover and take the post-teardown WFP/NDIS snapshots.
    SettleCover,
    /// Close the ETW consumer.
    CloseEtw,
    /// Drop what the service still holds after the proxy stop: the liveness
    /// lock, the shutdown token and the proxy-manager handles.
    DropResources,
    /// Shut down the tokio runtime, which joins outstanding blocking tasks.
    ShutdownRuntime,
}

impl StopPhase {
    pub const ALL: [StopPhase; 12] = [
        StopPhase::StopRequested,
        StopPhase::AcquireProxy,
        StopPhase::PersistTarget,
        StopPhase::RestoreDns,
        StopPhase::StopEngine,
        StopPhase::ReapPlugins,
        StopPhase::StopProxy,
        StopPhase::TearDownRoutes,
        StopPhase::SettleCover,
        StopPhase::CloseEtw,
        StopPhase::DropResources,
        StopPhase::ShutdownRuntime,
    ];

    /// SCM checkpoint while this phase is pending. Starts at 1: checkpoint 0
    /// means "no pending operation".
    pub const fn checkpoint(self) -> u32 {
        match self {
            StopPhase::StopRequested => 1,
            StopPhase::AcquireProxy => 2,
            StopPhase::PersistTarget => 3,
            StopPhase::RestoreDns => 4,
            StopPhase::StopEngine => 5,
            StopPhase::ReapPlugins => 6,
            StopPhase::StopProxy => 7,
            StopPhase::TearDownRoutes => 8,
            StopPhase::SettleCover => 9,
            StopPhase::CloseEtw => 10,
            StopPhase::DropResources => 11,
            StopPhase::ShutdownRuntime => 12,
        }
    }

    /// SCM wait hint: the estimated time before the next checkpoint. Advisory;
    /// see the module doc.
    pub const fn wait_hint(self) -> Duration {
        match self {
            // The main task leaves its current await; a startup recovery step
            // that shells out (`netsh`, `route`) can hold it for seconds.
            StopPhase::StopRequested => Duration::from_secs(10),
            // Held by an in-flight start, which is cancelled but unwinds its
            // own steps first.
            StopPhase::AcquireProxy => Duration::from_secs(30),
            // One small file write.
            StopPhase::PersistTarget => Duration::from_secs(10),
            // External-command DNS restore.
            StopPhase::RestoreDns => Duration::from_secs(20),
            // Closes the TUN device and joins the driver.
            StopPhase::StopEngine => Duration::from_secs(20),
            // Graceful stop, then kill, of the plugin processes.
            StopPhase::ReapPlugins => Duration::from_secs(20),
            // Aborts the shadowsocks task.
            StopPhase::StopProxy => Duration::from_secs(10),
            // Route deletes through external commands.
            StopPhase::TearDownRoutes => Duration::from_secs(30),
            // Cover release and the WFP/NDIS snapshots.
            StopPhase::SettleCover => Duration::from_secs(20),
            // A few synchronous Win32 calls and a thread join.
            StopPhase::CloseEtw => Duration::from_secs(15),
            // Releases a file lock and drops handles.
            StopPhase::DropResources => Duration::from_secs(10),
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
    /// reported. Reports reach the SCM in checkpoint order because the lock is
    /// held across each one; the log line follows it.
    pub fn enter(&self, phase: StopPhase) {
        let outcome = {
            let mut last = self.last.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            self.report_if_advancing(&mut last, phase)
        };
        Self::log(phase, outcome);
    }

    /// [`Self::enter`] for the first phase, without waiting on another thread's
    /// report. Whatever phase the lock holder is reporting is at or after the
    /// first, so this entry would be dropped anyway; skipping it loses nothing
    /// and keeps the control handler from waiting on an SCM call it did not
    /// make. Returns the outcome for [`Self::log`], which the caller runs once
    /// it has done whatever must not wait on a log write.
    fn try_enter_first(&self) -> Option<std::io::Result<()>> {
        let phase = StopPhase::ALL[0];
        let mut last = match self.last.try_lock() {
            Ok(last) => last,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return None,
        };
        self.report_if_advancing(&mut last, phase)
    }

    fn report_if_advancing(&self, last: &mut Option<StopPhase>, phase: StopPhase) -> Option<std::io::Result<()>> {
        if last.is_some_and(|last| last >= phase) {
            return None;
        }
        *last = Some(phase);
        Some((self.report)(phase))
    }

    fn log(phase: StopPhase, outcome: Option<std::io::Result<()>>) {
        let Some(outcome) = outcome else { return };
        tracing::info!(
            ?phase,
            checkpoint = phase.checkpoint(),
            wait_hint_ms = phase.wait_hint().as_millis() as u64,
            "service stop phase"
        );
        if let Err(e) = outcome {
            tracing::warn!(error = %e, ?phase, "failed to report StopPending to the SCM");
        }
    }
}

/// The Stop/Shutdown control: report [`StopPhase::StopRequested`], then `signal`
/// the main task, then log. The report goes first so the SCM never sees
/// `Running` after a Stop it has delivered; nothing before the signal can wait
/// on another thread or on the log writer.
pub fn request_stop<F: Fn(StopPhase) -> std::io::Result<()>>(progress: &StopProgress<F>, signal: impl FnOnce()) {
    let outcome = progress.try_enter_first();
    signal();
    StopProgress::<F>::log(StopPhase::ALL[0], outcome);
}

/// Teardown after the serve loop exits. `stop_proxy` receives `progress` and
/// enters the phases of the proxy stop itself; this brackets it with
/// [`StopPhase::AcquireProxy`] before and the ETW close and the drop of the
/// remaining resources after.
pub async fn tear_down<F, Fut>(
    progress: &std::sync::Arc<StopProgress<F>>,
    stop_proxy: impl FnOnce(std::sync::Arc<StopProgress<F>>) -> Fut,
    close_etw: impl FnOnce(),
    drop_resources: impl FnOnce(),
) where
    F: Fn(StopPhase) -> std::io::Result<()>,
    Fut: std::future::Future<Output = ()>,
{
    progress.enter(StopPhase::AcquireProxy);
    stop_proxy(std::sync::Arc::clone(progress)).await;
    progress.enter(StopPhase::CloseEtw);
    close_etw();
    progress.enter(StopPhase::DropResources);
    drop_resources();
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
