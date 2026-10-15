//! Windows SCM `StopPending` progress, kept platform-neutral so its logic is
//! testable on any OS; `platform::windows` maps a [`StopPhase`] onto a
//! `ServiceStatus`.
//!
//! The checkpoint advances only when [`StopProgress::enter`] is called, which
//! the service does when the previous teardown phase has finished. Nothing
//! reports on a timer: a hung phase stops the checkpoint, and that is the signal
//! the SCM (and anything watching it) reads. The wait hint is an estimate for the
//! phase, not a bound the bridge enforces.

use std::time::Duration;

/// A teardown phase the service reports to the SCM while stopping. Declaration
/// order is teardown order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StopPhase {
    /// Stop the proxy: engine, routes, DNS restore, plugin reap.
    StopProxy,
    /// Close the ETW consumer.
    CloseEtw,
    /// Shut down the tokio runtime, which joins outstanding blocking tasks.
    ShutdownRuntime,
}

impl StopPhase {
    pub const ALL: [StopPhase; 3] = [StopPhase::StopProxy, StopPhase::CloseEtw, StopPhase::ShutdownRuntime];

    /// SCM checkpoint while this phase is pending. Starts at 1: checkpoint 0
    /// means "no pending operation".
    pub const fn checkpoint(self) -> u32 {
        match self {
            StopPhase::StopProxy => 1,
            StopPhase::CloseEtw => 2,
            StopPhase::ShutdownRuntime => 3,
        }
    }

    /// SCM wait hint: how long this phase is expected to take before the next
    /// checkpoint. A client that sees no new checkpoint within it may call the
    /// service hung; the bridge itself does not act on it.
    pub const fn wait_hint(self) -> Duration {
        match self {
            StopPhase::StopProxy => Duration::from_secs(30),
            StopPhase::CloseEtw => Duration::from_secs(30),
            StopPhase::ShutdownRuntime => Duration::from_secs(30),
        }
    }
}

/// Reports teardown phases through `report`. A failed report is logged and
/// otherwise ignored: losing a status update must not abort the teardown it
/// describes.
pub struct StopProgress<F> {
    report: F,
    last: Option<StopPhase>,
}

impl<F: FnMut(StopPhase) -> std::io::Result<()>> StopProgress<F> {
    pub fn new(report: F) -> Self {
        Self { report, last: None }
    }

    /// Report `phase` as pending. Call it once the previous phase has finished.
    pub fn enter(&mut self, phase: StopPhase) {
        debug_assert!(
            self.last.is_none_or(|last| last < phase),
            "stop phase {phase:?} entered out of order after {:?}",
            self.last
        );
        self.last = Some(phase);
        if let Err(e) = (self.report)(phase) {
            tracing::warn!(error = %e, ?phase, "failed to report StopPending to the SCM");
        }
    }
}

#[cfg(test)]
#[path = "service_stop_tests.rs"]
mod service_stop_tests;
