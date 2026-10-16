//! Windows SCM `StopPending` progress, kept platform-neutral so its logic is
//! testable on any OS; `platform::windows` maps a [`StopPhase`] onto a
//! `ServiceStatus`.
//!
//! The checkpoint advances only when [`StopProgress::enter`] is called. Nothing
//! reports on a timer: a hung phase stops the checkpoint, and that is the signal
//! the SCM (and anything watching it) reads. Each entry is also logged, so
//! `bridge.log` carries a timestamped trail of the phases reached.
//!
//! Wait hints are advisory: the SCM or a service control program *may* treat a
//! checkpoint stuck past the hint as a failed stop (`SERVICE_STATUS` docs), so
//! the hints err long.
//!
//! The Stop control (SCM thread) and the main task both enter phases, so
//! [`StopProgress`] serializes the reports and drops an entry that would not
//! advance the checkpoint. A status report is the only thing done under that
//! lock. The control handler does no log I/O at all: the SCM gives `HandlerEx`
//! 30 s, and the file appender back-pressures, so a log write there could fail
//! the caller's `ControlService`. It hands the outcome to the main task, which
//! logs it at its next entry. A Stop control that lands after the last entry
//! (`ShutdownRuntime`) is not logged.

use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock, TryLockError};
use std::time::Duration;

use crate::proxy::Proxy;
use crate::proxy_manager::ProxyManager;
use crate::target::SessionEvent;
use tun_engine::routing::Routing;

/// A teardown phase the service reports to the SCM while stopping. Declaration
/// order is teardown order. A phase is entered when the previous one has
/// finished and names the work that is about to run, so a stuck checkpoint
/// identifies the step that is stuck. Phases whose work is absent in a given
/// session (no TUN engine in SOCKS-only mode, no plugin chain) are not entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StopPhase {
    /// The Stop (or Shutdown) control has arrived; the main task has not yet
    /// left whatever it was awaiting, shut the IPC server's connection tasks
    /// down, and probed the update marker. Reported from the control handler.
    StopRequested,
    /// Wait for the proxy-manager lock.
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
    /// Release the covers: the transient cover of a pending start, or the
    /// standing lockdown cover. A session stop also takes the post-teardown
    /// WFP/NDIS snapshots.
    SettleCover,
    /// Close the ETW consumer.
    CloseEtw,
    /// Drop what the service still holds after the proxy stop: the liveness
    /// lock, the shutdown token and the proxy manager, whose last handle is
    /// dropped here ([`drop_last_handle`]).
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
            // A startup recovery step that shells out (`netsh`, `route`) can
            // hold the main task for seconds; so can joining connection tasks.
            StopPhase::StopRequested => Duration::from_secs(10),
            // Normally immediate: the IPC connection tasks, the lock's holders,
            // are aborted and joined before this phase. The long hint is headroom
            // for a holder that outlives them.
            StopPhase::AcquireProxy => Duration::from_secs(30),
            StopPhase::PersistTarget => Duration::from_secs(10),
            // External-command DNS restore.
            StopPhase::RestoreDns => Duration::from_secs(20),
            StopPhase::StopEngine => Duration::from_secs(20),
            // Graceful stop, then kill, of the plugin processes.
            StopPhase::ReapPlugins => Duration::from_secs(20),
            StopPhase::StopProxy => Duration::from_secs(10),
            // Route deletes through external commands.
            StopPhase::TearDownRoutes => Duration::from_secs(30),
            StopPhase::SettleCover => Duration::from_secs(20),
            // A few synchronous Win32 calls and a thread join.
            StopPhase::CloseEtw => Duration::from_secs(15),
            StopPhase::DropResources => Duration::from_secs(10),
            // Joins outstanding blocking tasks, whose duration is unknown.
            StopPhase::ShutdownRuntime => Duration::from_secs(30),
        }
    }
}

/// What the Stop control's attempt to report [`StopPhase::StopRequested`]
/// came to. Held for the main task to log; see the module doc.
enum StopControl {
    Reported(std::io::Result<()>),
    /// Not reported: a later phase was already reported, or another thread was
    /// mid-report (and so is at or past the first phase).
    Superseded,
}

impl StopControl {
    /// The outcome to hold when `incoming` arrives while `held` is still
    /// waiting to be logged. A second Stop or Shutdown control is always
    /// `Superseded` by the first, so the first's report is the one that
    /// happened and must not be overwritten before it is logged.
    fn merge(held: StopControl, incoming: StopControl) -> StopControl {
        match (held, incoming) {
            (StopControl::Reported(held), StopControl::Reported(_)) => StopControl::Reported(held),
            (StopControl::Reported(held), StopControl::Superseded) => StopControl::Reported(held),
            (StopControl::Superseded, StopControl::Reported(incoming)) => StopControl::Reported(incoming),
            (StopControl::Superseded, StopControl::Superseded) => StopControl::Superseded,
        }
    }
}

/// Reports teardown phases through `report`. A failed report is logged and
/// otherwise ignored: losing a status update must not abort the teardown it
/// describes. Shareable between the control handler thread and the main task.
pub struct StopProgress<F> {
    report: F,
    last: Mutex<Option<StopPhase>>,
    /// The Stop control's outcome, waiting for the main task to log it. Held
    /// only to store or take a value, never across I/O.
    stop_control: Mutex<Option<StopControl>>,
}

impl<F: Fn(StopPhase) -> std::io::Result<()>> StopProgress<F> {
    pub fn new(report: F) -> Self {
        Self {
            report,
            last: Mutex::new(None),
            stop_control: Mutex::new(None),
        }
    }

    /// Report `phase` as pending, unless a phase at or after it has already been
    /// reported. Reports reach the SCM in checkpoint order because the lock is
    /// held across each one; the log lines follow it, the Stop control's
    /// hand-off first.
    pub fn enter(&self, phase: StopPhase) {
        let outcome = {
            let mut last = self.last.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            self.report_if_advancing(&mut last, phase)
        };
        self.log_stop_control();
        if let Some(outcome) = outcome {
            Self::log_reported(phase, outcome);
        }
    }

    /// Report [`StopPhase::StopRequested`] for the Stop control, without waiting
    /// on another thread's report. Whatever phase the lock holder is reporting is
    /// at or after the first, so this entry would be dropped anyway; skipping it
    /// loses nothing and keeps the control handler from waiting on an SCM call it
    /// did not make. The outcome is stored for the main task to log, while the
    /// report lock is still held when there is one: the main task's next `enter`
    /// takes that lock, so it cannot miss the outcome.
    fn report_stop_control(&self) {
        let phase = StopPhase::ALL[0];
        // Stored before the guard drops, so the outcome is visible to whoever
        // takes the report lock next.
        let report_and_store = |last: &mut Option<StopPhase>| {
            let outcome = match self.report_if_advancing(last, phase) {
                Some(outcome) => StopControl::Reported(outcome),
                None => StopControl::Superseded,
            };
            self.store_stop_control(outcome);
        };
        match self.last.try_lock() {
            Ok(mut last) => report_and_store(&mut last),
            Err(TryLockError::Poisoned(poisoned)) => report_and_store(&mut poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => self.store_stop_control(StopControl::Superseded),
        }
    }

    fn store_stop_control(&self, outcome: StopControl) {
        let mut slot = self
            .stop_control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = Some(match slot.take() {
            Some(held) => StopControl::merge(held, outcome),
            None => outcome,
        });
    }

    fn report_if_advancing(&self, last: &mut Option<StopPhase>, phase: StopPhase) -> Option<std::io::Result<()>> {
        if last.is_some_and(|last| last >= phase) {
            return None;
        }
        *last = Some(phase);
        Some((self.report)(phase))
    }

    fn log_stop_control(&self) {
        let taken = self
            .stop_control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        match taken {
            Some(StopControl::Reported(outcome)) => Self::log_reported(StopPhase::ALL[0], outcome),
            Some(StopControl::Superseded) => tracing::debug!(
                phase = ?StopPhase::ALL[0],
                "stop control superseded: a later phase was already reported or being reported"
            ),
            None => {}
        }
    }

    fn log_reported(phase: StopPhase, outcome: std::io::Result<()>) {
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
/// the main task. The report goes first so the SCM never sees `Running` after a
/// Stop it has delivered; nothing before the signal can wait on another thread,
/// and nothing here logs (see the module doc). The signal runs even if the
/// report panics: a lost signal is a lost Stop.
pub fn request_stop<F: Fn(StopPhase) -> std::io::Result<()>>(progress: &StopProgress<F>, signal: impl FnOnce()) {
    let _signal = SignalOnDrop(Some(signal));
    progress.report_stop_control();
}

/// Runs the closure when dropped, normally or by unwinding.
struct SignalOnDrop<S: FnOnce()>(Option<S>);

impl<S: FnOnce()> Drop for SignalOnDrop<S> {
    fn drop(&mut self) {
        if let Some(signal) = self.0.take() {
            signal();
        }
    }
}

/// [`request_stop`] signalling the main task through `shutdown_tx`, which holds
/// the sender until the first control takes it.
pub fn stop_control<F: Fn(StopPhase) -> std::io::Result<()>>(
    progress: &StopProgress<F>,
    shutdown_tx: &Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
) {
    request_stop(progress, || {
        if let Ok(mut guard) = shutdown_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(());
            }
        }
    });
}

/// A report closure that sends through the status handle in `cell` via `send`.
/// The handle exists only once the handler is registered, so a Stop that lands
/// before it is stored fails its report rather than panicking.
pub fn scm_reporter<H>(
    cell: Arc<OnceLock<H>>,
    send: impl Fn(&H, StopPhase) -> std::io::Result<()>,
) -> impl Fn(StopPhase) -> std::io::Result<()> {
    move |phase| match cell.get() {
        Some(handle) => send(handle, phase),
        None => Err(std::io::Error::other("service status handle not registered yet")),
    }
}

/// Enter `phase`, then run `work` on `item`, if there is an `item`. A phase
/// names work that is about to run, so it is entered only when that work
/// exists and never after it; routing every phase with optional work through
/// here makes both properties structural.
pub async fn run_phase<T, Fut: Future>(
    on_phase: &mut impl FnMut(StopPhase),
    phase: StopPhase,
    item: Option<T>,
    work: impl FnOnce(T) -> Fut,
) -> Option<Fut::Output> {
    let item = item?;
    on_phase(phase);
    Some(work(item).await)
}

/// Teardown after the serve loop exits. `stop_proxy` receives `progress` and
/// enters the phases of the proxy stop itself; this brackets it with
/// [`StopPhase::AcquireProxy`] before and the ETW close and the drop of the
/// remaining resources after. `etw` is the consumer to close, if one started;
/// without one [`StopPhase::CloseEtw`] is not entered.
pub async fn tear_down<F, Fut, E>(
    progress: &Arc<StopProgress<F>>,
    stop_proxy: impl FnOnce(Arc<StopProgress<F>>) -> Fut,
    etw: Option<E>,
    close_etw: impl FnOnce(E),
    drop_resources: impl FnOnce(),
) where
    F: Fn(StopPhase) -> std::io::Result<()>,
    Fut: Future<Output = ()>,
{
    progress.enter(StopPhase::AcquireProxy);
    stop_proxy(Arc::clone(progress)).await;
    run_phase(
        &mut |phase| progress.enter(phase),
        StopPhase::CloseEtw,
        etw,
        |etw| async move { close_etw(etw) },
    )
    .await;
    progress.enter(StopPhase::DropResources);
    drop_resources();
}

/// [`tear_down`] for the service: stop `proxy` in response to `shutdown_event()`,
/// close `etw` if there is one, then drop `held` and the last handle on `proxy`.
///
/// `shutdown_event` runs before [`StopPhase::AcquireProxy`], so that phase
/// covers only the wait for the proxy-manager lock, not the filesystem probe
/// the event is derived from.
pub async fn tear_down_service<F, P, R, E, H>(
    progress: &Arc<StopProgress<F>>,
    proxy: Arc<tokio::sync::Mutex<ProxyManager<P, R>>>,
    shutdown_event: impl FnOnce() -> SessionEvent,
    etw: Option<E>,
    held: H,
) where
    F: Fn(StopPhase) -> std::io::Result<()>,
    P: Proxy,
    R: Routing,
{
    let event = shutdown_event();
    let proxy_for_stop = Arc::clone(&proxy);
    tear_down(
        progress,
        |progress| async move {
            let mut pm = proxy_for_stop.lock().await;
            if let Err(e) = pm.stop_with_progress(event, |phase| progress.enter(phase)).await {
                tracing::error!(error = %e, "error stopping proxy during shutdown");
            }
        },
        etw,
        drop,
        move || {
            drop(held);
            drop_last_handle(proxy);
        },
    )
    .await;
}

/// Drop `handle` as the last owner of `T`, so `T`'s own drop runs here, in the
/// phase that names it, and not on whichever task or thread releases the last
/// clone. A clone that is still alive is logged: the drop then runs where that
/// clone is released.
pub fn drop_last_handle<T>(handle: Arc<T>) {
    if let Err(handle) = Arc::try_unwrap(handle) {
        tracing::error!(
            strong_count = Arc::strong_count(&handle),
            "a handle outlived the teardown; its drop runs where the last clone is released"
        );
    }
}

/// Last teardown step: `Stopped` is reported only once the runtime is gone,
/// because dropping it joins blocking tasks that can still hang. A failed
/// `Stopped` report is logged: the SCM stays on the last checkpoint, which
/// otherwise reads as a hang in [`StopPhase::ShutdownRuntime`].
pub fn finish_stop<F: Fn(StopPhase) -> std::io::Result<()>>(
    progress: &StopProgress<F>,
    drop_runtime: impl FnOnce(),
    report_stopped: impl FnOnce() -> std::io::Result<()>,
) {
    progress.enter(StopPhase::ShutdownRuntime);
    drop_runtime();
    if let Err(e) = report_stopped() {
        tracing::warn!(error = %e, "failed to report Stopped to the SCM");
    }
}

#[cfg(test)]
#[path = "service_stop_tests.rs"]
mod service_stop_tests;
