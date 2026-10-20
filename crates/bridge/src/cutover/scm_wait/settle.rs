//! The stop wait as a loop over queries. Every decision is taken on a look at
//! the service, and every sleep is an arm taken before the act it waits for, or
//! an arm followed by a confirming look.
//!
//! `NotifyServiceStatusChangeW` queues its callback at once if the service is
//! already in a requested state, and otherwise "the next time the service
//! enters the requested state", never for a state it merely stays in
//! ([Remarks](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-notifyservicestatuschangew#remarks)).
//! So an arm that excludes the state the service is in can miss a restart
//! that completes before the arm. Two rules close that, whatever the start
//! type is:
//!
//! - **A wait for the SCM's reaction to our own act arms before the act.** The
//!   Stop's effect, a state entry after the arm, then queues the callback
//!   whether the service stays down or is restarted at once.
//! - **A wait for the SCM's own transition arms, looks again, and sleeps only
//!   if that look still asks for the same wait.** A restart that completed
//!   between the first look and the arm leaves a RUNNING instance in a state
//!   the arm excludes; the second look finds it and the loop stops it instead.

use std::io;

use tracing::{info, warn};

use super::call_error::service_gone;
use super::hold::{Look, ProcessFate};
use super::Observed;

/// What kind of event a wait is for. How long an [`ExternalEvent`](WaitKind::ExternalEvent)
/// may take before it is a failure is not decided here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitKind {
    /// The kernel or the SCM is processing a fact it already has. No code of
    /// the service has to cooperate, so the wait needs no bound.
    Edge,
    /// The event depends on the service's own code, or its child's, finishing,
    /// and may never happen.
    ExternalEvent,
}

/// What the stop wait does on a look at the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleStep {
    /// The SCM says STOPPED and nothing held is alive: ask the scan whether
    /// anything else carries the service's token, and settle only if not.
    Quiescent,
    /// RUNNING over a process that takes a Stop.
    SendStop,
    /// STOPPED with a held process still alive: wait for it to exit.
    AwaitHeldExit,
    /// Wait for the service to leave this state.
    AwaitChange(Observed),
}

impl Look {
    /// The one decision of the stop wait, from the state the look read and
    /// the process it names.
    ///
    /// A Stop goes out only into RUNNING, the one state that takes it, and
    /// only over a process that has not exited. In the pending states the
    /// process id is documented "may not be valid" and in STOPPED "never
    /// valid" ([`QueryServiceStatusEx`, Remarks](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex#remarks)),
    /// so no fate is trusted there: they are left by the SCM's own
    /// transition, even with a live hold (a hold that outlives STOPPED is
    /// then waited out). STOPPED is final only with nothing held alive.
    pub fn settle_step(self) -> SettleStep {
        match self.observed {
            Observed::Running => match self.fate {
                ProcessFate::Unheld => SettleStep::SendStop,
                ProcessFate::Alive => SettleStep::SendStop,
                // The process is gone and the status lags: the SCM catches up.
                ProcessFate::Exited => SettleStep::AwaitChange(Observed::Running),
            },
            Observed::StartPending => SettleStep::AwaitChange(Observed::StartPending),
            Observed::StopPending => SettleStep::AwaitChange(Observed::StopPending),
            Observed::Stopped => {
                if self.held_alive {
                    SettleStep::AwaitHeldExit
                } else {
                    SettleStep::Quiescent
                }
            }
        }
    }
}

impl Observed {
    /// The kind of the wait for the service to leave this state.
    ///
    /// RUNNING is left by a wait only when its process has already exited and
    /// the SCM is catching up (an edge). The pending states end by the
    /// service's own code finishing its start or stop. A wait to leave STOPPED
    /// would be for an outside start, which no step makes.
    pub fn leaving_wait_kind(self) -> WaitKind {
        match self {
            Observed::Running => WaitKind::Edge,
            Observed::StartPending => WaitKind::ExternalEvent,
            Observed::StopPending => WaitKind::ExternalEvent,
            Observed::Stopped => WaitKind::ExternalEvent,
        }
    }
}

impl SettleStep {
    /// The kind of the wait this step makes, or `None` for a step that waits
    /// for nothing.
    pub fn wait_kind(self) -> Option<WaitKind> {
        match self {
            SettleStep::Quiescent => None,
            // The wait after an accepted Stop is for the service to exit.
            SettleStep::SendStop => Some(WaitKind::ExternalEvent),
            SettleStep::AwaitHeldExit => Some(WaitKind::ExternalEvent),
            SettleStep::AwaitChange(from) => Some(from.leaving_wait_kind()),
        }
    }

    /// The kind of the wait this step makes. Only a step that waits is asked.
    fn expected_wait_kind(self) -> WaitKind {
        self.wait_kind().expect("a step that waits has a wait kind")
    }

    /// Whether the wait is over on a look that decides this step, once the
    /// scan has run.
    pub fn ends_the_wait(self) -> bool {
        match self {
            SettleStep::Quiescent => true,
            SettleStep::SendStop => false,
            SettleStep::AwaitHeldExit => false,
            SettleStep::AwaitChange(_) => false,
        }
    }

    /// Whether a Stop sent now would be taken, which is what makes a refusal
    /// of one a failure instead of a race lost to the service's own exit.
    pub fn is_a_stop_the_service_takes(self) -> bool {
        match self {
            SettleStep::Quiescent => false,
            SettleStep::SendStop => true,
            SettleStep::AwaitHeldExit => false,
            SettleStep::AwaitChange(_) => false,
        }
    }
}

/// What an accepted Stop is followed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopWait {
    /// The held process exits. Its handle keeps its id from being reused, so
    /// nothing needs arming.
    HeldProcess,
    /// The SCM reports the service leaving RUNNING, armed before the Stop.
    StatusChange,
}

impl ProcessFate {
    /// What follows an accepted Stop to a process with this fate. Without a
    /// live held process, the SCM's transition is the only event there is.
    pub fn wait_after_stop(self) -> StopWait {
        match self {
            ProcessFate::Alive => StopWait::HeldProcess,
            ProcessFate::Unheld => StopWait::StatusChange,
            ProcessFate::Exited => StopWait::StatusChange,
        }
    }
}

/// What the stop wait does to the service and waits on, behind a seam so the
/// loop is testable without an SCM.
pub trait StopActor {
    /// Look at the service: one query for its state and process id, and the
    /// hold of the process it names (open, then confirm). Never waits.
    fn observe(&mut self) -> io::Result<Look>;
    /// Arm a notification for every state but `from`, on handles opened for
    /// this arm. Fails with the SCM's refusal if the service is marked for
    /// deletion.
    fn arm_leaving(&mut self, from: Observed) -> io::Result<()>;
    /// Send `ControlService(STOP)`.
    fn control_stop(&mut self) -> io::Result<()>;
    /// Sleep until the armed notification fires.
    fn await_callback(&mut self, kind: WaitKind) -> io::Result<()>;
    /// Wait until every held process has exited.
    fn await_held_exits(&mut self, kind: WaitKind) -> io::Result<()>;
    /// Hold every live process that carries the service's token, other than
    /// the calling one. Does nothing where there is no service token.
    fn hold_scanned(&mut self) -> io::Result<()>;
}

/// Why the stop wait failed, by the act that failed, so a caller's policy per
/// step is a match on this type and not a guess from the error's text.
#[derive(Debug, thiserror::Error)]
pub enum SettleError {
    /// A look at the service failed.
    #[error("the service's state could not be read: {0}")]
    Observe(io::Error),
    /// A notification could not be armed, and the SCM's refusal does not leave
    /// the open handle answering.
    #[error("a status notification could not be armed: {0}")]
    Arm(io::Error),
    /// The service refused a Stop while still running over a process.
    #[error("the service refused the Stop: {0}")]
    Stop(io::Error),
    /// The sleep on a status notification failed.
    #[error("the wait for a status change failed: {0}")]
    AwaitChange(io::Error),
    /// The scan for processes carrying the service's token failed.
    #[error("the service's processes could not be found: {0}")]
    Scan(io::Error),
    /// The wait on a held process failed.
    #[error("a process of the service could not be awaited: {0}")]
    AwaitExit(io::Error),
}

impl SettleError {
    /// The error the act failed with, for a caller that does not tell the
    /// steps apart.
    pub fn into_io(self) -> io::Error {
        match self {
            SettleError::Observe(error) => error,
            SettleError::Arm(error) => error,
            SettleError::Stop(error) => error,
            SettleError::AwaitChange(error) => error,
            SettleError::Scan(error) => error,
            SettleError::AwaitExit(error) => error,
        }
    }
}

/// Stop the service and return once the SCM says STOPPED, nothing held is
/// alive, and a scan finds no process carrying the service's token.
///
/// Every iteration ends in a real event (a process exit, an SCM notification)
/// or in a state change a query read; nothing is retried on a count or a
/// timer. A Stop the service refuses is an error only if the look that follows
/// still finds it RUNNING over a process.
///
/// A service marked for deletion refuses every arm. The handle already open
/// still queries and takes a Stop, so the loop goes on without arming: it
/// holds the processes the scan finds and waits on them. If a live state is
/// left with no held process to wait on, the only event is the SCM's, which
/// cannot be asked for, and the refusal is the result.
pub fn settle_stopped<A: StopActor>(actor: &mut A) -> Result<(), SettleError> {
    let mut settle = Settle { actor, refused: None };
    let mut look = settle.observe()?;
    loop {
        let step = look.settle_step();
        let next = match step {
            SettleStep::Quiescent => {
                settle.hold_scanned()?;
                look = settle.observe()?;
                if look.settle_step().ends_the_wait() {
                    info!("stop wait: the service is stopped and no process of it is left");
                    return Ok(());
                }
                Next::Look(look)
            }
            SettleStep::SendStop => settle.stop(look)?,
            SettleStep::AwaitHeldExit => {
                info!(?look, "stop wait: waiting for a process held past STOPPED");
                settle.await_held_exits(step.expected_wait_kind())?;
                Next::Look(settle.observe()?)
            }
            SettleStep::AwaitChange(_) => settle.await_change(step)?,
        };
        match next {
            Next::Look(again) => look = again,
            Next::Settled => return Ok(()),
        }
    }
}

/// Where a step leaves the loop.
enum Next {
    /// On this look.
    Look(Look),
    /// Settled without a STOPPED look: the service is marked for deletion, so
    /// the SCM cannot be asked again, and every process it showed has exited.
    Settled,
}

struct Settle<'a, A> {
    actor: &'a mut A,
    /// The SCM's refusal of an arm because the service is marked for deletion;
    /// no arm is tried once it is set.
    refused: Option<io::Error>,
}

impl<A: StopActor> Settle<'_, A> {
    fn observe(&mut self) -> Result<Look, SettleError> {
        self.actor.observe().map_err(SettleError::Observe)
    }

    fn hold_scanned(&mut self) -> Result<(), SettleError> {
        self.actor.hold_scanned().map_err(SettleError::Scan)
    }

    fn await_held_exits(&mut self, kind: WaitKind) -> Result<(), SettleError> {
        self.actor.await_held_exits(kind).map_err(SettleError::AwaitExit)
    }

    fn await_callback(&mut self, kind: WaitKind) -> Result<(), SettleError> {
        self.actor.await_callback(kind).map_err(SettleError::AwaitChange)
    }

    /// Arm leaving `from`. `Ok(false)` means the SCM refused because the
    /// service is marked for deletion, whose open handle still carries on.
    fn arm_leaving(&mut self, from: Observed) -> Result<bool, SettleError> {
        if self.refused.is_some() {
            return Ok(false);
        }
        match self.actor.arm_leaving(from) {
            Ok(()) => Ok(true),
            Err(error) => match service_gone(&error) {
                Some(gone) if gone.answers_through_an_open_handle() => {
                    warn!(%error, ?gone, "the SCM refused an arm; waiting on the service's processes instead");
                    self.refused = Some(error);
                    Ok(false)
                }
                Some(_) | None => Err(SettleError::Arm(error)),
            },
        }
    }

    /// Send the Stop `look` calls for and wait out its effect.
    fn stop(&mut self, look: Look) -> Result<Next, SettleError> {
        let wait = look.fate.wait_after_stop();
        let armed = match wait {
            StopWait::HeldProcess => false,
            // Before the Stop: its effect must be a state entry after the arm.
            StopWait::StatusChange => self.arm_leaving(look.observed)?,
        };
        info!(?look, "stop wait: sending Stop");
        if let Err(refused) = self.actor.control_stop() {
            let again = self.observe()?;
            if again.settle_step().is_a_stop_the_service_takes() {
                return Err(SettleError::Stop(refused));
            }
            info!(?again, error = %refused, "stop wait: the Stop was refused, but the service is no longer running");
            return Ok(Next::Look(again));
        }
        let kind = SettleStep::SendStop.expected_wait_kind();
        match wait {
            StopWait::HeldProcess => self.await_held_exits(kind)?,
            StopWait::StatusChange if armed => self.await_callback(kind)?,
            StopWait::StatusChange => return self.without_arm(),
        }
        Ok(Next::Look(self.observe()?))
    }

    /// Wait for the service to leave the state `step` names.
    fn await_change(&mut self, step: SettleStep) -> Result<Next, SettleError> {
        let SettleStep::AwaitChange(from) = step else {
            unreachable!("only a wait to leave a state is asked to await it: {step:?}")
        };
        if !self.arm_leaving(from)? {
            return self.without_arm();
        }
        let again = self.observe()?;
        // Not the same wait any more: the arm's mask does not cover where the
        // service is. Closing its handle cancels it.
        if again.settle_step() != step {
            return Ok(Next::Look(again));
        }
        info!(?again, "stop wait: waiting for the service to leave its state");
        self.await_callback(step.expected_wait_kind())?;
        Ok(Next::Look(self.observe()?))
    }

    /// What the loop does where it would have armed and cannot: hold what the
    /// scan finds and wait on that. With nothing held alive and the SCM's
    /// state still lagging, the processes that were held have exited and the
    /// scan finds no other: settled. If none was ever held, the state is left
    /// with no event to wait on.
    fn without_arm(&mut self) -> Result<Next, SettleError> {
        self.hold_scanned()?;
        let look = self.observe()?;
        if look.held_alive {
            self.await_held_exits(SettleStep::AwaitHeldExit.expected_wait_kind())?;
            return Ok(Next::Look(self.observe()?));
        }
        if look.settle_step().ends_the_wait() {
            return Ok(Next::Look(look));
        }
        if look.ever_held {
            info!(
                ?look,
                "stop wait: every process held has exited and none else carries the token"
            );
            return Ok(Next::Settled);
        }
        Err(SettleError::Arm(
            self.refused.take().expect("only reached after the SCM refused an arm"),
        ))
    }
}

#[cfg(test)]
#[path = "settle_tests.rs"]
mod settle_tests;
