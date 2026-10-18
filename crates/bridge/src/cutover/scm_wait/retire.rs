//! Retiring the bridge service in one SCM session: stop it, and optionally
//! deregister it, without trusting a state the SCM can change underneath, and
//! return only once no service process is left.

use std::io;

use tracing::{info, warn};

use super::call_error::{io_error_is_a_refused_process_open, io_error_is_absent_service};
use super::hold::{Look, ProcessFate};
use super::{stop_via_notify, DrainStep, Observed, ScmActor, WantState};

/// What a retirement leaves behind once the service is stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The service stays registered, stopped.
    StopOnly,
    /// The service is deleted.
    Deregister,
}

/// The SCM operations a retirement needs on top of the stop wait, all on one
/// open session so no step re-decides on a state a probe saw earlier.
pub trait ServiceSession: ScmActor {
    /// Turn restart-on-failure off, so STOPPED is final.
    fn disable_restart(&mut self) -> io::Result<()>;
    /// Put restart-on-failure back as `install` configures it.
    fn restore_restart(&mut self) -> io::Result<()>;
    /// `DeleteService`: mark the service for deletion.
    fn delete(&mut self) -> io::Result<()>;
    /// The service's state, read now with a query (not an arm: a handle opened
    /// before the delete answers a query, and whether it can be armed has not
    /// been measured). Holds the process it names, as
    /// [`hold_process`](Self::hold_process), and says whether that process is
    /// still alive.
    fn observe(&mut self) -> io::Result<Look>;
    /// Hold the process the service has now, if it has one, so that its exit
    /// can be awaited after the SCM stops reporting it. Returns its fate.
    fn hold_process(&mut self) -> io::Result<ProcessFate>;
    /// Block until every held process has exited. An external event, so no
    /// bound: the process of a service the SCM reports STOPPED can outlive it.
    fn await_exits(&mut self) -> io::Result<()>;
}

/// Why a retirement failed, by the step that failed.
#[derive(Debug, thiserror::Error)]
pub enum RetireError {
    #[error("the service's state could not be read: {0}")]
    Observe(io::Error),
    #[error("the service did not stop: {0}")]
    Stop(io::Error),
    #[error("the service's process could not be opened to wait for its exit: {0}")]
    Hold(io::Error),
    #[error("the service could not be deleted: {0}")]
    Delete(io::Error),
    #[error("the deleted service could not be confirmed stopped: {0}")]
    Drain(io::Error),
    #[error("the service's process could not be awaited: {0}")]
    Exit(io::Error),
}

impl RetireError {
    /// `error` as the failure of the step `step` names, unless it is the
    /// refusal to open the service's process: that is [`RetireError::Hold`]
    /// whichever step needed the process held, and is not the service failing
    /// to stop, to be read or to be drained.
    pub(super) fn of_step(step: fn(io::Error) -> RetireError, error: io::Error) -> RetireError {
        if io_error_is_a_refused_process_open(&error) {
            RetireError::Hold(error)
        } else {
            step(error)
        }
    }

    /// Whether the retirement failed because the SCM has no service left to
    /// act on. Only the first look and the stop can mean that: the service went
    /// away under them, which is what the caller wanted. A delete, a drain or a
    /// wait is this session's own act, and its failure is never "already done".
    pub fn means_service_is_gone(&self) -> bool {
        match self {
            RetireError::Observe(error) => io_error_is_absent_service(error),
            RetireError::Stop(error) => io_error_is_absent_service(error),
            RetireError::Hold(_) => false,
            RetireError::Delete(_) => false,
            RetireError::Drain(_) => false,
            RetireError::Exit(_) => false,
        }
    }
}

/// The session as the stop wait sees it, holding the process behind every
/// state a callback reports that has one. A restart can bring up a process the
/// first look never saw, and the stop wait is where it is seen.
struct Holding<'a, S> {
    session: &'a mut S,
    /// The fate of the process behind the latest callback.
    fate: ProcessFate,
}

impl<'a, S> Holding<'a, S> {
    fn new(session: &'a mut S) -> Self {
        Self {
            session,
            fate: ProcessFate::Unheld,
        }
    }
}

impl<S: ServiceSession> ScmActor for Holding<'_, S> {
    fn arm(&mut self, want: WantState, except: Option<Observed>) -> io::Result<()> {
        self.session.arm(want, except)
    }
    fn control_stop(&mut self) -> io::Result<()> {
        self.session.control_stop()
    }
    fn start(&mut self) -> io::Result<()> {
        self.session.start()
    }
    fn wait_callback(&mut self) -> io::Result<Observed> {
        let observed = self.session.wait_callback()?;
        self.fate = if observed.names_a_process() {
            self.session.hold_process()?
        } else {
            ProcessFate::Unheld
        };
        Ok(observed)
    }
    fn process_fate(&mut self) -> io::Result<ProcessFate> {
        Ok(self.fate)
    }
}

/// Stop the service and, per `disposition`, delete it, and return once no
/// process of it is left.
///
/// **Restart-on-failure is turned off first**, because it is what makes
/// STOPPED non-final: a service the SCM is about to restart reads STOPPED, and
/// a stop that returned on it is followed by a live service
/// (bindreams/hole#1099). If the write fails the retirement goes on with a
/// warning, since the drain after the delete covers the same slip; if the
/// retirement then fails, the restart is put back (a failed uninstall must
/// leave the hardening on).
///
/// **The process, not the state, is what is waited out.** The SCM reports
/// STOPPED before the process has exited, and the files its image maps are not
/// removable until it has. Every process the service shows, on the first look
/// and on every callback of the stop wait, is held, and the retirement ends
/// with a wait for all of them.
///
/// **The delete is followed by a drain on the same session** ([`drain`]).
pub fn retire<S: ServiceSession>(session: &mut S, disposition: Disposition) -> Result<(), RetireError> {
    session
        .observe()
        .map_err(|e| RetireError::of_step(RetireError::Observe, e))?;
    let restart_disabled = match session.disable_restart() {
        Ok(()) => true,
        Err(error) => {
            warn!(%error, "could not turn restart-on-failure off; relying on the drain after the delete");
            false
        }
    };
    let restore = |session: &mut S| {
        if restart_disabled {
            if let Err(error) = session.restore_restart() {
                warn!(%error, "could not put restart-on-failure back");
            }
        }
    };

    if let Err(error) = stop_via_notify(&mut Holding::new(session)) {
        restore(session);
        return Err(RetireError::of_step(RetireError::Stop, error));
    }

    match disposition {
        Disposition::StopOnly => {
            // Before the restart is put back: a process that fails on its way
            // out must not be restarted by the hardening being restored.
            let awaited = session.await_exits();
            restore(session);
            awaited.map_err(RetireError::Exit)
        }
        Disposition::Deregister => {
            if let Err(error) = session.delete() {
                restore(session);
                return Err(RetireError::Delete(error));
            }
            // Past the delete there is no hardening to put back.
            drain(session)
        }
    }
}

/// Bring a service marked for deletion to STOPPED, or to a process that has
/// exited, with every process it showed gone.
///
/// A service the SCM restarted between the stop and the delete is marked while
/// live; a handle opened before the delete still carries controls and queries.
/// What this does about each look is [`Observed::for_drain_step`], which reads
/// the process as well as the status, because the status can lag the process's
/// exit: a look whose process has exited leaves nothing to drain whatever the
/// SCM still says. None of the steps that have a process to wait on arms a
/// notification: whether `NotifyServiceStatusChangeW` works on a marked service
/// has not been measured (the stop probe in `tests/cutover_privileged.rs` prints
/// it), so the drain does not rest on it. START_PENDING with a live process, and
/// a live state with no process held, have no exit to wait on (a Stop is refused
/// in START_PENDING, and with no process held there is nothing to block on): they
/// go through the stop wait, and if that cannot arm the failure comes back as
/// [`RetireError::Drain`] rather than being hidden. Every iteration ends in a real
/// event, a process exit or a notification, so the drain never re-queries a
/// state that has not changed.
///
/// Public so the privileged tests can run it on a service they marked
/// themselves; `retire` is its one production caller.
///
/// Every wait for a process is followed by a fresh look, because the time it
/// takes is time in which the SCM could start another; the drain ends on a look
/// that finds nothing live after the last wait.
pub fn drain<S: ServiceSession>(session: &mut S) -> Result<(), RetireError> {
    let mut look = session
        .observe()
        .map_err(|e| RetireError::of_step(RetireError::Drain, e))?;
    loop {
        match look.observed.for_drain_step(look.fate) {
            DrainStep::Finished => {
                session.await_exits().map_err(RetireError::Exit)?;
                look = session
                    .observe()
                    .map_err(|e| RetireError::of_step(RetireError::Drain, e))?;
                if look.observed.for_drain_step(look.fate) == DrainStep::Finished {
                    return Ok(());
                }
            }
            DrainStep::StopThenAwaitExit => {
                info!(?look, "service is live after the delete; stopping it");
                if let Err(refused) = session.control_stop() {
                    // Refused on a RUNNING observation the service may have left
                    // since; only a service still RUNNING makes it a failure.
                    look = session
                        .observe()
                        .map_err(|e| RetireError::of_step(RetireError::Drain, e))?;
                    if look.observed.for_drain_step(look.fate) == DrainStep::StopThenAwaitExit {
                        return Err(RetireError::Drain(refused));
                    }
                    continue;
                }
                session.await_exits().map_err(RetireError::Exit)?;
                look = session
                    .observe()
                    .map_err(|e| RetireError::of_step(RetireError::Drain, e))?;
            }
            DrainStep::AwaitExit => {
                info!(?look, "service is stopping after the delete; awaiting its process");
                session.await_exits().map_err(RetireError::Exit)?;
                look = session
                    .observe()
                    .map_err(|e| RetireError::of_step(RetireError::Drain, e))?;
            }
            DrainStep::AwaitRunning => {
                info!(?look, "service is starting after the delete; stopping it once it runs");
                stop_via_notify(&mut Holding::new(session)).map_err(|e| RetireError::of_step(RetireError::Drain, e))?;
                look = session
                    .observe()
                    .map_err(|e| RetireError::of_step(RetireError::Drain, e))?;
            }
            DrainStep::AwaitStatus => {
                info!(?look, "service is live after the delete with no process to wait on");
                stop_via_notify(&mut Holding::new(session)).map_err(|e| RetireError::of_step(RetireError::Drain, e))?;
                look = session
                    .observe()
                    .map_err(|e| RetireError::of_step(RetireError::Drain, e))?;
            }
        }
    }
}

#[cfg(test)]
#[path = "retire_tests.rs"]
mod retire_tests;
