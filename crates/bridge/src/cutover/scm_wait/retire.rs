//! Retiring the bridge service in one SCM session: stop it, and optionally
//! deregister it, without trusting a state the SCM can change underneath, and
//! return only once no service process is left.
//!
//! The order is harden, settle, then delete last. The hardening disables the
//! start type, so the SCM cannot start the service once it stops; the settle
//! loop ([`settle_stopped`]) is the one the update cutover runs; and nothing
//! touches the service handle after the delete.

use std::io;

use tracing::{info, warn};

use super::call_error::{io_error_is_a_refused_process_open, service_gone, ServiceGone};
use super::settle::{settle_stopped, SettleError, StopActor};

/// What a retirement leaves behind once the service is stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The service stays registered, stopped.
    StopOnly,
    /// The service is deleted.
    Deregister,
}

/// What opening a retirement's session found.
pub enum Opening<S> {
    /// The session, with its service handle.
    Opened(S),
    /// The SCM has no entry for the service: never registered, or removed. A
    /// process of it can still be running.
    Absent,
}

/// A service's start type as the SCM reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartType {
    Auto,
    Demand,
    Disabled,
    /// A boot or system start, which a service of its own process never has.
    Other,
}

/// A start type the retirement writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartWrite {
    Auto,
    Demand,
    Disabled,
}

/// The failure actions the retirement writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureActions {
    /// Restart nothing.
    None,
    /// What `install` configures: restart on failure.
    Restart,
}

/// What [`harden`] changed, which [`restore`] puts back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// The start type before it was disabled.
    pub observed: StartType,
}

impl Hardening {
    /// The start type to put back. The observed one if it was `Auto` or
    /// `Demand`; anything else becomes `Auto`, because `Disabled` is what an
    /// interrupted retirement leaves and the product treats it as broken.
    pub fn restored(self) -> StartWrite {
        match self.observed {
            StartType::Auto => StartWrite::Auto,
            StartType::Demand => StartWrite::Demand,
            StartType::Disabled => StartWrite::Auto,
            StartType::Other => StartWrite::Auto,
        }
    }
}

/// The SCM operations a retirement needs on top of the stop wait, all through
/// one service handle opened before anything is changed, so the delete, which
/// only marks the service, cannot take it away.
pub trait ServiceSession: StopActor {
    /// The start type now.
    fn start_type(&mut self) -> io::Result<StartType>;
    /// Write the start type.
    fn set_start_type(&mut self, to: StartWrite) -> io::Result<()>;
    /// Write the failure actions.
    fn set_failure_actions(&mut self, actions: FailureActions) -> io::Result<()>;
    /// `DeleteService`: mark the service for deletion.
    fn delete(&mut self) -> io::Result<()>;
}

/// Why a retirement failed, by the step that failed.
#[derive(Debug, thiserror::Error)]
pub enum RetireError {
    #[error("the service could not be hardened against a restart: {0}")]
    Harden(io::Error),
    #[error("the service's state could not be read: {0}")]
    Observe(io::Error),
    #[error("the service did not stop: {0}")]
    Stop(io::Error),
    #[error("the service's process could not be opened to wait for its exit: {0}")]
    Hold(io::Error),
    #[error("the service could not be deleted: {0}")]
    Delete(io::Error),
    #[error("the service's process could not be awaited: {0}")]
    Exit(io::Error),
}

impl RetireError {
    /// `error` as the failure of the step `step` names, unless it is the
    /// refusal to open the service's process: that is [`RetireError::Hold`]
    /// whichever step needed the process held, and is not the service failing
    /// to stop or to be read.
    pub(super) fn of_step(step: fn(io::Error) -> RetireError, error: io::Error) -> RetireError {
        if io_error_is_a_refused_process_open(&error) {
            RetireError::Hold(error)
        } else {
            step(error)
        }
    }
}

impl From<SettleError> for RetireError {
    fn from(error: SettleError) -> Self {
        match error {
            SettleError::Observe(e) => RetireError::of_step(RetireError::Observe, e),
            SettleError::Arm(e) => RetireError::of_step(RetireError::Stop, e),
            SettleError::Stop(e) => RetireError::of_step(RetireError::Stop, e),
            SettleError::AwaitChange(e) => RetireError::of_step(RetireError::Stop, e),
            SettleError::Scan(e) => RetireError::of_step(RetireError::Hold, e),
            SettleError::AwaitExit(e) => RetireError::of_step(RetireError::Exit, e),
        }
    }
}

/// What [`harden`] found.
enum Hardened {
    /// The start type is disabled, which [`restore`] undoes.
    Disabled(Hardening),
    /// The service is already marked for deletion by someone else's delete:
    /// nothing was changed, so there is nothing to put back and no delete to
    /// issue.
    Marked,
}

/// Whether `error` is the SCM answering that the service is marked for
/// deletion, from a call through the retirement's own handle.
fn answered_as_marked(error: &io::Error) -> bool {
    service_gone(error).is_some_and(ServiceGone::harden_goes_on_marked)
}

/// Disable the start type, then turn restart-on-failure off.
///
/// A disabled start type is what makes STOPPED final: the SCM's own restart of
/// a service it is about to restart starts it, and a disabled service cannot be
/// started ([`ChangeServiceConfig2W`, Remarks](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w#remarks):
/// "The service must be explicitly disabled to prevent it from restarting").
/// The change binds when the service stops. A failed start-type write is the
/// retirement's failure with nothing changed, unless the SCM answers that the
/// service is marked for deletion ([`Hardened::Marked`]); a failed
/// failure-actions write only narrows what is queued, and is warned about.
fn harden<S: ServiceSession>(session: &mut S) -> Result<Hardened, RetireError> {
    let observed = match session.start_type() {
        Ok(observed) => observed,
        Err(error) if answered_as_marked(&error) => return Ok(marked(&error)),
        Err(error) => return Err(RetireError::Harden(error)),
    };
    match session.set_start_type(StartWrite::Disabled) {
        Ok(()) => {}
        Err(error) if answered_as_marked(&error) => return Ok(marked(&error)),
        Err(error) => return Err(RetireError::Harden(error)),
    }
    if let Err(error) = session.set_failure_actions(FailureActions::None) {
        warn!(%error, "could not turn restart-on-failure off; the disabled start type still stops a restart");
    }
    Ok(Hardened::Disabled(Hardening { observed }))
}

fn marked(error: &io::Error) -> Hardened {
    info!(%error, "the service is marked for deletion; stopping it through the open handle");
    Hardened::Marked
}

/// Put back what [`harden`] changed: the failure actions as `install`
/// configures them, then the start type last, so a failure of the first never
/// leaves the service disabled. Each failure is a warning.
fn restore<S: ServiceSession>(session: &mut S, hardening: Hardening) {
    if let Err(error) = session.set_failure_actions(FailureActions::Restart) {
        warn!(%error, "could not put restart-on-failure back");
    }
    if let Err(error) = session.set_start_type(hardening.restored()) {
        warn!(%error, "could not put the start type back");
    }
}

/// Stop the service and, per `disposition`, delete it, and return once no
/// process of it is left.
///
/// 1. [`harden`]. A failure here changes nothing. A service found marked for
///    deletion skips the rest of the steps but the stop wait: it is stopped
///    through the open handle, and is neither restored nor deleted.
/// 2. [`settle_stopped`]: stop on a RUNNING observation, wait on the held
///    process, and settle only when the SCM says STOPPED and a scan finds no
///    process carrying the service's token.
/// 3. `Deregister` deletes, and the session's handle is not used again;
///    `StopOnly` restores the hardening. A failure before the delete restores
///    it and returns the step's own error.
///
/// `DeleteService` answering that the service is already marked is a success:
/// someone else's delete got there first.
pub fn retire<S: ServiceSession>(session: &mut S, disposition: Disposition) -> Result<(), RetireError> {
    let hardening = match harden(session)? {
        Hardened::Disabled(hardening) => hardening,
        Hardened::Marked => return settle_stopped(session).map_err(RetireError::from),
    };
    if let Err(error) = settle_stopped(session) {
        restore(session, hardening);
        return Err(error.into());
    }
    match disposition {
        Disposition::StopOnly => {
            restore(session, hardening);
            Ok(())
        }
        Disposition::Deregister => match session.delete() {
            Ok(()) => Ok(()),
            Err(error) if service_gone(&error).is_some_and(ServiceGone::delete_is_done) => {
                info!("the service was already marked for deletion");
                Ok(())
            }
            Err(error) => {
                restore(session, hardening);
                Err(RetireError::Delete(error))
            }
        },
    }
}

/// What waiting out the processes of a service the SCM has no entry for needs.
pub trait Survivors {
    /// Hold every live process that carries the service's token, other than
    /// the calling one.
    fn hold_scanned(&mut self) -> io::Result<()>;
    /// Whether any held process has not exited: a state read of each handle,
    /// never a wait.
    fn any_alive(&mut self) -> io::Result<bool>;
    /// Wait until every held process has exited.
    fn await_exits(&mut self) -> io::Result<()>;
}

/// Wait out every process that carries a removed service's token.
///
/// The SCM drops an entry once the service is not running, which is its state
/// and not its process, so a process can outlive its entry, and only a scan by
/// token sees it. Scan, hold, and while a held process is alive wait for it;
/// scan again, because a process that exited can have started another. Every
/// iteration ends in a process exit or in a scan that leaves nothing alive.
pub fn wait_out_survivors<W: Survivors>(survivors: &mut W) -> Result<(), RetireError> {
    loop {
        survivors.hold_scanned().map_err(RetireError::Hold)?;
        if !survivors.any_alive().map_err(RetireError::Exit)? {
            return Ok(());
        }
        survivors.await_exits().map_err(RetireError::Exit)?;
    }
}

/// [`retire`] on what opening the service found. `Ok(false)`: the SCM has no
/// entry, and the processes of it that outlived the entry (if any) were waited
/// out. `Ok(true)`: the retirement ran. `survivors` is built only for an absent
/// entry.
pub fn retire_over<S: ServiceSession, G: Survivors>(
    opening: Opening<S>,
    survivors: impl FnOnce() -> G,
    disposition: Disposition,
) -> Result<bool, RetireError> {
    match opening {
        Opening::Absent => {
            wait_out_survivors(&mut survivors())?;
            Ok(false)
        }
        Opening::Opened(mut session) => {
            retire(&mut session, disposition)?;
            Ok(true)
        }
    }
}

#[cfg(test)]
#[path = "retire_tests.rs"]
mod retire_tests;
