//! Retiring the bridge service in one SCM session: stop it, and optionally
//! deregister it, without trusting a state the SCM can change underneath.

use std::io;

use tracing::{info, warn};

use super::call_error::io_error_is_absent_service;
use super::{stop_via_notify, Observed, ScmActor, StopStep};

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
    /// The service's state, read now. Answers on a handle opened before the
    /// delete, which `arm` may not.
    fn observe(&mut self) -> io::Result<Observed>;
}

/// Why a retirement failed, by the step that failed.
#[derive(Debug, thiserror::Error)]
pub enum RetireError {
    #[error("the service did not stop: {0}")]
    Stop(io::Error),
    #[error("the service could not be deleted: {0}")]
    Delete(io::Error),
    #[error("the deleted service could not be confirmed stopped: {0}")]
    Drain(io::Error),
}

impl RetireError {
    /// Whether the retirement failed because the SCM has no service left to
    /// act on. Only a failed stop can mean that: the service went away under
    /// it, which is what the caller wanted. A delete or a confirmation is this
    /// session's own act, and its failure is never "already done".
    pub fn means_service_is_gone(&self) -> bool {
        match self {
            RetireError::Stop(error) => io_error_is_absent_service(error),
            RetireError::Delete(_) => false,
            RetireError::Drain(_) => false,
        }
    }
}

/// Stop the service and, per `disposition`, delete it.
///
/// **Restart-on-failure is turned off first**, because it is what makes
/// STOPPED non-final: a service the SCM is about to restart reads STOPPED, and
/// a stop that returned on it is followed by a live service
/// (bindreams/hole#1099). If the write fails the retirement goes on with a
/// warning, since the check after the delete covers the same slip; if the
/// retirement then fails, the restart is put back (a failed uninstall must
/// leave the hardening on).
///
/// **The delete is followed by a check on the same session.** A service the
/// SCM restarted between the stop and the delete is marked for deletion while
/// live. A handle opened before the delete still carries controls, and a
/// marked service cannot start again, so a STOPPED read here is final; any
/// other state is stopped again through the same wait. This does not rest on
/// how the SCM treats a restart timer already pending when the restart is
/// disabled.
///
/// The check reads the state with a query, not with `arm`: whether a
/// notification can be armed on a handle whose service is marked for deletion
/// has not been measured (see the stop probe in `tests/cutover_privileged.rs`).
/// Until it has, a service found live after the delete is stopped through the
/// wait, and if that cannot arm, the failure comes back as
/// [`RetireError::Drain`] rather than being papered over.
pub fn retire<S: ServiceSession>(session: &mut S, disposition: Disposition) -> Result<(), RetireError> {
    let restart_disabled = match session.disable_restart() {
        Ok(()) => true,
        Err(error) => {
            warn!(%error, "could not turn restart-on-failure off; relying on the check after the delete");
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

    if let Err(error) = stop_via_notify(session) {
        restore(session);
        return Err(RetireError::Stop(error));
    }

    match disposition {
        Disposition::StopOnly => {
            restore(session);
            Ok(())
        }
        Disposition::Deregister => {
            if let Err(error) = session.delete() {
                restore(session);
                return Err(RetireError::Delete(error));
            }
            // Past the delete there is no hardening to put back.
            let observed = session.observe().map_err(RetireError::Drain)?;
            match observed.for_stop_wait() {
                StopStep::Finished => Ok(()),
                StopStep::SendStop | StopStep::KeepWaiting => {
                    info!(
                        ?observed,
                        "service was restarted before the delete landed; stopping it again"
                    );
                    stop_via_notify(session).map_err(RetireError::Drain)
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "retire_tests.rs"]
mod retire_tests;
