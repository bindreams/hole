//! The real SCM session behind [`retire`](crate::cutover::scm_wait::retire):
//! one open `HoleBridge` service, used for the restart toggle, the stop wait,
//! the delete and the check after it.

use std::io;

use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceState,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::{apply_failure_actions, SERVICE_NAME};
use crate::cutover::scm_wait::call_error::io_error_is_absent_service;
use crate::cutover::scm_wait::retire::ServiceSession;
use crate::cutover::scm_wait::{Observed, ScmActor, SystemScmActor, WantState};

/// Both handles are opened before anything is changed, so the delete, which
/// only marks the service, cannot take either away: a handle opened earlier
/// keeps carrying controls and queries after the mark.
pub struct RetireSession {
    /// Restart toggle, delete and state query.
    service: Service,
    /// The stop wait.
    actor: SystemScmActor,
}

impl RetireSession {
    /// Opens the session, or `None` when the SCM has no `HoleBridge` to act on
    /// (never registered, or already marked for deletion).
    pub fn open() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = match manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::DELETE,
        ) {
            Ok(service) => service,
            Err(e) if super::open_error_is_absent(&e) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match SystemScmActor::open(SERVICE_NAME) {
            Ok(actor) => Ok(Some(Self { service, actor })),
            // Deleted between the two opens.
            Err(e) if io_error_is_absent_service(&e) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

impl ScmActor for RetireSession {
    fn arm(&mut self, want: WantState) -> io::Result<()> {
        self.actor.arm(want)
    }
    fn control_stop(&mut self) -> io::Result<()> {
        self.actor.control_stop()
    }
    fn start(&mut self) -> io::Result<()> {
        self.actor.start()
    }
    fn wait_callback(&mut self) -> io::Result<Observed> {
        self.actor.wait_callback()
    }
}

impl ServiceSession for RetireSession {
    fn disable_restart(&mut self) -> io::Result<()> {
        self.service
            .update_failure_actions(no_restart_failure_actions())
            .map_err(io::Error::other)
    }

    fn restore_restart(&mut self) -> io::Result<()> {
        apply_failure_actions(&self.service).map_err(io::Error::other)
    }

    fn delete(&mut self) -> io::Result<()> {
        self.service.delete().map_err(io::Error::other)
    }

    fn observe(&mut self) -> io::Result<Observed> {
        let state = self.service.query_status().map_err(io::Error::other)?.current_state;
        observed_from_service_state(state).ok_or_else(|| {
            io::Error::other(format!(
                "the service reported state {state:?}, which is not one it can retire from"
            ))
        })
    }
}

/// Failure actions that restart nothing: one action, of type None, so a
/// failure of the service is acted on by doing nothing. The reset period is the
/// hardening's own, so restoring it changes only the actions.
pub(super) fn no_restart_failure_actions() -> ServiceFailureActions {
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(std::time::Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![ServiceAction {
            action_type: ServiceActionType::None,
            delay: std::time::Duration::ZERO,
        }]),
    }
}

/// The observation for a queried service state, or `None` for the pause states
/// the bridge never enters.
pub(super) fn observed_from_service_state(state: ServiceState) -> Option<Observed> {
    match state {
        ServiceState::Running => Some(Observed::Running),
        ServiceState::Stopped => Some(Observed::Stopped),
        ServiceState::StartPending => Some(Observed::StartPending),
        ServiceState::StopPending => Some(Observed::StopPending),
        ServiceState::ContinuePending | ServiceState::PausePending | ServiceState::Paused => None,
    }
}

#[cfg(test)]
#[path = "retire_session_tests.rs"]
mod retire_session_tests;
