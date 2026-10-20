//! The real SCM session behind [`retire`](crate::cutover::scm_wait::retire):
//! one open `HoleBridge` service, used for the restart toggle, the stop wait,
//! the delete, the state query and the wait for the service's process.

use std::io;
use std::mem::MaybeUninit;

use windows::Win32::System::Services::{
    QueryServiceStatusEx, SC_HANDLE, SC_STATUS_PROCESS_INFO, SERVICE_STATUS_PROCESS,
};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::service_processes::{has_exited, open_process, ServiceProcesses};
use super::service_sid::ServiceSid;
use super::{apply_failure_actions, scm_failure, SERVICE_NAME};
use crate::cutover::scm_wait::call_error::{io_error_is_absent_service, win32_code_of_hresult, ScmCall, ScmCallError};
use crate::cutover::scm_wait::hold::{Basis, Look, Opened, ProcessFate, ProcessSource, Reading};
use crate::cutover::scm_wait::retire::ServiceSession;
use crate::cutover::scm_wait::{observed_from_state, Observed, ScmActor, SystemScmActor, WantState};

/// Both handles are opened before anything is changed, so the delete, which
/// only marks the service, cannot take either away: a handle opened earlier
/// keeps carrying controls and queries after the mark.
pub struct RetireSession {
    /// Restart toggle, delete and state query.
    service: Service,
    /// The stop wait.
    actor: SystemScmActor,
    /// The SID a process of the service carries.
    sid: ServiceSid,
    /// The processes the service has shown.
    processes: ServiceProcesses,
}

impl RetireSession {
    /// Opens the session, or `None` when the SCM has no `HoleBridge` to act on
    /// (never registered, or already marked for deletion).
    pub fn open() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| scm_failure(ScmCall::OpenScManager, e))?;
        let service = match manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::DELETE,
        ) {
            Ok(service) => service,
            Err(e) if super::open_error_is_absent(&e) => return Ok(None),
            Err(e) => return Err(scm_failure(ScmCall::OpenService, e).into()),
        };
        match SystemScmActor::open(SERVICE_NAME) {
            Ok(actor) => Ok(Some(Self {
                service,
                actor,
                sid: ServiceSid::of(SERVICE_NAME),
                processes: ServiceProcesses::default(),
            })),
            // Deleted between the two opens.
            Err(e) if io_error_is_absent_service(&e) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Reads the service, holds the process it names, and says whether that
    /// process is still alive; the state returned is the one the hold was
    /// confirmed against.
    fn look(&mut self) -> io::Result<Look> {
        self.processes.look(&mut ServiceProbe {
            service: &self.service,
            sid: &self.sid,
        })
    }
}

/// The service as [`ProcessHolds`](crate::cutover::scm_wait::hold::ProcessHolds)
/// reads it: one query for the state and the process id, and an open by id
/// that keeps a process only if its token carries the service SID.
struct ServiceProbe<'a> {
    service: &'a Service,
    sid: &'a ServiceSid,
}

impl ProcessSource for ServiceProbe<'_> {
    type Process = std::os::windows::io::OwnedHandle;

    fn read(&mut self) -> io::Result<Reading> {
        let (state, pid) = self.query()?;
        let observed = observed_from_state(state).ok_or_else(|| {
            io::Error::other(format!(
                "the service reported state {state}, which is not one it can retire from"
            ))
        })?;
        Ok(Reading { observed, pid })
    }

    fn open(&mut self, pid: u32, basis: Basis) -> io::Result<Opened<Self::Process>> {
        open_process(pid, self.sid, basis)
    }

    fn has_exited(&mut self, process: &Self::Process) -> io::Result<bool> {
        has_exited(process)
    }
}

impl ServiceProbe<'_> {
    /// The service's state and process id, in one query. The id is 0 when
    /// there is no process.
    fn query(&self) -> io::Result<(u32, u32)> {
        let mut status = MaybeUninit::<SERVICE_STATUS_PROCESS>::zeroed();
        let mut needed = 0u32;
        // SAFETY: the buffer is `status`'s own storage, of exactly its size.
        let queried = unsafe {
            QueryServiceStatusEx(
                SC_HANDLE(self.service.raw_handle()),
                SC_STATUS_PROCESS_INFO,
                Some(std::slice::from_raw_parts_mut(
                    status.as_mut_ptr().cast::<u8>(),
                    std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
                )),
                &mut needed,
            )
        };
        queried.map_err(|e| {
            ScmCallError {
                call: ScmCall::QueryServiceStatusEx,
                code: win32_code_of_hresult(e.code().0),
            }
            .into_io()
        })?;
        // SAFETY: the SCM filled the buffer, and a zeroed one is valid too.
        let status = unsafe { status.assume_init() };
        Ok((status.dwCurrentState.0, status.dwProcessId))
    }
}

impl ScmActor for RetireSession {
    fn arm(&mut self, want: WantState, except: Option<Observed>) -> io::Result<()> {
        self.actor.arm(want, except)
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
    /// A bare session holds nothing on a callback; `retire` wraps it to.
    fn process_fate(&mut self) -> io::Result<ProcessFate> {
        Ok(ProcessFate::Unheld)
    }
}

impl ServiceSession for RetireSession {
    fn disable_restart(&mut self) -> io::Result<()> {
        self.service
            .update_failure_actions(no_restart_failure_actions())
            .map_err(|e| scm_failure(ScmCall::ChangeServiceConfig2, e))
    }

    fn restore_restart(&mut self) -> io::Result<()> {
        apply_failure_actions(&self.service)
    }

    fn delete(&mut self) -> io::Result<()> {
        self.service
            .delete()
            .map_err(|e| scm_failure(ScmCall::DeleteService, e))
    }

    fn observe(&mut self) -> io::Result<Look> {
        self.look()
    }

    fn hold_process(&mut self) -> io::Result<ProcessFate> {
        Ok(self.look()?.fate)
    }

    fn await_exits(&mut self) -> io::Result<()> {
        self.processes.await_exits()
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

#[cfg(test)]
#[path = "retire_session_tests.rs"]
mod retire_session_tests;
