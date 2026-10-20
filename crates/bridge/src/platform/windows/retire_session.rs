//! The real SCM session behind [`retire`](crate::cutover::scm_wait::retire):
//! one open `HoleBridge` service, used for the hardening writes, the stop wait,
//! the delete, the state query and the wait for the service's process.

use std::io;
use std::mem::MaybeUninit;

use tracing::info;
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    ChangeServiceConfigW, QueryServiceStatusEx, ENUM_SERVICE_TYPE, SC_HANDLE, SC_STATUS_PROCESS_INFO, SERVICE_ERROR,
    SERVICE_NO_CHANGE, SERVICE_START_TYPE, SERVICE_STATUS_PROCESS,
};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceStartType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::service_processes::{has_exited, open_process, ServiceProcesses};
use super::service_sid::ServiceSid;
use super::{apply_failure_actions, open_error_is_absent, scm_failure, FAILURE_ACTIONS_ACCESS, SERVICE_NAME};
use crate::cutover::scm_wait::call_error::{win32_code_of_hresult, ScmCall, ScmCallError};
use crate::cutover::scm_wait::hold::{Basis, Look, Opened, ProcessSource, Reading};
use crate::cutover::scm_wait::retire::{FailureActions, Opening, ServiceSession, StartType, StartWrite, Survivors};
use crate::cutover::scm_wait::settle::{StopActor, WaitKind};
use crate::cutover::scm_wait::{observed_from_state, Observed, SystemScmActor};

/// One service handle, opened before anything is changed, carries the queries,
/// the hardening writes, the Stop and the delete. The delete only marks the
/// service, so it cannot take the handle away. Notifications are armed on
/// handles of their own, opened per arm.
pub struct RetireSession {
    /// Queries, configuration, Stop and delete.
    service: Service,
    /// The notification arms and the sleep on them.
    actor: SystemScmActor,
    /// The SID a process of the service carries.
    sid: ServiceSid,
    /// The processes the service has shown.
    processes: ServiceProcesses,
}

/// The rights the session's handle is opened with: exactly those its calls
/// need.
///
/// - `QueryServiceStatusEx`: `SERVICE_QUERY_STATUS`.
/// - `QueryServiceConfig`: `SERVICE_QUERY_CONFIG`.
/// - `ChangeServiceConfigW`: `SERVICE_CHANGE_CONFIG`.
/// - `ChangeServiceConfig2W`: `SERVICE_CHANGE_CONFIG`, and for the restart
///   action the restore writes, `SERVICE_START` (the failure-actions right).
/// - `ControlService` with a stop: `SERVICE_STOP`.
/// - `DeleteService`: `DELETE`.
fn session_access() -> ServiceAccess {
    ServiceAccess::QUERY_STATUS
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::STOP
        | ServiceAccess::DELETE
        | FAILURE_ACTIONS_ACCESS
}

impl RetireSession {
    /// Opens the session, or says the SCM has no entry to open. A service
    /// marked for deletion opens: its mark is met on a call through the handle.
    pub fn open() -> Result<Opening<Self>, Box<dyn std::error::Error>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| scm_failure(ScmCall::OpenScManager, e))?;
        let service = match manager.open_service(SERVICE_NAME, session_access()) {
            Ok(service) => service,
            Err(e) if open_error_is_absent(&e) => return Ok(Opening::Absent),
            Err(e) => return Err(scm_failure(ScmCall::OpenService, e).into()),
        };
        // The first handle keeps the entry, so this open cannot find it gone.
        let actor = SystemScmActor::open(SERVICE_NAME)?;
        Ok(Opening::Opened(Self {
            service,
            actor,
            sid: ServiceSid::of(SERVICE_NAME),
            processes: ServiceProcesses::default(),
        }))
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

    fn raw(&self) -> SC_HANDLE {
        SC_HANDLE(self.service.raw_handle())
    }
}

/// The processes of a service the SCM has no entry for, found by its token
/// alone.
pub struct GoneSession {
    sid: ServiceSid,
    processes: ServiceProcesses,
}

impl GoneSession {
    pub fn new() -> Self {
        Self {
            sid: ServiceSid::of(SERVICE_NAME),
            processes: ServiceProcesses::default(),
        }
    }
}

impl Survivors for GoneSession {
    fn hold_scanned(&mut self) -> io::Result<()> {
        self.processes.hold_scanned(&self.sid)
    }

    fn any_alive(&mut self) -> io::Result<bool> {
        self.processes.any_alive()
    }

    fn await_exits(&mut self) -> io::Result<()> {
        info!(
            held = self.processes.held(),
            "waiting for the processes of a removed service entry to exit"
        );
        self.processes.await_exits()
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

impl StopActor for RetireSession {
    fn observe(&mut self) -> io::Result<Look> {
        self.look()
    }

    fn arm_leaving(&mut self, from: Observed) -> io::Result<()> {
        self.actor.arm_leaving(from)
    }

    fn control_stop(&mut self) -> io::Result<()> {
        self.service
            .stop()
            .map(drop)
            .map_err(|e| scm_failure(ScmCall::ControlService, e))
    }

    fn await_callback(&mut self, kind: WaitKind) -> io::Result<()> {
        self.actor.await_callback(kind)
    }

    fn await_held_exits(&mut self, _kind: WaitKind) -> io::Result<()> {
        self.processes.await_exits()
    }

    fn hold_scanned(&mut self) -> io::Result<()> {
        self.processes.hold_scanned(&self.sid)
    }
}

impl ServiceSession for RetireSession {
    fn start_type(&mut self) -> io::Result<StartType> {
        self.service
            .query_config()
            .map(|config| start_type_from(config.start_type))
            .map_err(|e| scm_failure(ScmCall::QueryServiceConfig, e))
    }

    fn set_start_type(&mut self, to: StartWrite) -> io::Result<()> {
        // SAFETY: the handle is the live one `self.service` owns; every pointer
        // argument is null, which `SERVICE_NO_CHANGE` and the documented null
        // defaults leave alone.
        unsafe {
            ChangeServiceConfigW(
                self.raw(),
                ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                SERVICE_START_TYPE(scm_start_type(to).to_raw()),
                SERVICE_ERROR(SERVICE_NO_CHANGE),
                PCWSTR::null(),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )
        }
        .map_err(|e| {
            ScmCallError {
                call: ScmCall::ChangeServiceConfig,
                code: win32_code_of_hresult(e.code().0),
            }
            .into_io()
        })
    }

    fn set_failure_actions(&mut self, actions: FailureActions) -> io::Result<()> {
        match actions {
            FailureActions::None => self
                .service
                .update_failure_actions(no_restart_failure_actions())
                .map_err(|e| scm_failure(ScmCall::ChangeServiceConfig2, e)),
            FailureActions::Restart => apply_failure_actions(&self.service),
        }
    }

    fn delete(&mut self) -> io::Result<()> {
        self.service
            .delete()
            .map_err(|e| scm_failure(ScmCall::DeleteService, e))
    }
}

/// The retirement's start type for what the SCM reports.
fn start_type_from(reported: ServiceStartType) -> StartType {
    match reported {
        ServiceStartType::AutoStart => StartType::Auto,
        ServiceStartType::OnDemand => StartType::Demand,
        ServiceStartType::Disabled => StartType::Disabled,
        ServiceStartType::SystemStart => StartType::Other,
        ServiceStartType::BootStart => StartType::Other,
    }
}

/// The SCM start type a write names.
fn scm_start_type(written: StartWrite) -> ServiceStartType {
    match written {
        StartWrite::Auto => ServiceStartType::AutoStart,
        StartWrite::Demand => ServiceStartType::OnDemand,
        StartWrite::Disabled => ServiceStartType::Disabled,
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
