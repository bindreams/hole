//! The real SCM session behind [`retire`](crate::cutover::scm_wait::retire):
//! one open `HoleBridge` service, used for the hardening writes, the stop wait,
//! the delete, the state query and the wait for the service's process.

use std::io;
use std::path::PathBuf;

use tracing::info;
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    ChangeServiceConfigW, ENUM_SERVICE_TYPE, SC_HANDLE, SERVICE_ERROR, SERVICE_NO_CHANGE, SERVICE_START_TYPE,
};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceStartType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::service_processes::ServiceProcesses;
use super::service_sid::ServiceSid;
use super::stop_session::StopSession;
use super::{apply_failure_actions, open_error_is_absent, scm_failure, FAILURE_ACTIONS_ACCESS, SERVICE_NAME};
use crate::cutover::scm_wait::call_error::{win32_code_of_hresult, ScmCall, ScmCallError};
use crate::cutover::scm_wait::hold::Look;
use crate::cutover::scm_wait::retire::{
    FailureActions, Opening, ServiceSession, StartConfig, StartType, StartWrite, Survivors,
};
use crate::cutover::scm_wait::settle::StopActor;
use crate::cutover::scm_wait::Observed;
use crate::disable_record::{self, RecordState};

/// One service handle, opened before anything is changed, carries the
/// hardening writes and the delete; the delete only marks the service, so it
/// cannot take the handle away. The stop wait, the state queries and the
/// processes the service shows are the [`StopSession`]'s.
pub struct RetireSession {
    /// Configuration and delete.
    service: Service,
    /// The stop wait.
    stop: StopSession,
    /// Where the record that an uninstall disabled the service lives.
    state_dir: PathBuf,
}

/// The rights the session's handle is opened with: exactly those its calls
/// need.
///
/// - `QueryServiceConfig`: `SERVICE_QUERY_CONFIG`.
/// - `ChangeServiceConfigW`: `SERVICE_CHANGE_CONFIG`.
/// - `ChangeServiceConfig2W`: `SERVICE_CHANGE_CONFIG`, and for the restart
///   action the restore writes, `SERVICE_START` (the failure-actions right).
/// - `DeleteService`: `DELETE`.
fn session_access() -> ServiceAccess {
    ServiceAccess::QUERY_CONFIG | ServiceAccess::DELETE | FAILURE_ACTIONS_ACCESS
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
        let stop = StopSession::open()?;
        Ok(Opening::Opened(Self {
            service,
            stop,
            state_dir: crate::cutover::service_state_dir(),
        }))
    }
}

/// The processes of a service the SCM has no entry for, found by its token
/// alone.
pub struct GoneSession {
    sid: ServiceSid,
    processes: ServiceProcesses,
}

impl Default for GoneSession {
    fn default() -> Self {
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

impl StopActor for RetireSession {
    fn observe(&mut self) -> io::Result<Look> {
        self.stop.observe()
    }

    fn arm_leaving(&mut self, from: Observed) -> io::Result<()> {
        self.stop.arm_leaving(from)
    }

    fn control_stop(&mut self) -> io::Result<()> {
        self.stop.control_stop()
    }

    fn await_callback(&mut self) -> io::Result<()> {
        self.stop.await_callback()
    }

    fn await_held_exits(&mut self) -> io::Result<()> {
        self.stop.await_held_exits()
    }

    fn hold_scanned(&mut self) -> io::Result<()> {
        self.stop.hold_scanned()
    }
}

impl StartConfig for RetireSession {
    fn start_type(&mut self) -> io::Result<StartType> {
        read_start_type(&self.service)
    }

    fn set_start_type(&mut self, to: StartWrite) -> io::Result<()> {
        write_start_type(&self.service, to)
    }

    fn record_state(&mut self) -> RecordState {
        disable_record::record_state(&self.state_dir)
    }

    fn clear_record(&mut self) -> io::Result<()> {
        disable_record::clear(&self.state_dir)
    }
}

impl ServiceSession for RetireSession {
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

    fn write_record(&mut self) -> io::Result<()> {
        disable_record::write(&self.state_dir)
    }
}

/// The start type of an open service (needs `SERVICE_QUERY_CONFIG`).
pub(super) fn read_start_type(service: &Service) -> io::Result<StartType> {
    service
        .query_config()
        .map(|config| start_type_from(config.start_type))
        .map_err(|e| scm_failure(ScmCall::QueryServiceConfig, e))
}

/// Writes the start type of an open service (needs `SERVICE_CHANGE_CONFIG`).
pub(super) fn write_start_type(service: &Service, to: StartWrite) -> io::Result<()> {
    // SAFETY: the handle is the live one `service` owns; every pointer
    // argument is null, which `SERVICE_NO_CHANGE` and the documented null
    // defaults leave alone.
    unsafe {
        ChangeServiceConfigW(
            SC_HANDLE(service.raw_handle()),
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
