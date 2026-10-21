//! The real SCM session behind [`retire`](crate::service_scm::retire):
//! one open `HoleBridge` service, used for the hardening writes, the stop wait,
//! the delete, the state query and the wait for the service's process.

use std::io;

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
use super::start_type_lock::{log_wait, Held, StartTypeLock};
use super::stop_session::StopSession;
use super::{apply_failure_actions, open_error_is_absent, scm_failure, FAILURE_ACTIONS_ACCESS, SERVICE_NAME};
use crate::disable_record::{Changer, RecordKey, RecordState};
use crate::service_scm::call_error::{win32_code_of_hresult, ScmCall, ScmCallError};
use crate::service_scm::hold::Look;
use crate::service_scm::retire::{FailureActions, Opening, ServiceSession, StartConfig, StartWrite, Survivors};
use crate::service_scm::scan::ScanFinding;
use crate::service_scm::settle::{ExitWait, StopActor};
use crate::service_scm::Observed;
use crate::service_start::StartType;

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
    record: RecordKey,
    /// Held from before the first read to after the last write. Last, so it is
    /// released after everything above is closed.
    _held: Held,
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
    /// Opens the session, or says the SCM has no entry to open, once the
    /// start-type lock is held; the session keeps it until it is dropped. A
    /// service marked for deletion opens: its mark is met on a call through
    /// the handle.
    pub fn open() -> Result<Opening<Self, GoneSession>, Box<dyn std::error::Error>> {
        Self::open_noting(&StartTypeLock::machine_wide(), log_wait)
    }

    /// [`open`](Self::open) over `lock`, calling `on_busy` if another holds it.
    pub(super) fn open_noting(
        lock: &StartTypeLock,
        on_busy: impl FnOnce(),
    ) -> Result<Opening<Self, GoneSession>, Box<dyn std::error::Error>> {
        Self::open_named(lock, SERVICE_NAME, on_busy)
    }

    /// [`open_noting`](Self::open_noting) for the service `name`.
    pub(super) fn open_named(
        lock: &StartTypeLock,
        name: &str,
        on_busy: impl FnOnce(),
    ) -> Result<Opening<Self, GoneSession>, Box<dyn std::error::Error>> {
        let held = lock.acquire_noting_wait(on_busy)?;
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| scm_failure(ScmCall::OpenScManager, e))?;
        let service = match manager.open_service(name, session_access()) {
            Ok(service) => service,
            Err(e) if open_error_is_absent(&e) => return Ok(Opening::Absent(GoneSession::new(name, held))),
            Err(e) => return Err(scm_failure(ScmCall::OpenService, e).into()),
        };
        // The first handle keeps the entry, so this open cannot find it gone.
        let stop = StopSession::open()?;
        Ok(Opening::Opened(Self {
            service,
            stop,
            record: RecordKey::service(),
            _held: held,
        }))
    }
}

/// The processes of a service the SCM has no entry for, found by its token
/// alone.
pub struct GoneSession {
    sid: ServiceSid,
    processes: ServiceProcesses,
    /// The start-type lock the open took, held while the survivors are waited
    /// out. Last, so it is released after the processes are closed.
    _held: Held,
}

impl GoneSession {
    fn new(name: &str, held: Held) -> Self {
        Self {
            sid: ServiceSid::of(name),
            processes: ServiceProcesses::default(),
            _held: held,
        }
    }
}

impl Survivors for GoneSession {
    fn hold_scanned(&mut self) -> io::Result<ScanFinding> {
        self.processes.hold_scanned(&self.sid)
    }

    fn await_exits(&mut self) -> io::Result<()> {
        info!(
            held = self.processes.held(),
            "waiting for the processes of a removed service entry to exit"
        );
        self.processes.await_exits(ExitWait::TerminateThenWait)
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

    fn await_held_exits(&mut self, wait: ExitWait) -> io::Result<()> {
        self.stop.await_held_exits(wait)
    }

    fn hold_scanned(&mut self) -> io::Result<ScanFinding> {
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
        self.record.state()
    }

    fn clear_record(&mut self) -> io::Result<()> {
        self.record.clear()
    }

    fn write_record(&mut self) -> io::Result<()> {
        self.record.write()
    }

    fn record_changer(&mut self) -> Option<Changer> {
        self.record.changer()
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
