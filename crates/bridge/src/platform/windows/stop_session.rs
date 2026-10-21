//! The real SCM session behind the stop wait ([`settle_stopped`]): one open
//! `HoleBridge` service for the queries and the Stop, the notification arms
//! on handles of their own, and the processes the service has shown, held so
//! their exit can be awaited. Both the update cutover and the retirement stop
//! the service through it, so a service process that outlives STOPPED is
//! waited out on both, by the scan for the service's token.
//!
//! [`settle_stopped`]: crate::cutover::scm_wait::settle::settle_stopped

use std::io;
use std::mem::MaybeUninit;

use windows::Win32::System::Services::{
    QueryServiceStatusEx, SC_HANDLE, SC_STATUS_PROCESS_INFO, SERVICE_STATUS_PROCESS,
};
use windows_service::service::{Service, ServiceAccess};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::service_processes::{has_exited, open_process, ServiceProcesses};
use super::service_sid::ServiceSid;
use super::{scm_failure, SERVICE_NAME};
use crate::cutover::scm_wait::call_error::{win32_code_of_hresult, ScmCall, ScmCallError};
use crate::cutover::scm_wait::hold::{Basis, Look, Opened, ProcessSource, Reading};
use crate::cutover::scm_wait::scan::ScanFinding;
use crate::cutover::scm_wait::settle::{ExitWait, StopActor};
use crate::cutover::scm_wait::{observed_from_state, Observed, SystemScmActor};

/// The rights the session's handle is opened with: exactly those its calls
/// need.
///
/// - `QueryServiceStatusEx`: `SERVICE_QUERY_STATUS`.
/// - `ControlService` with a stop: `SERVICE_STOP`.
fn stop_access() -> ServiceAccess {
    ServiceAccess::QUERY_STATUS | ServiceAccess::STOP
}

/// The stop wait's view of the service. The handle carries the queries and the
/// Stop; notifications are armed on handles of their own, opened per arm.
pub struct StopSession {
    service: Service,
    /// The notification arms and the sleep on them.
    actor: SystemScmActor,
    /// The SID a process of the service carries.
    sid: ServiceSid,
    /// The processes the service has shown.
    processes: ServiceProcesses,
}

impl StopSession {
    /// Opens the service. A service marked for deletion opens: its mark is met
    /// on a call through the handle.
    pub fn open() -> io::Result<Self> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| scm_failure(ScmCall::OpenScManager, e))?;
        let service = manager
            .open_service(SERVICE_NAME, stop_access())
            .map_err(|e| scm_failure(ScmCall::OpenService, e))?;
        Ok(Self {
            service,
            actor: SystemScmActor::open(SERVICE_NAME)?,
            sid: ServiceSid::of(SERVICE_NAME),
            processes: ServiceProcesses::default(),
        })
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

impl StopActor for StopSession {
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

    fn await_callback(&mut self) -> io::Result<()> {
        self.actor.await_callback()
    }

    fn await_held_exits(&mut self, wait: ExitWait) -> io::Result<()> {
        self.processes.await_exits(wait)
    }

    /// Holds every live process that carries the service's token, other than
    /// this one: the update cutover's child runs under the bridge's token and
    /// is never waited on.
    fn hold_scanned(&mut self) -> io::Result<ScanFinding> {
        self.processes.hold_scanned(&self.sid)
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
                "the service reported state {state}, which is not one it can be stopped from"
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
