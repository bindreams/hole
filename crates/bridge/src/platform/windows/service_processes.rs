//! The processes a service has shown, held so their exit can be awaited.
//!
//! The SCM reports a service STOPPED before its process has exited, and the
//! image the process maps cannot be removed until it has. Nothing the SCM
//! offers names that exit once the state is STOPPED (`dwProcessId` is 0 there),
//! so the process is opened while the service still names it, proven to be the
//! service's by its token's service SID, and confirmed by
//! [`ProcessHolds::look`].

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

use crate::cutover::scm_wait::call_error::{win32_code_of_hresult, ScmCall, ScmCallError};
use crate::cutover::scm_wait::hold::{Look, Opened, ProcessHolds, ProcessSource};

use super::service_sid::ServiceSid;

/// Open process `pid` for waiting and for reading its token, and keep it only
/// if the token carries the service SID. A process without it, or whose token
/// cannot be read, is closed and reported as not the service's.
pub(super) fn open_process(pid: u32, service: &ServiceSid) -> io::Result<Opened<OwnedHandle>> {
    // SAFETY: plain FFI call; no pointer is passed.
    match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => {
            // SAFETY: `OpenProcess` returned a new handle this value now owns.
            let process = unsafe { OwnedHandle::from_raw_handle(handle.0) };
            let read = service.is_in_token_of(&process);
            Ok(opened_from_token_read(process, pid, read))
        }
        Err(e) => {
            let code = win32_code_of_hresult(e.code().0);
            if code == ERROR_INVALID_PARAMETER.0 {
                return Ok(Opened::NoSuchProcess);
            }
            Err(ScmCallError {
                call: ScmCall::OpenProcess,
                code,
            }
            .into_io())
        }
    }
}

/// `process` (the process `pid`), classified by what reading its token for the
/// service SID gave. A token that cannot be read is not the service's: the
/// service's own is readable by SYSTEM and by an elevated administrator
/// (measured by the service-SID probes), so an unreadable one is some protected
/// process that reused the id. It is not an error either, which would fail an
/// uninstall for a process that has nothing to do with the service.
fn opened_from_token_read<P>(process: P, pid: u32, read: io::Result<bool>) -> Opened<P> {
    match read {
        Ok(true) => Opened::Service(process),
        Ok(false) => Opened::NotTheService,
        Err(e) => {
            tracing::warn!(pid, error = %e, "the token of the process the SCM names cannot be read: not the service's");
            Opened::NotTheService
        }
    }
}

/// Whether `process` has exited: a zero-timeout wait, which reads the process's
/// state and waits for nothing.
pub(super) fn has_exited(process: &OwnedHandle) -> io::Result<bool> {
    let handle = HANDLE(process.as_raw_handle());
    // SAFETY: `handle` is the live handle `process` owns.
    let waited = unsafe { WaitForSingleObject(handle, 0) };
    if waited == WAIT_OBJECT_0 {
        Ok(true)
    } else if waited == WAIT_TIMEOUT {
        Ok(false)
    } else {
        Err(ScmCall::WaitForSingleObject.failed_with(&io::Error::last_os_error()))
    }
}

/// Every process a retirement has seen its service run.
#[derive(Default)]
pub(super) struct ServiceProcesses {
    holds: ProcessHolds<OwnedHandle>,
}

impl ServiceProcesses {
    /// Reads the service through `source`, holds the process it names, and
    /// says whether that process is still alive.
    pub(super) fn look<S: ProcessSource<Process = OwnedHandle>>(&mut self, source: &mut S) -> io::Result<Look> {
        self.holds.look(source)
    }

    /// Blocks until every held process has exited. An external event with no
    /// bound of its own to choose: the exit of a process the SCM has been told
    /// to stop.
    pub(super) fn await_exits(&self) -> io::Result<()> {
        for process in self.holds.processes() {
            let handle = HANDLE(process.as_raw_handle());
            // SAFETY: `handle` is the live handle `process` owns.
            let waited = unsafe { WaitForSingleObject(handle, INFINITE) };
            if waited != WAIT_OBJECT_0 {
                return Err(ScmCall::WaitForSingleObject.failed_with(&io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_processes_tests.rs"]
mod service_processes_tests;
