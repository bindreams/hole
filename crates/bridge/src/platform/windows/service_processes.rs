//! The processes a service has shown, held so their exit can be awaited.
//!
//! The SCM reports a service STOPPED before its process has exited, and the
//! image the process maps cannot be removed until it has. Nothing the SCM
//! offers names that exit once the state is STOPPED (`dwProcessId` is 0 there),
//! so the process is opened while the service still names it, confirmed by
//! [`ProcessHolds::hold_current`].

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE};

use crate::cutover::scm_wait::call_error::{win32_code_of_hresult, ScmCall, ScmCallError};
use crate::cutover::scm_wait::hold::{ProcessHolds, ProcessSource, Reading};

/// Open process `pid` for waiting. `None` when no process has that id: it has
/// exited.
pub(super) fn open_process(pid: u32) -> io::Result<Option<OwnedHandle>> {
    // SAFETY: plain FFI call; no pointer is passed.
    match unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) } {
        // SAFETY: `OpenProcess` returned a new handle this value now owns.
        Ok(handle) => Ok(Some(unsafe { OwnedHandle::from_raw_handle(handle.0) })),
        Err(e) => {
            let code = win32_code_of_hresult(e.code().0);
            if code == ERROR_INVALID_PARAMETER.0 {
                return Ok(None);
            }
            Err(ScmCallError {
                call: ScmCall::OpenProcess,
                code,
            }
            .into_io())
        }
    }
}

/// Every process a retirement has seen its service run.
#[derive(Default)]
pub(super) struct ServiceProcesses {
    holds: ProcessHolds<OwnedHandle>,
}

impl ServiceProcesses {
    /// Reads the service through `source` and holds the process it names.
    pub(super) fn hold_current<S: ProcessSource<Process = OwnedHandle>>(
        &mut self,
        source: &mut S,
    ) -> io::Result<Reading> {
        self.holds.hold_current(source)
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
