//! The processes a service has shown, held so their exit can be awaited.
//!
//! The SCM reports a service STOPPED before its process has exited, and the
//! image the process maps cannot be removed until it has. Nothing the SCM
//! offers names that exit once the state is STOPPED (`dwProcessId` is 0 there),
//! so the process is opened while the service still names it.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE};

use crate::cutover::scm_wait::call_error::{win32_code_of_hresult, ScmCall, ScmCallError};

/// A process held by id. The handle closes only when this drops.
struct Held {
    pid: u32,
    process: OwnedHandle,
}

/// Every process a retirement has seen its service run.
#[derive(Default)]
pub(super) struct ServiceProcesses {
    held: Vec<Held>,
}

impl ServiceProcesses {
    /// Holds process `pid`, unless it is already held or has already gone.
    ///
    /// A process the SCM names is open to the SCM, which keeps its id from being
    /// reused while it tracks the process; the id is therefore the process's
    /// until the SCM lets go of it at its exit, and the window between reading
    /// the id and opening it is the SCM's own latency in noticing that exit.
    pub(super) fn hold(&mut self, pid: u32) -> io::Result<()> {
        if self.held.iter().any(|held| held.pid == pid) {
            return Ok(());
        }
        // SAFETY: plain FFI call; no pointer is passed.
        match unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) } {
            Ok(handle) => {
                // SAFETY: `OpenProcess` returned a new handle this value now owns.
                let process = unsafe { OwnedHandle::from_raw_handle(handle.0) };
                self.held.push(Held { pid, process });
                Ok(())
            }
            Err(e) => {
                let code = win32_code_of_hresult(e.code().0);
                if code == ERROR_INVALID_PARAMETER.0 {
                    // No process has this id any more: it has exited.
                    return Ok(());
                }
                Err(ScmCallError {
                    call: ScmCall::OpenProcess,
                    code,
                }
                .into_io())
            }
        }
    }

    /// Blocks until every held process has exited. An external event with no
    /// bound of its own to choose: the exit of a process the SCM has been told
    /// to stop.
    pub(super) fn await_exits(&self) -> io::Result<()> {
        for held in &self.held {
            let handle = HANDLE(held.process.as_raw_handle());
            // SAFETY: `handle` is the live handle `held` owns.
            let waited = unsafe { WaitForSingleObject(handle, INFINITE) };
            if waited != WAIT_OBJECT_0 {
                return Err(ScmCall::WaitForSingleObject.failed_with(&io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}
