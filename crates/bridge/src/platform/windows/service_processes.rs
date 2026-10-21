//! The processes a service has shown, held so their exit can be awaited.
//!
//! The SCM reports a service STOPPED before its process has exited, and the
//! image the process maps cannot be removed until it has. Nothing the SCM
//! offers names that exit once the state is STOPPED (`dwProcessId` is 0 there),
//! so the process is opened while the service still names it, proven to be the
//! service's by its token's service SID, and confirmed by
//! [`ProcessHolds::look`]. A process the SCM no longer names is found by its
//! token alone, by [`scan_service_processes`].

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE,
};

use crate::cutover::scm_wait::call_error::{win32_code_of_hresult, ScmCall, ScmCallError};
use crate::cutover::scm_wait::hold::{Basis, Look, Opened, ProcessHolds, ProcessSource};
use crate::cutover::scm_wait::scan::{scan, ProcessEnumerator, ScanFinding, ScanResult};

use super::service_sid::ServiceSid;

/// Open process `pid` for waiting and for reading its token, and keep it only
/// if the token carries the service SID. A failure is resolved by `basis`
/// ([`Opened::of_failure`]): what an id the SCM named in a state that makes it
/// valid, one that may not be valid, and one found by scanning the host each
/// mean is one table, `Basis::verdict`.
pub(super) fn open_process(pid: u32, service: &ServiceSid, basis: Basis) -> io::Result<Opened<OwnedHandle>> {
    // SAFETY: plain FFI call; no pointer is passed.
    match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => {
            // SAFETY: `OpenProcess` returned a new handle this value now owns.
            let process = unsafe { OwnedHandle::from_raw_handle(handle.0) };
            let read = service.is_in_token_of(&process);
            opened_from_token_read(process, basis, read, has_exited)
        }
        Err(e) => Opened::of_failure(
            basis,
            ScmCallError {
                call: ScmCall::OpenProcess,
                code: win32_code_of_hresult(e.code().0),
            }
            .into_io_unlogged(),
        ),
    }
}

/// `process`, classified by what reading its token for the service SID gave.
/// A token that cannot be read is resolved by `basis`, unless the process has
/// exited: a process that ends under the read explains the failure and is
/// simply gone.
fn opened_from_token_read<P>(
    process: P,
    basis: Basis,
    read: io::Result<bool>,
    has_exited: impl FnOnce(&P) -> io::Result<bool>,
) -> io::Result<Opened<P>> {
    match read {
        Ok(true) => Ok(Opened::Service(process)),
        Ok(false) => Ok(Opened::NotTheService),
        Err(error) if has_exited(&process)? => {
            tracing::debug!(%error, "the token of a process that has exited cannot be read");
            Ok(Opened::NoSuchProcess)
        }
        Err(error) => Opened::of_failure(basis, error),
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

/// `ERROR_NO_MORE_FILES`: the end of a Toolhelp enumeration.
const ERROR_NO_MORE_FILES: u32 = 18;

/// What a `Process32FirstW` / `Process32NextW` result says about the
/// enumeration: another entry (`true`), or its end (`false`). Only
/// `ERROR_NO_MORE_FILES` is the end; any other failure is returned, because a
/// list cut short would read as a host with no more processes.
pub fn enumeration_continues(step: windows::core::Result<()>) -> io::Result<bool> {
    match step {
        Ok(()) => Ok(true),
        Err(e) => match win32_code_of_hresult(e.code().0) {
            ERROR_NO_MORE_FILES => Ok(false),
            code => Err(io::Error::from_raw_os_error(code as i32)),
        },
    }
}

/// The System Idle Process's id.
const IDLE_PROCESS: u32 = 0;

/// Every process on the host, for [`scan_service_processes`].
struct HostProcesses<'a> {
    service: &'a ServiceSid,
}

impl ProcessEnumerator for HostProcesses<'_> {
    type Process = OwnedHandle;

    /// Every id the Toolhelp snapshot lists but 0: the System Idle Process is
    /// listed and never opens (`ERROR_INVALID_PARAMETER`), so the scan would
    /// find it vanished on every pass.
    fn pids(&mut self) -> io::Result<Vec<u32>> {
        // SAFETY: plain FFI call.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|e| io::Error::from_raw_os_error(win32_code_of_hresult(e.code().0) as i32))?;
        // SAFETY: `CreateToolhelp32Snapshot` returned a new handle this value now owns.
        let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot.0) };
        let handle = HANDLE(snapshot.as_raw_handle());
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut pids = Vec::new();
        // SAFETY: `handle` is the live snapshot just returned, and `entry` is
        // a `PROCESSENTRY32W` with its size set, as both calls require.
        let mut more = enumeration_continues(unsafe { Process32FirstW(handle, &mut entry) })?;
        while more {
            if entry.th32ProcessID != IDLE_PROCESS {
                pids.push(entry.th32ProcessID);
            }
            // SAFETY: as above.
            more = enumeration_continues(unsafe { Process32NextW(handle, &mut entry) })?;
        }
        Ok(pids)
    }

    fn this_process(&self) -> u32 {
        // SAFETY: plain FFI call.
        unsafe { GetCurrentProcessId() }
    }

    fn open(&mut self, pid: u32) -> io::Result<Opened<OwnedHandle>> {
        open_process(pid, self.service, Basis::Scanned)
    }

    fn has_exited(&mut self, process: &OwnedHandle) -> io::Result<bool> {
        has_exited(process)
    }
}

/// Every live process on the host whose token carries `service`, other than
/// the calling one, descendants included. The SCM's state does not say that no
/// such process is left (its id is never valid once STOPPED); this does.
///
/// A process that cannot be probed never fails the scan: see
/// [`Basis::verdict`] for `Basis::Scanned`. A listed process gone by its probe
/// is in `vanished`: only [`ScanResult::finding`] says whether the scan found
/// nothing.
pub fn scan_service_processes(service: &ServiceSid) -> io::Result<ScanResult<OwnedHandle>> {
    scan(&mut HostProcesses { service })
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

    /// Holds every live process on the host that carries `service`'s token, so
    /// the next [`look`](Self::look) shows it alive, and says what the scan
    /// found. A process the scan cannot tell is warned about by the scan and
    /// never fails it.
    pub(super) fn hold_scanned(&mut self, service: &ServiceSid) -> io::Result<ScanFinding> {
        self.holds
            .hold_scanned(&mut HostProcesses { service })
            .map(|scanned| scanned.finding)
    }

    /// How many processes are held, exited or not.
    pub(super) fn held(&self) -> usize {
        self.holds.processes().count()
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
