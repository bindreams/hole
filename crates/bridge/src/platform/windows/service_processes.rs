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

use tracing::{info, warn};
use windows::Win32::Foundation::{GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken, TerminateProcess, WaitForSingleObject,
    INFINITE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

use crate::cutover::scm_wait::call_error::{win32_code_of_hresult, ScmCall, ScmCallError};
use crate::cutover::scm_wait::hold::{Basis, Look, Opened, ProcessHolds, ProcessSource};
use crate::cutover::scm_wait::scan::{scan, ListedProcess, ProcessEnumerator, ScanFinding, ScanResult};
use crate::cutover::scm_wait::settle::ExitWait;
use crate::disable_record::{creation_time_of, Stamp};

use super::service_sid::ServiceSid;

/// Open process `pid` for waiting and for reading its token, and keep it only
/// if the token carries the service SID. A failure is resolved by `basis`
/// ([`Opened::of_failure`]): what an id the SCM named in a state that makes it
/// valid, one that may not be valid, and one found by scanning the host each
/// mean is one table, `Basis::verdict`.
pub(super) fn open_process(pid: u32, service: &ServiceSid, basis: Basis) -> io::Result<Opened<OwnedHandle>> {
    open_process_where(pid, service, basis, |_| Ok(true))
}

/// [`open_process`] for the process a listing named: the id held by a process
/// with another creation time is the OS's reuse of it, and the listed process
/// is gone ([`Opened::NoSuchProcess`]) whatever the stranger's token carries.
pub(super) fn open_listed_process(listed: ListedProcess, service: &ServiceSid) -> io::Result<Opened<OwnedHandle>> {
    open_process_where(listed.pid, service, Basis::Scanned, |process| {
        // SAFETY: `process` is the live handle opened with the query right.
        let created = unsafe { creation_time_of(HANDLE(process.as_raw_handle())) }
            .map_err(|error| ScmCall::GetProcessTimes.failed_with(&error))?;
        Ok(created == listed.created)
    })
}

/// [`open_process`] that keeps the process only if `is_the_one` says it is the
/// one wanted, which is read before its token. A failed read is resolved by
/// `basis` like a failed open.
fn open_process_where(
    pid: u32,
    service: &ServiceSid,
    basis: Basis,
    is_the_one: impl FnOnce(&OwnedHandle) -> io::Result<bool>,
) -> io::Result<Opened<OwnedHandle>> {
    // SAFETY: plain FFI call; no pointer is passed.
    match unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => {
            // SAFETY: `OpenProcess` returned a new handle this value now owns.
            let process = unsafe { OwnedHandle::from_raw_handle(handle.0) };
            match is_the_one(&process) {
                Ok(true) => {}
                Ok(false) => return Ok(Opened::NoSuchProcess),
                Err(error) => return Opened::of_failure(basis, error),
            }
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

/// The System Idle Process's id.
const IDLE_PROCESS: u32 = 0;

/// Every process on the host, for [`scan_service_processes`].
struct HostProcesses<'a> {
    service: &'a ServiceSid,
}

impl ProcessEnumerator for HostProcesses<'_> {
    type Process = OwnedHandle;

    /// Every process the system process list names but the System Idle
    /// Process, which is listed and never opens (`ERROR_INVALID_PARAMETER`), so
    /// the scan would find it vanished on every pass. The creation time is the
    /// list's, taken in the same read as the id.
    fn list(&mut self) -> io::Result<Vec<ListedProcess>> {
        Ok(Stamp::listed_processes()?
            .into_iter()
            .filter(|stamp| stamp.pid != IDLE_PROCESS)
            .map(|stamp| ListedProcess {
                pid: stamp.pid,
                created: stamp.created,
            })
            .collect())
    }

    fn this_process(&self) -> u32 {
        // SAFETY: plain FFI call.
        unsafe { GetCurrentProcessId() }
    }

    fn open(&mut self, listed: ListedProcess) -> io::Result<Opened<OwnedHandle>> {
        open_listed_process(listed, self.service)
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
/// nothing. One scan, with no scan before it; a wait goes through
/// [`ServiceProcesses::hold_scanned`], which remembers the last.
pub fn scan_service_processes(service: &ServiceSid) -> io::Result<ScanResult<OwnedHandle>> {
    scan(&mut HostProcesses { service }, &[])
}

/// Terminates the live process `held` is open on, whose id is `pid`. A failure
/// is an error unless the process had exited by then: `TerminateProcess`
/// answers an exited process with `ERROR_ACCESS_DENIED`.
fn terminate(pid: u32, held: &OwnedHandle) -> io::Result<()> {
    // The held handle has no `PROCESS_TERMINATE` right: asking for it there
    // would turn a denial for a SYSTEM process into "not the service's".
    // SAFETY: plain FFI call; no pointer is passed.
    let opened = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) };
    let terminated = opened.and_then(|handle| {
        // SAFETY: `OpenProcess` returned a new handle this value now owns.
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        // SAFETY: `handle` is the live handle just opened with the terminate right.
        unsafe { TerminateProcess(HANDLE(handle.as_raw_handle()), 1) }
    });
    match terminated {
        Ok(()) => Ok(()),
        Err(_) if has_exited(held)? => Ok(()),
        Err(e) => Err(ScmCallError {
            call: ScmCall::TerminateProcess,
            code: win32_code_of_hresult(e.code().0),
        }
        .into_io()),
    }
}

/// Enables `SeDebugPrivilege` on this process's token, which an elevated
/// administrator holds disabled. With it enabled `OpenProcess` grants the
/// requested access whatever the process's security descriptor says
/// ([`OpenProcess`, Remarks](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess#remarks)),
/// which a SYSTEM process's descriptor otherwise refuses an administrator for
/// `PROCESS_TERMINATE`. A token that does not hold it is warned about; the
/// terminate that needed it then fails with its own error.
fn enable_debug_privilege() {
    let mut token = HANDLE::default();
    // SAFETY: plain FFI calls on this process's own token, closed by `OwnedHandle`.
    let enabled = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token).and_then(|()| {
            let token = OwnedHandle::from_raw_handle(token.0);
            let mut luid = Default::default();
            LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid)?;
            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            AdjustTokenPrivileges(HANDLE(token.as_raw_handle()), false, Some(&privileges), 0, None, None)?;
            // Succeeds even when nothing was assigned; the last error says which.
            if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
                return Err(windows::core::Error::from(ERROR_NOT_ALL_ASSIGNED));
            }
            Ok(())
        })
    };
    if let Err(error) = enabled {
        warn!(%error, "SeDebugPrivilege could not be enabled; terminating a process of another principal may be refused");
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

    /// Terminates every held process that has not exited. Each is proven the
    /// service's by its token, and the held handle keeps its id from being
    /// reused, so the id names the same process at the second open.
    fn terminate_live(&self) -> io::Result<()> {
        let mut debug_enabled = false;
        for (pid, process) in self.holds.held() {
            if has_exited(process)? {
                continue;
            }
            if !debug_enabled {
                enable_debug_privilege();
                debug_enabled = true;
            }
            info!(pid, "terminating a process of the stopped service");
            terminate(pid, process)?;
        }
        Ok(())
    }

    /// Blocks until every held process has exited. An external event with no
    /// bound of its own to choose: the exit of a process the SCM has been told
    /// to stop, or one [`terminate_live`](Self::terminate_live) just ended.
    pub(super) fn await_exits(&self, wait: ExitWait) -> io::Result<()> {
        match wait {
            ExitWait::OnTheirOwn => {}
            ExitWait::TerminateThenWait => self.terminate_live()?,
        }
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
