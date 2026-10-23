//! The SCM and service handles, closed by `Drop` and nowhere else.
//!
//! `ScHandle`'s field is private to this module and `CloseServiceHandle` is
//! imported only here, so no other code can build an `ScHandle` or close one
//! through it. `Handles::service` hands out the raw `SC_HANDLE` for SCM calls;
//! closing that copy is the one thing callers must not do. A closed handle value may be reused by the OS for
//! an unrelated handle, and closing a handle that is not live can fault
//! (measured for NULL), so a second close is never relied on to report.

use std::io;

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
    SERVICE_START, SERVICE_STOP,
};

/// An open SCM or service handle, closed exactly once when this drops.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: `ScHandle` owns the handle from its open call, and `drop`
        // runs once. Closing a handle that is not live can fault (measured:
        // `CloseServiceHandle(NULL)` raises an access violation on Windows).
        // No panic here: one during unwinding aborts the process.
        if let Err(e) = unsafe { CloseServiceHandle(self.0) } {
            tracing::error!(error = %util::error_chain::error_chain(&e), "CloseServiceHandle failed on a handle this process opened");
        }
    }
}

/// The SCM handle and the service handle opened through it. `service` is
/// declared first so it closes first.
pub(super) struct Handles {
    service: ScHandle,
    _scm: ScHandle,
}

impl Handles {
    pub(super) fn open(service_name: &HSTRING) -> io::Result<Self> {
        let scm = ScHandle(
            // SAFETY: null machine and database names select the local, active
            // SCM database; no pointer is read.
            unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }.map_err(io::Error::other)?,
        );
        let service = ScHandle(
            // SAFETY: `scm.0` is live (it closes only when `scm` drops, after
            // this call), and an `HSTRING` is NUL-terminated and outlives it.
            unsafe {
                OpenServiceW(
                    scm.0,
                    PCWSTR(service_name.as_ptr()),
                    SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START,
                )
            }
            .map_err(io::Error::other)?,
        );
        Ok(Self { service, _scm: scm })
    }

    /// The service handle, valid while `self` lives.
    pub(super) fn service(&self) -> SC_HANDLE {
        self.service.0
    }
}
