//! Registration with the SCM and status reports, over the `windows` crate.

use std::io;

use windows::core::HSTRING;
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, ENUM_SERVICE_TYPE, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
    SERVICE_STATUS_HANDLE,
};
use windows_service::service::{ServiceExitCode, ServiceStatus};

use super::{own, Control, ControlResult, OwnedHandler, CONTROL_INTERROGATE, CONTROL_SHUTDOWN, CONTROL_STOP};

const _: () = {
    assert!(CONTROL_STOP == SERVICE_CONTROL_STOP);
    assert!(CONTROL_INTERROGATE == SERVICE_CONTROL_INTERROGATE);
    assert!(CONTROL_SHUTDOWN == SERVICE_CONTROL_SHUTDOWN);
    assert!(super::NO_ERROR == windows::Win32::Foundation::NO_ERROR.0);
    assert!(super::ERROR_CALL_NOT_IMPLEMENTED == windows::Win32::Foundation::ERROR_CALL_NOT_IMPLEMENTED.0);
};

/// Token for reporting this service's status to the SCM.
#[derive(Debug, Clone, Copy)]
pub struct StatusHandle(SERVICE_STATUS_HANDLE);

// SAFETY: a SERVICE_STATUS_HANDLE is an SCM token that `SetServiceStatus`
// accepts from any thread; MSDN's `SetServiceStatus` remarks say it is thread
// safe.
unsafe impl Send for StatusHandle {}
// SAFETY: as for `Send`; `SetServiceStatus` takes the handle by value.
unsafe impl Sync for StatusHandle {}

impl StatusHandle {
    /// Report `status` to the SCM.
    pub fn set_service_status(&self, status: &ServiceStatus) -> io::Result<()> {
        let raw = raw_status(status)?;
        // SAFETY: `self.0` came from a successful registration and `raw` is a
        // valid SERVICE_STATUS that outlives the call.
        unsafe { SetServiceStatus(self.0, &raw) }.map_err(io::Error::from)
    }
}

/// Register `handler` for the service `name` with the SCM, which keeps it for
/// the rest of the process (see [`own`]). Call it from the service main
/// function; a service process registers once.
pub fn register<F>(name: &str, handler: F) -> io::Result<StatusHandle>
where
    F: Fn(Control) -> ControlResult + Send + Sync + 'static,
{
    let OwnedHandler { entry, context } = own(handler);
    // SAFETY: `entry` is a valid `LPHANDLER_FUNCTION_EX` for the context
    // `own` paired it with, and that context is never freed.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(&HSTRING::from(name), Some(entry), Some(context)) }
        .map_err(io::Error::from)?;
    Ok(StatusHandle(handle))
}

/// The wire form of `status`. `process_id` is only meaningful on a query, so
/// it is not reported.
fn raw_status(status: &ServiceStatus) -> io::Result<SERVICE_STATUS> {
    let (win32_exit_code, service_specific_exit_code) = match status.exit_code {
        ServiceExitCode::Win32(code) => (code, 0),
        ServiceExitCode::ServiceSpecific(code) => (windows::Win32::Foundation::ERROR_SERVICE_SPECIFIC_ERROR.0, code),
    };
    let wait_hint = u32::try_from(status.wait_hint.as_millis()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "service wait hint exceeds u32 milliseconds",
        )
    })?;
    Ok(SERVICE_STATUS {
        dwServiceType: ENUM_SERVICE_TYPE(status.service_type.bits()),
        dwCurrentState: SERVICE_STATUS_CURRENT_STATE(status.current_state as u32),
        dwControlsAccepted: status.controls_accepted.bits(),
        dwWin32ExitCode: win32_exit_code,
        dwServiceSpecificExitCode: service_specific_exit_code,
        dwCheckPoint: status.checkpoint,
        dwWaitHint: wait_hint,
    })
}

#[cfg(test)]
#[path = "scm_tests.rs"]
mod scm_tests;
