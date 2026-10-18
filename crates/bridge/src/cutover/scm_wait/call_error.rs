//! SCM call failures, typed by the call and the Win32 code.

use std::io;

/// An SCM entry point whose failure is reported by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScmCall {
    OpenScManager,
    OpenService,
    NotifyServiceStatusChange,
    ControlService,
    StartService,
}

impl ScmCall {
    pub fn name(self) -> &'static str {
        match self {
            ScmCall::OpenScManager => "OpenSCManager",
            ScmCall::OpenService => "OpenService",
            ScmCall::NotifyServiceStatusChange => "NotifyServiceStatusChange",
            ScmCall::ControlService => "ControlService",
            ScmCall::StartService => "StartService",
        }
    }
}

/// An SCM call that failed, with the Win32 code it failed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{} failed: {}", call.name(), io::Error::from_raw_os_error(*code as i32))]
pub struct ScmCallError {
    pub call: ScmCall,
    pub code: u32,
}

impl ScmCallError {
    /// This failure as an `io::Error` for the `ScmActor` seam, and on the info
    /// log: the one line in `gui-cli.log` that names the call and the code.
    pub fn into_io(self) -> io::Error {
        tracing::info!(call = self.call.name(), win32_code = self.code, "SCM call failed");
        io::Error::other(self)
    }
}

/// `ERROR_SERVICE_DOES_NOT_EXIST`.
pub const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
/// `ERROR_SERVICE_MARKED_FOR_DELETE`.
pub const ERROR_SERVICE_MARKED_FOR_DELETE: u32 = 1072;
/// `ERROR_SERVICE_CANNOT_ACCEPT_CTRL`.
pub const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: u32 = 1061;
/// `ERROR_SERVICE_NOT_ACTIVE`.
pub const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;

/// Whether `code` says the SCM has no service left to act through: never
/// registered, or marked for deletion, which no handle opened afterwards can
/// carry a control through.
pub fn is_absent_service_code(code: u32) -> bool {
    matches!(code, ERROR_SERVICE_DOES_NOT_EXIST | ERROR_SERVICE_MARKED_FOR_DELETE)
}

/// Whether `error` failed BECAUSE the SCM has no service left to act on, in
/// either shape it travels in: a bare OS error, or a typed [`ScmCallError`]
/// wrapped by [`ScmCallError::into_io`].
pub fn io_error_is_absent_service(error: &io::Error) -> bool {
    if let Some(code) = error.raw_os_error() {
        return u32::try_from(code).is_ok_and(is_absent_service_code);
    }
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ScmCallError>())
        .is_some_and(|typed| is_absent_service_code(typed.code))
}

/// The Win32 code inside an `HRESULT` the `windows` bindings report, when it is
/// `HRESULT_FROM_WIN32` of one; otherwise the value as is.
pub fn win32_code_of_hresult(hresult: i32) -> u32 {
    let bits = hresult as u32;
    if bits >> 16 == 0x8007 {
        bits & 0xFFFF
    } else {
        bits
    }
}

/// How `ControlService(STOP)` answered, given its error code.
///
/// Two answers are about a race with the state the caller observed, and are
/// not failures: the stop wait's own arm is already queued, so the STOPPED it
/// waits for still arrives. Every other code is a real failure and is returned
/// by name.
pub fn classify_control_stop(code: u32) -> Result<(), ScmCallError> {
    match code {
        // The service stopped between the observation and this control.
        ERROR_SERVICE_NOT_ACTIVE => Ok(()),
        // The service left RUNNING between the observation and this control
        // (STOP_PENDING, or a restart's START_PENDING).
        ERROR_SERVICE_CANNOT_ACCEPT_CTRL => Ok(()),
        code => Err(ScmCallError {
            call: ScmCall::ControlService,
            code,
        }),
    }
}

#[cfg(test)]
#[path = "call_error_tests.rs"]
mod call_error_tests;
