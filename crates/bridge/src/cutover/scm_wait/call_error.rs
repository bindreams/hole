//! SCM call failures, typed by the call and the Win32 code.

use std::io;

/// An SCM entry point (or the process wait that goes with a service) whose
/// failure is reported by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScmCall {
    OpenScManager,
    OpenService,
    NotifyServiceStatusChange,
    ControlService,
    StartService,
    ChangeServiceConfig2,
    DeleteService,
    QueryServiceStatusEx,
    OpenProcess,
    WaitForSingleObject,
    CreateService,
    StartServiceCtrlDispatcher,
}

impl ScmCall {
    pub fn name(self) -> &'static str {
        match self {
            ScmCall::OpenScManager => "OpenSCManager",
            ScmCall::OpenService => "OpenService",
            ScmCall::NotifyServiceStatusChange => "NotifyServiceStatusChange",
            ScmCall::ControlService => "ControlService",
            ScmCall::StartService => "StartService",
            ScmCall::ChangeServiceConfig2 => "ChangeServiceConfig2",
            ScmCall::DeleteService => "DeleteService",
            ScmCall::QueryServiceStatusEx => "QueryServiceStatusEx",
            ScmCall::OpenProcess => "OpenProcess",
            ScmCall::WaitForSingleObject => "WaitForSingleObject",
            ScmCall::CreateService => "CreateService",
            ScmCall::StartServiceCtrlDispatcher => "StartServiceCtrlDispatcher",
        }
    }

    /// `failure`, the OS error a `windows_service` call carries inside its
    /// `Error::Winapi` (which displays only as "IO error in winapi call"), as
    /// this call's typed failure with the Win32 code.
    pub fn failed_with(self, failure: &io::Error) -> io::Error {
        match failure.raw_os_error().and_then(|code| u32::try_from(code).ok()) {
            Some(code) => ScmCallError { call: self, code }.into_io(),
            // Nothing to carry but the text.
            None => io::Error::other(format!("{} failed: {failure}", self.name())),
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

#[cfg(test)]
#[path = "call_error_tests.rs"]
mod call_error_tests;
