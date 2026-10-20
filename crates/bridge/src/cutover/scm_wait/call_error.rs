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
    QueryServiceConfig2,
    DeleteService,
    QueryServiceStatusEx,
    OpenProcess,
    OpenProcessToken,
    GetTokenInformation,
    LookupAccountName,
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
            ScmCall::QueryServiceConfig2 => "QueryServiceConfig2",
            ScmCall::DeleteService => "DeleteService",
            ScmCall::QueryServiceStatusEx => "QueryServiceStatusEx",
            ScmCall::OpenProcess => "OpenProcess",
            ScmCall::OpenProcessToken => "OpenProcessToken",
            ScmCall::GetTokenInformation => "GetTokenInformation",
            ScmCall::LookupAccountName => "LookupAccountName",
            ScmCall::WaitForSingleObject => "WaitForSingleObject",
            ScmCall::CreateService => "CreateService",
            ScmCall::StartServiceCtrlDispatcher => "StartServiceCtrlDispatcher",
        }
    }

    /// Whether a failure of this call is the refusal to open the service's
    /// process, or to read its token to prove it is the service's, which
    /// belongs to no step of a retirement: the step that was running only
    /// needed the process held.
    pub fn is_opening_the_service_process(self) -> bool {
        match self {
            ScmCall::OpenProcess => true,
            ScmCall::OpenProcessToken => true,
            ScmCall::GetTokenInformation => true,
            ScmCall::LookupAccountName => false,
            ScmCall::OpenScManager => false,
            ScmCall::OpenService => false,
            ScmCall::NotifyServiceStatusChange => false,
            ScmCall::ControlService => false,
            ScmCall::StartService => false,
            ScmCall::ChangeServiceConfig2 => false,
            ScmCall::QueryServiceConfig2 => false,
            ScmCall::DeleteService => false,
            ScmCall::QueryServiceStatusEx => false,
            ScmCall::WaitForSingleObject => false,
            ScmCall::CreateService => false,
            ScmCall::StartServiceCtrlDispatcher => false,
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
        self.into_io_unlogged()
    }

    /// [`into_io`](Self::into_io) without the log line, for a failure the
    /// caller expects in bulk (a scan of every process on the host) and
    /// resolves itself.
    pub fn into_io_unlogged(self) -> io::Error {
        io::Error::other(self)
    }
}

/// `ERROR_ACCESS_DENIED`.
pub const ERROR_ACCESS_DENIED: u32 = 5;
/// `ERROR_INVALID_PARAMETER`: what `OpenProcess` answers for an id no process has.
pub const ERROR_INVALID_PARAMETER: u32 = 87;
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

/// Why the SCM has no service to act through, from the code it answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceGone {
    /// `ERROR_SERVICE_DOES_NOT_EXIST`: no entry. A process of the service can
    /// still be running, because the SCM removes an entry once the service is
    /// not running, which is its state and not its process.
    DoesNotExist,
    /// `ERROR_SERVICE_MARKED_FOR_DELETE`: the entry is still there and a
    /// handle opened before the mark still queries and carries a Stop, but no
    /// notification can be armed on it and nothing can start it.
    MarkedForDeletion,
}

impl ServiceGone {
    /// The kind a Win32 `code` names, if it names one.
    pub fn of_code(code: u32) -> Option<ServiceGone> {
        match code {
            ERROR_SERVICE_DOES_NOT_EXIST => Some(ServiceGone::DoesNotExist),
            ERROR_SERVICE_MARKED_FOR_DELETE => Some(ServiceGone::MarkedForDeletion),
            _ => None,
        }
    }

    /// Whether a service gone this way still answers through a handle that was
    /// open before it went. A service marked for deletion does (queries and a
    /// Stop, measured), though no notification can be armed on it; an entry
    /// that no longer exists answers nothing.
    pub fn answers_through_an_open_handle(self) -> bool {
        match self {
            ServiceGone::DoesNotExist => false,
            ServiceGone::MarkedForDeletion => true,
        }
    }
}

/// The [`ServiceGone`] kind `error` failed with, in either shape it travels in:
/// a bare OS error, or a typed [`ScmCallError`] wrapped by
/// [`ScmCallError::into_io`].
pub fn service_gone(error: &io::Error) -> Option<ServiceGone> {
    if let Some(code) = error.raw_os_error() {
        return u32::try_from(code).ok().and_then(ServiceGone::of_code);
    }
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ScmCallError>())
        .and_then(|typed| ServiceGone::of_code(typed.code))
}

/// The [`ScmCallError`] inside `error`, if it was wrapped by
/// [`ScmCallError::into_io`].
pub fn scm_call_error(error: &io::Error) -> Option<&ScmCallError> {
    error.get_ref().and_then(|inner| inner.downcast_ref::<ScmCallError>())
}

/// Whether `error` is a [`ScmCallError`] of the call that opens the service's
/// process (see [`ScmCall::is_opening_the_service_process`]).
pub fn io_error_is_a_refused_process_open(error: &io::Error) -> bool {
    scm_call_error(error).is_some_and(|typed| typed.call.is_opening_the_service_process())
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
