//! The service SID: the identity that says a process is the bridge service's.
//!
//! The SCM puts `NT SERVICE\<name>` into the token of a process it starts as
//! that service, once the service's SID type is set
//! ([`apply_service_sid`]). A process id the SCM names proves nothing (see
//! `ProcessHolds::hold_current`); the SID in the token does.
//!
//! `hole bridge install` sets the type, but an in-app update runs the old
//! release's code and never does, so the running bridge makes sure of it itself
//! ([`ensure_own_service_sid`]).

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::Security::{
    EqualSid, GetTokenInformation, LookupAccountNameW, TokenGroups, PSID, SID_NAME_USE, TOKEN_GROUPS, TOKEN_QUERY,
};
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, QueryServiceConfig2W, SC_HANDLE, SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_SID_INFO,
    SERVICE_SID_TYPE_UNRESTRICTED,
};
use windows::Win32::System::Threading::OpenProcessToken;
use windows_service::service::{Service, ServiceAccess};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::{scm_failure, SERVICE_NAME};
use crate::cutover::scm_wait::call_error::{win32_code_of_hresult, ScmCall, ScmCallError};

fn failed(call: ScmCall, e: &windows::core::Error) -> io::Error {
    ScmCallError {
        call,
        code: win32_code_of_hresult(e.code().0),
    }
    .into_io()
}

/// Give `service` a service SID (`SERVICE_SID_TYPE_UNRESTRICTED`), which every
/// process the SCM starts as the service carries in its token from then on.
/// Needs `CHANGE_CONFIG`. Idempotent. A process started before this ran does
/// not carry it. Called by `hole bridge install` and, for a service installed
/// without it, by [`ensure_own_service_sid`].
pub fn apply_service_sid(service: &Service) -> io::Result<()> {
    let info = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };
    // SAFETY: the handle is the live one `service` owns, and `info` is a
    // `SERVICE_SID_INFO` as `SERVICE_CONFIG_SERVICE_SID_INFO` requires; the
    // call reads it and keeps no pointer.
    unsafe {
        ChangeServiceConfig2W(
            SC_HANDLE(service.raw_handle()),
            SERVICE_CONFIG_SERVICE_SID_INFO,
            Some(std::ptr::from_ref(&info).cast()),
        )
    }
    .map_err(|e| failed(ScmCall::ChangeServiceConfig2, &e))
}

/// What a service's current SID type calls for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidRepair {
    /// It is the type [`apply_service_sid`] sets: write nothing.
    Leave,
    /// It is any other: set it.
    Apply,
}

impl SidRepair {
    /// The decision for a service whose `SERVICE_SID_INFO.dwServiceSidType` is
    /// `current`.
    pub fn for_sid_type(current: u32) -> Self {
        if current == SERVICE_SID_TYPE_UNRESTRICTED {
            SidRepair::Leave
        } else {
            SidRepair::Apply
        }
    }
}

/// What [`ensure_own_service_sid`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidRepairOutcome {
    /// The service already had the SID type; nothing was written.
    AlreadySet,
    /// The service lacked it and now has it.
    Applied,
}

/// The `SERVICE_SID_INFO.dwServiceSidType` of `service`. Needs `QUERY_CONFIG`.
fn service_sid_type(service: &Service) -> io::Result<u32> {
    let mut info = SERVICE_SID_INFO::default();
    let mut needed = 0u32;
    // SAFETY: the handle is the live one `service` owns; the buffer is the
    // `SERVICE_SID_INFO` `info` is, which the call fills and keeps no pointer to.
    unsafe {
        let buffer = std::slice::from_raw_parts_mut(
            std::ptr::from_mut(&mut info).cast::<u8>(),
            std::mem::size_of::<SERVICE_SID_INFO>(),
        );
        QueryServiceConfig2W(
            SC_HANDLE(service.raw_handle()),
            SERVICE_CONFIG_SERVICE_SID_INFO,
            Some(buffer),
            &mut needed,
        )
    }
    .map_err(|e| failed(ScmCall::QueryServiceConfig2, &e))?;
    Ok(info.dwServiceSidType)
}

/// Makes sure the bridge's own service (`SERVICE_NAME`) has its service SID
/// type, writing only when it lacks it. The SCM applies the type at the
/// service's next start, so the running process is unchanged. Idempotent.
///
/// For the `--service` bridge to call at startup: an in-app update is run by
/// the old release's code, which never set the type.
pub fn ensure_own_service_sid() -> io::Result<SidRepairOutcome> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| scm_failure(ScmCall::OpenScManager, e))?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG | ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| scm_failure(ScmCall::OpenService, e))?;
    match SidRepair::for_sid_type(service_sid_type(&service)?) {
        SidRepair::Leave => Ok(SidRepairOutcome::AlreadySet),
        SidRepair::Apply => {
            apply_service_sid(&service)?;
            Ok(SidRepairOutcome::Applied)
        }
    }
}

/// The SID a service of this name carries, resolved by the OS.
pub struct ServiceSid {
    /// `u32`s for the alignment of a SID's sub-authorities.
    sid: Vec<u32>,
}

impl ServiceSid {
    /// Resolves `NT SERVICE\<service_name>`.
    pub fn of(service_name: &str) -> io::Result<Self> {
        let account = HSTRING::from(format!("NT SERVICE\\{service_name}"));
        let (mut sid_len, mut domain_len) = (0u32, 0u32);
        let mut kind = SID_NAME_USE::default();
        // SAFETY: the sizing call, with null buffers, reports the lengths
        // needed (as `ERROR_INSUFFICIENT_BUFFER`, which is expected).
        let sized = unsafe { LookupAccountNameW(None, &account, None, &mut sid_len, None, &mut domain_len, &mut kind) };
        match sized {
            Err(e) if e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {}
            Err(e) => return Err(failed(ScmCall::LookupAccountName, &e)),
            // A lookup that fits no bytes at all is not a SID.
            Ok(()) => return Err(io::Error::other("LookupAccountName returned an empty SID")),
        }
        let mut sid = vec![0u32; (sid_len as usize).div_ceil(4)];
        let mut domain = vec![0u16; domain_len as usize];
        // SAFETY: `sid` holds at least `sid_len` bytes and `domain` `domain_len`
        // UTF-16 units, the sizes the call above asked for.
        unsafe {
            LookupAccountNameW(
                None,
                &account,
                Some(PSID(sid.as_mut_ptr().cast())),
                &mut sid_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut kind,
            )
        }
        .map_err(|e| failed(ScmCall::LookupAccountName, &e))?;
        Ok(Self { sid })
    }

    /// `Everyone` (S-1-1-0: revision 1, one sub-authority, authority 1,
    /// sub-authority 0), which every readable token carries.
    #[cfg(test)]
    pub(super) fn everyone() -> Self {
        Self {
            sid: vec![0x0000_0101, 0x0100_0000, 0],
        }
    }

    /// `S-1-5-80-1` (revision 1, two sub-authorities, authority 5, then 80 and
    /// 1), the `NT SERVICE` domain's first virtual account, which no ordinary
    /// token carries.
    #[cfg(test)]
    pub(super) fn nothing_carries() -> Self {
        Self {
            sid: vec![0x0000_0201, 0x0500_0000, 80, 1],
        }
    }

    fn psid(&self) -> PSID {
        PSID(self.sid.as_ptr().cast_mut().cast())
    }

    /// Whether the token of `process` carries this SID, or the error that kept
    /// it from being read. `process` must have been opened with
    /// `PROCESS_QUERY_LIMITED_INFORMATION`.
    pub fn is_in_token_of(&self, process: &OwnedHandle) -> io::Result<bool> {
        let mut token = HANDLE::default();
        // SAFETY: `process` is a live handle, and `token` is an out-parameter.
        unsafe { OpenProcessToken(HANDLE(process.as_raw_handle()), TOKEN_QUERY, &mut token) }
            .map_err(|e| failed(ScmCall::OpenProcessToken, &e))?;
        // SAFETY: `OpenProcessToken` returned a new handle this value now owns.
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
        let token = HANDLE(token.as_raw_handle());

        // The sizing call is expected to fail with ERROR_INSUFFICIENT_BUFFER.
        let mut len = 0u32;
        // SAFETY: a null buffer of length 0 is the documented way to ask for the size.
        let _ = unsafe { GetTokenInformation(token, TokenGroups, None, 0, &mut len) };
        // `u64`s: `TOKEN_GROUPS` has pointer alignment.
        let mut buf = vec![0u64; (len as usize).div_ceil(std::mem::size_of::<u64>()).max(1)];
        // SAFETY: `buf` holds at least `len` bytes, the size reported above.
        unsafe { GetTokenInformation(token, TokenGroups, Some(buf.as_mut_ptr().cast()), len, &mut len) }
            .map_err(|e| failed(ScmCall::GetTokenInformation, &e))?;
        // SAFETY: on success `buf` holds a `TOKEN_GROUPS` whose `GroupCount`
        // entries follow it in the same allocation, which outlives the borrow.
        let groups = unsafe {
            let groups = &*buf.as_ptr().cast::<TOKEN_GROUPS>();
            std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
        };
        // SAFETY: both SIDs are valid for the call: the token's are inside
        // `buf`, and this one is inside `self`.
        Ok(groups
            .iter()
            .any(|group| unsafe { EqualSid(group.Sid, self.psid()) }.is_ok()))
    }
}

#[cfg(test)]
#[path = "service_sid_tests.rs"]
mod service_sid_tests;
