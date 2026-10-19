//! The service SID: the identity that says a process is the bridge service's.
//!
//! The SCM puts `NT SERVICE\<name>` into the token of a process it starts as
//! that service, once the service's SID type is set
//! ([`apply_service_sid`]). A process id the SCM names proves nothing (see
//! `ProcessHolds::hold_current`); the SID in the token does.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::Security::{
    EqualSid, GetTokenInformation, LookupAccountNameW, TokenGroups, PSID, SID_NAME_USE, TOKEN_GROUPS, TOKEN_QUERY,
};
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, SC_HANDLE, SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_SID_INFO, SERVICE_SID_TYPE_UNRESTRICTED,
};
use windows::Win32::System::Threading::OpenProcessToken;
use windows_service::service::Service;

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
/// not carry it.
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

    fn psid(&self) -> PSID {
        PSID(self.sid.as_ptr().cast_mut().cast())
    }

    /// Whether the token of `process` carries this SID. `process` must have
    /// been opened with `PROCESS_QUERY_LIMITED_INFORMATION`.
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
