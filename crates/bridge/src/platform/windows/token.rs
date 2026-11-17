//! Reading a token's information classes.

use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{GetTokenInformation, TOKEN_ACCESS_MASK, TOKEN_INFORMATION_CLASS};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::service_scm::call_error::{ScmCall, ScmCallError};

/// This process's own token, opened with `access`, closed when dropped. A failure
/// is the typed [`ScmCall::OpenProcessToken`] error, not logged.
pub fn open_own_token(access: TOKEN_ACCESS_MASK) -> io::Result<OwnedHandle> {
    let mut token = HANDLE::default();
    // SAFETY: plain FFI call on this process's own token; `token` is an out-parameter.
    unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) }
        .map_err(|e| ScmCall::OpenProcessToken.failed_with_windows(&e).into_io_unlogged())?;
    // SAFETY: `OpenProcessToken` returned a new handle this value now owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(token.0) })
}

/// The `class` information of `token`, in a buffer aligned for any token
/// information struct, which the caller reads as the struct `class` names. The
/// handle needs the access the class requires (`TOKEN_QUERY` for most). A
/// failure is the typed [`ScmCall::GetTokenInformation`] error, not logged: the
/// caller decides whether it is worth a line ([`ScmCallError::into_io`] logs,
/// `into_io_unlogged` does not).
pub fn information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>, ScmCallError> {
    let mut needed = 0u32;
    // SAFETY: the sizing call, with no buffer, which is expected to fail with `ERROR_INSUFFICIENT_BUFFER`.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut needed) };
    // `u64`s: token information structs have at most pointer alignment.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(size_of::<u64>()).max(1)];
    // SAFETY: `buffer` holds at least `needed` bytes, the size reported above.
    unsafe { GetTokenInformation(token, class, Some(buffer.as_mut_ptr().cast()), needed, &mut needed) }
        .map_err(|e| ScmCall::GetTokenInformation.failed_with_windows(&e))?;
    Ok(buffer)
}

#[cfg(test)]
#[path = "token_tests.rs"]
mod token_tests;
