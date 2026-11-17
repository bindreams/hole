use std::os::windows::io::AsRawHandle;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{TokenSessionId, TOKEN_QUERY};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::GetCurrentProcessId;

use super::{information, open_own_token};
use crate::service_scm::call_error::ScmCall;

#[skuld::test]
fn information_returns_what_the_class_names() {
    let token = open_own_token(TOKEN_QUERY).expect("open this process's token");
    let buffer = information(HANDLE(token.as_raw_handle()), TokenSessionId).expect("read the token's session");

    let mut expected = 0u32;
    // SAFETY: plain FFI call with an out-parameter.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut expected) }.expect("look up this process's session");
    assert_eq!(buffer[0] as u32, expected);
}

#[skuld::test]
fn information_of_a_bad_handle_is_a_typed_failure_of_the_call() {
    let typed = information(HANDLE::default(), TokenSessionId).expect_err("no token behind a null handle");
    assert_eq!(typed.call, ScmCall::GetTokenInformation);
    // ERROR_INVALID_HANDLE.
    assert_eq!(typed.code, 6);
}
