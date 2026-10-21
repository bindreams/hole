use super::windows::{refuses_posix_rename, win32_error};
use std::io;
use windows::core::{Error, HRESULT};

#[skuld::test]
fn the_three_unsupported_codes_are_refusals() {
    for code in [1, 50, 87] {
        assert!(refuses_posix_rename(&io::Error::from_raw_os_error(code)), "code {code}");
    }
}

#[skuld::test]
fn access_denied_and_sharing_violation_are_real_failures() {
    for code in [5, 32] {
        assert!(
            !refuses_posix_rename(&io::Error::from_raw_os_error(code)),
            "code {code}"
        );
    }
}

#[skuld::test]
fn a_win32_error_keeps_its_code_not_the_hresult() {
    // HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED) is 0x80070005.
    let e = win32_error(Error::from_hresult(HRESULT(0x8007_0005_u32 as i32)));
    assert_eq!(e.raw_os_error(), Some(5));
}

#[skuld::test]
fn a_non_win32_hresult_is_not_taken_for_an_os_error() {
    let e = win32_error(Error::from_hresult(HRESULT(0x8000_4005_u32 as i32))); // E_FAIL
    assert_eq!(e.raw_os_error(), None);
}
