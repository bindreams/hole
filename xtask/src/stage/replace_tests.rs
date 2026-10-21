use super::windows_impl::{refuses_posix_rename, target_name, win32_error};
use std::io;
use std::path::Path;
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

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

#[skuld::test]
fn a_bare_file_name_is_made_absolute_against_the_cwd() {
    let expected = format!(r"\\?\{}", std::env::current_dir().unwrap().join("hole").display());
    assert_eq!(target_name(Path::new("hole")).unwrap(), wide(&expected));
}

#[skuld::test]
fn a_path_over_max_path_is_verbatim() {
    let dir = "a".repeat(300);
    assert_eq!(
        target_name(Path::new(&format!(r"C:\{dir}\hole"))).unwrap(),
        wide(&format!(r"\\?\C:\{dir}\hole"))
    );
}

#[skuld::test]
fn a_unc_path_gets_the_verbatim_unc_prefix() {
    assert_eq!(
        target_name(Path::new(r"\\server\share\dir\hole")).unwrap(),
        wide(r"\\?\UNC\server\share\dir\hole")
    );
}

#[skuld::test]
fn dot_dot_is_resolved_before_the_prefix_is_added() {
    assert_eq!(target_name(Path::new(r"C:\a\..\hole")).unwrap(), wide(r"\\?\C:\hole"));
}

#[skuld::test]
fn a_verbatim_path_is_left_as_it_is() {
    assert_eq!(
        target_name(Path::new(r"\\?\C:\dir\hole")).unwrap(),
        wide(r"\\?\C:\dir\hole")
    );
}
