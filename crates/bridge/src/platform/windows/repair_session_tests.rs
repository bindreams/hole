use super::*;

fn winapi_error(code: u32) -> windows_service::Error {
    windows_service::Error::Winapi(io::Error::from_raw_os_error(code as i32))
}

#[skuld::test]
fn only_the_already_running_answer_to_a_start_is_success() {
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DISABLED, ERROR_SERVICE_DOES_NOT_EXIST,
    };
    assert!(already_running(&winapi_error(ERROR_SERVICE_ALREADY_RUNNING.0)));
    // Anything else, a disabled start type included, is the start failing.
    for code in [
        ERROR_SERVICE_DISABLED.0,
        ERROR_SERVICE_DOES_NOT_EXIST.0,
        ERROR_ACCESS_DENIED.0,
    ] {
        assert!(!already_running(&winapi_error(code)), "{code}");
    }
    assert!(!already_running(&windows_service::Error::LaunchArgumentsNotSupported));
}

#[skuld::test]
fn an_unprivileged_read_asks_for_the_query_right_alone() {
    // The GUI reads the start type through an interactive user's access, which
    // the default service DACL grants as SERVICE_QUERY_CONFIG; asking for
    // anything more would fail there.
    assert_eq!(READ_ACCESS, ServiceAccess::QUERY_CONFIG);
    assert!(REPAIR_ACCESS.contains(READ_ACCESS));
    assert!(ENABLE_ACCESS.contains(ServiceAccess::START | ServiceAccess::CHANGE_CONFIG));
}
