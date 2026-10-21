use super::*;
use crate::platform::os::StartTypeLock;

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

#[skuld::test]
fn opening_for_a_repair_or_an_enable_waits_for_the_start_type_lock() {
    for access in [REPAIR_ACCESS, ENABLE_ACCESS, READ_ACCESS] {
        let lock = StartTypeLock::scratch("repair-open");
        let opened = lock.while_another_waits(|on_busy| RepairSession::open_noting(&lock, access, on_busy).is_ok());
        assert!(opened, "{access:?}");
        assert!(
            !lock.is_held_for_another_thread(),
            "released with the session: {access:?}"
        );
    }
}

#[skuld::test]
fn the_status_read_does_not_wait_and_says_a_change_is_in_progress_while_the_lock_is_held() {
    let lock = StartTypeLock::scratch("status-open");
    let held = lock.acquire().expect("hold the lock");
    let in_change = std::thread::scope(|s| {
        s.spawn(|| {
            matches!(
                RepairSession::open_unless_in_change(&lock, READ_ACCESS),
                Ok(Reading::InChange)
            )
        })
        .join()
        .expect("the reader's thread")
    });
    assert!(in_change);
    drop(held);
    let read = RepairSession::open_unless_in_change(&lock, READ_ACCESS);
    assert!(matches!(read, Ok(Reading::Session(_))), "free: the record decides");
    drop(read);
    assert!(!lock.is_held_for_another_thread(), "released with the session");
}

#[skuld::test]
fn a_repair_session_holds_the_start_type_lock_for_as_long_as_it_is_open() {
    let lock = StartTypeLock::scratch("repair-held");
    // A service every Windows has, opened for the read the GUI's status makes.
    let session = RepairSession::open_named_holding(lock.acquire().expect("take the lock"), "EventLog", READ_ACCESS)
        .expect("open the service")
        .expect("the service exists");
    assert!(lock.is_held_for_another_thread(), "held while the session is open");
    drop(session);
    assert!(!lock.is_held_for_another_thread(), "let go with the session");
}
