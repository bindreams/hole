use super::*;

use std::time::Duration;
use windows_service::service::{ServiceControlAccept, ServiceState, ServiceType};

fn status(exit_code: ServiceExitCode, wait_hint: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code,
        checkpoint: 7,
        wait_hint,
        process_id: Some(1234),
    }
}

// Expected values are the winsvc.h constants, written out: SERVICE_WIN32_OWN_PROCESS
// 0x10, SERVICE_STOP_PENDING 3, SERVICE_ACCEPT_STOP 0x1 | SERVICE_ACCEPT_SHUTDOWN 0x4.
#[skuld::test]
fn raw_status_carries_every_reported_field() {
    let raw = raw_status(&status(ServiceExitCode::Win32(5), Duration::from_millis(1500))).unwrap();
    assert_eq!(raw.dwServiceType.0, 0x10);
    assert_eq!(raw.dwCurrentState.0, 3);
    assert_eq!(raw.dwControlsAccepted, 0x1 | 0x4);
    assert_eq!(raw.dwWin32ExitCode, 5);
    assert_eq!(raw.dwServiceSpecificExitCode, 0);
    assert_eq!(raw.dwCheckPoint, 7);
    assert_eq!(raw.dwWaitHint, 1500);
}

#[skuld::test]
fn service_specific_exit_code_is_reported_under_error_service_specific_error() {
    let raw = raw_status(&status(ServiceExitCode::ServiceSpecific(42), Duration::ZERO)).unwrap();
    assert_eq!(raw.dwWin32ExitCode, 1066);
    assert_eq!(raw.dwServiceSpecificExitCode, 42);
}

#[skuld::test]
fn a_wait_hint_that_overflows_the_wire_field_is_an_error_not_a_panic() {
    let too_long = Duration::from_millis(u64::from(u32::MAX) + 1);
    let err = raw_status(&status(ServiceExitCode::NO_ERROR, too_long)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}
