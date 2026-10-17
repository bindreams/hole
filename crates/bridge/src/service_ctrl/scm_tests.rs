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

// winsvc.h: SERVICE_STOPPED 1, SERVICE_START_PENDING 2, SERVICE_STOP_PENDING 3,
// SERVICE_RUNNING 4, SERVICE_CONTINUE_PENDING 5, SERVICE_PAUSE_PENDING 6,
// SERVICE_PAUSED 7. Written out per variant so a new `ServiceState` variant
// breaks this match instead of going unpinned.
#[skuld::test]
fn raw_status_reports_every_service_state_as_its_winsvc_constant() {
    let wire = |state: ServiceState| {
        let expected = match state {
            ServiceState::Stopped => 1,
            ServiceState::StartPending => 2,
            ServiceState::StopPending => 3,
            ServiceState::Running => 4,
            ServiceState::ContinuePending => 5,
            ServiceState::PausePending => 6,
            ServiceState::Paused => 7,
        };
        let mut reported = status(ServiceExitCode::NO_ERROR, Duration::ZERO);
        reported.current_state = state;
        (raw_status(&reported).unwrap().dwCurrentState.0, expected)
    };
    for state in [
        ServiceState::Stopped,
        ServiceState::StartPending,
        ServiceState::StopPending,
        ServiceState::Running,
        ServiceState::ContinuePending,
        ServiceState::PausePending,
        ServiceState::Paused,
    ] {
        let (raw, expected) = wire(state);
        assert_eq!(raw, expected, "{state:?}");
    }
}
